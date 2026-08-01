//! ForgeWire Fabric native hub daemon entry point.
//!
//! rqlite is the only supported backend and is a required fabric dependency.
//! On startup the hub will attempt to start the rqlite service if it is not
//! already running (NSSM on Windows, systemd on Linux).
//!
//! rqlite connection:
//!     FORGEWIRE_HUB_RQLITE_HOST      — rqlite host (default: 127.0.0.1)
//!     FORGEWIRE_HUB_RQLITE_PORT      — rqlite port (default: 4001)
//!     FORGEWIRE_HUB_RQLITE_CONSISTENCY — "none"|"weak"|"strong" (default: strong)
//!
//! Service config:
//!     FORGEWIRE_HUB_TOKEN_FILE       — bearer token file
//!     FORGEWIRE_HUB_HOST             — bind host (default: 127.0.0.1)
//!     FORGEWIRE_HUB_PORT             — bind port (default: 8765)
//!
//! Stream durability profile:
//!     FORGEWIRE_HUB_STREAM_PROFILE   — "strict" | "balanced" | "throughput" (default: strict)
//!     FORGEWIRE_HUB_DAILY_BUDGET_USD — native daily cost cap (default: none)
//!     FORGEWIRE_HUB_WEEKLY_BUDGET_USD — native weekly cost cap (default: none)
//!       strict     — every line written to store before HTTP response (default, strongest)
//!       balanced   — buffer 50 lines, flush to store as a batch
//!       throughput — buffer 200 lines, flush to store as a batch (operator opt-in only)

mod cluster_manager;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::middleware;
use axum::Router;
use fabric_hub::auth::require_bearer;
use fabric_hub::routes::{
    accounts, admin, agents, approvals, audit, authn, cluster, cost, dispatchers, health, history,
    labels, policy, runners, secrets, settings, setup, state, streams, tasks, webauthn_bridge,
    webauthn_doctor, whoami,
};
use fabric_hub::state::HubState;
use fabric_policy::{BudgetPolicy, DispatchGate, FabricPolicy};
use fabric_secrets::SecretBroker;
use fabric_store::{FabricStore, SchemaStore};
use fabric_streams::{DurabilityProfile, StreamBuffer};
use reqwest::Client as ReqwestClient;
use tracing::{info, warn};

const PROTOCOL_VERSION: i64 = 4;
const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Probe the rqlite cluster for voter + total node counts.
/// Returns (voters, total_nodes). Falls back to (1, 1) if unreachable.
fn probe_rqlite_cluster(rqlite_url: &str) -> (u16, u16) {
    let Ok(resp) = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .and_then(|c| c.get(format!("{rqlite_url}/nodes?nonvoters")).send())
    else {
        return (1, 1);
    };
    let Ok(map) = resp.json::<serde_json::Value>() else {
        return (1, 1);
    };
    let nodes = map.as_object().map(|o| o.len()).unwrap_or(1);
    let voters = map
        .as_object()
        .map(|o| {
            o.values()
                .filter(|v| v.get("voter").and_then(|b| b.as_bool()).unwrap_or(false))
                .count()
        })
        .unwrap_or(1);
    // A real rqlite cluster never has anywhere near u16::MAX nodes; saturate
    // rather than blindly truncate on the pathological case.
    (
        u16::try_from(voters).unwrap_or(u16::MAX),
        u16::try_from(nodes).unwrap_or(u16::MAX),
    )
}

/// Ensure rqlite is reachable, starting the OS service if needed.
///
/// Probes `http://{host}:{port}/status`. If unreachable, attempts to start:
///   - Windows: `nssm start ForgeWireRqlite`
///   - Linux/macOS: `systemctl start forgewire-rqlite` (falls back to `launchctl`)
///
/// Waits up to 30 s for the service to become ready. Hard-exits if it never does.
async fn ensure_rqlite_running(host: &str, port: u16) {
    let url = format!("http://{host}:{port}/status");
    if is_rqlite_reachable(&url).await {
        return;
    }
    info!("rqlite not reachable on {host}:{port} — attempting to start service");
    start_rqlite_service();
    // Wait up to 30 s in 1 s increments.
    for attempt in 1..=30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if is_rqlite_reachable(&url).await {
            info!("rqlite ready after {attempt}s");
            return;
        }
    }
    eprintln!("FATAL: rqlite did not become ready within 30 s after service start.");
    eprintln!("  Check: nssm status ForgeWireRqlite  (Windows)");
    eprintln!("         systemctl status forgewire-rqlite  (Linux)");
    eprintln!("  rqlite must be running — it is a required ForgeWire Fabric dependency.");
    eprintln!("  Reinstall with: install-fabric.ps1 (Windows) or install-fabric.sh (Linux)");
    std::process::exit(1);
}

async fn is_rqlite_reachable(url: &str) -> bool {
    let Ok(client) = ReqwestClient::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    client
        .get(url)
        .send()
        .await
        .map(|r| r.status().as_u16() < 500)
        .unwrap_or(false)
}

fn start_rqlite_service() {
    #[cfg(target_os = "windows")]
    {
        // Try ForgeWireRqlite first (primary node), then numbered nodes.
        for svc in &[
            "ForgeWireRqlite",
            "ForgeWireRqliteNode1",
            "ForgeWireRqliteNode2",
        ] {
            let status = std::process::Command::new("nssm")
                .args(["start", svc])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if status.map(|s| s.success()).unwrap_or(false) {
                info!("started rqlite via nssm service {svc}");
                return;
            }
        }
        warn!("nssm start ForgeWireRqlite* did not succeed — rqlite may already be starting");
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["start", "forgewire-rqlite"])
            .status();
        info!("attempted systemctl start forgewire-rqlite");
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("launchctl")
            .args(["start", "com.forgewire.rqlite"])
            .status();
        info!("attempted launchctl start com.forgewire.rqlite");
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let host = std::env::var("FORGEWIRE_HUB_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("FORGEWIRE_HUB_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8765);
    let token_file = std::env::var("FORGEWIRE_HUB_TOKEN_FILE").unwrap_or_else(|_| {
        // Platform-appropriate fallback, only consulted when the installer
        // (nssm-install-hub.ps1 / the systemd unit) hasn't already passed
        // FORGEWIRE_HUB_TOKEN_FILE explicitly, which every shipped installer
        // does -- so this never relocates an already-configured install.
        if cfg!(windows) {
            r"C:\ProgramData\forgewire\hub.token".into()
        } else if cfg!(target_os = "macos") {
            std::env::var("HOME")
                .map(|home| format!("{home}/Library/Application Support/forgewire/hub.token"))
                .unwrap_or_else(|_| "/var/lib/forgewire/hub.token".into())
        } else {
            "/var/lib/forgewire/hub.token".into()
        }
    });
    let token = std::fs::read_to_string(&token_file)
        .unwrap_or_else(|e| {
            eprintln!("cannot read token file {token_file}: {e}");
            std::process::exit(1);
        })
        .trim()
        .to_owned();

    if token.len() < 16 {
        eprintln!("hub token must be >= 16 characters");
        std::process::exit(1);
    }
    tracing::warn!(
        "legacy cluster bearer enabled as the explicit dispatcher+runner+observer compatibility bundle; split into role-separated tokens before migrating approver/reviewer clients"
    );

    // ── LAN discovery beacon ──────────────────────────────────────────────
    // Broadcast our presence so runners and the VS Code extension find this hub
    // by identity, not a pinned address. Survives DHCP/subnet changes; the token
    // is never sent (only its hash). Opt out with FORGEWIRE_BEACON_DISABLE=1.
    if std::env::var("FORGEWIRE_BEACON_DISABLE").ok().as_deref() != Some("1") {
        let beacon_port: u16 = std::env::var("FORGEWIRE_BEACON_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(fabric_beacon::DEFAULT_BEACON_PORT);
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "forgewire-hub".into());

        // Capture rqlite connection details for the beacon (so joining nodes can
        // auto-discover the cluster without a pre-configured join address).
        let b_rqlite_host =
            std::env::var("FORGEWIRE_HUB_RQLITE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let b_rqlite_http: u16 = std::env::var("FORGEWIRE_HUB_RQLITE_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4001);
        let b_rqlite_raft: u16 = std::env::var("FORGEWIRE_HUB_RQLITE_RAFT_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4002);
        let b_token_hash = fabric_beacon::token_hash(&token);
        let b_hostname = hostname.clone();
        let b_hub_port = port;

        std::thread::spawn(move || {
            // Probe rqlite cluster state every beacon cycle and embed live voter /
            // node counts so installing machines can make the right join decision.
            let rqlite_url = format!("http://{b_rqlite_host}:{b_rqlite_http}");
            loop {
                let (voters, nodes) = probe_rqlite_cluster(&rqlite_url);
                let advert = fabric_beacon::HubAdvert {
                    hub_id: b_hostname.clone(),
                    http_port: b_hub_port,
                    proto: PROTOCOL_VERSION,
                    name: b_hostname.clone(),
                    token_hash: b_token_hash.clone(),
                    raft_port: b_rqlite_raft,
                    rqlite_http_port: b_rqlite_http,
                    rqlite_voters: voters,
                    rqlite_nodes: nodes,
                };
                if let Err(e) = fabric_beacon::serve_once(&advert, beacon_port) {
                    tracing::warn!("beacon cycle failed: {e}");
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        });
        tracing::info!(
            "discovery beacon broadcasting on udp/{beacon_port} (includes rqlite cluster info)"
        );
    }

    // ── rqlite backend (only option) ──────────────────────────────────────
    let rqlite_host =
        std::env::var("FORGEWIRE_HUB_RQLITE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let rqlite_port: u16 = std::env::var("FORGEWIRE_HUB_RQLITE_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4001);
    let consistency =
        std::env::var("FORGEWIRE_HUB_RQLITE_CONSISTENCY").unwrap_or_else(|_| "strong".into());

    let rqlite = fabric_store_rqlite::RqliteStore::new(&rqlite_host, rqlite_port, &consistency);

    // rqlite is a required fabric dependency. If it is not reachable, attempt
    // to start the NSSM service (Windows) or systemd unit (Linux/macOS) and
    // wait up to 30 s for it to become ready. Hard-exit if it never comes up.
    ensure_rqlite_running(&rqlite_host, rqlite_port).await;

    rqlite.init_schema().await.unwrap_or_else(|e| {
        eprintln!("rqlite schema init failed after service start attempt: {e}");
        eprintln!("  host={rqlite_host} port={rqlite_port}");
        eprintln!("  Check logs: nssm status ForgeWireRqlite");
        std::process::exit(1);
    });
    rqlite.run_additive_migrations().await.unwrap_or_else(|e| {
        eprintln!("rqlite migration failed: {e}");
        std::process::exit(1);
    });
    // 114C human-account tables (additive, idempotent -- see
    // `init_human_accounts_schema`'s own doc comment). Without this call the
    // human_* tables never exist on a real deployment and every account
    // route fails closed as AuthServiceUnavailable; only the ephemeral-rqlite
    // test harnesses were calling it directly until now.
    rqlite
        .init_human_accounts_schema()
        .await
        .unwrap_or_else(|e| {
            eprintln!("rqlite human-accounts schema init failed: {e}");
            std::process::exit(1);
        });
    info!("backend=rqlite host={rqlite_host} port={rqlite_port} consistency={consistency}");

    // ── Cluster topology manager ──────────────────────────────────────────────
    // Runs in the background: enforces the voter/standby rule and triggers
    // periodic snapshots to keep the Raft log compact.
    //   1-2 nodes → 1 voter (stable leader) + 0-1 non-voter (hot standby)
    //   3+ nodes  → all voters (full Raft quorum)
    //
    // is_bootstrap: true when this node is the sole voter (i.e. it either
    // just bootstrapped a new cluster, or was already the only voter).
    // This marks it as the preferred leader so 3+-node clusters restore
    // leadership to it after a failover.
    {
        let cm_host = rqlite_host.clone();
        let cm_port = rqlite_port;
        let local_node_id = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".into())
            .to_lowercase()
            + "-rqlite";
        // Detect bootstrap: this node is a voter AND the only node in the cluster.
        let (voters, total_nodes) =
            probe_rqlite_cluster(&format!("http://{rqlite_host}:{rqlite_port}"));
        let is_bootstrap = voters == 1 && total_nodes == 1;
        if is_bootstrap {
            info!(node = %local_node_id, "bootstrap node detected — will record as preferred leader");
        }
        tokio::spawn(async move {
            cluster_manager::run(cm_host, cm_port, local_node_id, is_bootstrap).await;
        });
    }

    let store: Arc<dyn FabricStore> = Arc::new(rqlite);

    // Secret-key readiness is deliberately not a startup requirement: health,
    // topology, task inspection, and other unrelated control-plane flows stay
    // available. Secret mutation/claim and potentially secret-bearing telemetry
    // fail closed with structured errors until the provider is usable.
    let secret_broker = SecretBroker::from_env().unwrap_or_else(|error| {
        warn!(error = %error, "secret provider configuration unavailable; secret operations will fail closed");
        SecretBroker::new(Arc::new(fabric_secrets::UnavailableKeyProvider::new(error.to_string())))
    });
    match secret_broker.check_key() {
        Ok(()) => info!(
            provider = secret_broker.provider_name(),
            "secret broker ready"
        ),
        Err(error) => {
            warn!(provider = secret_broker.provider_name(), error = %error, "secret broker unavailable; secret operations will fail closed");
        }
    }

    let stream_profile = DurabilityProfile::from_profile_str(
        &std::env::var("FORGEWIRE_HUB_STREAM_PROFILE").unwrap_or_default(),
    );
    info!("stream_profile={}", stream_profile.as_str());

    // Native cost caps (M2.5.3) — Rust owns budget enforcement; read from env.
    // Absent vars mean "no cap". Enforced against the persistent budget_state
    // accumulators on every dispatch.
    let budget_caps = BudgetPolicy {
        daily_cost_cap_usd: std::env::var("FORGEWIRE_HUB_DAILY_BUDGET_USD")
            .ok()
            .and_then(|v| v.parse().ok()),
        weekly_cost_cap_usd: std::env::var("FORGEWIRE_HUB_WEEKLY_BUDGET_USD")
            .ok()
            .and_then(|v| v.parse().ok()),
        ..Default::default()
    };
    if budget_caps.has_cost_caps() {
        tracing::info!(
            daily = ?budget_caps.daily_cost_cap_usd,
            weekly = ?budget_caps.weekly_cost_cap_usd,
            "native budget enforcement enabled"
        );
    }

    // Preserve one authoritative startup snapshot for both enforcement and the
    // authenticated read-only /policy surface.
    let policy = if let Ok(path) = std::env::var("FORGEWIRE_HUB_POLICY_FILE") {
        match FabricPolicy::load_or_create(&path) {
            Ok(policy) => {
                info!(path = %path, "policy loaded");
                policy
            }
            Err(error) => {
                tracing::warn!(path = %path, error = %error, "policy load failed - using permissive default");
                FabricPolicy::default()
            }
        }
    } else {
        tracing::info!(
            "FORGEWIRE_HUB_POLICY_FILE not set - using permissive default (no file written)"
        );
        FabricPolicy::default()
    };
    let effective_policy = serde_json::to_value(&policy).unwrap_or_else(|_| serde_json::json!({}));

    // Bootstrap secret (optional): if set, `POST /auth/bootstrap` requires
    // both a loopback source address AND this shared secret in the
    // `X-Forgewire-Bootstrap-Secret` header. If unset, loopback alone is
    // sufficient -- the plan's "protected by a one-time bootstrap secret or
    // local console proof" alternative. Read from a file, matching the hub
    // token's own file-based distribution pattern (never an env var literal,
    // which would linger in shell history/process listings).
    // WebAuthn relying-party instance (114C.6): built once at startup from
    // the effective `auth.passkeys` settings, never a startup failure --
    // `None` on any misconfiguration, matching `bootstrap_secret`/`token`'s
    // own fail-closed-per-feature (not fail-closed-whole-hub) pattern above.
    // Read the effective settings snapshot once, then derive both the
    // WebAuthn instance and the step-up freshness window from it (both are
    // `auth.*` settings). A missing/invalid document degrades each to its
    // own safe default, never a startup failure.
    let effective_auth = match store.get_settings_document().await {
        Ok(document) => fabric_settings::SettingsSnapshot::new(
            document.revision,
            document.value,
            serde_json::json!({}),
        )
        .map(|snapshot| snapshot.effective)
        .unwrap_or_else(|error| {
            warn!(error = %error, "settings document invalid; auth features use defaults");
            serde_json::json!({})
        }),
        Err(error) => {
            warn!(error = %error, "settings document unreadable at startup; auth features use defaults");
            serde_json::json!({})
        }
    };
    // 114D D.1: prefer the realm's founding identity over legacy per-node
    // `auth.passkeys` settings when a realm has been established -- this is
    // what closes the per-node relying-party trap (114D sec 5), since every
    // node then builds its verifier from the same replicated rp_id/origins
    // instead of its own local settings document. `None` on a pre-genesis
    // cluster or a read failure degrades to the settings fallback, matching
    // this whole block's existing "never a startup failure" discipline.
    let realm_identity = fabric_accounts::repository::RealmRepository::get_realm_identity(&*store)
        .await
        .unwrap_or_else(|error| {
            warn!(error = %error, "realm identity unreadable at startup; falling back to auth.passkeys settings");
            None
        });
    let webauthn = fabric_hub::webauthn::build_from_realm_or_settings(
        realm_identity.as_ref(),
        &effective_auth,
    );
    if webauthn.is_some() {
        if realm_identity.is_some() {
            info!("passkeys enabled (WebAuthn relying party from realm identity)");
        } else {
            info!("passkeys enabled (WebAuthn relying party configured)");
        }
    } else {
        info!("passkeys disabled or unconfigured (auth.passkeys)");
    }
    // Default 10, schema-capped at 10 -- "permit policy to shorten but not
    // silently lengthen security limits beyond the reviewed maximum."
    let step_up_freshness_minutes = effective_auth
        .pointer("/auth/sessions/step_up_freshness_minutes")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(10);

    let bootstrap_secret = std::env::var("FORGEWIRE_HUB_BOOTSTRAP_SECRET_FILE")
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    let state = Arc::new(HubState {
        store,
        secrets: secret_broker,
        token,
        bootstrap_secret,
        webauthn,
        step_up_freshness_minutes,
        started_at: Instant::now(),
        started_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
        gate: DispatchGate::new(policy),
        effective_policy,
        budget_caps,
        host: host.clone(),
        port,
        protocol_version: PROTOCOL_VERSION,
        package_version: PACKAGE_VERSION.into(),
        sidecar_integrity: "trusted_bearer".into(),
        backend: format!("rqlite:{rqlite_host}:{rqlite_port}"),
        stream_buffer: Arc::new(StreamBuffer::new(stream_profile)),
        input_queues: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        forgelink: {
            let cfg = fabric_hub::forgelink::ForgeLinkConfig::from_env();
            if cfg.enabled() {
                info!(channel = %cfg.channel_id, "ForgeLink HITL routing enabled (AGH-028)");
            } else {
                tracing::info!(
                    "ForgeLink HITL routing disabled — using Fabric's built-in approval pane"
                );
            }
            cfg
        },
        history_status: Arc::new(tokio::sync::Mutex::new(serde_json::json!({
            "health": "disabled",
            "mode": "thin",
            "exported": 0,
        }))),
    });

    history::spawn_export_loop(Arc::clone(&state));

    // Public routes (no auth). `authn::public_router()` covers bootstrap/
    // login/refresh -- a caller with no credential yet (or a possibly-
    // expired one, for refresh) cannot reach an authenticated-tier route to
    // obtain one, so these cannot sit behind `require_bearer` below.
    let public = Router::new()
        .merge(health::router())
        .merge(authn::public_router())
        // The WebAuthn bridge page is public by construction: it is opened in
        // the system browser with no credential, and performs its own
        // authentication inside the page (114C.6 Slice 5b).
        .merge(webauthn_bridge::public_router())
        // Deployment diagnostic, not account data -- see webauthn_doctor.rs's
        // own doc comment for why this is safe to leave unauthenticated
        // (114C.6 Slice 7).
        .merge(webauthn_doctor::public_router())
        // The genesis setup backend (114D D.2): unreachable behind
        // require_bearer by construction (no credential exists yet), and
        // additionally loopback-gated at the handler level -- see
        // routes::setup's own module doc comment.
        .merge(setup::public_router());

    // Authenticated routes
    let authed = Router::new()
        .merge(tasks::router())
        .merge(streams::router())
        .merge(tasks::intent_router())
        .merge(streams::input_router())
        .merge(state::router())
        .merge(runners::router())
        .merge(dispatchers::router())
        .merge(approvals::router())
        .merge(agents::router())
        .merge(cluster::router())
        .merge(audit::router())
        .merge(cluster::audit_router())
        .merge(admin::router())
        .merge(cost::router())
        .merge(policy::router())
        .merge(history::router())
        .merge(secrets::router())
        .merge(settings::router())
        .merge(labels::router())
        .merge(accounts::router())
        .merge(authn::router())
        .merge(whoami::router())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));

    let app = Router::new().merge(public).merge(authed).with_state(state);

    let addr: SocketAddr = format!("{host}:{port}").parse().unwrap_or_else(|e| {
        eprintln!("invalid bind address {host}:{port}: {e}");
        std::process::exit(1);
    });

    info!("forgewire-hub (Rust) v{PACKAGE_VERSION} listening on {addr}");
    info!("backend=rqlite protocol_version={PROTOCOL_VERSION} sidecar_integrity=trusted_bearer");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("bind failed on {addr}: {e}");
            std::process::exit(1);
        });
    // `into_make_service_with_connect_info` (rather than plain `app`) so
    // `POST /auth/bootstrap` can extract the real peer address via
    // `ConnectInfo<SocketAddr>` and enforce its loopback-only guard.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap_or_else(|e| {
        eprintln!("server error: {e}");
        std::process::exit(1);
    });

    info!("forgewire-hub shutdown complete");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.ok();
    info!("received shutdown signal");
}
