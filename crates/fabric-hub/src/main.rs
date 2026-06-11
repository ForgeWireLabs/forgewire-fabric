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
use axum::routing::{delete, get, post, put};
use axum::Router;
use fabric_hub::auth::require_bearer;
use fabric_hub::routes::{admin, agents, approvals, audit, cluster, cost, dispatchers, health, labels, runners, secrets, streams, tasks};
use fabric_hub::state::HubState;
use fabric_policy::{BudgetPolicy, DispatchGate, FabricPolicy};
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
    let voters = map.as_object()
        .map(|o| o.values()
            .filter(|v| v.get("voter").and_then(|b| b.as_bool()).unwrap_or(false))
            .count())
        .unwrap_or(1);
    (voters as u16, nodes as u16)
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
    client.get(url).send().await
        .map(|r| r.status().as_u16() < 500)
        .unwrap_or(false)
}

fn start_rqlite_service() {
    #[cfg(target_os = "windows")]
    {
        // Try ForgeWireRqlite first (primary node), then numbered nodes.
        for svc in &["ForgeWireRqlite", "ForgeWireRqliteNode1", "ForgeWireRqliteNode2"] {
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
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let host = std::env::var("FORGEWIRE_HUB_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("FORGEWIRE_HUB_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8765);
    let token_file = std::env::var("FORGEWIRE_HUB_TOKEN_FILE").unwrap_or_else(|_| {
        if cfg!(windows) {
            r"C:\ProgramData\forgewire\hub.token".into()
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
        let b_rqlite_host = std::env::var("FORGEWIRE_HUB_RQLITE_HOST")
            .unwrap_or_else(|_| "127.0.0.1".into());
        let b_rqlite_http: u16 = std::env::var("FORGEWIRE_HUB_RQLITE_PORT")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(4001);
        let b_rqlite_raft: u16 = std::env::var("FORGEWIRE_HUB_RQLITE_RAFT_PORT")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(4002);
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
                if let Err(e) = fabric_beacon::serve_once(advert, beacon_port) {
                    tracing::warn!("beacon cycle failed: {e}");
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        });
        tracing::info!("discovery beacon broadcasting on udp/{beacon_port} (includes rqlite cluster info)");
    }

    // ── rqlite backend (only option) ──────────────────────────────────────
    let rqlite_host = std::env::var("FORGEWIRE_HUB_RQLITE_HOST")
        .unwrap_or_else(|_| "127.0.0.1".into());
    let rqlite_port: u16 = std::env::var("FORGEWIRE_HUB_RQLITE_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4001);
    let consistency = std::env::var("FORGEWIRE_HUB_RQLITE_CONSISTENCY")
        .unwrap_or_else(|_| "strong".into());

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
            .to_lowercase() + "-rqlite";
        // Detect bootstrap: this node is a voter AND the only node in the cluster.
        let (voters, total_nodes) = probe_rqlite_cluster(&format!("http://{rqlite_host}:{rqlite_port}"));
        let is_bootstrap = voters == 1 && total_nodes == 1;
        if is_bootstrap {
            info!(node = %local_node_id, "bootstrap node detected — will record as preferred leader");
        }
        tokio::spawn(async move {
            cluster_manager::run(cm_host, cm_port, local_node_id, is_bootstrap).await;
        });
    }

    let store: Arc<dyn FabricStore> = Arc::new(rqlite);

    let stream_profile = DurabilityProfile::from_str(
        &std::env::var("FORGEWIRE_HUB_STREAM_PROFILE").unwrap_or_default()
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

    let state = Arc::new(HubState {
        store,
        token,
        started_at: Instant::now(),
        started_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
        gate: {
            // Load policy from FORGEWIRE_HUB_POLICY_FILE if set.
            // If the file does not exist, a safe annotated default is written
            // automatically so operators can tune from the first dispatch.
            let policy = if let Ok(path) = std::env::var("FORGEWIRE_HUB_POLICY_FILE") {
                match FabricPolicy::load_or_create(&path) {
                    Ok(p) => {
                        info!(path = %path, "policy loaded");
                        p
                    }
                    Err(e) => {
                        tracing::warn!(path = %path, error = %e, "policy load failed — using permissive default");
                        FabricPolicy::default()
                    }
                }
            } else {
                tracing::info!("FORGEWIRE_HUB_POLICY_FILE not set — using permissive default (no file written)");
                FabricPolicy::default()
            };
            DispatchGate::new(policy)
        },
        budget_caps,
        host: host.clone(),
        port,
        protocol_version: PROTOCOL_VERSION,
        package_version: PACKAGE_VERSION.into(),
        sidecar_integrity: "trusted_bearer".into(),
        backend: format!("rqlite:{rqlite_host}:{rqlite_port}"),
        stream_buffer: Arc::new(StreamBuffer::new(stream_profile)),
        input_queues: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
    });

    // Public routes (no auth)
    let public = Router::new()
        .route("/healthz", get(health::healthz));

    // Authenticated routes
    let authed = Router::new()
        // --- Tasks ---
        .route("/tasks", get(tasks::list_tasks))
        .route("/tasks", post(tasks::dispatch_task))
        .route("/tasks/v2", post(tasks::dispatch_task_signed))
        .route("/tasks/claim-loom", post(tasks::claim_task_loom))
        .route("/tasks/claim-fabric", post(tasks::claim_task_fabric))
        .route("/tasks/{task_id}", get(tasks::get_task))
        // --- Task state & streams ---
        .route("/tasks/{task_id}/start", post(streams::mark_running))
        .route("/tasks/{task_id}/cancel", post(streams::cancel_task))
        .route("/tasks/{task_id}/progress", post(streams::append_progress))
        .route("/tasks/{task_id}/stream", post(streams::append_stream))
        .route("/tasks/{task_id}/stream", get(streams::read_stream))
        .route("/tasks/{task_id}/stream/bulk", post(streams::append_stream_bulk))
        .route("/tasks/{task_id}/result", post(streams::submit_result))
        .route("/tasks/{task_id}/notes", post(streams::post_note))
        .route("/tasks/{task_id}/notes", get(streams::read_notes))
        .route("/tasks/{task_id}/intent", post(tasks::evaluate_intent))
        .route("/tasks/{task_id}/input", post(streams::post_task_input))
        .route("/tasks/{task_id}/input", get(streams::get_task_input))
        // --- Runners ---
        .route("/runners", get(runners::list_runners))
        .route("/runners/register", post(runners::register_runner))
        .route("/runners/{runner_id}/heartbeat", post(runners::heartbeat_runner))
        .route("/runners/{runner_id}/drain", post(runners::drain_runner))
        .route("/runners/{runner_id}/drain-by-dispatcher", post(runners::drain_runner_by_dispatcher))
        .route("/runners/{runner_id}/undrain-by-dispatcher", post(runners::undrain_runner_by_dispatcher))
        .route("/runners/{runner_id}", delete(runners::deregister_runner))
        // --- Dispatchers ---
        .route("/dispatchers/register", post(dispatchers::register_dispatcher))
        .route("/dispatchers", get(dispatchers::list_dispatchers))
        .route("/dispatchers/{dispatcher_id}", delete(dispatchers::deregister_dispatcher))
        // --- Approvals ---
        .route("/approvals", get(approvals::list_approvals))
        .route("/approvals/{approval_id}", get(approvals::get_approval))
        .route("/approvals/{approval_id}/approve", post(approvals::approve_approval))
        .route("/approvals/{approval_id}/deny", post(approvals::deny_approval))
        // --- Agents + capabilities (Phase 2.8 M2.8.2) ---
        .route("/agents", get(agents::list_agents))
        .route("/capabilities/{kind}/{name}", get(agents::get_capability))
        // --- Cluster / hosts ---
        .route("/cluster/health", get(cluster::cluster_health))
        .route("/hosts", get(cluster::list_hosts))
        // --- Audit ---
        .route("/audit/tasks/{task_id}", get(audit::audit_for_task))
        .route("/audit/tail", get(audit::audit_tail))
        .route("/audit/day/{day}", get(cluster::audit_day))
        // --- Self-update (M2.5.10) ---
        .route("/admin/binaries/manifest", get(admin::binaries_manifest))
        .route("/admin/binaries/{name}", get(admin::binary_download))
        .route("/admin/update", post(admin::trigger_update))
        // --- Cost (M2.5.2 — rqlite only) ---
        .route("/cost/summary", get(cost::cost_summary))
        .route("/cost/records", get(cost::cost_records))
        .route("/cost/budget", get(cost::cost_budget))
        // --- Secrets ---
        .route("/secrets", post(secrets::put_or_rotate_secret))
        .route("/secrets", get(secrets::list_secrets))
        .route("/secrets/{name}", delete(secrets::delete_secret))
        // --- Labels ---
        .route("/labels", get(labels::get_labels))
        .route("/labels/hub", put(labels::set_hub_label))
        .route("/labels/runners/{runner_id}", put(labels::set_runner_label))
        .route("/labels/hosts/{hostname}", put(labels::set_host_label))
        .route("/hosts/roles", post(labels::set_host_role))
        .layer(middleware::from_fn_with_state(state.clone(), require_bearer));

    let app = Router::new()
        .merge(public)
        .merge(authed)
        .with_state(state);

    let addr: SocketAddr = format!("{host}:{port}").parse().unwrap_or_else(|e| {
        eprintln!("invalid bind address {host}:{port}: {e}");
        std::process::exit(1);
    });

    info!("forgewire-hub (Rust) v{PACKAGE_VERSION} listening on {addr}");
    info!("backend=rqlite protocol_version={PROTOCOL_VERSION} sidecar_integrity=trusted_bearer");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| {
        eprintln!("bind failed on {addr}: {e}");
        std::process::exit(1);
    });
    axum::serve(listener, app)
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

