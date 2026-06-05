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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use fabric_hub::auth::require_bearer;
use fabric_hub::routes::{admin, approvals, audit, cluster, cost, dispatchers, health, labels, runners, secrets, streams, tasks};
use fabric_hub::state::HubState;
use fabric_policy::{BudgetPolicy, DispatchGate, FabricPolicy};
use fabric_store::{FabricStore, SchemaStore};
use fabric_streams::{DurabilityProfile, StreamBuffer};
use reqwest::Client as ReqwestClient;
use tracing::{info, warn};

const PROTOCOL_VERSION: i64 = 3;
const PACKAGE_VERSION: &str = "0.7.1";

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
        let advert = fabric_beacon::HubAdvert {
            hub_id: hostname.clone(),
            http_port: port,
            proto: PROTOCOL_VERSION,
            name: hostname,
            token_hash: fabric_beacon::token_hash(&token),
        };
        std::thread::spawn(move || {
            if let Err(e) = fabric_beacon::serve(advert, beacon_port, std::time::Duration::from_secs(5)) {
                tracing::warn!("discovery beacon disabled: cannot bind UDP {beacon_port}: {e}");
            }
        });
        tracing::info!("discovery beacon broadcasting on udp/{beacon_port}");
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
        gate: DispatchGate::new(FabricPolicy::default()),
        budget_caps,
        host: host.clone(),
        port,
        protocol_version: PROTOCOL_VERSION,
        package_version: PACKAGE_VERSION.into(),
        sidecar_integrity: "trusted_bearer".into(),
        backend: format!("rqlite:{rqlite_host}:{rqlite_port}"),
        stream_buffer: Arc::new(StreamBuffer::new(stream_profile)),
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
        .route("/tasks/claim-v2", post(tasks::claim_task_v2))
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

