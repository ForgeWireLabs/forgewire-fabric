//! ForgeWire Fabric native hub daemon entry point.
//!
//! Usage:
//!     forgewire-hub [--host 0.0.0.0] [--port 8765] [--db-path hub.sqlite3] [--token-file hub.token]
//!
//! Environment variables (same as Python hub):
//!     FORGEWIRE_HUB_TOKEN_FILE  — path to bearer token file
//!     FORGEWIRE_HUB_DB_PATH     — SQLite database path
//!     FORGEWIRE_HUB_HOST        — bind host (default 127.0.0.1)
//!     FORGEWIRE_HUB_PORT        — bind port (default 8765)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::middleware;
use axum::routing::get;
use axum::Router;
use fabric_hub::auth::require_bearer;
use fabric_hub::routes::{audit, health, runners, tasks};
use fabric_hub::state::HubState;
use fabric_policy::{DispatchGate, FabricPolicy};
use fabric_store::SchemaStore;
use fabric_store_sqlite::SqliteStore;
use tracing::info;

const PROTOCOL_VERSION: i64 = 3;
const PACKAGE_VERSION: &str = "0.5.0-rust";

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
    let db_path = std::env::var("FORGEWIRE_HUB_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                PathBuf::from(r"C:\ProgramData\forgewire\hub.sqlite3")
            } else {
                PathBuf::from("/var/lib/forgewire/hub.sqlite3")
            }
        });
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

    // Initialize store
    let store = SqliteStore::open(&db_path).unwrap_or_else(|e| {
        eprintln!("cannot open database {}: {e}", db_path.display());
        std::process::exit(1);
    });
    store.init_schema().await.unwrap_or_else(|e| {
        eprintln!("schema init failed: {e}");
        std::process::exit(1);
    });
    store.run_additive_migrations().await.unwrap_or_else(|e| {
        eprintln!("migration failed: {e}");
        std::process::exit(1);
    });
    let store = Arc::new(store);

    let state = Arc::new(HubState {
        store,
        token,
        started_at: Instant::now(),
        started_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
        gate: DispatchGate::new(FabricPolicy::default()),
        host: host.clone(),
        port,
        protocol_version: PROTOCOL_VERSION,
        package_version: PACKAGE_VERSION.into(),
        sidecar_integrity: "trusted_bearer".into(),
    });

    // Public routes (no auth)
    let public = Router::new().route("/healthz", get(health::healthz));

    // Authenticated routes
    let authed = Router::new()
        .route("/tasks", get(tasks::list_tasks))
        .route("/tasks/{task_id}", get(tasks::get_task))
        .route("/runners", get(runners::list_runners))
        .route("/audit/tasks/{task_id}", get(audit::audit_for_task))
        .route("/audit/tail", get(audit::audit_tail))
        .layer(middleware::from_fn_with_state(state.clone(), require_bearer));

    let app = Router::new()
        .merge(public)
        .merge(authed)
        .with_state(state);

    let addr: SocketAddr = format!("{host}:{port}").parse().unwrap_or_else(|e| {
        eprintln!("invalid bind address {host}:{port}: {e}");
        std::process::exit(1);
    });

    info!("forgewire-hub (native Rust) listening on {addr}");
    info!("protocol_version={PROTOCOL_VERSION} sidecar_integrity=trusted_bearer");

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
