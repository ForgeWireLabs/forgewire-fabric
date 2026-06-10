//! ForgeWire Loom runner entry point.
//!
//! All configuration via environment variables (NSSM sets these).
//! See `LoomConfig::from_env()` for the full list.
//!
//! Env knobs:
//!   FORGEWIRE_HUB_URL            -- hub base URL (optional; falls back to mDNS discovery)
//!   FORGEWIRE_HUB_TOKEN_FILE     -- path to bearer token file
//!   FORGEWIRE_RUNNER_IDENTITY    -- path to identity JSON (default: /var/lib/forgewire/loom_runner_identity.json)
//!   FORGEWIRE_RUNNER_TAGS        -- comma-separated extra routing tags
//!   FORGEWIRE_RUNNER_SCOPE_PREFIXES -- comma-separated path prefix allowlist
//!   FORGEWIRE_RUNNER_TENANT      -- tenant id for multi-tenant routing
//!   FORGEWIRE_RUNNER_MAX_CONCURRENT -- task concurrency cap (default 2)
//!   FORGEWIRE_RUNNER_POLL_INTERVAL  -- claim poll interval in seconds (default 3.0)
//!   FORGEWIRE_BEACON_PORT        -- UDP LAN discovery port (default 47890)

use std::sync::Arc;

use fabric_client::{HeartbeatStats, HubClient};
use loom_runner::{
    claim_loop, drain_and_shutdown, heartbeat_loop, load_or_create_identity,
    register_with_retries, resolve_hub_url, LoomConfig,
};
use tokio::sync::{watch, Mutex};
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut config = match LoomConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("loom-runner configuration error: {e}");
            std::process::exit(1);
        }
    };

    let resolved = resolve_hub_url(&config).await;
    config.hub_url = resolved;

    info!(
        hub = %config.hub_url,
        "starting forgewire-loom-runner (native Rust)"
    );

    let identity = Arc::new(load_or_create_identity(&config.identity_path));
    let client = Arc::new(HubClient::new(&config.hub_url, &config.token));
    let config = Arc::new(config);

    register_with_retries(&client, &identity, &config).await;

    let stats = Arc::new(Mutex::new(HeartbeatStats::default()));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let tx = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("loom-runner received shutdown signal");
        let _ = tx.send(true);
    });

    let hb = tokio::spawn(heartbeat_loop(
        client.clone(),
        identity.clone(),
        config.clone(),
        shutdown_rx.clone(),
        stats.clone(),
    ));
    let cl = tokio::spawn(claim_loop(
        client.clone(),
        identity.clone(),
        config.clone(),
        shutdown_rx,
        stats,
    ));

    tokio::select! {
        _ = hb => {}
        _ = cl => {}
    }

    drain_and_shutdown(&client, &identity).await;
    info!("forgewire-loom-runner shutdown complete");
}
