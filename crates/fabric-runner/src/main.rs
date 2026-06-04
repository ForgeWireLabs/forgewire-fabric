//! ForgeWire Fabric native runner daemon entry point.
//!
//! All configuration via environment variables (NSSM sets these).
//! See `RunnerConfig::from_env()` for the full list.

use std::sync::Arc;

use fabric_client::{HeartbeatStats, HubClient};
use fabric_runner::{
    claim_loop, drain_and_shutdown, heartbeat_loop, load_or_create_identity,
    register_with_retries, RunnerConfig,
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

    let mut config = match RunnerConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(1);
        }
    };

    // Resolve the hub dynamically: a reachable configured URL wins, otherwise we
    // discover it on the LAN by token hash. No pinned address required.
    let resolved = fabric_runner::resolve_hub_url(&config).await;
    config.hub_url = resolved;

    info!(
        hub = %config.hub_url,
        workspace = %config.workspace_root.display(),
        "starting forgewire-runner (native Rust)"
    );

    let identity = Arc::new(load_or_create_identity(&config.identity_path));
    let client = Arc::new(HubClient::new(&config.hub_url, &config.token));
    let config = Arc::new(config);

    // Register (retries until success)
    register_with_retries(&client, &identity, &config).await;

    // Shared stats for heartbeat reporting
    let stats = Arc::new(Mutex::new(HeartbeatStats::default()));

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let tx = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("received shutdown signal");
        let _ = tx.send(true);
    });

    // Run heartbeat and claim loops concurrently
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
    info!("forgewire-runner shutdown complete");
}
