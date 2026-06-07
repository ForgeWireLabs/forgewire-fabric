//! Automatic rqlite cluster topology manager.
//!
//! Enforces the ForgeWire Fabric cluster invariant:
//!
//! | Nodes | Topology | Rationale |
//! |-------|----------|-----------|
//! | 1     | 1 voter  | Single stable leader |
//! | 2     | 1 voter (leader) + 1 non-voter (standby) | Stable single leader; standby replicates and serves reads but never votes, so a slow follower can never cause a leader election |
//! | 3+    | All voters | Full Raft quorum (⌊N/2⌋+1), proper fault tolerance |
//!
//! ## What this manager does at runtime
//!
//! **Promotion** (non-voter → voter): Handled automatically when a 3rd+ node
//! is present and has non-voter status. Calls `POST <leader>/join` with
//! `{"voter": true}` for each non-voter. rqlite's `/join` endpoint doubles as
//! the voter-status mutation API and can be called by any node on behalf of
//! another node.
//!
//! **Demotion** (voter → non-voter): Cannot be done at runtime without
//! restarting the target node's rqlite service. Demotion is therefore handled
//! at install time via `-raft-non-voter` in the service startup parameters
//! (see `scripts/install/nssm-install-rqlite.ps1`). When a 2-node cluster has
//! two voters, the manager logs a warning and leaves correction to the operator
//! (re-run the install script on the standby machine with the new parameters).
//!
//! ## Scheduled snapshot
//!
//! `POST /snapshot` is triggered every `SNAPSHOT_INTERVAL_SECS` to keep the
//! Raft log compact. A large log tail (>>8 k entries) slows snapshot-triggered
//! log replays which can cause heartbeat misses and leader elections.

use std::time::Duration;

use serde::Deserialize;
use tracing::{debug, info, warn};

const POLL_INTERVAL_SECS: u64      = 60;
const SNAPSHOT_INTERVAL_SECS: u64  = 3_600; // hourly

// ── rqlite types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct RqliteNode {
    id:        String,
    api_addr:  String,
    addr:      String,  // raft addr
    #[serde(default)]
    voter:     bool,
    #[serde(default)]
    reachable: bool,
    #[serde(default)]
    leader:    bool,
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default()
}

async fn fetch_nodes(base_url: &str) -> anyhow::Result<Vec<RqliteNode>> {
    // ?nonvoters includes non-voter (standby) nodes in the response;
    // without it rqlite omits them from the default /nodes output.
    let resp = http_client()
        .get(format!("{base_url}/nodes?nonvoters"))
        .send().await?.error_for_status()?
        .json::<serde_json::Value>().await?;

    // /nodes → { "node-id": { id, api_addr, addr, voter, leader, ... }, ... }
    Ok(resp.as_object()
        .ok_or_else(|| anyhow::anyhow!("/nodes returned non-object"))?
        .values()
        .filter_map(|v| serde_json::from_value::<RqliteNode>(v.clone()).ok())
        .collect())
}

/// Promote a non-voter to full voter status.
///
/// rqlite's `/join` endpoint accepts `{"voter": true}` to promote an existing
/// non-voter without requiring a service restart.
async fn promote_to_voter(leader_http: &str, node: &RqliteNode) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "id":    node.id,
        "addr":  node.addr,
        "voter": true,
    });
    let r = http_client()
        .post(format!("{leader_http}/join"))
        .json(&body).send().await?;
    if r.status().is_success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "promote_to_voter({}) → HTTP {}", node.id, r.status()
        ))
    }
}

async fn trigger_snapshot(base_url: &str) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build().unwrap_or_default();
    match client.post(format!("{base_url}/snapshot?wait=true")).send().await {
        Ok(r) if r.status().is_success() =>
            info!("rqlite snapshot complete — Raft log compacted"),
        Ok(r) => warn!("rqlite snapshot → {}", r.status()),
        Err(e) => warn!("rqlite snapshot failed: {e}"),
    }
}

// ── topology logic ────────────────────────────────────────────────────────────

async fn apply_topology(base_url: &str) -> anyhow::Result<Option<String>> {
    let nodes = fetch_nodes(base_url).await?;
    let total = nodes.len();
    if total == 0 { return Ok(None); }

    let voters:     Vec<&RqliteNode> = nodes.iter().filter(|n| n.voter).collect();
    let non_voters: Vec<&RqliteNode> = nodes.iter().filter(|n| !n.voter).collect();
    let leader = nodes.iter().find(|n| n.leader);

    debug!(
        total, voters = voters.len(), non_voters = non_voters.len(),
        leader = ?leader.map(|l| &l.id),
        "cluster topology check"
    );

    match total {
        // ── Single node ────────────────────────────────────────────────────
        1 => {
            debug!("single-node cluster: stable leader, nothing to do");
            Ok(None)
        }

        // ── Two nodes ──────────────────────────────────────────────────────
        // Target: 1 voter (leader) + 1 non-voter (hot standby).
        2 => {
            match voters.len() {
                1 => {
                    // Already correct.
                    debug!("2-node cluster: correct topology (1 voter, 1 standby)");
                    Ok(None)
                }
                2 => {
                    // Both are voters. This is stable with generous Raft timeouts
                    // but ideally the non-leader should be a non-voter for maximum
                    // stability. Runtime demotion requires a service restart on the
                    // standby; the install script handles this on next deploy.
                    warn!(
                        "2-node cluster has 2 voters — Raft elections may occur on slow heartbeats. \
                         Re-run nssm-install-rqlite.ps1 on the standby machine to make it a \
                         non-voter (hot standby). The hub's cluster manager cannot demote a \
                         running node without a service restart."
                    );
                    Ok(None)
                }
                0 => {
                    // No voters — cluster is leaderless. Attempt recovery by
                    // promoting the first reachable non-voter.
                    warn!("2-node cluster has 0 voters — attempting emergency recovery");
                    if let Some(node) = non_voters.iter().find(|n| n.reachable) {
                        let target_http = &node.api_addr;
                        info!("emergency: promoting {} to voter for recovery", node.id);
                        promote_to_voter(target_http, node).await?;
                        Ok(Some(format!("emergency recovery: promoted {} to voter", node.id)))
                    } else {
                        Err(anyhow::anyhow!("2-node cluster has 0 voters and no reachable nodes"))
                    }
                }
                _ => Ok(None),
            }
        }

        // ── Three or more nodes ────────────────────────────────────────────
        // Target: all voters for full Raft quorum.
        n => {
            if non_voters.is_empty() {
                debug!("{n}-node cluster: all voters, full quorum active");
                return Ok(None);
            }

            // Promote non-voters to voters. Use the leader's HTTP endpoint.
            let leader_http = leader
                .map(|l| l.api_addr.as_str())
                .unwrap_or(base_url);

            let mut promoted = Vec::new();
            for node in &non_voters {
                if !node.reachable {
                    warn!("skipping promotion of {} — not reachable", node.id);
                    continue;
                }
                info!("promoting {} to voter ({n}-node cluster, full quorum)", node.id);
                match promote_to_voter(leader_http, node).await {
                    Ok(()) => {
                        info!("{} promoted to voter", node.id);
                        promoted.push(node.id.clone());
                    }
                    Err(e) => warn!("promotion of {} failed: {e}", node.id),
                }
            }

            if promoted.is_empty() {
                Ok(None)
            } else {
                Ok(Some(format!(
                    "{n}-node cluster: promoted to voter: {}",
                    promoted.join(", ")
                )))
            }
        }
    }
}

// ── entry point ───────────────────────────────────────────────────────────────

/// Spawn the cluster topology manager as a background task.
pub async fn run(rqlite_host: String, rqlite_port: u16) {
    let base_url = format!("http://{rqlite_host}:{rqlite_port}");

    let mut topo_tick     = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));
    let mut snapshot_tick = tokio::time::interval(Duration::from_secs(SNAPSHOT_INTERVAL_SECS));

    // Consume the immediate first tick on both intervals.
    topo_tick.tick().await;
    snapshot_tick.tick().await;

    info!(
        rqlite = %base_url,
        topology_poll_secs = POLL_INTERVAL_SECS,
        snapshot_interval_secs = SNAPSHOT_INTERVAL_SECS,
        "cluster manager started (2-node: stable-leader/standby; 3+: full quorum)"
    );

    loop {
        tokio::select! {
            _ = topo_tick.tick() => {
                match apply_topology(&base_url).await {
                    Ok(Some(action)) => info!(action = %action, "cluster topology adjusted"),
                    Ok(None)         => {}
                    Err(e)           => warn!("topology check failed (non-fatal): {e}"),
                }
            }
            _ = snapshot_tick.tick() => {
                info!("scheduled rqlite snapshot (log compaction)");
                trigger_snapshot(&base_url).await;
            }
        }
    }
}
