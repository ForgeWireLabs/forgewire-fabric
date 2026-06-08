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

async fn apply_topology_from(base_url: &str, nodes: &[RqliteNode]) -> anyhow::Result<Option<String>> {
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

// ── preferred leader (3+ node case) ──────────────────────────────────────────
//
// In a 3+ node cluster with full Raft quorum, failover can move leadership to
// any voter. The "preferred leader" is the node that bootstrapped the cluster
// (the first machine installed). When it comes back online after a failover,
// we request a leadership transfer back to it.
//
// The preferred leader node ID is stored in a rqlite label
// `cluster.preferred_leader_node_id`. The bootstrap node writes it on first
// startup; subsequent nodes read it and never overwrite it.

const PREFERRED_LEADER_LABEL: &str = "cluster.preferred_leader_node_id";

async fn get_preferred_leader(base_url: &str) -> Option<String> {
    let resp = http_client()
        .get(format!("{base_url}/db/query?level=strong"))
        .json(&serde_json::json!([[
            "SELECT value_json FROM labels WHERE key = ?",
            PREFERRED_LEADER_LABEL
        ]]))
        .send().await.ok()?;
    let v: serde_json::Value = resp.json().await.ok()?;
    let raw = v["results"][0]["values"][0][0].as_str()?;
    // value_json is a JSON-encoded string: "\"node-id\""
    serde_json::from_str::<String>(raw).ok()
}

async fn set_preferred_leader(base_url: &str, node_id: &str) -> anyhow::Result<()> {
    let value_json = serde_json::to_string(node_id)?;
    http_client()
        .post(format!("{base_url}/db/execute"))
        .json(&serde_json::json!([[
            "INSERT INTO labels (key, value_json, updated_at) VALUES (?, ?, ?) \
             ON CONFLICT(key) DO NOTHING",
            PREFERRED_LEADER_LABEL,
            value_json,
            chrono_now_iso(),
        ]]))
        .send().await?;
    Ok(())
}

fn chrono_now_iso() -> String {
    // Hand-rolled ISO timestamp — no date crate dep.
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let mins   = (secs / 60) % 60;
    let hours  = (secs / 3600) % 24;
    let mut days = (secs / 86400) as i64;
    let mut year = 1970i64;
    loop {
        let diy = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < diy { break; }
        days -= diy; year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let md = [31i64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0usize;
    for (i, &m) in md.iter().enumerate() {
        if days < m { month = i; break; }
        days -= m;
    }
    let secs_in_min = secs % 60;
    format!("{year:04}-{:02}-{:02}T{hours:02}:{mins:02}:{secs_in_min:02}Z", month + 1, days + 1)
}

/// For 3+ node clusters: if the preferred leader is back online and not the
/// current leader, request a leadership transfer to it.
async fn maybe_transfer_leadership(base_url: &str, nodes: &[RqliteNode]) -> anyhow::Result<()> {
    let total = nodes.len();
    if total < 3 { return Ok(()); }  // only relevant for full-quorum clusters

    let preferred_id = match get_preferred_leader(base_url).await {
        Some(id) => id,
        None => return Ok(()),  // no preference recorded yet
    };

    let current_leader = nodes.iter().find(|n| n.leader);
    let preferred_node = nodes.iter().find(|n| n.id == preferred_id);

    match (current_leader, preferred_node) {
        (Some(leader), Some(preferred)) if leader.id != preferred_id && preferred.reachable && preferred.voter => {
            info!(
                from = %leader.id,
                to   = %preferred_id,
                "requesting leadership transfer to preferred leader (original bootstrap node)"
            );
            // rqlite v10: POST /leader with the target node ID
            let r = http_client()
                .post(format!("{}/leader", leader.api_addr))
                .json(&serde_json::json!({ "id": preferred_id }))
                .send().await?;
            if r.status().is_success() {
                info!("leadership transfer requested to {preferred_id}");
            } else {
                warn!("leadership transfer returned {}", r.status());
            }
        }
        _ => {}
    }
    Ok(())
}

// ── entry point ───────────────────────────────────────────────────────────────

/// Spawn the cluster topology manager as a background task.
///
/// Also accepts the local node ID and whether this node bootstrapped
/// (was the first node) so it can record the preferred leader.
pub async fn run(rqlite_host: String, rqlite_port: u16, local_node_id: String, is_bootstrap: bool) {
    let base_url = format!("http://{rqlite_host}:{rqlite_port}");

    // If this node bootstrapped the cluster, record it as the preferred leader.
    // Uses INSERT ... ON CONFLICT DO NOTHING so subsequent nodes never overwrite.
    if is_bootstrap {
        if let Err(e) = set_preferred_leader(&base_url, &local_node_id).await {
            warn!("could not record preferred leader (non-fatal): {e}");
        } else {
            info!(node = %local_node_id, "recorded as preferred leader (bootstrap node)");
        }
    }

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
                match fetch_nodes(&base_url).await {
                    Ok(nodes) => {
                        match apply_topology_from(&base_url, &nodes).await {
                            Ok(Some(action)) => info!(action = %action, "cluster topology adjusted"),
                            Ok(None)         => {}
                            Err(e)           => warn!("topology adjustment failed: {e}"),
                        }
                        // For 3+ node clusters, restore preferred leader if needed.
                        if let Err(e) = maybe_transfer_leadership(&base_url, &nodes).await {
                            warn!("leadership transfer check failed (non-fatal): {e}");
                        }
                    }
                    Err(e) => warn!("topology check failed (non-fatal): {e}"),
                }
            }
            _ = snapshot_tick.tick() => {
                info!("scheduled rqlite snapshot (log compaction)");
                trigger_snapshot(&base_url).await;
            }
        }
    }
}
