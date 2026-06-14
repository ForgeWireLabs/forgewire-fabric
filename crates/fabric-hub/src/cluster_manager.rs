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
//! **Demotion** (voter → non-voter, ADDR-5): the manager attempts an in-place
//! demote of the **non-leader** voter via `POST <leader>/join` with
//! `{"voter": false}` (the mirror of promotion), then **verifies** by
//! re-reading `/nodes`.
//!
//! ⚠️ **rqlite v10 limitation (found by the 2026-06-12 live drill):** rqlite
//! v10.0.3 does **not** expose an HTTP `/join` endpoint (it 404s; only
//! `DELETE /remove` exists). Suffrage is fixed at *join time* via the rqlited
//! `-raft-non-voter` flag and cannot be mutated at runtime over HTTP. So on
//! v10 both this demote and the promotion above degrade to their verified
//! fallback: record the needed action and log an operator/runner instruction.
//! The deployed safety net for the 2-voter quorum trap is therefore:
//!   1. install-time prevention (ADDR-3: the 2nd node joins as non-voter),
//!   2. the `forgewire-fabric doctor` **Suffrage** warning,
//!   3. **ADDR-5b (follow-up): runner-side self-heal** — a node that finds
//!      itself a voter in a 2-node non-leader position restarts its *own*
//!      rqlite with `-raft-non-voter` (local service control the hub lacks).
//! This is strictly better than the old warn-only behavior (no verify, no
//! record, no instruction), but full automatic demote needs ADDR-5b.
//!
//! Every suffrage change/attempt is recorded in `cluster.last_suffrage_action`
//! (timestamp + action), surfaced by `forgewire-fabric doctor`.
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

/// Demote an existing voter to non-voter in place (ADDR-5).
///
/// `POST <leader>/join` with `{"voter": false}` maps to Raft `AddNonvoter`,
/// which forces an existing voter to non-voter status without a restart — the
/// mirror of [`promote_to_voter`]. The config change commits under current
/// quorum, then quorum drops by one.
async fn demote_to_nonvoter(leader_http: &str, node: &RqliteNode) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "id":    node.id,
        "addr":  node.addr,
        "voter": false,
    });
    let r = http_client()
        .post(format!("{leader_http}/join"))
        .json(&body).send().await?;
    if r.status().is_success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "demote_to_nonvoter({}) → HTTP {}", node.id, r.status()
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

/// The suffrage action the topology rules call for. Pure decision, separated
/// from execution so it is unit-testable without a live cluster (the ADDR-5
/// rules are the load-bearing part — a wrong decision can strand the quorum
/// trap or force an election).
#[derive(Debug, Clone, PartialEq)]
enum TopologyAction {
    /// Correct topology — nothing to do.
    Nothing,
    /// Promote these reachable non-voters to voter (3+-node full quorum).
    Promote(Vec<String>),
    /// Demote this non-leader voter to non-voter (2-node quorum-trap fix).
    Demote(String),
    /// Leaderless recovery: promote this reachable non-voter.
    EmergencyPromote(String),
}

/// Pure topology decision from a node snapshot. See the module table.
fn decide_topology(nodes: &[RqliteNode]) -> TopologyAction {
    let total = nodes.len();
    if total == 0 {
        return TopologyAction::Nothing;
    }
    let voters: Vec<&RqliteNode> = nodes.iter().filter(|n| n.voter).collect();
    let non_voters: Vec<&RqliteNode> = nodes.iter().filter(|n| !n.voter).collect();

    match total {
        // Single node: stable leader.
        1 => TopologyAction::Nothing,

        // Two nodes → 1 voter (leader) + 1 non-voter (standby).
        2 => match voters.len() {
            1 => TopologyAction::Nothing,
            // The quorum trap: demote the NON-LEADER voter (never the leader,
            // which would force an election). Demote only if it is reachable.
            2 => match nodes.iter().find(|n| n.voter && !n.leader && n.reachable) {
                Some(target) => TopologyAction::Demote(target.id.clone()),
                None => TopologyAction::Nothing, // can't safely act this cycle
            },
            // Leaderless: promote a reachable non-voter to recover.
            0 => match non_voters.iter().find(|n| n.reachable) {
                Some(n) => TopologyAction::EmergencyPromote(n.id.clone()),
                None => TopologyAction::Nothing,
            },
            _ => TopologyAction::Nothing,
        },

        // Three or more nodes → all voters for full quorum.
        _ => {
            let to_promote: Vec<String> = non_voters
                .iter()
                .filter(|n| n.reachable)
                .map(|n| n.id.clone())
                .collect();
            if to_promote.is_empty() {
                TopologyAction::Nothing
            } else {
                TopologyAction::Promote(to_promote)
            }
        }
    }
}

async fn apply_topology_from(base_url: &str, nodes: &[RqliteNode]) -> anyhow::Result<Option<String>> {
    let voters = nodes.iter().filter(|n| n.voter).count();
    let leader = nodes.iter().find(|n| n.leader);
    let leader_http = leader.map(|l| l.api_addr.as_str()).unwrap_or(base_url);

    debug!(
        total = nodes.len(), voters, non_voters = nodes.len() - voters,
        leader = ?leader.map(|l| &l.id),
        "cluster topology check"
    );

    match decide_topology(nodes) {
        TopologyAction::Nothing => Ok(None),

        TopologyAction::Promote(ids) => {
            let mut promoted = Vec::new();
            let mut failed = false;
            for id in &ids {
                if let Some(node) = nodes.iter().find(|n| &n.id == id) {
                    info!("promoting {} to voter ({}-node cluster, full quorum)", id, nodes.len());
                    match promote_to_voter(leader_http, node).await {
                        Ok(()) => promoted.push(id.clone()),
                        // rqlite v10 has no HTTP /join → this 404s. Fall back to
                        // guidance instead of silently failing every cycle.
                        Err(e) => { warn!("promotion of {id} failed: {e}"); failed = true; }
                    }
                }
            }
            if !promoted.is_empty() {
                let action = format!("promoted to voter: {}", promoted.join(", "));
                record_suffrage_action(base_url, &action).await;
                Ok(Some(action))
            } else if failed {
                warn!(
                    "could not promote non-voter(s) to voter over HTTP (rqlite v10 has no \
                     runtime /join). OPERATOR/ADDR-5b: the standby must restart its rqlite \
                     as a voter to reach full quorum."
                );
                record_suffrage_action(base_url, "promote-to-voter unsupported on this rqlite (needs node restart)").await;
                Ok(None)
            } else {
                Ok(None)
            }
        }

        TopologyAction::EmergencyPromote(id) => {
            let node = nodes.iter().find(|n| n.id == id)
                .ok_or_else(|| anyhow::anyhow!("emergency target vanished"))?;
            warn!("2-node cluster leaderless — emergency promoting {id} to voter");
            promote_to_voter(&node.api_addr, node).await?;
            let action = format!("emergency recovery: promoted {id} to voter");
            record_suffrage_action(base_url, &action).await;
            Ok(Some(action))
        }

        TopologyAction::Demote(id) => {
            let node = nodes.iter().find(|n| n.id == id)
                .ok_or_else(|| anyhow::anyhow!("demote target vanished"))?;
            info!("2-node cluster has 2 voters (quorum trap) — demoting non-leader voter {id} to standby");
            match demote_to_nonvoter(leader_http, node).await {
                Ok(()) => {
                    // Verify rqlite actually honored the in-place demote.
                    let demoted = match fetch_nodes(base_url).await {
                        Ok(after) => after.iter().any(|n| n.id == id && !n.voter),
                        Err(_) => false,
                    };
                    if demoted {
                        let action = format!("demoted {id} to non-voter (quorum-trap fix)");
                        record_suffrage_action(base_url, &action).await;
                        Ok(Some(action))
                    } else {
                        warn!(
                            "in-place demote of {id} did not take effect (rqlite v10 has no \
                             runtime suffrage mutation). 2-VOTER QUORUM TRAP ACTIVE — losing \
                             either node halts writes. ADDR-5b/OPERATOR: restart {id}'s rqlite \
                             with -raft-non-voter (re-run nssm-install-rqlite.ps1 on the standby)."
                        );
                        record_suffrage_action(base_url, &format!(
                            "2-voter trap: demote of {id} needs node restart (rqlite v10, ADDR-5b)"
                        )).await;
                        Ok(None)
                    }
                }
                Err(e) => {
                    warn!(
                        "demote of {id} over HTTP failed: {e} (rqlite v10 has no /join). \
                         2-VOTER QUORUM TRAP ACTIVE. ADDR-5b/OPERATOR: restart {id}'s rqlite \
                         with -raft-non-voter (re-run nssm-install-rqlite.ps1 on the standby)."
                    );
                    record_suffrage_action(base_url, &format!(
                        "2-voter trap: demote of {id} needs node restart (rqlite v10, ADDR-5b)"
                    )).await;
                    Ok(None)
                }
            }
        }
    }
}

const SUFFRAGE_ACTION_LABEL: &str = "cluster.last_suffrage_action";

/// Record the most recent suffrage change as an operator-visible label
/// (timestamp + action). Surfaced by `forgewire-fabric doctor`. Best-effort.
async fn record_suffrage_action(base_url: &str, action: &str) {
    let payload = serde_json::json!({ "action": action, "at": chrono_now_iso() });
    let value_json = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = http_client()
        .post(format!("{base_url}/db/execute"))
        .json(&serde_json::json!([[
            "INSERT INTO labels (key, value_json, updated_at) VALUES (?, ?, ?) \
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
            SUFFRAGE_ACTION_LABEL,
            value_json,
            chrono_now_iso(),
        ]]))
        .send().await;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, voter: bool, leader: bool, reachable: bool) -> RqliteNode {
        RqliteNode {
            id: id.to_owned(),
            api_addr: format!("http://{id}:4001"),
            addr: format!("{id}:4002"),
            voter,
            reachable,
            leader,
        }
    }

    #[test]
    fn single_node_is_stable() {
        assert_eq!(decide_topology(&[node("a", true, true, true)]), TopologyAction::Nothing);
    }

    #[test]
    fn two_nodes_one_voter_is_correct() {
        let nodes = [node("a", true, true, true), node("b", false, false, true)];
        assert_eq!(decide_topology(&nodes), TopologyAction::Nothing);
    }

    #[test]
    fn two_voters_demotes_the_non_leader() {
        // The quorum trap: must demote the NON-LEADER voter, never the leader.
        let nodes = [node("leader", true, true, true), node("standby", true, false, true)];
        assert_eq!(decide_topology(&nodes), TopologyAction::Demote("standby".to_owned()));
    }

    #[test]
    fn two_voters_never_demotes_when_non_leader_unreachable() {
        // If the candidate is unreachable we cannot safely commit the change.
        let nodes = [node("leader", true, true, true), node("standby", true, false, false)];
        assert_eq!(decide_topology(&nodes), TopologyAction::Nothing);
    }

    #[test]
    fn two_nodes_leaderless_emergency_promotes() {
        let nodes = [node("a", false, false, true), node("b", false, false, false)];
        assert_eq!(decide_topology(&nodes), TopologyAction::EmergencyPromote("a".to_owned()));
    }

    #[test]
    fn three_nodes_promotes_reachable_non_voters() {
        let nodes = [
            node("a", true, true, true),
            node("b", false, false, true),
            node("c", false, false, true),
        ];
        match decide_topology(&nodes) {
            TopologyAction::Promote(ids) => {
                assert_eq!(ids.len(), 2);
                assert!(ids.contains(&"b".to_owned()) && ids.contains(&"c".to_owned()));
            }
            other => panic!("expected Promote, got {other:?}"),
        }
    }

    #[test]
    fn three_nodes_skips_unreachable_non_voter() {
        let nodes = [
            node("a", true, true, true),
            node("b", false, false, false), // unreachable — don't promote
            node("c", true, false, true),
        ];
        assert_eq!(decide_topology(&nodes), TopologyAction::Nothing);
    }

    #[test]
    fn three_nodes_all_voters_is_stable() {
        let nodes = [
            node("a", true, true, true),
            node("b", true, false, true),
            node("c", true, false, true),
        ];
        assert_eq!(decide_topology(&nodes), TopologyAction::Nothing);
    }

    #[test]
    fn empty_is_nothing() {
        assert_eq!(decide_topology(&[]), TopologyAction::Nothing);
    }
}

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
