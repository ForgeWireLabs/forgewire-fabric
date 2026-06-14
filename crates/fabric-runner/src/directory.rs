//! Node directory + managed hosts reconciler (ADDR-2, dhcp-proof-addressing.md).
//!
//! This is the piece that makes beacon v2 presence *useful* without changing
//! any name-based consumer. Each node:
//!
//! 1. Actively queries the LAN for signed presence (broadcast, plus unicast
//!    to last-known-good addresses on broadcast-hostile media), every cycle
//!    with a fresh nonce — so every accepted record is replay-proof and
//!    proves the responder controls the node key *right now*.
//! 2. Merges verified records into a persistent directory
//!    (`fabric-hosts.json`): hostname → {ip, node_id, last_seen, verified}.
//! 3. Reconciles a **managed block** in the OS hosts file. rqlite keeps
//!    advertising flat hostnames; write-forwarding, raft elections, SSH
//!    watchdogs, DR chains, and smoke scripts all resolve through this block.
//!    A DHCP lease change self-heals within one query cycle, no restarts.
//!
//! Trust gate (v1): a record is acted on only if its **signature verifies**
//! (key possession) AND its **token_hash matches** this node's cluster token
//! (cluster membership — spoofing requires the cluster secret). Cross-checking
//! the embedded public key against the hub `/runners` registry is a documented
//! hardening step (requires a hub round-trip; the directory stays functional
//! without it).
//!
//! Announces (the unsolicited broadcast) are deliberately NOT the directory's
//! input — they are advisory only. The directory consumes the *query* path so
//! that a captured announce can never relocate a peer.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fabric_beacon::{collect_presence_addrs, ObservedPresence};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Markers delimiting the block this reconciler owns in the OS hosts file.
/// Everything between them is rewritten; everything else is preserved.
pub const BLOCK_BEGIN: &str = "# forgewire-managed begin (do not edit; rewritten by ForgeWireRunner)";
pub const BLOCK_END: &str = "# forgewire-managed end";

/// Default: drop a directory entry whose presence has been silent this long.
/// Removal *exposes* an outage rather than masking it with a stale address.
pub const DEFAULT_EXPIRY: Duration = Duration::from_secs(180);

/// One known node's current location, as last confirmed by a signed,
/// nonce-fresh presence response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirectoryEntry {
    pub hostname: String,
    pub ip: String,
    pub node_id: String,
    /// Unix seconds of the last confirming presence record.
    pub last_seen: u64,
    /// Signature verified against the record's embedded key.
    pub verified: bool,
    /// Record `ts` at last update — used for conflict tie-breaks.
    pub record_ts: u64,
}

/// The persistent directory: hostname → entry. Hostname is the key because the
/// managed hosts block maps names → IPs, and a node keeps its hostname across
/// DHCP moves (the whole point).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeDirectory {
    pub entries: BTreeMap<String, DirectoryEntry>,
}

impl NodeDirectory {
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Atomic save (temp file + rename) so a crash mid-write cannot corrupt
    /// the directory.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap_or_default())?;
        std::fs::rename(&tmp, path)
    }

    /// Merge a batch of observed presence records.
    ///
    /// Returns the set of hostnames whose IP actually changed (callers can log
    /// / audit relocations). Only signature-valid, token-matched records reach
    /// here — see [`directory_tick`]. On a hostname conflict (two live records,
    /// same name, different IP) the newer `record_ts` wins.
    pub fn merge(&mut self, observed: &[ObservedPresence], self_node_id: &str) -> Vec<String> {
        let mut changed = Vec::new();
        for o in observed {
            if !o.sig_valid {
                continue;
            }
            // Skip self: localhost already resolves; advertising our own LAN IP
            // to ourselves is noise and risks a flap if we see our own announce
            // from two interfaces.
            if o.record.node_id == self_node_id {
                continue;
            }
            let ip = o.source.to_string();
            let hostname = o.record.hostname.clone();
            let ts = o.record.ts;
            match self.entries.get(&hostname) {
                Some(existing) => {
                    // Conflict tie-break: ignore an older record claiming a
                    // different IP for a name we already have fresher data for.
                    if existing.ip != ip && ts < existing.record_ts {
                        warn!(
                            hostname = %hostname,
                            kept = %existing.ip,
                            ignored = %ip,
                            "directory conflict: keeping newer record for hostname"
                        );
                        continue;
                    }
                    if existing.ip != ip {
                        changed.push(hostname.clone());
                    }
                }
                None => changed.push(hostname.clone()),
            }
            self.entries.insert(
                hostname.clone(),
                DirectoryEntry {
                    hostname,
                    ip,
                    node_id: o.record.node_id.clone(),
                    last_seen: now_unix(),
                    verified: true,
                    record_ts: ts,
                },
            );
        }
        changed
    }

    /// Drop entries silent for longer than `expiry`. Returns expired hostnames.
    pub fn expire(&mut self, expiry: Duration) -> Vec<String> {
        let now = now_unix();
        let cutoff = expiry.as_secs();
        let dead: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.last_seen) > cutoff)
            .map(|(h, _)| h.clone())
            .collect();
        for h in &dead {
            self.entries.remove(h);
        }
        dead
    }

    /// Current `(ip, [hostname, hostname.local])` pairs for the managed block.
    pub fn host_lines(&self) -> Vec<(String, Vec<String>)> {
        self.entries
            .values()
            .filter(|e| e.verified)
            .map(|e| {
                let names = vec![e.hostname.clone(), format!("{}.local", e.hostname)];
                (e.ip.clone(), names)
            })
            .collect()
    }

    /// Unicast targets for the next query cycle: every known IP at `port`. This
    /// is the broadcast-hostile-media fallback — even if the hotspot eats the
    /// broadcast query, peers we already know still answer.
    pub fn unicast_targets(&self, port: u16) -> Vec<SocketAddr> {
        self.entries
            .values()
            .filter_map(|e| e.ip.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, port)))
            .collect()
    }
}

/// Render the managed block body (between, not including, the markers).
/// Pure + deterministic so it is trivially testable and produces stable diffs.
pub fn render_block(lines: &[(String, Vec<String>)]) -> String {
    let mut out = String::new();
    out.push_str(BLOCK_BEGIN);
    out.push('\n');
    for (ip, names) in lines {
        out.push_str(ip);
        for n in names {
            out.push(' ');
            out.push_str(n);
        }
        out.push('\n');
    }
    out.push_str(BLOCK_END);
    out.push('\n');
    out
}

/// Splice the managed block into `existing` hosts-file content, replacing any
/// previous managed block and preserving everything else verbatim. Pure.
pub fn splice_block(existing: &str, block: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut in_block = false;
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("# forgewire-managed begin") {
            in_block = true;
            continue;
        }
        if in_block {
            if trimmed == BLOCK_END {
                in_block = false;
            }
            continue;
        }
        kept.push(line);
    }
    // Drop trailing blank lines from the kept section for a clean join.
    while matches!(kept.last(), Some(l) if l.trim().is_empty()) {
        kept.pop();
    }
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(block);
    out
}

/// Reconcile the OS hosts file to the directory's current entries. Atomic
/// (temp + rename). Returns `Ok(true)` if the file content changed.
///
/// Idempotent: running it twice with the same directory is a no-op the second
/// time (used as a change-detector in the loop).
pub fn reconcile_hosts_file(
    hosts_path: &Path,
    directory: &NodeDirectory,
) -> std::io::Result<bool> {
    let existing = std::fs::read_to_string(hosts_path).unwrap_or_default();
    let block = render_block(&directory.host_lines());
    let updated = splice_block(&existing, &block);
    if updated == existing {
        return Ok(false);
    }
    let tmp = hosts_path.with_extension("fwtmp");
    std::fs::write(&tmp, &updated)?;
    std::fs::rename(&tmp, hosts_path)?;
    Ok(true)
}

/// Default OS hosts-file path.
pub fn default_hosts_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

/// Default directory cache path.
pub fn default_directory_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\forgewire\fabric-hosts.json")
    } else {
        PathBuf::from("/var/lib/forgewire/fabric-hosts.json")
    }
}

/// One directory maintenance cycle: query (broadcast + known-address unicast),
/// merge verified records, expire the silent, persist, and reconcile the hosts
/// file. Returns the loaded+updated directory so the caller can keep it warm.
///
/// `want_token_hash` gates records to this cluster. `nonce` must be fresh per
/// call (replay-proofing). All file writes are atomic; a hosts-file write
/// failure (e.g. not elevated) is logged, not fatal — the in-memory/JSON
/// directory still updates, so the next elevated run reconciles.
#[allow(clippy::too_many_arguments)]
pub fn directory_tick(
    directory_path: &Path,
    hosts_path: &Path,
    presence_port: u16,
    want_token_hash: &str,
    self_node_id: &str,
    nonce: &str,
    expiry: Duration,
    query_timeout: Duration,
) -> NodeDirectory {
    let mut dir = NodeDirectory::load(directory_path);

    // Broadcast + unicast-to-known in one query batch.
    let mut targets = vec![SocketAddr::from(([255, 255, 255, 255], presence_port))];
    targets.extend(dir.unicast_targets(presence_port));

    let observed = collect_presence_addrs(&targets, query_timeout, Some(want_token_hash), nonce)
        .unwrap_or_default();

    let changed = dir.merge(&observed, self_node_id);
    let expired = dir.expire(expiry);

    for h in &changed {
        if let Some(e) = dir.entries.get(h) {
            info!(hostname = %h, ip = %e.ip, node_id = %e.node_id, "directory: peer address learned/changed");
        }
    }
    for h in &expired {
        warn!(hostname = %h, "directory: peer presence expired (removed from managed hosts)");
    }

    if let Err(e) = dir.save(directory_path) {
        warn!("directory save failed: {e}");
    }
    match reconcile_hosts_file(hosts_path, &dir) {
        Ok(true) => info!(
            hosts = %hosts_path.display(),
            entries = dir.entries.len(),
            "reconciled managed hosts block"
        ),
        Ok(false) => {}
        Err(e) => warn!(
            "hosts-file reconcile failed (continuing; will retry next cycle): {e}"
        ),
    }
    dir
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fabric_beacon::PresenceRecord;

    fn observed(
        node_id: &str,
        hostname: &str,
        ip: [u8; 4],
        ts: u64,
        sig_valid: bool,
        token_hash: &str,
    ) -> ObservedPresence {
        let mut services = std::collections::BTreeMap::new();
        services.insert("rqlite_http".to_owned(), 4001u16);
        ObservedPresence {
            record: PresenceRecord {
                magic: "FWBEACON".to_owned(),
                v: 2,
                role: "node".to_owned(),
                node_id: node_id.to_owned(),
                hostname: hostname.to_owned(),
                services,
                ts,
                token_hash: token_hash.to_owned(),
                nonce: "n".to_owned(),
                public_key_hex: "0".repeat(64),
                sig: "0".repeat(128),
            },
            source: IpAddr::from(ip),
            sig_valid,
        }
    }

    #[test]
    fn merge_learns_and_skips_self_and_unverified() {
        let mut dir = NodeDirectory::default();
        let batch = vec![
            observed("peer", "PEER-HOST", [10, 0, 0, 2], 100, true, "t"),
            observed("self", "SELF-HOST", [10, 0, 0, 1], 100, true, "t"),
            observed("bad", "BAD-HOST", [10, 0, 0, 9], 100, false, "t"),
        ];
        let changed = dir.merge(&batch, "self");
        assert_eq!(changed, vec!["PEER-HOST"]);
        assert_eq!(dir.entries.len(), 1);
        assert_eq!(dir.entries["PEER-HOST"].ip, "10.0.0.2");
    }

    #[test]
    fn merge_detects_address_change() {
        let mut dir = NodeDirectory::default();
        dir.merge(&[observed("peer", "PEER", [10, 0, 0, 2], 100, true, "t")], "self");
        // Newer record, new IP (a DHCP move).
        let changed = dir.merge(&[observed("peer", "PEER", [10, 9, 9, 9], 200, true, "t")], "self");
        assert_eq!(changed, vec!["PEER"]);
        assert_eq!(dir.entries["PEER"].ip, "10.9.9.9");
    }

    #[test]
    fn conflict_keeps_newer_record() {
        let mut dir = NodeDirectory::default();
        dir.merge(&[observed("peer", "PEER", [10, 0, 0, 2], 200, true, "t")], "self");
        // Older record claiming a different IP must be ignored.
        let changed = dir.merge(&[observed("peer", "PEER", [10, 0, 0, 3], 100, true, "t")], "self");
        assert!(changed.is_empty());
        assert_eq!(dir.entries["PEER"].ip, "10.0.0.2");
    }

    #[test]
    fn expire_removes_silent_entries() {
        let mut dir = NodeDirectory::default();
        dir.merge(&[observed("peer", "PEER", [10, 0, 0, 2], 100, true, "t")], "self");
        // Force last_seen into the past.
        dir.entries.get_mut("PEER").unwrap().last_seen = now_unix() - 1000;
        let expired = dir.expire(Duration::from_secs(180));
        assert_eq!(expired, vec!["PEER"]);
        assert!(dir.entries.is_empty());
    }

    #[test]
    fn render_block_is_stable_and_includes_local_alias() {
        let lines = vec![
            ("10.0.0.2".to_owned(), vec!["A".to_owned(), "A.local".to_owned()]),
            ("10.0.0.3".to_owned(), vec!["B".to_owned(), "B.local".to_owned()]),
        ];
        let block = render_block(&lines);
        assert!(block.starts_with(BLOCK_BEGIN));
        assert!(block.trim_end().ends_with(BLOCK_END));
        assert!(block.contains("10.0.0.2 A A.local\n"));
        assert!(block.contains("10.0.0.3 B B.local\n"));
    }

    #[test]
    fn splice_preserves_foreign_lines_and_replaces_old_block() {
        let existing = "\
127.0.0.1 localhost
# forgewire-managed begin (do not edit; rewritten by ForgeWireRunner)
10.0.0.99 STALE STALE.local
# forgewire-managed end
192.168.1.5 printer
";
        let block = render_block(&[("10.0.0.2".to_owned(), vec!["A".to_owned(), "A.local".to_owned()])]);
        let out = splice_block(existing, &block);
        assert!(out.contains("127.0.0.1 localhost"));
        assert!(out.contains("192.168.1.5 printer"));
        assert!(!out.contains("STALE"));
        assert!(out.contains("10.0.0.2 A A.local"));
        // Exactly one managed block.
        assert_eq!(out.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn reconcile_is_idempotent_and_atomic() {
        let tmp = std::env::temp_dir().join(format!("fw_hosts_{}.txt", now_unix()));
        std::fs::write(&tmp, "127.0.0.1 localhost\n").unwrap();
        let mut dir = NodeDirectory::default();
        dir.merge(&[observed("peer", "PEER", [10, 0, 0, 2], 100, true, "t")], "self");

        let changed1 = reconcile_hosts_file(&tmp, &dir).unwrap();
        assert!(changed1, "first reconcile should change the file");
        let changed2 = reconcile_hosts_file(&tmp, &dir).unwrap();
        assert!(!changed2, "second reconcile with same dir is a no-op");

        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("127.0.0.1 localhost"));
        assert!(content.contains("10.0.0.2 PEER PEER.local"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn directory_save_load_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("fw_dir_{}.json", now_unix()));
        let mut dir = NodeDirectory::default();
        dir.merge(&[observed("peer", "PEER", [10, 0, 0, 2], 100, true, "t")], "self");
        dir.save(&tmp).unwrap();
        let loaded = NodeDirectory::load(&tmp);
        assert_eq!(loaded.entries["PEER"].ip, "10.0.0.2");
        let _ = std::fs::remove_file(&tmp);
    }
}
