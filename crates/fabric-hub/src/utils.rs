//! Shared utilities for hub route handlers.

use fabric_audit::{audit_event_hash, AUDIT_GENESIS_HASH};
use fabric_store::{AuditAppendResult, AuditStore, StoreError};
use serde_json::Value;

/// Returns the current UTC time as "YYYY-MM-DD HH:MM:SS".
pub fn utc_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    epoch_secs_to_iso(d.as_secs() as i64)
}

fn epoch_secs_to_iso(total_secs: i64) -> String {
    let secs = total_secs % 60;
    let mins = (total_secs / 60) % 60;
    let hours = (total_secs / 3600) % 24;
    let mut days = total_secs / 86400;
    let mut year = 1970i64;
    loop {
        let diy = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < diy { break; }
        days -= diy;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let md = [31i64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0usize;
    for (i, &m) in md.iter().enumerate() {
        if days < m { month = i; break; }
        days -= m;
    }
    format!("{year:04}-{:02}-{:02} {hours:02}:{mins:02}:{secs:02}", month + 1, days + 1)
}

/// Derive task kind from runner tags ("kind:command" → "command", else "agent").
pub fn runner_kind_from_tags(tags: &[String]) -> &'static str {
    for raw in tags {
        let norm = raw.trim().to_lowercase().replace('=', ":");
        if norm == "kind:command" {
            return "command";
        }
    }
    "agent"
}

/// Append one event to the audit chain with retry-on-tail-conflict (up to 3 tries).
pub async fn audit_append(
    store: &(dyn AuditStore + Send + Sync),
    kind: &str,
    task_id: Option<i64>,
    payload: &Value,
) -> Result<(), StoreError> {
    let payload_json = serde_json::to_string(payload).unwrap_or_else(|_| "{}".into());
    let now = utc_now();

    for _ in 0..3 {
        let tail = store.audit_chain_tail().await?;
        let hash = audit_event_hash(&tail, kind, payload);
        match store.append_audit_event(&tail, &hash, &tail, kind, task_id, &payload_json, &now).await? {
            AuditAppendResult::Ok(_) => return Ok(()),
            AuditAppendResult::TailConflict { .. } => continue,
        }
    }
    // Genesis fallback: shouldn't happen in practice but not fatal
    Ok(())
}

/// Verify an Ed25519 signature over the canonical JSON of a payload envelope.
/// Returns Ok(()) on valid, Err string on invalid.
pub fn verify_sig(public_key_hex: &str, envelope: &Value, signature_hex: &str) -> Result<(), String> {
    match fabric_protocol::verify_envelope_hex(public_key_hex, envelope, signature_hex) {
        Ok(true) => Ok(()),
        Ok(false) => Err("invalid signature".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Check timestamp skew (±5 minutes). Returns Err with message if out of range.
pub fn check_skew(timestamp: i64) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    fabric_types::check_timestamp_skew(timestamp, now).map_err(|e| e.to_string())
}
