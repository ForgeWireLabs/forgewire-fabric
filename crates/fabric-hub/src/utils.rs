//! Shared utilities for hub route handlers.

use fabric_audit::audit_event_hash;
use fabric_policy::BudgetPolicy;
use fabric_store::{AuditAppendResult, BudgetStore, FabricStore, StoreError};
use serde_json::{json, Value};

use crate::auth::AuthContext;

/// The dual-attribution fields (114C.4): which human (if any) was signed
/// in, their raw authenticated subject (a role-token ID or
/// "legacy-cluster-bearer" when there is no human), and whether the legacy
/// compatibility bearer was used. Shared by every audit call site that
/// carries an `AuthContext` -- dispatch, claim, approval, and completion --
/// so "audit reconstructs human -> client -> dispatch -> runner ->
/// completion" (114C.4's own acceptance line) has one consistent
/// `"attribution"` shape to correlate on, not a per-route reinvention. A
/// `null` `human_account_id` is the explicit, queryable signal that a step
/// was automation, never silently mistaken for a person.
pub fn attribution(actor: &AuthContext) -> Value {
    json!({
        "human_account_id": actor.human_principal,
        "authenticated_subject": actor.subject,
        "legacy_bearer": actor.legacy_compat,
    })
}

/// Returns the current UTC time as "YYYY-MM-DD HH:MM:SS".
pub fn utc_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    epoch_secs_to_iso(d.as_secs() as i64)
}

/// Returns UTC now plus `offset_secs`, same format as [`utc_now`]. Used for
/// short-lived expiry stamps (WebAuthn ceremony challenges, 114C.6) where
/// computing an offset from "now" in the same string format the rest of
/// this codebase already uses is simpler than a second date representation.
pub fn utc_now_plus_secs(offset_secs: i64) -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    epoch_secs_to_iso(d.as_secs() as i64 + offset_secs)
}

fn epoch_secs_to_iso(total_secs: i64) -> String {
    let secs = total_secs % 60;
    let mins = (total_secs / 60) % 60;
    let hours = (total_secs / 3600) % 24;
    let mut days = total_secs / 86400;
    let mut year = 1970i64;
    loop {
        let diy = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if days < diy {
            break;
        }
        days -= diy;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let md = [
        31i64,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0usize;
    for (i, &m) in md.iter().enumerate() {
        if days < m {
            month = i;
            break;
        }
        days -= m;
    }
    format!(
        "{year:04}-{:02}-{:02} {hours:02}:{mins:02}:{secs:02}",
        month + 1,
        days + 1
    )
}

/// Native budget gate (M2.5.3): deny a dispatch when the current daily or
/// weekly accumulated spend has reached its configured cap. Reads the persistent
/// `budget_state` accumulators (point lookups), so it is correct across hub
/// restarts. Returns `Some(reason)` to deny, `None` to allow. Skips the store
/// read entirely when no caps are configured.
pub async fn budget_denial(
    store: &(dyn BudgetStore + Send + Sync),
    caps: &BudgetPolicy,
    now: &str,
) -> Result<Option<String>, StoreError> {
    if !caps.has_cost_caps() {
        return Ok(None);
    }
    let budget = store.current_budget(now).await?;
    let decision = caps.check_cost(budget.daily_spend_usd, budget.weekly_spend_usd);
    if decision.denied {
        Ok(Some(
            decision
                .reasons
                .into_iter()
                .next()
                .unwrap_or_else(|| "budget exceeded".to_owned()),
        ))
    } else {
        Ok(None)
    }
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

/// Derive primary task-kind from the stored runner row's `kinds` JSON field.
///
/// M2.8.3+: runners send `kinds: ["agent"|"command"]` instead of `kind:*`
/// tags. Prefers the first-class column; falls back to the legacy tag scan
/// so runners that pre-date M2.8.3 still route correctly.
pub fn runner_kind_from_row(kinds: &Value, tags: &[String]) -> &'static str {
    if let Some(arr) = kinds.as_array() {
        for v in arr {
            if let Some(s) = v.as_str() {
                match s {
                    "command" => return "command",
                    "agent" => return "agent",
                    _ => {}
                }
            }
        }
    }
    runner_kind_from_tags(tags)
}

/// Append one event to the audit chain with retry-on-tail-conflict (up to 3 tries).
pub async fn audit_append(
    store: &(dyn FabricStore + Send + Sync),
    secrets: &fabric_secrets::SecretBroker,
    kind: &str,
    task_id: Option<i64>,
    payload: &Value,
) -> Result<(), StoreError> {
    let envelopes = store.all_secret_envelopes().await?;
    let payload = secrets
        .redact_value(
            payload,
            envelopes
                .iter()
                .map(|(name, envelope)| (name.as_str(), envelope.as_str())),
        )
        .map_err(|e| StoreError::Backend(format!("audit redaction failed closed: {e}")))?;
    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| StoreError::Backend(format!("redacted audit payload invalid: {e}")))?;
    let now = utc_now();

    for _ in 0..3 {
        let tail = store.audit_chain_tail().await?;
        let hash = audit_event_hash(&tail, kind, &payload);
        match store
            .append_audit_event(&tail, &hash, &tail, kind, task_id, &payload_json, &now)
            .await?
        {
            AuditAppendResult::Ok(_) => return Ok(()),
            AuditAppendResult::TailConflict { .. } => continue,
        }
    }
    // Genesis fallback: shouldn't happen in practice but not fatal
    Ok(())
}

/// Verify an Ed25519 signature over the canonical JSON of a payload envelope.
/// Returns Ok(()) on valid, Err string on invalid.
pub fn verify_sig(
    public_key_hex: &str,
    envelope: &Value,
    signature_hex: &str,
) -> Result<(), String> {
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

#[cfg(test)]
mod attribution_tests {
    use super::*;

    #[test]
    fn a_human_sessions_attribution_carries_its_account_id() {
        let actor = AuthContext::for_test("acct-abc123", &["dispatcher"], Some("acct-abc123"));
        let attributed = attribution(&actor);
        assert_eq!(attributed["human_account_id"], json!("acct-abc123"));
        assert_eq!(attributed["authenticated_subject"], json!("acct-abc123"));
        assert_eq!(attributed["legacy_bearer"], json!(false));
    }

    #[test]
    fn an_automation_role_tokens_attribution_has_a_null_human_account_id() {
        // The plan's "Legacy automation remains functional and is never
        // labeled as a person" -- a null human_account_id next to a present
        // authenticated_subject is the explicit, queryable signal that this
        // was automation, not a silently-blank field a query could confuse
        // with "unknown."
        let actor = AuthContext::for_test("token-xyz789", &["dispatcher", "runner"], None);
        let attributed = attribution(&actor);
        assert_eq!(attributed["human_account_id"], Value::Null);
        assert_eq!(attributed["authenticated_subject"], json!("token-xyz789"));
        assert_eq!(attributed["legacy_bearer"], json!(false));
    }

    #[test]
    fn the_legacy_cluster_bearer_is_flagged_distinctly_and_is_not_a_human() {
        let mut actor = AuthContext::for_test(
            "legacy-cluster-bearer",
            &["dispatcher", "runner", "observer"],
            None,
        );
        actor.legacy_compat = true;
        let attributed = attribution(&actor);
        assert_eq!(attributed["human_account_id"], Value::Null);
        assert_eq!(attributed["legacy_bearer"], json!(true));
    }

    #[test]
    fn attribution_json_contains_no_key_other_than_the_three_documented_fields() {
        // A guard against silently widening what this helper exposes --
        // dual-attribution audit fields are deliberately minimal (safe IDs
        // only, per the plan's payload discipline), not a dump of the whole
        // AuthContext (which would risk a future field, e.g. a raw secret,
        // being added to AuthContext and silently flowing into every audit
        // event through this helper).
        let actor = AuthContext::for_test("acct-1", &[], Some("acct-1"));
        let attributed = attribution(&actor);
        let mut keys: Vec<&String> = attributed.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["authenticated_subject", "human_account_id", "legacy_bearer"]
        );
    }
}
