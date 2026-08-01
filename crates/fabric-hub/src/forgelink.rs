//! Optional routing of Fabric HITL approvals to ForgeLink as the governed decision
//! surface (work item 016 AGH-028; decision 0004).
//!
//! When ForgeLink is configured and reachable, a held approval is forwarded to
//! ForgeLink's `agent-governance-v1` contract (an evidence-bearing approval request
//! on the agent channel). Routing is best-effort and time-bounded: any failure —
//! ForgeLink absent, unreachable, or the operator opted out — falls back silently to
//! Fabric's built-in approval pane with no loss of function. ForgeLink is an
//! enhancement, never a hard dependency.

use std::time::Duration;

use serde_json::{json, Value};

/// ForgeLink routing configuration, read from the environment:
/// - `FORGELINK_BASE_URL`     — ForgeLink local API base (e.g. `http://127.0.0.1:8765`)
/// - `FORGELINK_CHANNEL_ID`   — agent channel id (default `forgewire`)
/// - `FORGELINK_CHANNEL_TOKEN`— the agent channel credential
/// - `FORGELINK_HITL`         — set to `off`/`0`/`false`/`disabled` to opt out
#[derive(Clone, Debug, Default)]
pub struct ForgeLinkConfig {
    pub base_url: Option<String>,
    pub channel_id: String,
    pub channel_token: Option<String>,
    /// MCP token used to poll a routed approval's decision (the status route is
    /// MCP-safe). Required for decision write-back; routing alone needs only the
    /// channel token.
    pub mcp_token: Option<String>,
    pub opted_out: bool,
}

impl ForgeLinkConfig {
    pub fn from_env() -> Self {
        let opt = std::env::var("FORGELINK_HITL")
            .ok()
            .map(|v| v.trim().to_lowercase());
        let opted_out = matches!(
            opt.as_deref(),
            Some("off") | Some("0") | Some("false") | Some("disabled")
        );
        let clean = |k: &str| {
            std::env::var(k)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        Self {
            base_url: clean("FORGELINK_BASE_URL").map(|s| s.trim_end_matches('/').to_string()),
            channel_id: clean("FORGELINK_CHANNEL_ID").unwrap_or_else(|| "forgewire".into()),
            channel_token: clean("FORGELINK_CHANNEL_TOKEN"),
            mcp_token: clean("FORGELINK_MCP_TOKEN"),
            opted_out,
        }
    }

    /// ForgeLink routing is active only when a base URL and channel token are
    /// configured and the operator has not opted out.
    pub fn enabled(&self) -> bool {
        !self.opted_out && self.base_url.is_some() && self.channel_token.is_some()
    }

    /// Decision write-back (polling a routed approval's decision) additionally needs
    /// an MCP token, since the ForgeLink status route is MCP-safe.
    pub fn reconcile_enabled(&self) -> bool {
        self.enabled() && self.mcp_token.is_some()
    }
}

/// The resolved decision read back from ForgeLink for a routed approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForgeLinkDecision {
    Approved,
    Denied,
}

/// Map a Fabric dispatch kind to the ForgeLink authority scope it requires.
pub fn authority_for_kind(kind: &str) -> &'static str {
    match kind {
        "merge" | "push" | "release" => "release_approval",
        _ => "general_approval",
    }
}

/// Build the `agent-governance-v1` approval-request body ForgeLink expects, from a
/// held Fabric approval. Pure (no I/O) so it is unit-testable.
pub fn build_approval_request(
    approval_id: &str,
    title: &str,
    reason: &str,
    kind: &str,
    branch: Option<&str>,
    scope_globs: &[String],
    source: &str,
) -> Value {
    let resources: Vec<String> = scope_globs.to_vec();
    let branch_note = branch
        .map(|b| format!(" on branch {b}"))
        .unwrap_or_default();
    json!({
        "id": format!("fabric-{approval_id}"),
        "kind": "approval_request",
        "source": source,
        "source_kind": "forgewire_fabric",
        "urgency": "normal",
        "title": title,
        "body": reason,
        "intent": format!("Fabric dispatch requires approval: {title}"),
        "requested_action": format!("Run the held Fabric task ({kind})"),
        "reason_for_interrupt": reason,
        "risk": "normal",
        "required_authority": authority_for_kind(kind),
        "to_human": "operator:primary",
        "affected_resources": resources,
        "timeout_behavior": "deny_on_timeout",
        "deny_behavior": "do_not_run",
        "expected_response_time": "soon",
        "no_response_behavior": "deny_on_timeout",
        "decision_options": [{"id": "approve", "label": "Approve"}, {"id": "deny", "label": "Deny"}],
        "template_id": "git_commit",
        "evidence_pack": {
            "summary": format!("Fabric is holding \"{title}\" pending approval."),
            "affected_resources": resources,
            "diff_summary": "Diff not transmitted to ForgeLink; review in Fabric.",
            "proposed_operation": format!("Fabric dispatch of kind {kind}{branch_note}"),
            "checks": ["fabric policy gate: needs_approval"],
            "rollback_plan": "Deny to keep the task held; no action runs without approval.",
            "links": [],
            "limitations": "Evidence summarized by Fabric; full context lives in the Fabric hub.",
            "redaction_profile": "desktop_full"
        }
    })
}

/// Forward a held approval to ForgeLink. Returns the ForgeLink message id on
/// success. Errors (unreachable, non-2xx, misconfigured) are returned to the caller
/// so it can fall back to Fabric's built-in pane.
pub async fn route_approval(cfg: &ForgeLinkConfig, body: &Value) -> Result<String, String> {
    let base = cfg
        .base_url
        .as_deref()
        .ok_or("forgelink base_url not configured")?;
    let token = cfg
        .channel_token
        .as_deref()
        .ok_or("forgelink channel_token not configured")?;
    let url = format!("{base}/api/agent-channels/{}/messages", cfg.channel_id);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(&url)
        .header("X-ForgeLink-Channel-Token", token)
        .json(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!(
            "forgelink returned HTTP {}",
            resp.status().as_u16()
        ));
    }
    let v: Value = resp.json().await.map_err(|e| e.to_string())?;
    Ok(v.get("message")
        .and_then(|m| m.get("id"))
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_string())
}

/// Classify a ForgeLink agent-request status payload into a Fabric decision. Pure
/// (no I/O) so it is unit-testable. Returns `None` while the request is undecided.
pub fn decision_from_status(v: &Value) -> Option<ForgeLinkDecision> {
    if !v.get("decided").and_then(|d| d.as_bool()).unwrap_or(false) {
        return None;
    }
    let decision = v.get("decision").and_then(|d| d.as_str()).unwrap_or("");
    const DENIALS: [&str; 5] = ["deny", "dismiss", "reject", "decline", "cancel"];
    if DENIALS.contains(&decision) {
        Some(ForgeLinkDecision::Denied)
    } else {
        // A decided, non-denial decision (authority granted or an approve-like
        // option) resolves the held approval as approved.
        Some(ForgeLinkDecision::Approved)
    }
}

/// Poll ForgeLink for the decision on a routed approval (decision write-back,
/// AGH-028). The ForgeLink request id is deterministic: `fabric-<approval_id>`.
/// Returns `Ok(None)` while undecided or when ForgeLink has no such request (404),
/// so the caller simply leaves the approval pending.
pub async fn fetch_decision(
    cfg: &ForgeLinkConfig,
    approval_id: &str,
) -> Result<Option<ForgeLinkDecision>, String> {
    let base = cfg
        .base_url
        .as_deref()
        .ok_or("forgelink base_url not configured")?;
    let token = cfg
        .mcp_token
        .as_deref()
        .ok_or("forgelink mcp_token not configured")?;
    let url = format!("{base}/api/agent-messages/fabric-{approval_id}/status");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!(
            "forgelink returned HTTP {}",
            resp.status().as_u16()
        ));
    }
    let v: Value = resp.json().await.map_err(|e| e.to_string())?;
    Ok(decision_from_status(&v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_without_config() {
        let cfg = ForgeLinkConfig::default();
        assert!(!cfg.enabled());
    }

    #[test]
    fn enabled_with_base_and_token() {
        let cfg = ForgeLinkConfig {
            base_url: Some("http://127.0.0.1:8765".into()),
            channel_id: "forgewire".into(),
            channel_token: Some("flchan_x".into()),
            mcp_token: None,
            opted_out: false,
        };
        assert!(cfg.enabled());
        // Reconcile (decision write-back) needs the MCP token too.
        assert!(!cfg.reconcile_enabled());
        let cfg2 = ForgeLinkConfig {
            mcp_token: Some("flmcp_x".into()),
            ..cfg
        };
        assert!(cfg2.reconcile_enabled());
    }

    #[test]
    fn opt_out_disables_even_when_configured() {
        let cfg = ForgeLinkConfig {
            base_url: Some("http://127.0.0.1:8765".into()),
            channel_id: "forgewire".into(),
            channel_token: Some("flchan_x".into()),
            mcp_token: Some("flmcp_x".into()),
            opted_out: true,
        };
        assert!(!cfg.enabled());
        assert!(!cfg.reconcile_enabled());
    }

    #[test]
    fn decision_from_status_classifies_decisions() {
        use serde_json::json;
        // Undecided -> None.
        assert_eq!(decision_from_status(&json!({ "decided": false })), None);
        // Decided approve -> Approved.
        assert_eq!(
            decision_from_status(
                &json!({ "decided": true, "decision": "approve", "authority_granted": true })
            ),
            Some(ForgeLinkDecision::Approved)
        );
        // Decided deny/dismiss -> Denied.
        assert_eq!(
            decision_from_status(&json!({ "decided": true, "decision": "deny" })),
            Some(ForgeLinkDecision::Denied)
        );
        assert_eq!(
            decision_from_status(&json!({ "decided": true, "decision": "dismiss" })),
            Some(ForgeLinkDecision::Denied)
        );
    }

    #[test]
    fn authority_maps_protected_kinds_to_release() {
        assert_eq!(authority_for_kind("merge"), "release_approval");
        assert_eq!(authority_for_kind("push"), "release_approval");
        assert_eq!(authority_for_kind("write"), "general_approval");
    }

    #[test]
    fn approval_request_matches_the_contract() {
        let body = build_approval_request(
            "appr-1",
            "Merge release branch",
            "protected branch requires approval",
            "merge",
            Some("main"),
            &["repo/**".to_string()],
            "forgewire-fabric",
        );
        assert_eq!(body["kind"], "approval_request");
        assert_eq!(body["id"], "fabric-appr-1");
        assert_eq!(body["required_authority"], "release_approval");
        assert_eq!(body["source_kind"], "forgewire_fabric");
        // Evidence pack carries the required, non-empty contract fields.
        let ev = &body["evidence_pack"];
        assert!(ev["summary"]
            .as_str()
            .unwrap()
            .contains("Merge release branch"));
        assert_eq!(ev["redaction_profile"], "desktop_full");
        assert!(ev["proposed_operation"]
            .as_str()
            .unwrap()
            .contains("branch main"));
        // Decision options are approve/deny.
        assert_eq!(body["decision_options"][0]["id"], "approve");
        assert_eq!(body["decision_options"][1]["id"], "deny");
    }
}
