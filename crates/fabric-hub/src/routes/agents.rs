//! Phase 2.8 (M2.8.2): Fabric agent registry and capability index routes.
//!
//! - GET /agents                        — Fabric runners (kinds ∋ "agent")
//! - GET /capabilities/{kind}/{name}    — runners advertising a capability

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use crate::state::HubState;

// ── GET /agents ───────────────────────────────────────────────────────────────
//
// Returns every runner whose `kinds` array contains "agent", with its full
// `mcp_manifest`. Used by `list_agents` in the forgewire-fabric dispatcher MCP.

pub async fn list_agents(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let labels = state.store.get_labels().await.unwrap_or(json!({}));
    let runner_aliases = labels["runner_aliases"].as_object().cloned().unwrap_or_default();
    let host_aliases = labels["host_aliases"].as_object().cloned().unwrap_or_default();

    let runners = state
        .store
        .list_runners()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let agents: Vec<Value> = runners
        .into_iter()
        .filter(|r| {
            r.kinds
                .as_array()
                .map(|a| a.iter().any(|v| v.as_str() == Some("agent")))
                .unwrap_or(false)
        })
        .map(|r| {
            let hostname = r.hostname.to_lowercase();
            let host_alias = host_aliases
                .get(&hostname)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let alias = runner_aliases
                .get(&r.runner_id)
                .and_then(|v| v.as_str())
                .unwrap_or(&host_alias)
                .to_owned();
            json!({
                "runner_id": r.runner_id,
                "agent_type": r.agent_type,
                "hostname": r.hostname,
                "alias": alias,
                "state": r.state,
                "drain_requested": r.drain_requested,
                "last_heartbeat": r.last_heartbeat,
                "mcp_manifest": r.mcp_manifest,
                "mcp_manifest_version": r.mcp_manifest_version,
                "kinds": r.kinds,
                "max_concurrent": r.max_concurrent,
                "tenant": r.tenant,
                "workspace_root": r.workspace_root,
            })
        })
        .collect();

    Ok(Json(json!({ "agents": agents })))
}

// ── GET /capabilities/{kind}/{name} ───────────────────────────────────────────
//
// Returns runners that advertise the requested capability. Used by the
// dispatcher to preview routing before submitting a skill/tool brief.
// `kind` is one of "tool" | "resource" | "prompt".

pub async fn get_capability(
    State(state): State<Arc<HubState>>,
    Path((kind, name)): Path<(String, String)>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !matches!(kind.as_str(), "tool" | "resource" | "prompt") {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("capability kind must be 'tool', 'resource', or 'prompt'; got '{kind}'"),
        ));
    }

    let runner_ids = state
        .store
        .query_runners_by_capability(&kind, &name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Fetch runner rows to include state and manifest summary.
    let mut runners_out: Vec<Value> = Vec::new();
    for runner_id in &runner_ids {
        if let Ok(r) = state.store.get_runner(runner_id).await {
            runners_out.push(json!({
                "runner_id": r.runner_id,
                "agent_type": r.agent_type,
                "hostname": r.hostname,
                "state": r.state,
                "drain_requested": r.drain_requested,
            }));
        }
    }

    Ok(Json(json!({
        "capability_kind": kind,
        "name": name,
        "runners": runners_out,
    })))
}
