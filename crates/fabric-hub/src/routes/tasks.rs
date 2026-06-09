//! Task dispatch, listing, claim, and state routes.
//!
//! - GET  /tasks
//! - GET  /tasks/{task_id}
//! - POST /tasks          (rejected; protocol v3 requires signed dispatch)
//! - POST /tasks/v2       (signed dispatch with registered dispatcher key)
//! - POST /tasks/claim-v2 (runner claim with Ed25519 signature)

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use fabric_claim_router::{pick_task, CandidateTask, RunnerView};
use fabric_store::{ClaimResult, CreateTaskParams, TaskRow};

use crate::state::HubState;
use crate::utils::{
    audit_append, budget_denial, check_skew, runner_kind_from_tags, utc_now, verify_sig,
};

// ---- Shared request types --------------------------------------------------

#[derive(Deserialize)]
pub struct DispatchPayload {
    pub title: String,
    pub prompt: String,
    pub scope_globs: Vec<String>,
    pub base_commit: String,
    pub branch: String,
    pub todo_id: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_minutes: i64,
    #[serde(default = "default_priority")]
    pub priority: i64,
    #[serde(default = "default_kind")]
    pub kind: String,
    #[serde(default)]
    pub metadata: Value,
    pub required_tools: Option<Vec<String>>,
    pub required_tags: Option<Vec<String>>,
    pub tenant: Option<String>,
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub require_base_commit: bool,
    pub required_capabilities: Option<Vec<String>>,
    pub secrets_needed: Option<Vec<String>>,
    pub network_egress: Option<Value>,
    pub approval_id: Option<String>,
    pub max_cost_usd: Option<f64>,
    // Phase 2.8 (M2.8.2): typed dispatch discriminator + capability identifiers.
    // Missing values are backward-compat: absent `dispatch` → "prompt" for
    // kind="agent" briefs; absent `kind` → "agent".
    pub dispatch: Option<String>,
    pub skill: Option<String>,
    pub tool: Option<String>,
    pub args: Option<Value>,
    pub input: Option<Value>,
    // Loom-specific fields (kind="command" briefs).
    pub command: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub env: Option<Value>,
    pub target: Option<Value>,
}

#[derive(Deserialize)]
pub struct SignedDispatchPayload {
    #[serde(flatten)]
    pub base: DispatchPayload,
    pub dispatcher_id: String,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct ClaimV2Payload {
    pub runner_id: String,
    pub scope_prefixes: Vec<String>,
    pub tools: Vec<String>,
    pub tags: Vec<String>,
    pub tenant: Option<String>,
    pub workspace_root: Option<String>,
    pub last_known_commit: Option<String>,
    pub cpu_load_pct: Option<f64>,
    pub ram_free_mb: Option<i64>,
    pub battery_pct: Option<i64>,
    #[serde(default)]
    pub on_battery: bool,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_timeout() -> i64 {
    60
}
fn default_priority() -> i64 {
    100
}
fn default_kind() -> String {
    "agent".into()
}
fn default_limit() -> i64 {
    100
}

// ---- GET /tasks ------------------------------------------------------------

pub async fn list_tasks(
    State(state): State<Arc<HubState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let tasks = state
        .store
        .list_tasks(q.status.as_deref(), q.limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "tasks": tasks })))
}

// ---- GET /tasks/{task_id} --------------------------------------------------

pub async fn get_task(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let task = state.store.get_task(task_id).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    Ok(Json(serde_json::to_value(task).unwrap_or(Value::Null)))
}

// ---- POST /tasks (unsigned, compat quarantine) -----------------------------

pub async fn dispatch_task(
    State(_state): State<Arc<HubState>>,
    Json(_payload): Json<DispatchPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    Err((
        StatusCode::UPGRADE_REQUIRED,
        "protocol v3 requires signed dispatch via POST /tasks/v2".into(),
    ))
}

// ---- POST /tasks/v2 (signed dispatch) --------------------------------------

pub async fn dispatch_task_signed(
    State(state): State<Arc<HubState>>,
    Json(payload): Json<SignedDispatchPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    check_skew(payload.timestamp).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let public_key = state
        .store
        .dispatcher_public_key(&payload.dispatcher_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "dispatcher not registered".into()))?;

    let envelope = json!({
        "op": "dispatch",
        "dispatcher_id": payload.dispatcher_id,
        "title": payload.base.title,
        "prompt": payload.base.prompt,
        "scope_globs": payload.base.scope_globs,
        "base_commit": payload.base.base_commit,
        "branch": payload.base.branch,
        "todo_id": payload.base.todo_id,
        "timeout_minutes": payload.base.timeout_minutes,
        "priority": payload.base.priority,
        "metadata": payload.base.metadata,
        "required_tools": payload.base.required_tools,
        "required_tags": payload.base.required_tags,
        "required_capabilities": payload.base.required_capabilities,
        "secrets_needed": payload.base.secrets_needed,
        "network_egress": payload.base.network_egress,
        "tenant": payload.base.tenant,
        "workspace_root": payload.base.workspace_root,
        "require_base_commit": payload.base.require_base_commit,
        "kind": payload.base.kind,
        "max_cost_usd": payload.base.max_cost_usd,
        "timestamp": payload.timestamp,
        "nonce": payload.nonce,
    });
    verify_sig(&public_key, &envelope, &payload.signature)
        .map_err(|e| (StatusCode::FORBIDDEN, e))?;

    state
        .store
        .consume_dispatcher_nonce(&payload.dispatcher_id, &payload.nonce, &utc_now())
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "dispatcher not registered".into())
            }
            fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;

    let now = utc_now();

    // Native budget gate (M2.5.3): reject before creating the task if a cost cap
    // is already met. Reads the persistent budget_state accumulators.
    if let Some(reason) = budget_denial(&*state.store, &state.budget_caps, &now)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        let _ = audit_append(
            &*state.store,
            "dispatch_denied",
            None,
            &json!({
                "reason": "budget_exceeded", "detail": reason, "signed": true,
                "dispatcher_id": payload.dispatcher_id,
            }),
        )
        .await;
        return Err((StatusCode::PAYMENT_REQUIRED, reason));
    }

    let p = dispatch_params(&payload.base, Some(&payload.dispatcher_id));
    let task = state
        .store
        .create_task(p, &now)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let audit_payload = json!({
        "task_id": task.id,
        "title": task.title,
        "base_commit": task.base_commit,
        "branch": task.branch,
        "scope_globs": task.scope_globs,
        "signed": true,
        "dispatcher_id": payload.dispatcher_id,
        "approval_id": payload.base.approval_id,
    });
    let _ = audit_append(&*state.store, "dispatch", Some(task.id), &audit_payload).await;

    Ok(Json(serde_json::to_value(task).unwrap_or(Value::Null)))
}

// ---- POST /tasks/claim-v2 --------------------------------------------------

pub async fn claim_task_v2(
    State(state): State<Arc<HubState>>,
    Json(payload): Json<ClaimV2Payload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    check_skew(payload.timestamp).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let public_key = state
        .store
        .runner_public_key(&payload.runner_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "runner not registered".into()))?;

    let envelope = json!({
        "op": "claim",
        "runner_id": payload.runner_id,
        "timestamp": payload.timestamp,
        "nonce": payload.nonce,
    });
    verify_sig(&public_key, &envelope, &payload.signature)
        .map_err(|e| (StatusCode::FORBIDDEN, e))?;

    let runner = state
        .store
        .get_runner(&payload.runner_id)
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "runner not registered".into())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;

    if runner.drain_requested {
        return Ok(Json(json!({"task": null, "info": {"reason": "drain"}})));
    }

    // Concurrency cap
    let active_tasks = state
        .store
        .list_tasks(Some("claimed"), 200)
        .await
        .unwrap_or_default();
    let active_tasks_running = state
        .store
        .list_tasks(Some("running"), 200)
        .await
        .unwrap_or_default();
    let current_load = active_tasks
        .iter()
        .chain(active_tasks_running.iter())
        .filter(|t| t.worker_id.as_deref() == Some(&payload.runner_id))
        .count() as i64;
    if current_load >= runner.max_concurrent {
        return Ok(Json(
            json!({"task": null, "info": {"reason": "concurrency_cap", "current_load": current_load, "max_concurrent": runner.max_concurrent}}),
        ));
    }

    // Resource gates
    if let Some(ram) = payload.ram_free_mb {
        if ram < 512 {
            return Ok(Json(
                json!({"task": null, "info": {"reason": "resource_gate", "detail": format!("ram_free_mb {ram} < 512")}}),
            ));
        }
    }
    if payload.on_battery {
        if let Some(batt) = payload.battery_pct {
            if batt < 20 {
                return Ok(Json(
                    json!({"task": null, "info": {"reason": "resource_gate", "detail": format!("on battery {batt}% < 20")}}),
                ));
            }
        }
    }

    // Fetch queued tasks matching kind
    let task_kind = runner_kind_from_tags(&payload.tags);
    let queued = state
        .store
        .list_tasks(Some("queued"), 50)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let queued: Vec<_> = queued
        .into_iter()
        .filter(|t| !t.cancel_requested && t.kind == task_kind)
        .collect();

    if queued.is_empty() {
        return Ok(Json(
            json!({"task": null, "info": {"reason": "queue_empty"}}),
        ));
    }

    let candidates: Vec<CandidateTask> = queued.iter().map(|t| build_candidate(t)).collect();

    // Use from_raw so scope_prefixes get the same normalization the task globs
    // get (backslashes -> '/', trailing '/'). Building RunnerView directly left
    // Windows backslash prefixes unnormalized, so no path-scoped task ever
    // matched a Windows runner.
    let runner_view = RunnerView::from_raw(
        &payload.scope_prefixes,
        &payload.tools,
        &payload.tags,
        payload.tenant.clone(),
        payload.workspace_root.clone(),
        payload.last_known_commit.clone(),
    );

    let (picked_idx, candidates_seen) = pick_task(&candidates, &runner_view);
    let chosen_idx = match picked_idx {
        None => {
            tracing::debug!(
                runner_id = %payload.runner_id,
                candidates_seen,
                scope_prefixes = ?runner_view.scope_prefixes,
                workspace_root = ?runner_view.workspace_root,
                tags = ?runner_view.tags,
                "no eligible task for runner"
            );
            return Ok(Json(
                json!({"task": null, "info": {"reason": "no_eligible_runner", "candidates_seen": candidates_seen}}),
            ));
        }
        Some(i) => i,
    };

    let chosen_task = &queued[chosen_idx];
    let now = utc_now();
    let claim_result = state
        .store
        .claim_task(chosen_task.id, &payload.runner_id, &now)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let task = match claim_result {
        ClaimResult::Claimed(t) => t,
        ClaimResult::AlreadyClaimed => {
            return Ok(Json(
                json!({"task": null, "info": {"reason": "no_eligible_runner", "detail": "lost_claim_race"}}),
            ));
        }
    };

    // Resolve secrets
    let mut task_val = serde_json::to_value(&task).unwrap_or(Value::Null);
    let mut secrets_dispatched: Vec<String> = vec![];
    let requested: Vec<String> = task
        .secrets_needed
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_owned()))
                .collect()
        })
        .unwrap_or_default();
    if !requested.is_empty() {
        if let Ok(resolved) = state.store.resolve_secrets(&requested).await {
            if !resolved.is_empty() {
                secrets_dispatched = resolved.keys().cloned().collect();
                if let Some(obj) = task_val.as_object_mut() {
                    obj.insert("secrets".into(), json!(resolved));
                }
            }
        }
    }

    // Audit claim
    let audit_payload = json!({
        "task_id": task.id,
        "worker_id": payload.runner_id,
        "hostname": runner.hostname,
        "secrets_dispatched": secrets_dispatched,
    });
    let _ = audit_append(&*state.store, "claim", Some(task.id), &audit_payload).await;

    Ok(Json(
        json!({"task": task_val, "info": {"reason": "claimed"}}),
    ))
}

// ---- POST /tasks/claim-loom ------------------------------------------------
//
// Phase 2.8 (M2.8.2): Loom queue claim — command-kind tasks only.
// Verifies the runner has "command" in its `kinds` column. No capability
// index lookup; eligibility is tool-list + host target only.

pub async fn claim_task_loom(
    State(state): State<Arc<HubState>>,
    Json(payload): Json<ClaimV2Payload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    check_skew(payload.timestamp).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let public_key = state
        .store
        .runner_public_key(&payload.runner_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "runner not registered".into()))?;

    let envelope = json!({
        "op": "claim",
        "runner_id": payload.runner_id,
        "timestamp": payload.timestamp,
        "nonce": payload.nonce,
    });
    verify_sig(&public_key, &envelope, &payload.signature)
        .map_err(|e| (StatusCode::FORBIDDEN, e))?;

    let runner = state
        .store
        .get_runner(&payload.runner_id)
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "runner not registered".into())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;

    // Verify this runner can handle Loom (command) tasks.
    let runner_kinds: Vec<&str> = runner
        .kinds
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !runner_kinds.contains(&"command") {
        return Err((
            StatusCode::FORBIDDEN,
            "runner is not registered as a Loom (command) runner".into(),
        ));
    }

    if runner.drain_requested {
        return Ok(Json(json!({"task": null, "info": {"reason": "drain"}})));
    }

    // Concurrency cap
    let active = state.store.list_tasks(Some("claimed"), 200).await.unwrap_or_default();
    let running = state.store.list_tasks(Some("running"), 200).await.unwrap_or_default();
    let current_load = active
        .iter()
        .chain(running.iter())
        .filter(|t| t.worker_id.as_deref() == Some(&payload.runner_id))
        .count() as i64;
    if current_load >= runner.max_concurrent {
        return Ok(Json(
            json!({"task": null, "info": {"reason": "concurrency_cap", "current_load": current_load, "max_concurrent": runner.max_concurrent}}),
        ));
    }

    // Resource gates
    if let Some(ram) = payload.ram_free_mb {
        if ram < 512 {
            return Ok(Json(
                json!({"task": null, "info": {"reason": "resource_gate", "detail": format!("ram_free_mb {ram} < 512")}}),
            ));
        }
    }

    // Loom queue: kind='command' tasks only.
    let queued = state
        .store
        .list_tasks(Some("queued"), 50)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let queued: Vec<_> = queued
        .into_iter()
        .filter(|t| !t.cancel_requested && t.kind == "command")
        .collect();

    if queued.is_empty() {
        return Ok(Json(json!({"task": null, "info": {"reason": "queue_empty"}})));
    }

    let candidates: Vec<CandidateTask> = queued
        .iter()
        .map(|t| build_candidate(t))
        .collect();

    let runner_view = RunnerView::from_raw(
        &payload.scope_prefixes,
        &payload.tools,
        &payload.tags,
        payload.tenant.clone(),
        payload.workspace_root.clone(),
        payload.last_known_commit.clone(),
    );

    let (picked_idx, candidates_seen) = pick_task(&candidates, &runner_view);
    let chosen_idx = match picked_idx {
        None => {
            return Ok(Json(
                json!({"task": null, "info": {"reason": "no_eligible_runner", "candidates_seen": candidates_seen}}),
            ));
        }
        Some(i) => i,
    };

    do_claim(&*state, &queued[chosen_idx], &payload.runner_id, &runner.hostname).await
}

// ---- POST /tasks/claim-fabric -----------------------------------------------
//
// Phase 2.8 (M2.8.2): Fabric queue claim — agent-kind tasks only.
// For dispatch="skill" and dispatch="tool" tasks, intersects the eligible set
// with runner_capabilities before scoring. Prompt dispatch skips the
// capability filter (backward-compat for legacy freeform briefs).

pub async fn claim_task_fabric(
    State(state): State<Arc<HubState>>,
    Json(payload): Json<ClaimV2Payload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    check_skew(payload.timestamp).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let public_key = state
        .store
        .runner_public_key(&payload.runner_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "runner not registered".into()))?;

    let envelope = json!({
        "op": "claim",
        "runner_id": payload.runner_id,
        "timestamp": payload.timestamp,
        "nonce": payload.nonce,
    });
    verify_sig(&public_key, &envelope, &payload.signature)
        .map_err(|e| (StatusCode::FORBIDDEN, e))?;

    let runner = state
        .store
        .get_runner(&payload.runner_id)
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "runner not registered".into())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;

    // Verify this runner can handle Fabric (agent) tasks.
    let runner_kinds: Vec<&str> = runner
        .kinds
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !runner_kinds.contains(&"agent") {
        return Err((
            StatusCode::FORBIDDEN,
            "runner is not registered as a Fabric (agent) runner".into(),
        ));
    }

    if runner.drain_requested {
        return Ok(Json(json!({"task": null, "info": {"reason": "drain"}})));
    }

    // Concurrency cap
    let active = state.store.list_tasks(Some("claimed"), 200).await.unwrap_or_default();
    let running = state.store.list_tasks(Some("running"), 200).await.unwrap_or_default();
    let current_load = active
        .iter()
        .chain(running.iter())
        .filter(|t| t.worker_id.as_deref() == Some(&payload.runner_id))
        .count() as i64;
    if current_load >= runner.max_concurrent {
        return Ok(Json(
            json!({"task": null, "info": {"reason": "concurrency_cap", "current_load": current_load, "max_concurrent": runner.max_concurrent}}),
        ));
    }

    // Resource gates
    if let Some(ram) = payload.ram_free_mb {
        if ram < 512 {
            return Ok(Json(
                json!({"task": null, "info": {"reason": "resource_gate", "detail": format!("ram_free_mb {ram} < 512")}}),
            ));
        }
    }

    // Load this runner's capability set once for capability filtering below.
    let runner_caps = state
        .store
        .runner_capabilities(&payload.runner_id)
        .await
        .unwrap_or_default();

    // Fabric queue: kind='agent' tasks only.
    let queued = state
        .store
        .list_tasks(Some("queued"), 50)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Filter to agent tasks; apply capability filter for skill/tool dispatch.
    let eligible: Vec<_> = queued
        .into_iter()
        .filter(|t| !t.cancel_requested && t.kind == "agent")
        .filter(|t| {
            match t.dispatch.as_deref() {
                Some("skill") => {
                    // Runner must advertise the skill as a prompt capability.
                    let skill_name = t.skill.as_deref().unwrap_or("");
                    runner_caps.iter().any(|c| {
                        c.capability_kind == "prompt" && c.name == skill_name
                    })
                }
                Some("tool") => {
                    // Runner must advertise the tool capability.
                    let tool_name = t.tool.as_deref().unwrap_or("");
                    runner_caps.iter().any(|c| {
                        c.capability_kind == "tool" && c.name == tool_name
                    })
                }
                // "prompt" or NULL: no capability gate, route by scope/tags.
                _ => true,
            }
        })
        .collect();

    if eligible.is_empty() {
        return Ok(Json(json!({"task": null, "info": {"reason": "queue_empty"}})));
    }

    let candidates: Vec<CandidateTask> = eligible.iter().map(|t| build_candidate(t)).collect();

    let runner_view = RunnerView::from_raw(
        &payload.scope_prefixes,
        &payload.tools,
        &payload.tags,
        payload.tenant.clone(),
        payload.workspace_root.clone(),
        payload.last_known_commit.clone(),
    );

    let (picked_idx, candidates_seen) = pick_task(&candidates, &runner_view);
    let chosen_idx = match picked_idx {
        None => {
            return Ok(Json(
                json!({"task": null, "info": {"reason": "no_eligible_runner", "candidates_seen": candidates_seen}}),
            ));
        }
        Some(i) => i,
    };

    do_claim(&*state, &eligible[chosen_idx], &payload.runner_id, &runner.hostname).await
}

// ---- Helpers ---------------------------------------------------------------

/// Build a `CandidateTask` from a stored `TaskRow` for the claim-router.
fn build_candidate(t: &TaskRow) -> CandidateTask {
    let scope_globs = t
        .scope_globs
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_owned()))
                .collect()
        })
        .unwrap_or_default();
    let required_tools = t
        .required_tools
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_owned()))
                .collect()
        })
        .unwrap_or_default();
    let required_tags = t
        .required_tags
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_owned()))
                .collect()
        })
        .unwrap_or_default();
    CandidateTask {
        scope_globs,
        required_tools,
        required_tags,
        tenant: t.tenant.clone(),
        workspace_root: t.workspace_root.clone(),
        require_base_commit: t.require_base_commit,
        base_commit: t.base_commit.clone(),
    }
}

/// Perform the atomic claim + secret resolution + audit for a chosen task.
async fn do_claim(
    state: &crate::state::HubState,
    task: &TaskRow,
    runner_id: &str,
    hostname: &str,
) -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;

    let now = utc_now();
    let claim_result = state
        .store
        .claim_task(task.id, runner_id, &now)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let claimed_task = match claim_result {
        ClaimResult::Claimed(t) => t,
        ClaimResult::AlreadyClaimed => {
            return Ok(axum::Json(
                json!({"task": null, "info": {"reason": "no_eligible_runner", "detail": "lost_claim_race"}}),
            ));
        }
    };

    let mut task_val = serde_json::to_value(&claimed_task).unwrap_or(Value::Null);
    let mut secrets_dispatched: Vec<String> = vec![];
    let requested: Vec<String> = claimed_task
        .secrets_needed
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_owned()))
                .collect()
        })
        .unwrap_or_default();
    if !requested.is_empty() {
        if let Ok(resolved) = state.store.resolve_secrets(&requested).await {
            if !resolved.is_empty() {
                secrets_dispatched = resolved.keys().cloned().collect();
                if let Some(obj) = task_val.as_object_mut() {
                    obj.insert("secrets".into(), json!(resolved));
                }
            }
        }
    }

    let audit_payload = json!({
        "task_id": claimed_task.id,
        "worker_id": runner_id,
        "hostname": hostname,
        "secrets_dispatched": secrets_dispatched,
    });
    let _ = audit_append(&*state.store, "claim", Some(claimed_task.id), &audit_payload).await;

    Ok(axum::Json(json!({"task": task_val, "info": {"reason": "claimed"}})))
}

fn dispatch_params(p: &DispatchPayload, dispatcher_id: Option<&str>) -> CreateTaskParams {
    let metadata = if p.metadata.is_null() {
        json!({})
    } else {
        p.metadata.clone()
    };

    // Phase 2.8 (M2.8.2): resolve dispatch discriminator. Missing `dispatch`
    // on kind="agent" briefs is treated as "prompt" (legacy behavior).
    // kind="command" briefs keep dispatch=NULL.
    let dispatch = p.dispatch.clone().or_else(|| {
        if p.kind == "agent" {
            Some("prompt".into())
        } else {
            None
        }
    });

    CreateTaskParams {
        title: p.title.clone(),
        prompt: p.prompt.clone(),
        scope_globs: p.scope_globs.clone(),
        base_commit: p.base_commit.clone(),
        branch: p.branch.clone(),
        todo_id: p.todo_id.clone(),
        timeout_minutes: p.timeout_minutes,
        priority: p.priority,
        kind: p.kind.clone(),
        metadata,
        required_tools: p.required_tools.clone(),
        required_tags: p.required_tags.clone(),
        tenant: p.tenant.clone(),
        workspace_root: p.workspace_root.clone(),
        require_base_commit: p.require_base_commit,
        required_capabilities: p.required_capabilities.clone(),
        secrets_needed: p.secrets_needed.clone(),
        network_egress: p.network_egress.clone(),
        dispatcher_id: dispatcher_id.map(|s| s.to_owned()),
        dispatch,
        skill: p.skill.clone(),
        tool: p.tool.clone(),
    }
}
