//! Task dispatch, listing, claim, and state routes.
//!
//! - GET  /tasks
//! - GET  /tasks/{task_id}
//! - POST /tasks          (rejected; protocol v3 requires signed dispatch)
//! - POST /tasks/v2       (signed dispatch with registered dispatcher key)
//! - POST /tasks/claim-loom   (command-kind runner claim, Ed25519 signature)
//! - POST /tasks/claim-fabric (agent-kind runner claim, Ed25519 signature)

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use fabric_claim_router::{pick_task, CandidateTask, RunnerView};
use fabric_policy::{DispatchRequest, PolicyDecision};
use fabric_store::{ClaimResult, CreateTaskParams, DispatcherRow, TaskRow};

use crate::auth::AuthContext;
use crate::capabilities::match_required;
use crate::error::ApiError;
use crate::state::HubState;

owned_router! {
    pub fn router, ROUTES {
        "GET" get "/tasks" => list_tasks;
        "POST" post "/tasks" => dispatch_task;
        "POST" post "/tasks/v2" => dispatch_task_signed;
        "GET" get "/tasks/waiting" => list_waiting_tasks;
        "POST" post "/tasks/claim" => claim_task_legacy;
        "POST" post "/tasks/claim-loom" => claim_task_loom;
        "POST" post "/tasks/claim-fabric" => claim_task_fabric;
        "GET" get "/tasks/{task_id}" => get_task;
    }
}

owned_router! {
    pub fn intent_router, INTENT_ROUTES {
        "POST" post "/tasks/{task_id}/intent" => evaluate_intent;
    }
}
use crate::utils::{attribution, audit_append, budget_denial, check_skew, utc_now, verify_sig};

/// SHA-256 of the canonical JSON of the (string-only) env map. Byte-identical to
/// the Python signer's `_loom_env_digest` (via `canonical_payload`) and the Rust
/// loom-runner's `compute_env_digest` (both go through `fabric_protocol::canonicalize`).
/// Used to verify env-value integrity at dispatch (M2.9.5).
fn loom_env_digest(env: Option<&Value>) -> String {
    use sha2::{Digest, Sha256};
    let string_only: serde_json::Map<String, Value> = env
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), Value::String(s.to_owned()))))
                .collect()
        })
        .unwrap_or_default();
    let canonical = fabric_protocol::canonicalize(&Value::Object(string_only)).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    hex::encode(hasher.finalize())
}

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
    // M2.8.9: `kind` is required. A missing field deserializes to "" (via
    // serde default) and is hard-rejected with 400 in the dispatch handler —
    // the legacy "absent kind → agent" backward-compat is gone.
    #[serde(default)]
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
    // Absent `dispatch` → "prompt" for kind="agent" briefs (kind itself is
    // required as of M2.8.9; see the `kind` field above).
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
    // M2.9.1 (F1): SHA-256 of canonical JSON of the sorted env map, set by signer.
    pub loom_env_digest: Option<String>,
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
pub struct LegacyClaimPayload {
    pub worker_id: String,
    #[serde(default)]
    pub hostname: String,
    /// Accepted for wire compatibility only. Unsigned capabilities are not
    /// trusted and cannot satisfy capability-gated tasks.
    #[serde(default)]
    pub capabilities: Value,
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
fn default_limit() -> i64 {
    100
}

// ---- GET /tasks ------------------------------------------------------------

pub async fn list_tasks(
    State(state): State<Arc<HubState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let tasks = state
        .store
        .list_tasks(q.status.as_deref(), q.limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "tasks": tasks })))
}

/// List queued capability-gated tasks that no online runner can satisfy.
pub async fn list_waiting_tasks(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, ApiError> {
    let runners = state
        .store
        .list_runners()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let online: Vec<_> = runners
        .iter()
        .filter(|runner| {
            matches!(runner.state.as_str(), "online" | "degraded") && !runner.drain_requested
        })
        .collect();
    let tasks = state
        .store
        .list_tasks(Some("queued"), 200)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut waiting = Vec::new();
    for task in tasks {
        let required = task
            .required_capabilities
            .as_ref()
            .filter(|value| value.as_array().is_some_and(|items| !items.is_empty()));
        let Some(required) = required else {
            continue;
        };
        let mut satisfied_by = Vec::new();
        let mut missing_per_runner = serde_json::Map::new();
        for runner in &online {
            let (ok, missing) = match_required(required, &runner.capabilities);
            if ok {
                satisfied_by.push(runner.runner_id.clone());
            } else {
                missing_per_runner.insert(runner.runner_id.clone(), json!(missing));
            }
        }
        if satisfied_by.is_empty() {
            waiting.push(json!({
                "task_id": task.id,
                "title": task.title,
                "branch": task.branch,
                "required_capabilities": required,
                "missing_per_runner": missing_per_runner,
            }));
        }
    }
    Ok(Json(json!({
        "tasks": waiting,
        "online_runners": online.iter().map(|runner| &runner.runner_id).collect::<Vec<_>>(),
    })))
}

/// Legacy unsigned claim, retained during the compatibility window.
///
/// It is intentionally degraded: agent tasks only, no capability-gated
/// tasks, no supplied capability trust, and an audit event on every use.
pub async fn claim_task_legacy(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(payload): Json<LegacyClaimPayload>,
) -> Result<(HeaderMap, Json<Value>), ApiError> {
    let candidates = state
        .store
        .list_tasks(Some("queued"), 200)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let candidate = candidates.into_iter().find(|task| {
        task.kind == "agent"
            && !task.cancel_requested
            && task
                .required_capabilities
                .as_ref()
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
    });

    let compatibility_audit = json!({
        "worker_id": payload.worker_id,
        "hostname": payload.hostname,
        "supplied_capabilities_ignored": !payload.capabilities.is_null(),
        "posture": "degraded",
        "attribution": attribution(&actor),
    });
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "legacy_claim_degraded",
        candidate.as_ref().map(|task| task.id),
        &compatibility_audit,
    )
    .await;

    let Json(mut body) = if let Some(task) = candidate {
        do_claim(&state, &actor, &task, &payload.worker_id, &payload.hostname).await?
    } else {
        Json(json!({"task": null, "info": {"reason": "queue_empty"}}))
    };
    if let Some(info) = body.get_mut("info").and_then(Value::as_object_mut) {
        info.insert("compatibility".into(), Value::String("degraded".into()));
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::WARNING,
        HeaderValue::from_static(
            "299 ForgeWire \"legacy unsigned claim is degraded; migrate to signed kind-specific claim\"",
        ),
    );
    Ok((headers, Json(body)))
}

// ---- GET /tasks/{task_id} --------------------------------------------------

pub async fn get_task(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
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
    Extension(actor): Extension<AuthContext>,
    Json(payload): Json<SignedDispatchPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    check_skew(payload.timestamp).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    // M2.8.9: `kind` is mandatory — the legacy "absent kind → agent" shim is
    // gone. A missing/blank or unrecognized kind is a hard 400 before any
    // signature/queue work.
    if payload.base.kind.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "kind is required (one of: agent, command)".into(),
        ));
    }
    if payload.base.kind != "agent" && payload.base.kind != "command" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "kind must be 'agent' or 'command'; got '{}'",
                payload.base.kind
            ),
        ));
    }

    let dispatcher = state
        .store
        .get_dispatcher(&payload.dispatcher_id)
        .await
        .map_err(|error| match error {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "dispatcher not registered".into())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    let public_key = dispatcher.public_key.clone();

    // M2.9.1 (F1): for command-kind briefs, detect whether the signer included
    // the executable payload in the envelope. If the signed fields are present,
    // include them in the reconstructed envelope so signature verification covers
    // command/cwd/env_keys/env_digest. If absent (legacy brief), accept during
    // the deprecation window and log a legacy audit event.
    let is_command = payload.base.kind == "command";
    let has_signed_command =
        is_command && payload.base.command.is_some() && payload.base.loom_env_digest.is_some();

    let envelope = if has_signed_command {
        let loom_command = payload.base.command.as_deref().unwrap_or(&[]);
        let loom_cwd = payload.base.cwd.as_deref().unwrap_or("");
        let loom_env_keys: Vec<String> = payload
            .base
            .env
            .as_ref()
            .and_then(|v| v.as_object())
            .map(|obj| {
                let mut keys: Vec<String> = obj.keys().cloned().collect();
                keys.sort();
                keys
            })
            .unwrap_or_default();
        json!({
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
            "loom_command": loom_command,
            "loom_cwd": loom_cwd,
            "loom_env_keys": loom_env_keys,
            "loom_env_digest": payload.base.loom_env_digest,
        })
    } else {
        json!({
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
        })
    };
    verify_sig(&public_key, &envelope, &payload.signature)
        .map_err(|e| (StatusCode::FORBIDDEN, e))?;

    // M2.9.7 legacy flip: unsigned command briefs are now hard-rejected (403).
    // The deprecation window (M2.9.1–M2.9.6) is closed.
    if is_command && !has_signed_command {
        let _ = audit_append(
            &*state.store,
            &state.secrets,
            "legacy_loom_unsigned_command",
            None,
            &json!({
                "dispatcher_id": payload.dispatcher_id,
                "title": payload.base.title,
                "warning": "command/cwd/env not covered by dispatcher signature; rejected",
                "attribution": attribution(&actor),
            }),
        )
        .await;
        return Err((
            StatusCode::FORBIDDEN,
            "unsigned Loom command brief rejected: dispatcher must sign command/cwd/env fields (upgrade to M2.9.1+)".into(),
        ));
    }

    // M2.9.5 (F5-followup): the signature covers loom_env_digest but not the env
    // *values* (they may carry secrets). Recompute the digest over the env map
    // actually present in the payload and reject at dispatch if it doesn't match
    // the signed digest — this catches env-value tampering before the task is
    // queued, instead of failing confusingly at the runner post-claim.
    if has_signed_command {
        if let Some(signed_digest) = payload.base.loom_env_digest.as_deref() {
            let actual = loom_env_digest(payload.base.env.as_ref());
            if actual != signed_digest {
                let _ = audit_append(
                    &*state.store,
                    &state.secrets,
                    "dispatch_denied",
                    None,
                    &json!({
                        "reason": "loom_env_digest_mismatch",
                        "signed": true,
                        "dispatcher_id": payload.dispatcher_id,
                        "attribution": attribution(&actor),
                    }),
                )
                .await;
                return Err((
                    StatusCode::BAD_REQUEST,
                    "loom_env_digest does not match the env map in the brief".into(),
                ));
            }
        }
    }

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
            &state.secrets,
            "dispatch_denied",
            None,
            &json!({
                "reason": "budget_exceeded", "detail": reason, "signed": true,
                "dispatcher_id": payload.dispatcher_id,
                "attribution": attribution(&actor),
            }),
        )
        .await;
        return Err((StatusCode::PAYMENT_REQUIRED, reason));
    }

    // M2.9.2 (F2): evaluate the dispatch policy gate (forbidden-path, scope,
    // branch protection, approval holds) before creating the task.
    let gate_req = DispatchRequest {
        task_id: String::new(), // not yet assigned
        scope_globs: payload.base.scope_globs.clone(),
        target_branch: if payload.base.branch.is_empty() {
            None
        } else {
            Some(payload.base.branch.clone())
        },
        dispatcher_id: Some(payload.dispatcher_id.clone()),
        kind: payload.base.kind.clone(),
        cwd: payload.base.cwd.clone(),
    };
    let gate_decision = state.gate.evaluate_dispatch(&gate_req);
    if gate_decision.denied {
        let reason = gate_decision.reasons.join("; ");
        let _ = audit_append(
            &*state.store,
            &state.secrets,
            "dispatch_denied",
            None,
            &json!({
                "reason": "policy_denied",
                "detail": reason,
                "signed": true,
                "dispatcher_id": payload.dispatcher_id,
                "kind": payload.base.kind,
                "attribution": attribution(&actor),
            }),
        )
        .await;
        return Err((
            StatusCode::FORBIDDEN,
            format!("dispatch denied by policy: {reason}"),
        ));
    }
    if gate_decision.needs_approval {
        let reason = gate_decision.reasons.join("; ");
        // M2.9.2: create an approval record and a held task instead of 403.
        // The dispatcher can poll GET /approvals/{id} or the approval inbox.
        let envelope_hash = {
            use sha2::{Digest, Sha256};
            let canonical = fabric_protocol::canonicalize(&envelope).unwrap_or_default();
            hex::encode(Sha256::digest(&canonical))
        };
        let (approval_id, _created) = state
            .store
            .create_or_get_pending_approval(
                &envelope_hash,
                json!({ "reason": reason, "kind": payload.base.kind }),
                &payload.base.title,
                if payload.base.branch.is_empty() {
                    None
                } else {
                    Some(payload.base.branch.as_str())
                },
                payload.base.scope_globs.clone(),
                Some(payload.dispatcher_id.as_str()),
                &now,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let mut p = dispatch_params(
            &payload.base,
            &dispatcher,
            &gate_decision,
            &now,
            Some(&approval_id),
            1,
            0,
        );
        p.initial_status = Some("held".into());
        let task = state
            .store
            .create_task(p, &now)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let _ = audit_append(
            &*state.store,
            &state.secrets,
            "dispatch_held",
            Some(task.id),
            &json!({
                "reason": reason,
                "approval_id": approval_id,
                "signed": true,
                "dispatcher_id": payload.dispatcher_id,
                "kind": payload.base.kind,
                "title": payload.base.title,
                "attribution": attribution(&actor),
            }),
        )
        .await;

        // Route the approval to ForgeLink as the governed decision surface when it
        // is configured and reachable (AGH-028, decision 0004). Best-effort and
        // time-bounded: any failure falls back to Fabric's built-in approval pane.
        let mut forgelink_routed: Option<String> = None;
        if state.forgelink.enabled() {
            let body = crate::forgelink::build_approval_request(
                &approval_id,
                &payload.base.title,
                &reason,
                &payload.base.kind,
                if payload.base.branch.is_empty() {
                    None
                } else {
                    Some(payload.base.branch.as_str())
                },
                &payload.base.scope_globs,
                "forgewire-fabric",
            );
            match crate::forgelink::route_approval(&state.forgelink, &body).await {
                Ok(fl_id) => {
                    forgelink_routed = Some(fl_id.clone());
                    let _ = audit_append(
                        &*state.store,
                        &state.secrets,
                        "forgelink_routed",
                        Some(task.id),
                        &json!({ "approval_id": approval_id, "forgelink_request_id": fl_id, "attribution": attribution(&actor) }),
                    )
                    .await;
                }
                Err(e) => {
                    let _ = audit_append(
                        &*state.store,
                        &state.secrets,
                        "forgelink_unavailable",
                        Some(task.id),
                        &json!({ "approval_id": approval_id, "error": e, "fallback": "fabric_builtin_pane", "attribution": attribution(&actor) }),
                    )
                    .await;
                }
            }
        }

        return Ok(Json(json!({
            "status": "held",
            "task_id": task.id,
            "approval_id": approval_id,
            "reason": reason,
            "forgelink_routed": forgelink_routed,
            "message": "dispatch requires approval; task is held pending review",
        })));
    }

    let p = dispatch_params(
        &payload.base,
        &dispatcher,
        &gate_decision,
        &now,
        payload.base.approval_id.as_deref(),
        i64::from(payload.base.approval_id.is_some()),
        i64::from(payload.base.approval_id.is_some()),
    );
    let task = state
        .store
        .create_task(p, &now)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // M2.9.1 (F5): include the executed command in the audit chain so a Loom task's
    // audit entry can answer "what command ran." Agent briefs have no command field.
    let audit_payload = if has_signed_command {
        let loom_env_keys: Vec<String> = payload
            .base
            .env
            .as_ref()
            .and_then(|v| v.as_object())
            .map(|obj| {
                let mut keys: Vec<String> = obj.keys().cloned().collect();
                keys.sort();
                keys
            })
            .unwrap_or_default();
        json!({
            "task_id": task.id,
            "title": task.title,
            "base_commit": task.base_commit,
            "branch": task.branch,
            "scope_globs": task.scope_globs,
            "signed": true,
            "dispatcher_id": payload.dispatcher_id,
            "approval_id": payload.base.approval_id,
            "loom_command": payload.base.command,
            "loom_cwd": payload.base.cwd,
            "loom_env_keys": loom_env_keys,
            "attribution": attribution(&actor),
        })
    } else {
        json!({
            "task_id": task.id,
            "title": task.title,
            "base_commit": task.base_commit,
            "branch": task.branch,
            "scope_globs": task.scope_globs,
            "signed": true,
            "dispatcher_id": payload.dispatcher_id,
            "approval_id": payload.base.approval_id,
            "attribution": attribution(&actor),
        })
    };
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "dispatch",
        Some(task.id),
        &audit_payload,
    )
    .await;

    Ok(Json(serde_json::to_value(task).unwrap_or(Value::Null)))
}

// ---- POST /tasks/claim-loom ------------------------------------------------
//
// Phase 2.8 (M2.8.2): Loom queue claim — command-kind tasks only.
// Verifies the runner has "command" in its `kinds` column. No capability
// index lookup; eligibility is tool-list + host target only.

pub async fn claim_task_loom(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(payload): Json<ClaimV2Payload>,
) -> Result<Json<Value>, ApiError> {
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
        )
            .into());
    }

    if runner.drain_requested {
        return Ok(Json(json!({"task": null, "info": {"reason": "drain"}})));
    }

    // Concurrency cap
    let active = state
        .store
        .list_tasks(Some("claimed"), 200)
        .await
        .unwrap_or_default();
    let running = state
        .store
        .list_tasks(Some("running"), 200)
        .await
        .unwrap_or_default();
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
        return Ok(Json(
            json!({"task": null, "info": {"reason": "queue_empty"}}),
        ));
    }

    let candidates: Vec<CandidateTask> = queued.iter().map(build_candidate).collect();

    let runner_view = RunnerView::from_raw(
        &payload.scope_prefixes,
        &payload.tools,
        &payload.tags,
        payload.tenant.clone(),
        payload.workspace_root.clone(),
        payload.last_known_commit.clone(),
    );

    let (picked_idx, candidates_seen) = pick_task(&candidates, &runner_view);
    let Some(chosen_idx) = picked_idx else {
        return Ok(Json(
            json!({"task": null, "info": {"reason": "no_eligible_runner", "candidates_seen": candidates_seen}}),
        ));
    };

    do_claim(
        &state,
        &actor,
        &queued[chosen_idx],
        &payload.runner_id,
        &runner.hostname,
    )
    .await
}

// ---- POST /tasks/claim-fabric -----------------------------------------------
//
// Phase 2.8 (M2.8.2): Fabric queue claim — agent-kind tasks only.
// For dispatch="skill" and dispatch="tool" tasks, intersects the eligible set
// with runner_capabilities before scoring. Prompt dispatch skips the
// capability filter (backward-compat for legacy freeform briefs).

pub async fn claim_task_fabric(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(payload): Json<ClaimV2Payload>,
) -> Result<Json<Value>, ApiError> {
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
        )
            .into());
    }

    if runner.drain_requested {
        return Ok(Json(json!({"task": null, "info": {"reason": "drain"}})));
    }

    // Concurrency cap
    let active = state
        .store
        .list_tasks(Some("claimed"), 200)
        .await
        .unwrap_or_default();
    let running = state
        .store
        .list_tasks(Some("running"), 200)
        .await
        .unwrap_or_default();
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
                    runner_caps
                        .iter()
                        .any(|c| c.capability_kind == "prompt" && c.name == skill_name)
                }
                Some("tool") => {
                    // Runner must advertise the tool capability.
                    let tool_name = t.tool.as_deref().unwrap_or("");
                    runner_caps
                        .iter()
                        .any(|c| c.capability_kind == "tool" && c.name == tool_name)
                }
                // "prompt" or NULL: no capability gate, route by scope/tags.
                _ => true,
            }
        })
        .collect();

    if eligible.is_empty() {
        return Ok(Json(
            json!({"task": null, "info": {"reason": "queue_empty"}}),
        ));
    }

    let candidates: Vec<CandidateTask> = eligible.iter().map(build_candidate).collect();

    let runner_view = RunnerView::from_raw(
        &payload.scope_prefixes,
        &payload.tools,
        &payload.tags,
        payload.tenant.clone(),
        payload.workspace_root.clone(),
        payload.last_known_commit.clone(),
    );

    let (picked_idx, candidates_seen) = pick_task(&candidates, &runner_view);
    let Some(chosen_idx) = picked_idx else {
        return Ok(Json(
            json!({"task": null, "info": {"reason": "no_eligible_runner", "candidates_seen": candidates_seen}}),
        ));
    };

    do_claim(
        &state,
        &actor,
        &eligible[chosen_idx],
        &payload.runner_id,
        &runner.hostname,
    )
    .await
}

// ---- POST /tasks/{task_id}/intent (M2.9.2 — runtime intent gate) -----------

// The intent body matches the established `HubClient::post_intent` shape and the
// Python hub's `enforce_intent_gate` (kind + paths/hosts/command/...). The action
// the policy evaluates is `kind`; `action` is accepted as an alias for any caller
// using the original M2.9.2 shape. The remaining fields are optional context for
// the audit record (serde ignores unknown fields, so extra keys are harmless).
#[derive(serde::Deserialize)]
pub struct IntentPayload {
    #[serde(alias = "action")]
    pub kind: String,
    #[serde(default)]
    pub worker_id: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
}

/// Runtime intent gate: evaluate whether a runner action requires approval.
/// Loom and Fabric runners call this before executing gated actions (shell_exec,
/// fs_write, network_egress, merge, push). Returns
/// `{"allowed": bool, "needs_approval": bool, "reasons": [...]}`.
pub async fn evaluate_intent(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(task_id): Path<i64>,
    Json(payload): Json<IntentPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let decision = state.gate.evaluate_intent(&payload.kind);
    let evidence = policy_evidence(
        "intent",
        &decision,
        &utc_now(),
        json!({
            "kind": payload.kind,
            "worker_id": payload.worker_id,
            "command_present": payload.command.is_some(),
        }),
    );
    state
        .store
        .append_task_policy_decision(task_id, evidence)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        if decision.allowed {
            "intent_allowed"
        } else {
            "intent_denied"
        },
        Some(task_id),
        &json!({
            "kind": payload.kind,
            "worker_id": payload.worker_id,
            "command": payload.command,
            "allowed": decision.allowed,
            "reasons": decision.reasons,
            "actor": attribution(&actor),
        }),
    )
    .await;
    Ok(Json(json!({
        "allowed": decision.allowed,
        "needs_approval": decision.needs_approval,
        "reasons": decision.reasons,
    })))
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
    actor: &AuthContext,
    task: &TaskRow,
    runner_id: &str,
    hostname: &str,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    use axum::http::StatusCode;

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

    // Resolve before the claim CAS. If key material, an envelope, or a named
    // secret is unavailable, the task remains queued rather than becoming a
    // permanently claimed task with silently missing credentials.
    let mut resolved = std::collections::HashMap::new();
    if !requested.is_empty() {
        let envelopes = state
            .store
            .secret_envelopes(&requested)
            .await
            .map_err(|e| {
                ApiError::secret(fabric_secrets::SecretError::ProviderIo(e.to_string()))
            })?;
        for name in &requested {
            let envelope = envelopes.get(name).ok_or_else(|| {
                ApiError::secret(fabric_secrets::SecretError::MissingSecret(name.clone()))
            })?;
            let value = state
                .secrets
                .open(name, envelope)
                .map_err(ApiError::secret)?;
            resolved.insert(name.clone(), value);
        }
    }

    let now = utc_now();
    let claim_result = state
        .store
        .claim_task(task.id, runner_id, hostname, &now)
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
    let mut secrets_dispatched: Vec<String> = resolved.keys().cloned().collect();
    secrets_dispatched.sort();
    if !resolved.is_empty() {
        let secret_json: serde_json::Map<String, Value> = resolved
            .iter()
            .map(|(name, value)| (name.clone(), Value::String(value.to_string())))
            .collect();
        if let Some(obj) = task_val.as_object_mut() {
            obj.insert("secrets".into(), Value::Object(secret_json));
        }
    }

    let audit_payload = json!({
        "task_id": claimed_task.id,
        "worker_id": runner_id,
        "hostname": hostname,
        "secrets_dispatched": secrets_dispatched,
        "attribution": attribution(actor),
    });
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "claim",
        Some(claimed_task.id),
        &audit_payload,
    )
    .await;

    Ok(axum::Json(
        json!({"task": task_val, "info": {"reason": "claimed"}}),
    ))
}

fn dispatch_params(
    p: &DispatchPayload,
    dispatcher: &DispatcherRow,
    decision: &PolicyDecision,
    now: &str,
    approval_id: Option<&str>,
    approvals_required: i64,
    approvals_received: i64,
) -> CreateTaskParams {
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
        dispatcher_id: Some(dispatcher.dispatcher_id.clone()),
        dispatch,
        skill: p.skill.clone(),
        tool: p.tool.clone(),
        // Phase 2.8 (M2.8.10): carry the Loom executable payload through to the
        // task row. Without this the command was signed + audited but lost, and
        // the runner fell back to executing the (empty) prompt.
        command: p.command.clone(),
        cwd: p.cwd.clone(),
        env: p.env.clone(),
        initial_status: None,
        dispatched_by_user: actor_value(
            &p.metadata,
            &dispatcher.metadata,
            &["user", "username", "operator"],
        )
        .or_else(|| Some(dispatcher.label.clone())),
        dispatched_by_host: actor_value(&p.metadata, &dispatcher.metadata, &["host", "hostname"])
            .or_else(|| dispatcher.hostname.clone()),
        dispatched_by_agent: actor_value(
            &p.metadata,
            &dispatcher.metadata,
            &["agent", "agent_type", "source", "client"],
        )
        .or_else(|| Some(dispatcher.label.clone())),
        dispatcher_pubkey_fingerprint: Some(public_key_fingerprint(&dispatcher.public_key)),
        approval_id: approval_id.map(str::to_owned),
        policy_decisions: json!([policy_evidence(
            "dispatch",
            decision,
            now,
            json!({
                "dispatcher_id": dispatcher.dispatcher_id,
                "kind": p.kind,
                "branch": p.branch,
            })
        )]),
        approvals_required,
        approvals_received,
    }
}

fn actor_value(request: &Value, registered: &Value, keys: &[&str]) -> Option<String> {
    for source in [request, registered] {
        for key in keys {
            if let Some(value) = source.get(*key).and_then(Value::as_str) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
    }
    None
}

fn public_key_fingerprint(public_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let bytes = hex::decode(public_key).unwrap_or_else(|_| public_key.as_bytes().to_vec());
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

// `context` is moved directly into the `json!` object below; call sites
// build it fresh from a `json!({...})` literal, so by-value is the natural
// shape here, not an accidental extra clone.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn policy_evidence(
    stage: &str,
    decision: &PolicyDecision,
    at: &str,
    context: Value,
) -> Value {
    json!({
        "stage": stage,
        "at": at,
        "allowed": decision.allowed,
        "denied": decision.denied,
        "needs_approval": decision.needs_approval,
        "reasons": decision.reasons,
        "context": context,
    })
}
