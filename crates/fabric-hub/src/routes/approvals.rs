//! Approval queue routes.
//!
//! - GET  /approvals
//! - GET  /approvals/{id}
//! - POST /approvals/{id}/approve
//! - POST /approvals/{id}/deny

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AuthContext;
use crate::forgelink::{self, ForgeLinkDecision};
use crate::state::HubState;
use crate::utils::{attribution, audit_append, utc_now};

owned_router! {
    pub fn router, ROUTES {
        "GET" get "/approvals" => list_approvals;
        "GET" get "/approvals/{approval_id}" => get_approval;
        "POST" post "/approvals/{approval_id}/approve" => approve_approval;
        "POST" post "/approvals/{approval_id}/deny" => deny_approval;
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}
fn default_limit() -> i64 {
    200
}

#[derive(Deserialize)]
pub struct DecisionPayload {
    pub approver: Option<String>,
    pub reason: Option<String>,
}

// ---- GET /approvals --------------------------------------------------------

pub async fn list_approvals(
    State(state): State<Arc<HubState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if let Some(ref s) = q.status {
        if !["pending", "approved", "denied", "consumed"].contains(&s.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                "status must be one of pending|approved|denied|consumed".into(),
            ));
        }
    }
    let approvals = state
        .store
        .list_approvals(q.status.as_deref(), q.limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "approvals": approvals })))
}

// ---- GET /approvals/{id} ---------------------------------------------------

pub async fn get_approval(
    State(state): State<Arc<HubState>>,
    Path(approval_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let row = state
        .store
        .get_approval(&approval_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    match row {
        None => Err((StatusCode::NOT_FOUND, "approval not found".into())),
        Some(a) => {
            // Decision write-back (AGH-028, decision 0004): if this approval is still
            // pending and was routed to ForgeLink, poll ForgeLink for the operator's
            // decision and resolve it here — exactly as Fabric's built-in approve/deny
            // would — so the dispatcher's poll observes the governed decision. Best
            // effort: any failure leaves the approval pending (Fabric's pane still works).
            if a.status == "pending" && state.forgelink.reconcile_enabled() {
                if let Ok(Some(decision)) =
                    forgelink::fetch_decision(&state.forgelink, &approval_id).await
                {
                    let (status_str, reason) = match decision {
                        ForgeLinkDecision::Approved => ("approved", "approved in ForgeLink"),
                        ForgeLinkDecision::Denied => ("denied", "denied in ForgeLink"),
                    };
                    let now = utc_now();
                    if state
                        .store
                        .resolve_approval(
                            &approval_id,
                            status_str,
                            Some("forgelink"),
                            Some(reason),
                            &now,
                        )
                        .await
                        .is_ok()
                    {
                        let provenance = json!({
                            "stage": "approval",
                            "at": now,
                            "allowed": status_str == "approved",
                            "denied": status_str == "denied",
                            "needs_approval": false,
                            "reasons": [reason],
                            "context": {
                                "approval_id": approval_id,
                                "approver": "forgelink",
                                "status": status_str,
                            },
                        });
                        if let Err(error) = state
                            .store
                            .record_task_approval_decision(
                                &approval_id,
                                provenance,
                                status_str == "approved",
                            )
                            .await
                        {
                            tracing::warn!(
                                approval_id,
                                error = %error,
                                "ForgeLink decision resolved but task provenance update failed"
                            );
                        }
                        let _ = audit_append(
                            &*state.store,
                            &state.secrets,
                            "forgelink_decision_synced",
                            None,
                            &json!({ "approval_id": approval_id, "decision": status_str }),
                        )
                        .await;
                        if let Ok(Some(updated)) = state.store.get_approval(&approval_id).await {
                            return Ok(Json(serde_json::to_value(updated).unwrap_or(Value::Null)));
                        }
                    }
                }
            }
            Ok(Json(serde_json::to_value(a).unwrap_or(Value::Null)))
        }
    }
}

// ---- POST /approvals/{id}/approve ------------------------------------------

pub async fn approve_approval(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(approval_id): Path<String>,
    Json(payload): Json<DecisionPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let now = utc_now();
    let row = state
        .store
        .resolve_approval(
            &approval_id,
            "approved",
            payload.approver.as_deref(),
            payload.reason.as_deref(),
            &now,
        )
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "approval not found".into())
            }
            fabric_store::StoreError::Conflict(m) => (StatusCode::CONFLICT, m),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    let decided_task = state
        .store
        .record_task_approval_decision(
            &approval_id,
            json!({
                "stage": "approval",
                "at": now,
                "allowed": true,
                "denied": false,
                "needs_approval": false,
                "reasons": payload.reason,
                "context": { "approval_id": approval_id, "approver": payload.approver, "status": "approved" },
            }),
            true,
        )
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    // `record_task_approval_decision` already resolves this approval_id to
    // its task (if any) -- correlate the audit event by that task_id
    // instead of `None`, so "audit reconstructs human -> client -> dispatch
    // -> runner -> completion" (114C.4's acceptance line) actually holds for
    // the approval leg of the chain, not just dispatch/claim/completion.
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "approval_approved",
        decided_task.as_ref().map(|t| t.id),
        &json!({ "approval_id": approval_id, "approver": payload.approver, "attribution": attribution(&actor) }),
    )
    .await;
    Ok(Json(serde_json::to_value(row).unwrap_or(Value::Null)))
}

// ---- POST /approvals/{id}/deny ---------------------------------------------

pub async fn deny_approval(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(approval_id): Path<String>,
    Json(payload): Json<DecisionPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let now = utc_now();
    let row = state
        .store
        .resolve_approval(
            &approval_id,
            "denied",
            payload.approver.as_deref(),
            payload.reason.as_deref(),
            &now,
        )
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "approval not found".into())
            }
            fabric_store::StoreError::Conflict(m) => (StatusCode::CONFLICT, m),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    let decided_task = state
        .store
        .record_task_approval_decision(
            &approval_id,
            json!({
                "stage": "approval",
                "at": now,
                "allowed": false,
                "denied": true,
                "needs_approval": false,
                "reasons": payload.reason,
                "context": { "approval_id": approval_id, "approver": payload.approver, "status": "denied" },
            }),
            false,
        )
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "approval_denied",
        decided_task.as_ref().map(|t| t.id),
        &json!({ "approval_id": approval_id, "approver": payload.approver, "attribution": attribution(&actor) }),
    )
    .await;
    Ok(Json(serde_json::to_value(row).unwrap_or(Value::Null)))
}
