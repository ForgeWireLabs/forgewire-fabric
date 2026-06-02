//! Approval queue routes.
//!
//! - GET  /approvals
//! - GET  /approvals/{id}
//! - POST /approvals/{id}/approve
//! - POST /approvals/{id}/deny

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use fabric_store::ApprovalStore;

use crate::state::HubState;
use crate::utils::utc_now;

#[derive(Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}
fn default_limit() -> i64 { 200 }

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
        if !["pending","approved","denied","consumed"].contains(&s.as_str()) {
            return Err((StatusCode::BAD_REQUEST, "status must be one of pending|approved|denied|consumed".into()));
        }
    }
    let approvals = state.store.list_approvals(q.status.as_deref(), q.limit).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "approvals": approvals })))
}

// ---- GET /approvals/{id} ---------------------------------------------------

pub async fn get_approval(
    State(state): State<Arc<HubState>>,
    Path(approval_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let row = state.store.get_approval(&approval_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    match row {
        None => Err((StatusCode::NOT_FOUND, "approval not found".into())),
        Some(a) => Ok(Json(serde_json::to_value(a).unwrap_or(Value::Null))),
    }
}

// ---- POST /approvals/{id}/approve ------------------------------------------

pub async fn approve_approval(
    State(state): State<Arc<HubState>>,
    Path(approval_id): Path<String>,
    Json(payload): Json<DecisionPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let now = utc_now();
    let row = state.store.resolve_approval(
        &approval_id, "approved",
        payload.approver.as_deref(),
        payload.reason.as_deref(),
        &now,
    ).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "approval not found".into()),
        fabric_store::StoreError::Conflict(m) => (StatusCode::CONFLICT, m),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    Ok(Json(serde_json::to_value(row).unwrap_or(Value::Null)))
}

// ---- POST /approvals/{id}/deny ---------------------------------------------

pub async fn deny_approval(
    State(state): State<Arc<HubState>>,
    Path(approval_id): Path<String>,
    Json(payload): Json<DecisionPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let now = utc_now();
    let row = state.store.resolve_approval(
        &approval_id, "denied",
        payload.approver.as_deref(),
        payload.reason.as_deref(),
        &now,
    ).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "approval not found".into()),
        fabric_store::StoreError::Conflict(m) => (StatusCode::CONFLICT, m),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    Ok(Json(serde_json::to_value(row).unwrap_or(Value::Null)))
}
