//! Audit log routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use crate::state::HubState;

pub async fn audit_for_task(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let events = state
        .store
        .audit_events_for_task(task_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (ok, err) = state
        .store
        .verify_audit_chain(&events)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "events": events, "verified": ok, "error": err })))
}

pub async fn audit_tail(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let tail = state
        .store
        .audit_chain_tail()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "chain_tail": tail })))
}
