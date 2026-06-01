//! Task dispatch, listing, and claim routes.
//!
//! Maps to: POST /tasks, GET /tasks, GET /tasks/{id}, POST /tasks/claim-v2

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::HubState;
use fabric_store::TaskStore;

#[derive(Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
}

pub async fn list_tasks(
    State(state): State<Arc<HubState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let limit = q.limit.unwrap_or(100);
    let tasks = state
        .store
        .list_tasks(q.status.as_deref(), limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "tasks": tasks })))
}

pub async fn get_task(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, String)> {
    use fabric_store::TaskStore;
    let task = state
        .store
        .get_task(task_id)
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    Ok(Json(serde_json::to_value(task).unwrap_or(Value::Null)))
}

pub async fn healthz_tasks_stub() -> Json<Value> {
    Json(json!({"status": "stub - task routes operational"}))
}
