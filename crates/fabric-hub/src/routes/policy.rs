//! Read-only effective policy and recent task decision evidence.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use fabric_store::TaskRow;
use serde_json::{json, Value};

use crate::state::HubState;

owned_router! {
    pub fn router, ROUTES {
        "GET" get "/policy" => get_policy;
    }
}

pub async fn get_policy(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let tasks = state
        .store
        .list_tasks(None, 200)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    Ok(Json(json!({
        "authority": "hub",
        "effective_policy": state.effective_policy,
        "recent_decisions": recent_decisions(&tasks, 100),
    })))
}

fn recent_decisions(tasks: &[TaskRow], limit: usize) -> Vec<Value> {
    let mut entries: Vec<Value> = tasks
        .iter()
        .flat_map(|task| {
            task.policy_decisions
                .as_array()
                .into_iter()
                .flatten()
                .map(move |decision| {
                    let mut entry = decision.as_object().cloned().unwrap_or_default();
                    entry.insert("task_id".into(), json!(task.id));
                    entry.insert("task_title".into(), json!(task.title));
                    entry.insert("task_status".into(), json!(task.status));
                    Value::Object(entry)
                })
        })
        .collect();
    entries.sort_by(|left, right| {
        right
            .get("at")
            .and_then(Value::as_str)
            .cmp(&left.get("at").and_then(Value::as_str))
    });
    entries.truncate(limit);
    entries
}
