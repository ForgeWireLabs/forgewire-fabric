//! Runner registration, heartbeat, and management routes.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use crate::state::HubState;

pub async fn list_runners(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    use fabric_store::RunnerStore;
    let runners = state
        .store
        .list_runners()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({
        "hub_protocol_version": state.protocol_version,
        "runners": runners,
    })))
}
