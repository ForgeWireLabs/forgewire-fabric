//! Dispatcher registration and management routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::HubState;
use crate::utils::{check_skew, utc_now, verify_sig};

const PROTOCOL_VERSION: i64 = 4;

#[derive(Deserialize)]
pub struct RegisterDispatcherPayload {
    pub dispatcher_id: String,
    pub public_key: String,
    pub label: String,
    pub hostname: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

// ---- POST /dispatchers/register --------------------------------------------

pub async fn register_dispatcher(
    State(state): State<Arc<HubState>>,
    Json(payload): Json<RegisterDispatcherPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    check_skew(payload.timestamp).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let envelope = json!({
        "op": "register-dispatcher",
        "dispatcher_id": payload.dispatcher_id,
        "public_key": payload.public_key,
        "timestamp": payload.timestamp,
        "nonce": payload.nonce,
    });
    verify_sig(&payload.public_key, &envelope, &payload.signature)
        .map_err(|e| (StatusCode::FORBIDDEN, e))?;

    let data = json!({
        "dispatcher_id": payload.dispatcher_id,
        "public_key": payload.public_key,
        "label": payload.label,
        "hostname": payload.hostname,
        "metadata": payload.metadata,
    });

    let record = state.store.upsert_dispatcher(data).await.map_err(|e| match e {
        fabric_store::StoreError::PermissionDenied(m) => (StatusCode::CONFLICT, m),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;

    // Register host role
    if let Some(ref hostname) = payload.hostname {
        let now = utc_now();
        let _ = state.store.set_host_role(
            hostname, "dispatch", true, Some("registered"),
            json!({"dispatcher_id": payload.dispatcher_id, "label": payload.label}),
            &now,
        ).await;
    }

    Ok(Json(json!({
        "hub_protocol_version": PROTOCOL_VERSION,
        "dispatcher": serde_json::to_value(record).unwrap_or(Value::Null),
    })))
}

// ---- GET /dispatchers ------------------------------------------------------

pub async fn list_dispatchers(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let dispatchers = state.store.list_dispatchers().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({
        "hub_protocol_version": PROTOCOL_VERSION,
        "dispatchers": dispatchers,
    })))
}

// ---- DELETE /dispatchers/{dispatcher_id} -----------------------------------

pub async fn deregister_dispatcher(
    State(state): State<Arc<HubState>>,
    Path(dispatcher_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let record = state.store.delete_dispatcher(&dispatcher_id).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "dispatcher not registered".into()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    Ok(Json(serde_json::to_value(record).unwrap_or(Value::Null)))
}
