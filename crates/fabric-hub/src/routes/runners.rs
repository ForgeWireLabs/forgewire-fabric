//! Runner registration, heartbeat, drain, and management routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::HubState;
use crate::utils::{check_skew, utc_now, verify_sig};

// Protocol version bounds (matching Python PROTOCOL_VERSION / MIN_COMPATIBLE)
const PROTOCOL_VERSION: i64 = 4;
const MIN_COMPATIBLE: i64 = 4;

#[derive(Deserialize)]
pub struct RegisterPayload {
    pub runner_id: String,
    pub public_key: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub cpu_model: Option<String>,
    pub cpu_count: Option<i64>,
    pub ram_mb: Option<i64>,
    pub gpu: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub scope_prefixes: Vec<String>,
    pub tenant: Option<String>,
    pub workspace_root: Option<String>,
    pub runner_version: String,
    pub protocol_version: i64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: i64,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub capabilities: Value,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

fn default_max_concurrent() -> i64 { 1 }

#[derive(Deserialize)]
pub struct HeartbeatPayload {
    pub runner_id: String,
    pub cpu_load_pct: Option<f64>,
    pub ram_free_mb: Option<i64>,
    pub battery_pct: Option<i64>,
    #[serde(default)]
    pub on_battery: bool,
    pub last_known_commit: Option<String>,
    pub nonce: String,
    pub claim_failures_total: Option<i64>,
    pub claim_failures_consecutive: Option<i64>,
    pub last_claim_error: Option<String>,
    pub heartbeat_failures_total: Option<i64>,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct DrainPayload {
    pub runner_id: String,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

// ---- GET /runners ----------------------------------------------------------

pub async fn list_runners(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let labels = state.store.get_labels().await.unwrap_or(json!({}));
    let aliases = labels["runner_aliases"].as_object().cloned().unwrap_or_default();
    let host_aliases = labels["host_aliases"].as_object().cloned().unwrap_or_default();
    let mut runners = state.store.list_runners().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let runners_val: Vec<Value> = runners.iter_mut().map(|r| {
        let hostname = r.hostname.to_lowercase();
        let host_alias = host_aliases.get(&hostname).and_then(|v| v.as_str()).unwrap_or("").to_owned();
        let alias = aliases.get(&r.runner_id).and_then(|v| v.as_str()).unwrap_or(&host_alias).to_owned();
        let mut v = serde_json::to_value(&*r).unwrap_or(Value::Null);
        if let Some(obj) = v.as_object_mut() {
            obj.insert("alias".into(), json!(alias));
            obj.insert("host_alias".into(), json!(host_alias));
        }
        v
    }).collect();
    let hub_name = labels["hub_name"].as_str().unwrap_or("").to_owned();
    Ok(Json(json!({
        "hub_protocol_version": state.protocol_version,
        "hub_name": hub_name,
        "runners": runners_val,
    })))
}

// ---- POST /runners/register ------------------------------------------------

pub async fn register_runner(
    State(state): State<Arc<HubState>>,
    Json(payload): Json<RegisterPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // Protocol version check
    if payload.protocol_version < MIN_COMPATIBLE {
        return Err((StatusCode::UPGRADE_REQUIRED, format!(
            "runner protocol_version={} is older than hub minimum {MIN_COMPATIBLE}", payload.protocol_version
        )));
    }
    if payload.protocol_version > PROTOCOL_VERSION {
        return Err((StatusCode::UPGRADE_REQUIRED, format!(
            "runner protocol_version={} is newer than hub {PROTOCOL_VERSION}", payload.protocol_version
        )));
    }

    check_skew(payload.timestamp).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let envelope = json!({
        "op": "register",
        "runner_id": payload.runner_id,
        "public_key": payload.public_key,
        "protocol_version": payload.protocol_version,
        "timestamp": payload.timestamp,
        "nonce": payload.nonce,
    });
    verify_sig(&payload.public_key, &envelope, &payload.signature)
        .map_err(|e| (StatusCode::FORBIDDEN, e))?;

    let record_data = json!({
        "runner_id": payload.runner_id,
        "public_key": payload.public_key,
        "hostname": payload.hostname,
        "os": payload.os,
        "arch": payload.arch,
        "cpu_model": payload.cpu_model,
        "cpu_count": payload.cpu_count,
        "ram_mb": payload.ram_mb,
        "gpu": payload.gpu,
        "tools": payload.tools,
        "tags": payload.tags,
        "scope_prefixes": payload.scope_prefixes,
        "tenant": payload.tenant,
        "workspace_root": payload.workspace_root,
        "runner_version": payload.runner_version,
        "protocol_version": payload.protocol_version,
        "max_concurrent": payload.max_concurrent,
        "metadata": payload.metadata,
        "capabilities": payload.capabilities,
    });

    let record = state.store.upsert_runner(record_data).await.map_err(|e| match e {
        fabric_store::StoreError::PermissionDenied(m) => (StatusCode::CONFLICT, m),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;

    // Register host role
    let now = utc_now();
    let _ = state.store.set_host_role(
        &payload.hostname, "agent_runner", true, Some("registered"),
        json!({"runner_id": payload.runner_id}), &now,
    ).await;

    Ok(Json(json!({
        "hub_protocol_version": state.protocol_version,
        "runner": serde_json::to_value(record).unwrap_or(Value::Null),
    })))
}

// ---- POST /runners/{runner_id}/heartbeat -----------------------------------

pub async fn heartbeat_runner(
    State(state): State<Arc<HubState>>,
    Path(runner_id): Path<String>,
    Json(payload): Json<HeartbeatPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if runner_id != payload.runner_id {
        return Err((StatusCode::BAD_REQUEST, "runner_id mismatch".into()));
    }

    check_skew(payload.timestamp).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let public_key = state.store.runner_public_key(&runner_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "runner not registered".into()))?;

    let envelope = json!({
        "op": "heartbeat",
        "runner_id": payload.runner_id,
        "timestamp": payload.timestamp,
        "nonce": payload.nonce,
    });
    verify_sig(&public_key, &envelope, &payload.signature)
        .map_err(|e| (StatusCode::FORBIDDEN, e))?;

    let now = utc_now();
    let data = json!({
        "nonce": payload.nonce,
        "cpu_load_pct": payload.cpu_load_pct,
        "ram_free_mb": payload.ram_free_mb,
        "battery_pct": payload.battery_pct,
        "on_battery": payload.on_battery,
        "last_known_commit": payload.last_known_commit,
        "claim_failures_total": payload.claim_failures_total,
        "claim_failures_consecutive": payload.claim_failures_consecutive,
        "last_claim_error": payload.last_claim_error,
        "heartbeat_failures_total": payload.heartbeat_failures_total,
    });

    let record = state.store.heartbeat_runner(&runner_id, data, &now).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "runner not registered".into()),
        fabric_store::StoreError::PermissionDenied(m) => (StatusCode::CONFLICT, m),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;

    Ok(Json(serde_json::to_value(record).unwrap_or(Value::Null)))
}

// ---- POST /runners/{runner_id}/drain ---------------------------------------

pub async fn drain_runner(
    State(state): State<Arc<HubState>>,
    Path(runner_id): Path<String>,
    Json(payload): Json<DrainPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if runner_id != payload.runner_id {
        return Err((StatusCode::BAD_REQUEST, "runner_id mismatch".into()));
    }
    check_skew(payload.timestamp).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let public_key = state.store.runner_public_key(&runner_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "runner not registered".into()))?;

    let envelope = json!({
        "op": "drain",
        "runner_id": payload.runner_id,
        "timestamp": payload.timestamp,
        "nonce": payload.nonce,
    });
    verify_sig(&public_key, &envelope, &payload.signature)
        .map_err(|e| (StatusCode::FORBIDDEN, e))?;

    let record = state.store.request_drain(&runner_id).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "runner not registered".into()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    Ok(Json(serde_json::to_value(record).unwrap_or(Value::Null)))
}

// ---- POST /runners/{runner_id}/drain-by-dispatcher -------------------------

pub async fn drain_runner_by_dispatcher(
    State(state): State<Arc<HubState>>,
    Path(runner_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let record = state.store.request_drain(&runner_id).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "runner not registered".into()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    Ok(Json(serde_json::to_value(record).unwrap_or(Value::Null)))
}

// ---- POST /runners/{runner_id}/undrain-by-dispatcher -----------------------

pub async fn undrain_runner_by_dispatcher(
    State(state): State<Arc<HubState>>,
    Path(runner_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let record = state.store.request_undrain(&runner_id).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "runner not registered".into()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    Ok(Json(serde_json::to_value(record).unwrap_or(Value::Null)))
}

// ---- DELETE /runners/{runner_id} -------------------------------------------

pub async fn deregister_runner(
    State(state): State<Arc<HubState>>,
    Path(runner_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let record = state.store.delete_runner(&runner_id).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "runner not registered".into()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    Ok(Json(serde_json::to_value(record).unwrap_or(Value::Null)))
}
