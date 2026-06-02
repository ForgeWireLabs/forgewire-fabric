//! Label and host-role routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use fabric_store::{HostRoleStore, LabelStore};

use crate::state::HubState;
use crate::utils::utc_now;

// ---- GET /labels -----------------------------------------------------------

pub async fn get_labels(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let labels = state.store.get_labels().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(labels))
}

// ---- PUT /labels/hub -------------------------------------------------------

#[derive(Deserialize)]
pub struct HubLabelPayload {
    pub name: String,
    pub updated_by: Option<String>,
}

pub async fn set_hub_label(
    State(state): State<Arc<HubState>>,
    Json(payload): Json<HubLabelPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let name = payload.name.trim();
    if name.len() > 80 {
        return Err((StatusCode::BAD_REQUEST, "hub name max 80 chars".into()));
    }
    let now = utc_now();
    state.store.set_hub_name(name, payload.updated_by.as_deref(), &now).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let labels = state.store.get_labels().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(labels))
}

// ---- PUT /labels/runners/{runner_id} ---------------------------------------

#[derive(Deserialize)]
pub struct RunnerLabelPayload {
    pub alias: String,
    pub updated_by: Option<String>,
}

pub async fn set_runner_label(
    State(state): State<Arc<HubState>>,
    Path(runner_id): Path<String>,
    Json(payload): Json<RunnerLabelPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let alias = payload.alias.trim();
    if alias.len() > 80 {
        return Err((StatusCode::BAD_REQUEST, "runner alias max 80 chars".into()));
    }
    let now = utc_now();
    state.store.set_runner_alias(&runner_id, alias, payload.updated_by.as_deref(), &now).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let labels = state.store.get_labels().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(labels))
}

// ---- PUT /labels/hosts/{hostname} ------------------------------------------

#[derive(Deserialize)]
pub struct HostLabelPayload {
    pub alias: String,
    pub updated_by: Option<String>,
}

pub async fn set_host_label(
    State(state): State<Arc<HubState>>,
    Path(hostname): Path<String>,
    Json(payload): Json<HostLabelPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let alias = payload.alias.trim();
    if alias.len() > 80 {
        return Err((StatusCode::BAD_REQUEST, "host alias max 80 chars".into()));
    }
    let now = utc_now();
    state.store.set_host_alias(&hostname, alias, payload.updated_by.as_deref(), &now).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let labels = state.store.get_labels().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(labels))
}

// ---- POST /hosts/roles -----------------------------------------------------

#[derive(Deserialize)]
pub struct HostRolePayload {
    pub hostname: String,
    pub role: String,
    pub enabled: bool,
    pub status: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

pub async fn set_host_role(
    State(state): State<Arc<HubState>>,
    Json(payload): Json<HostRolePayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let now = utc_now();
    let row = state.store.set_host_role(
        &payload.hostname, &payload.role, payload.enabled,
        payload.status.as_deref(), payload.metadata, &now,
    ).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"role": serde_json::to_value(row).unwrap_or(Value::Null)})))
}
