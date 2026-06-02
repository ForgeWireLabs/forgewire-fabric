//! Secret broker routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use fabric_store::SecretStore;

use crate::state::HubState;
use crate::utils::utc_now;

#[derive(Deserialize)]
pub struct SecretPayload {
    pub name: String,
    pub value: String,
}

// ---- POST /secrets ---------------------------------------------------------

pub async fn put_or_rotate_secret(
    State(state): State<Arc<HubState>>,
    Json(payload): Json<SecretPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let now = utc_now();
    // Check if it already exists
    let existing = state.store.list_secrets().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let existed = existing.iter().any(|m| m.name == payload.name);

    let meta = if existed {
        state.store.rotate_secret(&payload.name, &payload.value, &now).await
    } else {
        state.store.put_secret(&payload.name, &payload.value, &now).await
    }.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({"secret": meta, "rotated": existed})))
}

// ---- GET /secrets ----------------------------------------------------------

pub async fn list_secrets(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let secrets = state.store.list_secrets().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"secrets": secrets})))
}

// ---- DELETE /secrets/{name} ------------------------------------------------

pub async fn delete_secret(
    State(state): State<Arc<HubState>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let deleted = state.store.delete_secret(&name).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !deleted {
        return Err((StatusCode::NOT_FOUND, "secret not found".into()));
    }
    Ok(Json(json!({"deleted": true, "name": name})))
}
