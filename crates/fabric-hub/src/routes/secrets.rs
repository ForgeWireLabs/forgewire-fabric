//! Secret broker routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::error::ApiError;
use crate::state::HubState;
use crate::utils::{audit_append, utc_now};

owned_router! {
    pub fn router, ROUTES {
        "POST" post "/secrets" => put_or_rotate_secret;
        "GET" get "/secrets" => list_secrets;
        "DELETE" delete "/secrets/{name}" => delete_secret;
    }
}

#[derive(Deserialize)]
pub struct SecretPayload {
    pub name: String,
    pub value: String,
}

// ---- POST /secrets ---------------------------------------------------------

pub async fn put_or_rotate_secret(
    State(state): State<Arc<HubState>>,
    Json(mut payload): Json<SecretPayload>,
) -> Result<Json<Value>, ApiError> {
    let now = utc_now();
    // Check if it already exists
    let existing = state
        .store
        .list_secrets()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let existed = existing.iter().any(|m| m.name == payload.name);

    let envelope = state
        .secrets
        .seal(&payload.name, &payload.value)
        .map_err(ApiError::secret)?;
    payload.value.zeroize();

    let meta = if existed {
        state
            .store
            .rotate_secret(&payload.name, &envelope, &now)
            .await
    } else {
        state.store.put_secret(&payload.name, &envelope, &now).await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "secret_rotated",
        None,
        &json!({"name": payload.name, "version": meta.version, "rotated": existed}),
    )
    .await;

    Ok(Json(json!({"secret": meta, "rotated": existed})))
}

// ---- GET /secrets ----------------------------------------------------------

pub async fn list_secrets(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let secrets = state
        .store
        .list_secrets()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"secrets": secrets})))
}

// ---- DELETE /secrets/{name} ------------------------------------------------

pub async fn delete_secret(
    State(state): State<Arc<HubState>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let deleted = state
        .store
        .delete_secret(&name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !deleted {
        return Err((StatusCode::NOT_FOUND, "secret not found".into()));
    }
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "secret_deleted",
        None,
        &json!({"name": name}),
    )
    .await;
    Ok(Json(json!({"deleted": true, "name": name})))
}
