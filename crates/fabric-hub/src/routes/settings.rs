//! Schema-backed, three-tier Fabric settings.
//!
//! Defaults are compiled into `fabric-settings`; this route persists only the
//! validated hub overlay in rqlite. Repo/task policy remains the highest tier
//! and is supplied by the caller that resolves a task. Sensitive keys are
//! always redacted from HTTP and audit responses.

use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use fabric_settings::{SettingsError, SettingsSnapshot};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AuthContext;
use crate::state::HubState;
use crate::utils::{attribution, audit_append, utc_now};

owned_router! {
    pub fn router, ROUTES {
        "GET" get "/settings" => get_settings;
        "GET" get "/settings/schema" => get_settings_schema;
        "PUT" put "/settings/{*key}" => set_setting;
        "DELETE" delete "/settings/{*key}" => reset_setting;
    }
}

#[derive(Debug, Deserialize)]
pub struct MutationRequest {
    pub expected_revision: i64,
    pub value: Value,
}

#[derive(Debug, Deserialize)]
pub struct ResetRequest {
    pub expected_revision: i64,
}

pub async fn get_settings(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    Ok(Json(snapshot(&state).await?))
}

pub async fn get_settings_schema() -> Result<Json<Value>, (StatusCode, String)> {
    fabric_settings::schema().map(Json).map_err(settings_error)
}

pub async fn set_setting(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(key): Path<String>,
    Json(request): Json<MutationRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    mutate(
        state,
        actor,
        key,
        request.expected_revision,
        Some(request.value),
    )
    .await
}

pub async fn reset_setting(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(key): Path<String>,
    Json(request): Json<ResetRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    mutate(state, actor, key, request.expected_revision, None).await
}

async fn mutate(
    state: Arc<HubState>,
    actor: AuthContext,
    key: String,
    expected_revision: i64,
    value: Option<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let document = state
        .store
        .get_settings_document()
        .await
        .map_err(store_error)?;
    if document.revision != expected_revision {
        return Err((
            StatusCode::CONFLICT,
            "settings revision changed; refresh and retry".into(),
        ));
    }
    let current = SettingsSnapshot::new(document.revision, document.value, json!({}))
        .map_err(settings_error)?;
    let next = match value {
        Some(value) => current.set_hub(&key, value),
        None => current.reset_hub(&key),
    }
    .map_err(settings_error)?;
    let (_, changes) = current
        .import_hub(next.hub.clone())
        .map_err(settings_error)?;
    let now = utc_now();
    state
        .store
        .put_settings_document(expected_revision, &next.hub, &actor.subject, &now)
        .await
        .map_err(store_error)?;

    if let Err(error) = audit_append(
        &*state.store,
        &state.secrets,
        "settings.changed",
        None,
        &json!({
            "actor": actor.subject,
            "revision": next.revision,
            "changes": changes,
            "attribution": attribution(&actor),
        }),
    )
    .await
    {
        tracing::error!(
            revision = next.revision,
            error = %error,
            "settings mutation audit append failed; compensating to prior value"
        );
        state
            .store
            .put_settings_document(
                next.revision,
                &current.hub,
                "system:audit-rollback",
                &utc_now(),
            )
            .await
            .map_err(|rollback| {
                tracing::error!(
                    revision = next.revision,
                    error = %rollback,
                    "settings audit compensation failed"
                );
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "settings audit and compensation failed".into(),
                )
            })?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "settings change was rolled back because audit recording failed".into(),
        ));
    }

    let mut body = serde_json::to_value(next)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    body["audit_recorded"] = json!(true);
    Ok(Json(body))
}

async fn snapshot(state: &HubState) -> Result<Value, (StatusCode, String)> {
    let document = state
        .store
        .get_settings_document()
        .await
        .map_err(store_error)?;
    let snapshot = SettingsSnapshot::new(document.revision, document.value, json!({}))
        .map_err(settings_error)?;
    serde_json::to_value(snapshot)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}

// Takes ownership (not `&SettingsError`) so every call site can stay the
// ergonomic `.map_err(settings_error)` (a `FnOnce(SettingsError) -> _`)
// instead of a closure at each of its several call sites.
#[allow(clippy::needless_pass_by_value)]
fn settings_error(error: SettingsError) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, error.to_string())
}

fn store_error(error: fabric_store::StoreError) -> (StatusCode, String) {
    match error {
        fabric_store::StoreError::Conflict(message) => (StatusCode::CONFLICT, message),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}
