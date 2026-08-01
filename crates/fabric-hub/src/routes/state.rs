//! Operator-only rqlite snapshot and import routes.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, HeaderValue, Response, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::auth::AuthContext;
use crate::error::ApiError;
use crate::state::HubState;
use crate::utils::{attribution, audit_append};

owned_router! {
    pub fn router, ROUTES {
        "GET" get "/state/snapshot" => state_snapshot;
        "POST" post "/state/import" => state_import;
    }
}

fn rqlite_url(state: &HubState) -> Result<String, ApiError> {
    let address = state
        .backend
        .strip_prefix("rqlite:")
        .filter(|value| value.contains(':'))
        .ok_or_else(|| {
            ApiError::from((
                StatusCode::INTERNAL_SERVER_ERROR,
                "hub rqlite backend address is unavailable".to_owned(),
            ))
        })?;
    Ok(format!("http://{address}"))
}

pub async fn state_snapshot(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
) -> Result<Response<Body>, ApiError> {
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .get(format!("{}/db/backup", rqlite_url(&state)?))
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("rqlite unreachable: {e}")))?;
    if !response.status().is_success() {
        let status = response.status();
        let detail = response.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "rqlite /db/backup failed: {status} {}",
                &detail[..detail.len().min(200)]
            ),
        )
            .into());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    audit_append(
        &*state.store,
        &state.secrets,
        "state_snapshot",
        None,
        &json!({"bytes": bytes.len(), "attribution": attribution(&actor)}),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("snapshot audit failed: {e}"),
        )
    })?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-snapshot-source", "rqlite")
        .header("x-snapshot-generated-at", format!("{}", chrono_like_unix()))
        .header("x-hub-started-at", format!("{}", state.started_at_unix))
        .body(Body::from(bytes))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into())
}

fn chrono_like_unix() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub async fn state_import(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty body".to_owned()).into());
    }
    let digest = hex::encode(Sha256::digest(&body));
    let expected_confirmation = format!("sha256:{digest}");
    let confirmation = headers
        .get("x-forgewire-import-confirmation")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if confirmation != expected_confirmation {
        return Err((
            StatusCode::PRECONDITION_REQUIRED,
            "X-Forgewire-Import-Confirmation must equal sha256:<body digest>".to_owned(),
        )
            .into());
    }
    let force = headers
        .get("x-force")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == "1");
    let task_count = state
        .store
        .count_tasks()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if task_count > 0 && !force {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "refusing to import over a non-empty hub ({task_count} tasks); send X-Force: 1 to override"
            ),
        )
            .into());
    }

    let audit_payload = json!({
        "bytes": body.len(),
        "body_sha256": digest,
        "force": force,
        "tasks_before": task_count,
        "attribution": attribution(&actor),
    });
    audit_append(
        &*state.store,
        &state.secrets,
        "state_import_requested",
        None,
        &audit_payload,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("import audit failed: {e}"),
        )
    })?;

    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .post(format!("{}/db/load", rqlite_url(&state)?))
        .header(
            header::CONTENT_TYPE.as_str(),
            HeaderValue::from_static("application/octet-stream"),
        )
        .body(body.clone())
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("rqlite unreachable: {e}")))?;
    if !response.status().is_success() {
        let status = response.status();
        let detail = response.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "rqlite /db/load failed: {status} {}",
                &detail[..detail.len().min(200)]
            ),
        )
            .into());
    }
    audit_append(
        &*state.store,
        &state.secrets,
        "state_import_completed",
        None,
        &audit_payload,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "state import succeeded but completion audit failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("state imported, but mandatory completion audit failed: {e}"),
        )
    })?;
    Ok(Json(json!({
        "status": "imported",
        "bytes": body.len(),
        "backend": "rqlite",
        "body_sha256": digest,
    })))
}
