//! Bearer-token authentication middleware.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::state::HubState;
use std::sync::Arc;

pub async fn require_bearer(
    axum::extract::State(state): axum::extract::State<Arc<HubState>>,
    req: Request,
    next: Next,
) -> Response {
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !auth.to_lowercase().starts_with("bearer ") {
        return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response();
    }

    let presented = auth.split_once(' ').map(|(_, t)| t.trim()).unwrap_or("");
    if !constant_time_eq(presented.as_bytes(), state.token.as_bytes()) {
        return (StatusCode::FORBIDDEN, "invalid bearer token").into_response();
    }

    next.run(req).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
