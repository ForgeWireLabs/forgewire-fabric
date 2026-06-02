//! Health endpoints — no authentication required.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::HubState;

pub async fn healthz(State(state): State<Arc<HubState>>) -> Json<Value> {
    let uptime = state.started_at.elapsed().as_secs_f64();
    let buf = &state.stream_buffer;
    Json(json!({
        "status": "ok",
        "version": state.package_version,
        "package_version": state.package_version,
        "protocol_version": state.protocol_version,
        "rust_hub": true,
        "backend": state.backend,
        "sidecar_integrity": state.sidecar_integrity,
        "started_at": state.started_at_unix,
        "uptime_seconds": uptime,
        "host": state.host,
        "port": state.port,
        "stream_profile": buf.profile().as_str(),
        "stream_buffered_tasks": buf.buffered_task_count(),
        "stream_buffered_lines": buf.buffered_line_count(),
    }))
}
