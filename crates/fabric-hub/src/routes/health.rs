//! Health endpoints — no authentication required.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::HubState;

pub async fn healthz(State(state): State<Arc<HubState>>) -> Json<Value> {
    let uptime = state.started_at.elapsed().as_secs_f64();
    let buf = &state.stream_buffer;

    // Phase 2.8 (M2.8.2): queue depth counters for loom and fabric queues.
    // Non-fatal — healthz must never fail even if the store is degraded.
    let (loom_depth, fabric_depth, capability_index_rows) = {
        let queued = state.store.list_tasks(Some("queued"), 500).await.unwrap_or_default();
        let loom = queued.iter().filter(|t| t.kind == "command").count();
        let fabric = queued.iter().filter(|t| t.kind == "agent").count();
        // Count capability index rows across all runners.
        let runners = state.store.list_runners().await.unwrap_or_default();
        let mut cap_rows: usize = 0;
        for r in &runners {
            if let Ok(caps) = state.store.runner_capabilities(&r.runner_id).await {
                cap_rows += caps.len();
            }
        }
        (loom, fabric, cap_rows)
    };

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
        "kinds_supported": ["agent", "command"],
        "queues": {
            "loom": loom_depth,
            "fabric": fabric_depth,
        },
        "capability_index_rows": capability_index_rows,
    }))
}
