//! Task state transitions, streams, progress, result, and notes routes.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use fabric_store::{NoteStore, ProgressStore, ResultStore, StreamStore, SubmitResultParams, TaskStore};
use fabric_streams::{DurabilityProfile, PendingEntry};

use crate::state::HubState;
use crate::utils::{audit_append, utc_now};

#[derive(Deserialize)]
pub struct ProgressPayload {
    pub worker_id: String,
    pub message: String,
    pub files_touched: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct StreamPayload {
    pub worker_id: String,
    pub channel: String,
    pub line: String,
}

#[derive(Deserialize)]
pub struct StreamEntry {
    pub channel: String,
    pub line: String,
}

#[derive(Deserialize)]
pub struct StreamBulkPayload {
    pub worker_id: String,
    pub entries: Vec<StreamEntry>,
}

#[derive(Deserialize)]
pub struct ResultPayload {
    pub worker_id: String,
    pub status: String,
    pub head_commit: Option<String>,
    #[serde(default)]
    pub commits: Vec<String>,
    #[serde(default)]
    pub files_touched: Vec<String>,
    pub test_summary: Option<String>,
    pub log_tail: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct NotePayload {
    pub author: String,
    pub body: String,
}

#[derive(Deserialize)]
pub struct StreamQuery {
    #[serde(default)]
    pub after_seq: i64,
    #[serde(default = "default_stream_limit")]
    pub limit: i64,
}

fn default_stream_limit() -> i64 { 500 }

// ── helpers ──────────────────────────────────────────────────────────────────

/// Flush a batch of buffered entries to the store, grouped by worker_id.
/// Uses a single timestamp (flush time) for all entries in the group.
async fn flush_batch(
    state: &HubState,
    task_id: i64,
    batch: Vec<PendingEntry>,
) -> Result<usize, (StatusCode, String)> {
    if batch.is_empty() {
        return Ok(0);
    }
    let now = utc_now();
    // Group by worker_id — in practice always one runner per task.
    let mut groups: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for entry in batch {
        if let Some(g) = groups.iter_mut().find(|(wid, _)| wid == &entry.worker_id) {
            g.1.push((entry.channel, entry.line));
        } else {
            groups.push((entry.worker_id, vec![(entry.channel, entry.line)]));
        }
    }
    let mut total = 0usize;
    for (worker_id, entries) in groups {
        let written = state.store
            .append_stream_bulk(task_id, &worker_id, &entries, &now)
            .await
            .map_err(|e| match e {
                fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
                fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
                other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
            })?;
        total += written.len();
    }
    Ok(total)
}

// ---- POST /tasks/{task_id}/start -------------------------------------------

pub async fn mark_running(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let task = state.store.mark_running(task_id, &utc_now()).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    Ok(Json(serde_json::to_value(task).unwrap_or(Value::Null)))
}

// ---- POST /tasks/{task_id}/cancel ------------------------------------------

pub async fn cancel_task(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let task = state.store.cancel_task(task_id, &utc_now()).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    Ok(Json(serde_json::to_value(task).unwrap_or(Value::Null)))
}

// ---- POST /tasks/{task_id}/progress ----------------------------------------

pub async fn append_progress(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Json(payload): Json<ProgressPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let entry = state.store.append_progress(task_id, &payload.worker_id, &payload.message, payload.files_touched, &utc_now())
        .await.map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
            fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    Ok(Json(serde_json::to_value(entry).unwrap_or(Value::Null)))
}

// ---- POST /tasks/{task_id}/stream ------------------------------------------

pub async fn append_stream(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Json(payload): Json<StreamPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let valid_channels = ["stdout", "stderr", "info"];
    if !valid_channels.contains(&payload.channel.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("invalid stream channel: {}", payload.channel)));
    }

    match state.stream_buffer.profile() {
        DurabilityProfile::Strict => {
            // Bypass the buffer entirely — write to store and return the StreamLine.
            let line = state.store
                .append_stream(task_id, &payload.worker_id, &payload.channel, &payload.line, &utc_now())
                .await
                .map_err(|e| match e {
                    fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
                    fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
                    other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
                })?;
            Ok(Json(serde_json::to_value(line).unwrap_or(Value::Null)))
        }
        _ => {
            // Balanced / Throughput: accumulate in buffer.
            let maybe_batch = state.stream_buffer.push(
                task_id,
                payload.worker_id,
                payload.channel,
                payload.line,
                utc_now(),
            );
            if let Some(batch) = maybe_batch {
                let count = flush_batch(&state, task_id, batch).await?;
                Ok(Json(json!({"task_id": task_id, "count": count, "buffered": false})))
            } else {
                Ok(Json(json!({"task_id": task_id, "buffered": true})))
            }
        }
    }
}

// ---- POST /tasks/{task_id}/stream/bulk -------------------------------------

pub async fn append_stream_bulk(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Json(payload): Json<StreamBulkPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if payload.entries.is_empty() {
        return Ok(Json(json!({"task_id": task_id, "count": 0})));
    }

    match state.stream_buffer.profile() {
        DurabilityProfile::Strict => {
            let entries: Vec<(String, String)> = payload.entries.into_iter()
                .map(|e| (e.channel, e.line))
                .collect();
            let lines = state.store
                .append_stream_bulk(task_id, &payload.worker_id, &entries, &utc_now())
                .await
                .map_err(|e| match e {
                    fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
                    fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
                    other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
                })?;
            let count = lines.len();
            let first_seq = lines.first().map(|l| l.seq);
            let last_seq = lines.last().map(|l| l.seq);
            Ok(Json(json!({"task_id": task_id, "count": count, "first_seq": first_seq, "last_seq": last_seq})))
        }
        _ => {
            let now = utc_now();
            let pending: Vec<PendingEntry> = payload.entries.into_iter()
                .map(|e| PendingEntry {
                    task_id,
                    worker_id: payload.worker_id.clone(),
                    channel: e.channel,
                    line: e.line,
                    ts: now.clone(),
                })
                .collect();
            let n_in = pending.len();
            let maybe_batch = state.stream_buffer.push_bulk(task_id, pending);
            if let Some(batch) = maybe_batch {
                let count = flush_batch(&state, task_id, batch).await?;
                Ok(Json(json!({"task_id": task_id, "count": count, "buffered": false})))
            } else {
                Ok(Json(json!({"task_id": task_id, "count": n_in, "buffered": true})))
            }
        }
    }
}

// ---- GET /tasks/{task_id}/stream -------------------------------------------

pub async fn read_stream(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Query(q): Query<StreamQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let lines = state.store.streams_since(task_id, q.after_seq, q.limit).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"lines": lines})))
}

// ---- POST /tasks/{task_id}/result ------------------------------------------

pub async fn submit_result(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Json(payload): Json<ResultPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let valid_statuses = ["done", "failed", "cancelled", "timed_out"];
    if !valid_statuses.contains(&payload.status.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("invalid terminal status: {}", payload.status)));
    }

    // Force-flush any buffered stream lines before marking the task terminal.
    // This ensures no lines are lost regardless of the durability profile.
    let pending = state.stream_buffer.flush_task(task_id);
    if !pending.is_empty() {
        flush_batch(&state, task_id, pending).await?;
    }
    state.stream_buffer.forget(task_id);

    // Capture fields for audit before moving into SubmitResultParams.
    let worker_id = payload.worker_id.clone();
    let status = payload.status.clone();
    let head_commit = payload.head_commit.clone();
    let commits = payload.commits.clone();
    let files_touched = payload.files_touched.clone();

    let p = SubmitResultParams {
        task_id,
        worker_id: payload.worker_id,
        status: payload.status,
        head_commit: payload.head_commit,
        commits: payload.commits,
        files_touched: payload.files_touched,
        test_summary: payload.test_summary,
        log_tail: payload.log_tail,
        error: payload.error,
    };

    let task = state.store.submit_result(p, &utc_now()).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
        fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;

    let audit_payload = json!({
        "task_id": task_id,
        "worker_id": worker_id,
        "status": status,
        "head_commit": head_commit,
        "commits": commits,
        "files_touched": files_touched,
    });
    let _ = audit_append(&*state.store, "result", Some(task_id), &audit_payload).await;

    Ok(Json(serde_json::to_value(task).unwrap_or(Value::Null)))
}

// ---- POST /tasks/{task_id}/notes -------------------------------------------

pub async fn post_note(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Json(payload): Json<NotePayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let note = state.store.post_note(task_id, &payload.author, &payload.body, &utc_now()).await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    Ok(Json(serde_json::to_value(note).unwrap_or(Value::Null)))
}

// ---- GET /tasks/{task_id}/notes --------------------------------------------

pub async fn read_notes(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Query(q): Query<NoteQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let notes = state.store.read_notes(task_id, q.after_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"notes": notes})))
}

#[derive(Deserialize)]
pub struct NoteQuery {
    #[serde(default)]
    pub after_id: i64,
}
