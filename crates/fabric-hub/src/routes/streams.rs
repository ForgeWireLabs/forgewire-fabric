//! Task state transitions, streams, progress, result, and notes routes.

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::Json;
use fabric_policy::CompletionRequest;
use serde::Deserialize;
use serde_json::{json, Value};

use fabric_store::SubmitResultParams;
use fabric_streams::{DurabilityProfile, PendingEntry};

use crate::auth::AuthContext;
use crate::state::HubState;
use crate::utils::{attribution, audit_append, check_skew, utc_now, verify_sig};

owned_router! {
    pub fn router, ROUTES {
        "GET" get "/tasks/{task_id}/events" => task_events;
        "POST" post "/tasks/{task_id}/start" => mark_running;
        "POST" post "/tasks/{task_id}/cancel" => cancel_task;
        "POST" post "/tasks/{task_id}/progress" => append_progress;
        "POST" post "/tasks/{task_id}/stream" => append_stream;
        "GET" get "/tasks/{task_id}/stream" => read_stream;
        "POST" post "/tasks/{task_id}/stream/bulk" => append_stream_bulk;
        "POST" post "/tasks/{task_id}/result" => submit_result;
        "POST" post "/tasks/{task_id}/notes" => post_note;
        "GET" get "/tasks/{task_id}/notes" => read_notes;
    }
}

/// True server-sent event stream for task progress and state transitions.
pub async fn task_events(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let output = async_stream::stream! {
        let mut last_seq = 0_i64;
        loop {
            let task = match state.store.get_task(task_id).await {
                Ok(task) => task,
                Err(fabric_store::StoreError::NotFound(_)) => {
                    yield Ok(Event::default().event("error").data(r#"{"error":"not_found"}"#));
                    break;
                }
                Err(error) => {
                    let data = json!({"error": "store_error", "detail": error.to_string()}).to_string();
                    yield Ok(Event::default().event("error").data(data));
                    break;
                }
            };

            match state.store.progress_since(task_id, last_seq).await {
                Ok(entries) => {
                    for entry in entries {
                        last_seq = entry.seq;
                        let data = serde_json::to_string(&entry)
                            .unwrap_or_else(|_| r#"{"error":"serialization"}"#.into());
                        yield Ok(Event::default().event("progress").data(data));
                    }
                }
                Err(error) => {
                    let data = json!({"error": "store_error", "detail": error.to_string()}).to_string();
                    yield Ok(Event::default().event("error").data(data));
                    break;
                }
            }

            let terminal = matches!(task.status.as_str(), "done" | "failed" | "cancelled" | "timed_out");
            let data = serde_json::to_string(&task)
                .unwrap_or_else(|_| r#"{"error":"serialization"}"#.into());
            yield Ok(Event::default().event("task").data(data));
            if terminal {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    };
    Sse::new(output).keep_alive(KeepAlive::default())
}

owned_router! {
    pub fn input_router, INPUT_ROUTES {
        "POST" post "/tasks/{task_id}/input" => post_task_input;
        "GET" get "/tasks/{task_id}/input" => get_task_input;
    }
}

#[derive(Deserialize)]
pub struct ProgressPayload {
    pub worker_id: String,
    pub message: String,
    pub files_touched: Option<Vec<String>>,
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub details: Option<Value>,
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
    // Cost actuals (M2.5.2/M2.5.3). When cost_usd is present the hub records a
    // cost_ledger row and atomically bumps the budget_state accumulators.
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub prompt_tokens: Option<i64>,
    #[serde(default)]
    pub completion_tokens: Option<i64>,
    #[serde(default)]
    pub cost_usd: Option<f64>,
    #[serde(default)]
    pub wall_seconds: Option<f64>,
    #[serde(default)]
    pub runner_cpu_seconds: Option<f64>,
    #[serde(default)]
    pub exit_code: Option<i64>,
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

fn default_stream_limit() -> i64 {
    500
}

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
        let line = state
            .redact_text(&entry.line)
            .await
            .map_err(redaction_error)?;
        if let Some(g) = groups.iter_mut().find(|(wid, _)| wid == &entry.worker_id) {
            g.1.push((entry.channel, line));
        } else {
            groups.push((entry.worker_id, vec![(entry.channel, line)]));
        }
    }
    let mut total = 0usize;
    for (worker_id, entries) in groups {
        let written = state
            .store
            .append_stream_bulk(task_id, &worker_id, &entries, &now)
            .await
            .map_err(|e| match e {
                fabric_store::StoreError::NotFound(_) => {
                    (StatusCode::NOT_FOUND, "task not found".into())
                }
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
    let task = state
        .store
        .mark_running(task_id, &utc_now())
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "task not found".into())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    Ok(Json(serde_json::to_value(task).unwrap_or(Value::Null)))
}

// ---- POST /tasks/{task_id}/cancel ------------------------------------------

pub async fn cancel_task(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let task = state
        .store
        .cancel_task(task_id, &utc_now())
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "task not found".into())
            }
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
    if payload
        .event
        .as_deref()
        .is_some_and(|event| event != "egress_denied")
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "unsupported progress event kind".into(),
        ));
    }
    let message = state
        .redact_text(&payload.message)
        .await
        .map_err(redaction_error)?;
    let entry = state
        .store
        .append_progress(
            task_id,
            &payload.worker_id,
            &message,
            payload.files_touched,
            &utc_now(),
        )
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "task not found".into())
            }
            fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    if payload.event.as_deref() == Some("egress_denied") {
        let _ = audit_append(
            &*state.store,
            &state.secrets,
            "egress_denied",
            Some(task_id),
            &json!({
                "worker_id": payload.worker_id,
                "details": payload.details.unwrap_or(Value::Null),
            }),
        )
        .await;
    }
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
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid stream channel: {}", payload.channel),
        ));
    }

    match state.stream_buffer.profile() {
        DurabilityProfile::Strict => {
            // Bypass the buffer entirely — write to store and return the StreamLine.
            let line_text = state
                .redact_text(&payload.line)
                .await
                .map_err(redaction_error)?;
            let line = state
                .store
                .append_stream(
                    task_id,
                    &payload.worker_id,
                    &payload.channel,
                    &line_text,
                    &utc_now(),
                )
                .await
                .map_err(|e| match e {
                    fabric_store::StoreError::NotFound(_) => {
                        (StatusCode::NOT_FOUND, "task not found".into())
                    }
                    fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
                    other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
                })?;
            Ok(Json(serde_json::to_value(line).unwrap_or(Value::Null)))
        }
        _ => {
            // Balanced / Throughput: accumulate in buffer.
            let line = state
                .redact_text(&payload.line)
                .await
                .map_err(redaction_error)?;
            let maybe_batch = state.stream_buffer.push(
                task_id,
                payload.worker_id,
                payload.channel,
                line,
                utc_now(),
            );
            if let Some(batch) = maybe_batch {
                let count = flush_batch(&state, task_id, batch).await?;
                Ok(Json(
                    json!({"task_id": task_id, "count": count, "buffered": false}),
                ))
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
            let mut entries = Vec::with_capacity(payload.entries.len());
            for entry in payload.entries {
                entries.push((
                    entry.channel,
                    state
                        .redact_text(&entry.line)
                        .await
                        .map_err(redaction_error)?,
                ));
            }
            let lines = state
                .store
                .append_stream_bulk(task_id, &payload.worker_id, &entries, &utc_now())
                .await
                .map_err(|e| match e {
                    fabric_store::StoreError::NotFound(_) => {
                        (StatusCode::NOT_FOUND, "task not found".into())
                    }
                    fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
                    other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
                })?;
            let count = lines.len();
            let first_seq = lines.first().map(|l| l.seq);
            let last_seq = lines.last().map(|l| l.seq);
            Ok(Json(
                json!({"task_id": task_id, "count": count, "first_seq": first_seq, "last_seq": last_seq}),
            ))
        }
        _ => {
            let now = utc_now();
            let mut pending = Vec::with_capacity(payload.entries.len());
            for entry in payload.entries {
                pending.push(PendingEntry {
                    task_id,
                    worker_id: payload.worker_id.clone(),
                    channel: entry.channel,
                    line: state
                        .redact_text(&entry.line)
                        .await
                        .map_err(redaction_error)?,
                    ts: now.clone(),
                });
            }
            let n_in = pending.len();
            let maybe_batch = state.stream_buffer.push_bulk(task_id, pending);
            if let Some(batch) = maybe_batch {
                let count = flush_batch(&state, task_id, batch).await?;
                Ok(Json(
                    json!({"task_id": task_id, "count": count, "buffered": false}),
                ))
            } else {
                Ok(Json(
                    json!({"task_id": task_id, "count": n_in, "buffered": true}),
                ))
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
    let lines = state
        .store
        .streams_since(task_id, q.after_seq, q.limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"lines": lines})))
}

// ---- POST /tasks/{task_id}/result ------------------------------------------

pub async fn submit_result(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(task_id): Path<i64>,
    Json(mut payload): Json<ResultPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let valid_statuses = ["done", "failed", "cancelled", "timed_out"];
    if !valid_statuses.contains(&payload.status.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid terminal status: {}", payload.status),
        ));
    }

    // Force-flush any buffered stream lines before marking the task terminal.
    // This ensures no lines are lost regardless of the durability profile.
    let pending = state.stream_buffer.flush_task(task_id);
    if !pending.is_empty() {
        flush_batch(&state, task_id, pending).await?;
    }
    state.stream_buffer.forget(task_id);

    let completion_decision = state.gate.evaluate_completion(&CompletionRequest {
        task_id: task_id.to_string(),
        changed_paths: payload.files_touched.clone(),
        // The result contract does not yet carry a diff-line total. File-path
        // policy is still enforced; the cap remains neutral until a measured
        // total is added out-of-band in a future protocol revision.
        diff_lines: 0,
    });
    let completion_evidence = crate::routes::tasks::policy_evidence(
        "completion",
        &completion_decision,
        &utc_now(),
        json!({
            "worker_id": payload.worker_id,
            "terminal_status": payload.status,
            "files_touched": payload.files_touched,
        }),
    );
    state
        .store
        .append_task_policy_decision(task_id, completion_evidence)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    if completion_decision.denied {
        let reason = completion_decision.reasons.join("; ");
        let _ = audit_append(
            &*state.store,
            &state.secrets,
            "completion_denied",
            Some(task_id),
            &json!({ "reason": reason, "worker_id": payload.worker_id, "attribution": attribution(&actor) }),
        )
        .await;
        return Err((
            StatusCode::FORBIDDEN,
            format!("completion denied by policy: {reason}"),
        ));
    }

    // Capture fields for audit before moving into SubmitResultParams.
    let worker_id = payload.worker_id.clone();
    let status = payload.status.clone();
    let head_commit = payload.head_commit.clone();
    let commits = payload.commits.clone();
    let files_touched = payload.files_touched.clone();
    // Capture cost actuals before payload is moved.
    let cost_usd = payload.cost_usd;
    let cost_model = payload.model_id.clone().unwrap_or_default();
    let cost_prompt = payload.prompt_tokens.unwrap_or(0);
    let cost_completion = payload.completion_tokens.unwrap_or(0);
    let cost_wall = payload.wall_seconds.unwrap_or(0.0);
    let cost_cpu = payload.runner_cpu_seconds.unwrap_or(0.0);
    let exit_code = payload.exit_code;

    payload.test_summary = redact_optional(&state, payload.test_summary).await?;
    payload.log_tail = redact_optional(&state, payload.log_tail).await?;
    payload.error = redact_optional(&state, payload.error).await?;
    let exit_reason = terminal_exit_reason(&payload.status, exit_code, payload.error.as_deref());

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
        wall_seconds: payload.wall_seconds,
        runner_cpu_seconds: payload.runner_cpu_seconds,
        exit_reason,
        exit_code,
    };

    let task = state
        .store
        .submit_result(p, &utc_now())
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "task not found".into())
            }
            fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;

    // M2.9.4 (F4): the task is terminal — drop any queued stdin so secret-bearing
    // input lines don't linger in hub memory readable via GET /tasks/{id}/input.
    {
        let mut queues = state.input_queues.lock().await;
        queues.remove(&task_id);
    }

    let audit_payload = json!({
        "task_id": task_id,
        "worker_id": worker_id,
        "status": status,
        "head_commit": head_commit,
        "commits": commits,
        "files_touched": files_touched,
        "exit_reason": task.exit_reason,
        "exit_code": task.exit_code,
        "wall_seconds": task.wall_seconds,
        "runner_cpu_seconds": task.runner_cpu_seconds,
        "attribution": attribution(&actor),
    });
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "result",
        Some(task_id),
        &audit_payload,
    )
    .await;

    // Record cost actuals (atomically bumps budget_state) when the runner
    // reported a cost. Best-effort: a ledger failure must not fail the result.
    if let Some(cost) = cost_usd {
        let dispatcher_id = task.dispatcher_id.as_deref();
        if let Err(e) = state
            .store
            .record_cost(
                &task_id.to_string(),
                dispatcher_id,
                Some(&worker_id),
                &cost_model,
                cost_prompt,
                cost_completion,
                cost,
                cost_wall,
                cost_cpu,
                &utc_now(),
            )
            .await
        {
            tracing::warn!("record_cost failed for task {task_id}: {e}");
        }
    }

    Ok(Json(serde_json::to_value(task).unwrap_or(Value::Null)))
}

// ---- POST /tasks/{task_id}/notes -------------------------------------------

pub async fn post_note(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Json(payload): Json<NotePayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let body = state
        .redact_text(&payload.body)
        .await
        .map_err(redaction_error)?;
    let note = state
        .store
        .post_note(task_id, &payload.author, &body, &utc_now())
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "task not found".into())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    Ok(Json(serde_json::to_value(note).unwrap_or(Value::Null)))
}

// Takes ownership (not `&SecretError`) so every call site can stay the
// ergonomic `.map_err(redaction_error)` (a `FnOnce(SecretError) -> _`)
// instead of a closure at each of its several call sites.
#[allow(clippy::needless_pass_by_value)]
fn redaction_error(error: fabric_secrets::SecretError) -> (StatusCode, String) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        format!("secret redaction failed closed: {error}"),
    )
}

async fn redact_optional(
    state: &HubState,
    value: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
    match value {
        Some(value) => state
            .redact_text(&value)
            .await
            .map(Some)
            .map_err(redaction_error),
        None => Ok(None),
    }
}

fn terminal_exit_reason(status: &str, exit_code: Option<i64>, error: Option<&str>) -> String {
    match status {
        "done" if exit_code.unwrap_or(0) == 0 => "completed".into(),
        "done" => format!("completed_with_exit_code:{}", exit_code.unwrap_or_default()),
        "failed" if exit_code.is_some() => {
            format!("process_exit:{}", exit_code.unwrap_or_default())
        }
        "failed" if error.is_some() => "runner_error".into(),
        "failed" => "failed".into(),
        "cancelled" => "cancelled".into(),
        "timed_out" => "timeout".into(),
        other => format!("terminal_status:{other}"),
    }
}

// ---- GET /tasks/{task_id}/notes --------------------------------------------

pub async fn read_notes(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Query(q): Query<NoteQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let notes = state
        .store
        .read_notes(task_id, q.after_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"notes": notes})))
}

#[derive(Deserialize)]
pub struct NoteQuery {
    #[serde(default)]
    pub after_id: i64,
}

// ---- POST /tasks/{task_id}/input (M2.9.4 — signed stdin) -------------------

#[derive(Deserialize)]
pub struct TaskInputPayload {
    pub dispatcher_id: String,
    pub lines: Vec<String>,
    pub seq: i64,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct InputQuery {
    #[serde(default)]
    pub after_seq: i64,
}

/// Accept a signed stdin batch from a dispatcher and push it into the
/// per-task in-memory input queue. Unsigned posts are rejected (403).
pub async fn post_task_input(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Json(payload): Json<TaskInputPayload>,
) -> Result<Json<Value>, (StatusCode, String)> {
    check_skew(payload.timestamp).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let public_key = state
        .store
        .dispatcher_public_key(&payload.dispatcher_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                "dispatcher not registered — stdin post rejected".into(),
            )
        })?;

    let envelope = json!({
        "op": "task-input",
        "task_id": task_id,
        "dispatcher_id": payload.dispatcher_id,
        "lines": payload.lines,
        "seq": payload.seq,
        "timestamp": payload.timestamp,
        "nonce": payload.nonce,
    });
    verify_sig(&public_key, &envelope, &payload.signature).map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            format!("stdin signature invalid: {e}"),
        )
    })?;

    // M2.9.4 (F3): consume the signed nonce so a captured batch can't be replayed
    // within the skew window. Hard rule #6 (nonce replay rejection) applies to this
    // route exactly like dispatch/claim.
    state
        .store
        .consume_dispatcher_nonce(&payload.dispatcher_id, &payload.nonce, &utc_now())
        .await
        .map_err(|e| match e {
            fabric_store::StoreError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "dispatcher not registered".into())
            }
            fabric_store::StoreError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;

    // M2.9.4 (F4): the task must exist, be owned by this dispatcher, and still be
    // running. Otherwise any registered dispatcher could inject stdin into any
    // task, or push secret-bearing lines into a queue that is never drained.
    let task = state.store.get_task(task_id).await.map_err(|e| match e {
        fabric_store::StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "task not found".into()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    if task.dispatcher_id.as_deref() != Some(payload.dispatcher_id.as_str()) {
        return Err((
            StatusCode::FORBIDDEN,
            "stdin rejected: task was dispatched by a different dispatcher".into(),
        ));
    }
    if matches!(
        task.status.as_str(),
        "done" | "failed" | "cancelled" | "timed_out"
    ) {
        return Err((
            StatusCode::CONFLICT,
            format!("stdin rejected: task is terminal (status={})", task.status),
        ));
    }

    let assigned_seq = {
        let mut queues = state.input_queues.lock().await;
        let bucket = queues.entry(task_id).or_default();
        let seq = bucket.last().map(|(s, _)| s + 1).unwrap_or(1);
        bucket.push((seq, payload.lines.clone()));
        seq
    };

    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "stdin_input",
        Some(task_id),
        &json!({
            "dispatcher_id": payload.dispatcher_id,
            "line_count": payload.lines.len(),
            "seq": assigned_seq,
        }),
    )
    .await;

    Ok(Json(json!({
        "task_id": task_id,
        "seq": assigned_seq,
        "accepted": payload.lines.len(),
    })))
}

/// Return all signed stdin batches for a task with seq > after_seq.
/// Called by runners to drain queued input into the running process stdin.
pub async fn get_task_input(
    State(state): State<Arc<HubState>>,
    Path(task_id): Path<i64>,
    Query(q): Query<InputQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let queues = state.input_queues.lock().await;
    let entries: Vec<Value> = queues
        .get(&task_id)
        .map(|bucket| {
            bucket
                .iter()
                .filter(|(seq, _)| *seq > q.after_seq)
                .map(|(seq, lines)| json!({"seq": seq, "lines": lines}))
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(json!({"task_id": task_id, "entries": entries})))
}

#[cfg(test)]
mod exit_code_projection_tests {
    // 114F.7A — `terminal_exit_reason` itself did not change (it already took
    // `exit_code` as an argument), but it had no prior unit coverage and it is
    // the function whose output must stay consistent once the real exit code
    // is persisted rather than discarded. See 114F-0-contract-inventory.md §13.
    use super::terminal_exit_reason;

    #[test]
    fn done_with_zero_code_is_completed() {
        assert_eq!(terminal_exit_reason("done", Some(0), None), "completed");
    }

    #[test]
    fn done_with_no_code_defaults_to_completed() {
        assert_eq!(terminal_exit_reason("done", None, None), "completed");
    }

    #[test]
    fn done_with_nonzero_code_is_reported() {
        assert_eq!(
            terminal_exit_reason("done", Some(3), None),
            "completed_with_exit_code:3"
        );
    }

    #[test]
    fn negative_windows_status_survives_unreinterpreted() {
        // e.g. STATUS_STACK_BUFFER_OVERRUN — must not be truncated or
        // reinterpreted as an unsigned value anywhere in the reason string.
        assert_eq!(
            terminal_exit_reason("failed", Some(-1073740791), None),
            "process_exit:-1073740791"
        );
    }

    #[test]
    fn failed_without_code_but_with_error_is_runner_error() {
        assert_eq!(
            terminal_exit_reason("failed", None, Some("spawn failed")),
            "runner_error"
        );
    }

    #[test]
    fn failed_without_code_or_error_is_failed() {
        assert_eq!(terminal_exit_reason("failed", None, None), "failed");
    }

    #[test]
    fn timeout_keeps_timeout_sentinel_regardless_of_code() {
        assert_eq!(terminal_exit_reason("timed_out", None, None), "timeout");
    }

    #[test]
    fn cancelled_is_cancelled() {
        assert_eq!(terminal_exit_reason("cancelled", None, None), "cancelled");
    }
}
