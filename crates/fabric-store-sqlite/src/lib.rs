//! SQLite backend for the ForgeWire Fabric store contract.
//!
//! Uses `rusqlite` with WAL mode. Schema initialization and additive
//! migrations match the Python oracle at `oracle/v2.7.0-baseline`.

#![deny(rust_2018_idioms)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use tracing::info;

use fabric_audit::{audit_event_hash, AUDIT_GENESIS_HASH};
use fabric_store::*;

/// SQLite-backed store. Thread-safe via an internal Mutex around the connection.
pub struct SqliteStore {
    conn: Mutex<Connection>,
    db_path: PathBuf,
}

impl SqliteStore {
    pub fn open(path: &Path) -> StoreResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        let conn = Connection::open(path).map_err(|e| StoreError::Backend(e.to_string()))?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;")
            .map_err(|e| StoreError::Schema(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
            db_path: path.to_owned(),
        };
        Ok(store)
    }

    pub fn open_in_memory() -> StoreResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| StoreError::Backend(e.to_string()))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| StoreError::Schema(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
            db_path: PathBuf::from(":memory:"),
        };
        Ok(store)
    }

    fn with_conn<F, T>(&self, f: F) -> StoreResult<T>
    where
        F: FnOnce(&Connection) -> StoreResult<T>,
    {
        let conn = self.conn.lock().map_err(|e| StoreError::Backend(format!("lock poisoned: {e}")))?;
        f(&conn)
    }
}

// -- Schema ------------------------------------------------------------------

const SCHEMA_SQL: &str = include_str!("schema.sql");

const ADDITIVE_COLUMNS: &[(&str, &str, &str)] = &[
    ("tasks", "kind", "TEXT NOT NULL DEFAULT 'agent'"),
    ("tasks", "required_tools", "TEXT"),
    ("tasks", "required_tags", "TEXT"),
    ("tasks", "tenant", "TEXT"),
    ("tasks", "workspace_root", "TEXT"),
    ("tasks", "require_base_commit", "INTEGER NOT NULL DEFAULT 0"),
    ("tasks", "required_capabilities", "TEXT"),
    ("tasks", "secrets_needed", "TEXT"),
    ("tasks", "network_egress", "TEXT"),
    ("tasks", "dispatcher_id", "TEXT"),
    ("runners", "capabilities", "TEXT NOT NULL DEFAULT '{}'"),
    ("runners", "claim_failures_total", "INTEGER NOT NULL DEFAULT 0"),
    ("runners", "claim_failures_consecutive", "INTEGER NOT NULL DEFAULT 0"),
    ("runners", "last_claim_error", "TEXT"),
    ("runners", "last_claim_error_at", "TEXT"),
    ("runners", "heartbeat_failures_total", "INTEGER NOT NULL DEFAULT 0"),
];

fn has_column(conn: &Connection, table: &str, column: &str) -> bool {
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&sql).unwrap();
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap();
    for name in rows.flatten() {
        if name == column {
            return true;
        }
    }
    false
}

#[async_trait]
impl SchemaStore for SqliteStore {
    async fn init_schema(&self) -> StoreResult<()> {
        self.with_conn(|conn| {
            conn.execute_batch(SCHEMA_SQL)
                .map_err(|e| StoreError::Schema(e.to_string()))?;
            // Insert schema version rows (idempotent, matches Python server.py)
            let now = utc_now();
            conn.execute(
                "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (1, ?1)",
                params![now],
            ).map_err(|e| StoreError::Schema(e.to_string()))?;
            conn.execute(
                "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (2, ?1)",
                params![now],
            ).map_err(|e| StoreError::Schema(e.to_string()))?;
            info!("schema initialized");
            Ok(())
        })
    }

    async fn schema_version(&self) -> StoreResult<i64> {
        self.with_conn(|conn| {
            let v: Option<i64> = conn
                .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(v.unwrap_or(0))
        })
    }

    async fn run_additive_migrations(&self) -> StoreResult<()> {
        self.with_conn(|conn| {
            for (table, column, col_type) in ADDITIVE_COLUMNS {
                if !has_column(conn, table, column) {
                    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {col_type}");
                    conn.execute(&sql, [])
                        .map_err(|e| StoreError::Schema(format!("migration {table}.{column}: {e}")))?;
                    info!("added column {table}.{column}");
                }
            }
            Ok(())
        })
    }
}

// -- Audit -------------------------------------------------------------------

#[async_trait]
impl AuditStore for SqliteStore {
    async fn audit_chain_tail(&self) -> StoreResult<String> {
        self.with_conn(|conn| {
            let result: Option<String> = conn
                .query_row(
                    "SELECT event_id_hash FROM audit_event ORDER BY seq DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .ok();
            Ok(result.unwrap_or_else(|| AUDIT_GENESIS_HASH.to_owned()))
        })
    }

    async fn append_audit_event(
        &self,
        expected_tail: &str,
        event_id_hash: &str,
        prev_hash: &str,
        kind: &str,
        task_id: Option<i64>,
        payload_json: &str,
        now: &str,
    ) -> StoreResult<AuditAppendResult> {
        self.with_conn(|conn| {
            let actual_tail: String = conn
                .query_row(
                    "SELECT event_id_hash FROM audit_event ORDER BY seq DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or_else(|_| AUDIT_GENESIS_HASH.to_owned());

            if actual_tail != expected_tail {
                return Ok(AuditAppendResult::TailConflict {
                    expected: expected_tail.to_owned(),
                    actual: actual_tail,
                });
            }

            conn.execute(
                "INSERT INTO audit_event (event_id_hash, prev_event_id_hash, kind, task_id, payload_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![event_id_hash, prev_hash, kind, task_id, payload_json, now],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;

            let seq = conn.last_insert_rowid();
            Ok(AuditAppendResult::Ok(AuditEventRow {
                seq,
                event_id_hash: event_id_hash.to_owned(),
                prev_event_id_hash: prev_hash.to_owned(),
                kind: kind.to_owned(),
                task_id,
                payload_json: payload_json.to_owned(),
                created_at: now.to_owned(),
            }))
        })
    }

    async fn audit_events_for_task(&self, task_id: i64) -> StoreResult<Vec<AuditEventRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT seq, event_id_hash, prev_event_id_hash, kind, task_id, payload_json, created_at FROM audit_event WHERE task_id = ?1 ORDER BY seq")
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let rows = stmt
                .query_map(params![task_id], |r| {
                    Ok(AuditEventRow {
                        seq: r.get(0)?,
                        event_id_hash: r.get(1)?,
                        prev_event_id_hash: r.get(2)?,
                        kind: r.get(3)?,
                        task_id: r.get(4)?,
                        payload_json: r.get(5)?,
                        created_at: r.get(6)?,
                    })
                })
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn audit_events_for_day(&self, day: &str) -> StoreResult<Vec<AuditEventRow>> {
        self.with_conn(|conn| {
            let pattern = format!("{day}%");
            let mut stmt = conn
                .prepare("SELECT seq, event_id_hash, prev_event_id_hash, kind, task_id, payload_json, created_at FROM audit_event WHERE created_at LIKE ?1 ORDER BY seq")
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let rows = stmt
                .query_map(params![pattern], |r| {
                    Ok(AuditEventRow {
                        seq: r.get(0)?,
                        event_id_hash: r.get(1)?,
                        prev_event_id_hash: r.get(2)?,
                        kind: r.get(3)?,
                        task_id: r.get(4)?,
                        payload_json: r.get(5)?,
                        created_at: r.get(6)?,
                    })
                })
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn verify_audit_chain(&self, events: &[AuditEventRow]) -> StoreResult<(bool, Option<String>)> {
        let mut prev: Option<&str> = None;
        for event in events.iter() {
            if let Some(expected) = prev {
                if event.prev_event_id_hash != expected {
                    return Ok((false, Some(format!(
                        "chain break at seq={}: prev {} != expected {}",
                        event.seq, event.prev_event_id_hash, expected
                    ))));
                }
            }
            let payload: Value = serde_json::from_str(&event.payload_json)
                .map_err(|e| StoreError::Backend(format!("invalid payload JSON at seq={}: {e}", event.seq)))?;
            let recomputed = audit_event_hash(&event.prev_event_id_hash, &event.kind, &payload);
            if recomputed != event.event_id_hash {
                return Ok((false, Some(format!(
                    "hash mismatch at seq={}: stored {} != recomputed {}",
                    event.seq, event.event_id_hash, recomputed
                ))));
            }
            prev = Some(&event.event_id_hash);
        }
        Ok((true, None))
    }
}

// -- Tasks -------------------------------------------------------------------

fn row_to_task(r: &rusqlite::Row<'_>) -> rusqlite::Result<TaskRow> {
    let scope_globs_str: String = r.get("scope_globs")?;
    let metadata_str: String = r.get("metadata")?;
    let required_tools_str: Option<String> = r.get("required_tools")?;
    let required_tags_str: Option<String> = r.get("required_tags")?;
    let required_capabilities_str: Option<String> = r.get("required_capabilities")?;
    let secrets_needed_str: Option<String> = r.get("secrets_needed")?;
    let network_egress_str: Option<String> = r.get("network_egress")?;
    let cancel_requested_int: i64 = r.get("cancel_requested")?;
    let require_base_commit_int: i64 = r.get("require_base_commit")?;

    Ok(TaskRow {
        id: r.get("id")?,
        title: r.get("title")?,
        prompt: r.get("prompt")?,
        scope_globs: serde_json::from_str(&scope_globs_str).unwrap_or(json!([])),
        base_commit: r.get("base_commit")?,
        branch: r.get("branch")?,
        status: r.get("status")?,
        kind: r.get("kind")?,
        worker_id: r.get("worker_id")?,
        created_at: r.get("created_at")?,
        claimed_at: r.get("claimed_at")?,
        started_at: r.get("started_at")?,
        completed_at: r.get("completed_at")?,
        cancel_requested: cancel_requested_int != 0,
        metadata: serde_json::from_str(&metadata_str).unwrap_or(json!({})),
        todo_id: r.get("todo_id")?,
        timeout_minutes: r.get("timeout_minutes")?,
        priority: r.get("priority")?,
        required_tools: required_tools_str.as_deref().map(|s| serde_json::from_str(s).unwrap_or(json!([]))),
        required_tags: required_tags_str.as_deref().map(|s| serde_json::from_str(s).unwrap_or(json!([]))),
        tenant: r.get("tenant")?,
        workspace_root: r.get("workspace_root")?,
        require_base_commit: require_base_commit_int != 0,
        required_capabilities: required_capabilities_str.as_deref().map(|s| serde_json::from_str(s).unwrap_or(json!([]))),
        secrets_needed: secrets_needed_str.as_deref().map(|s| serde_json::from_str(s).unwrap_or(json!([]))),
        network_egress: network_egress_str.as_deref().and_then(|s| serde_json::from_str(s).ok()),
        dispatcher_id: r.get("dispatcher_id")?,
    })
}

#[async_trait]
impl TaskStore for SqliteStore {
    async fn create_task(&self, p: CreateTaskParams, now: &str) -> StoreResult<TaskRow> {
        let scope_json = serde_json::to_string(&p.scope_globs).unwrap_or_else(|_| "[]".into());
        let meta_json = serde_json::to_string(&p.metadata).unwrap_or_else(|_| "{}".into());
        let tools_json = p.required_tools.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let tags_json = p.required_tags.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let caps_json = p.required_capabilities.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let secrets_json = p.secrets_needed.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let egress_json = p.network_egress.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "null".into()));
        let require_bc: i64 = if p.require_base_commit { 1 } else { 0 };

        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO tasks (
                    todo_id, title, prompt, scope_globs, base_commit, branch,
                    timeout_minutes, priority, metadata,
                    required_tools, required_tags, tenant, workspace_root,
                    require_base_commit, dispatcher_id, required_capabilities,
                    secrets_needed, network_egress, kind, created_at, status
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,'queued')",
                params![
                    p.todo_id, p.title, p.prompt, scope_json, p.base_commit, p.branch,
                    p.timeout_minutes, p.priority, meta_json,
                    tools_json, tags_json, p.tenant, p.workspace_root,
                    require_bc, p.dispatcher_id, caps_json,
                    secrets_json, egress_json, p.kind, now
                ],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            let id = conn.last_insert_rowid();
            let task = conn.query_row(
                "SELECT * FROM tasks WHERE id = ?1",
                params![id],
                row_to_task,
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(task)
        })
    }

    async fn get_task(&self, id: i64) -> StoreResult<TaskRow> {
        self.with_conn(|conn| {
            conn.query_row("SELECT * FROM tasks WHERE id = ?1", params![id], row_to_task)
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("task {id}")),
                    other => StoreError::Backend(other.to_string()),
                })
        })
    }

    async fn list_tasks(&self, status: Option<&str>, limit: i64) -> StoreResult<Vec<TaskRow>> {
        self.with_conn(|conn| {
            let rows: Vec<TaskRow> = if let Some(s) = status {
                let mut stmt = conn.prepare(
                    "SELECT * FROM tasks WHERE status = ?1 ORDER BY priority DESC, id ASC LIMIT ?2"
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
                let r = stmt.query_map(params![s, limit], row_to_task)
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                r
            } else {
                let mut stmt = conn.prepare(
                    "SELECT * FROM tasks ORDER BY priority DESC, id ASC LIMIT ?1"
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
                let r = stmt.query_map(params![limit], row_to_task)
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                r
            };
            Ok(rows)
        })
    }

    async fn claim_task(&self, task_id: i64, worker_id: &str, now: &str) -> StoreResult<ClaimResult> {
        self.with_conn(|conn| {
            // Atomic CAS: update only if status = 'queued' and cancel_requested = 0
            let rows_changed = conn.execute(
                "UPDATE tasks SET status = 'claimed', worker_id = ?1, claimed_at = ?2
                 WHERE id = ?3 AND status = 'queued' AND cancel_requested = 0",
                params![worker_id, now, task_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;

            if rows_changed == 0 {
                return Ok(ClaimResult::AlreadyClaimed);
            }

            let task = conn.query_row("SELECT * FROM tasks WHERE id = ?1", params![task_id], row_to_task)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(ClaimResult::Claimed(task))
        })
    }

    async fn mark_running(&self, task_id: i64, now: &str) -> StoreResult<TaskRow> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE tasks SET status = 'running', started_at = COALESCE(started_at, ?1)
                 WHERE id = ?2 AND status IN ('claimed', 'running')",
                params![now, task_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            conn.query_row("SELECT * FROM tasks WHERE id = ?1", params![task_id], row_to_task)
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("task {task_id}")),
                    other => StoreError::Backend(other.to_string()),
                })
        })
    }

    async fn cancel_task(&self, task_id: i64, now: &str) -> StoreResult<TaskRow> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE tasks SET cancel_requested = 1 WHERE id = ?1",
                params![task_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            // If still queued, terminate immediately
            conn.execute(
                "UPDATE tasks SET status = 'cancelled', completed_at = ?1 WHERE id = ?2 AND status = 'queued'",
                params![now, task_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            conn.query_row("SELECT * FROM tasks WHERE id = ?1", params![task_id], row_to_task)
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("task {task_id}")),
                    other => StoreError::Backend(other.to_string()),
                })
        })
    }

    async fn count_tasks(&self) -> StoreResult<i64> {
        self.with_conn(|conn| {
            conn.query_row("SELECT COUNT(*) FROM tasks", [], |r| r.get(0))
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }
}

// -- Results -----------------------------------------------------------------

#[async_trait]
impl ResultStore for SqliteStore {
    async fn submit_result(&self, p: SubmitResultParams, now: &str) -> StoreResult<TaskRow> {
        let commits_json = serde_json::to_string(&p.commits).unwrap_or_else(|_| "[]".into());
        let files_json = serde_json::to_string(&p.files_touched).unwrap_or_else(|_| "[]".into());

        self.with_conn(|conn| {
            // Ownership CAS: update only if this worker owns the task
            let rows_changed = conn.execute(
                "UPDATE tasks SET status = ?1, completed_at = ?2 WHERE id = ?3 AND worker_id = ?4",
                params![p.status, now, p.task_id, p.worker_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;

            if rows_changed == 0 {
                // Disambiguate: does task exist but wrong worker?
                let exists: Option<String> = conn
                    .query_row("SELECT worker_id FROM tasks WHERE id = ?1", params![p.task_id], |r| r.get(0))
                    .ok();
                return match exists {
                    None => Err(StoreError::NotFound(format!("task {}", p.task_id))),
                    Some(owner) => Err(StoreError::PermissionDenied(format!(
                        "worker {} cannot report result for task owned by {}", p.worker_id, owner
                    ))),
                };
            }

            // Upsert result row, pulling branch from tasks
            conn.execute(
                "INSERT OR REPLACE INTO results (
                    task_id, status, branch, head_commit, commits_json,
                    files_touched, test_summary, log_tail, error, reported_at
                ) SELECT ?1, ?2, branch, ?3, ?4, ?5, ?6, ?7, ?8, ?9 FROM tasks WHERE id = ?1",
                params![
                    p.task_id, p.status, p.head_commit, commits_json,
                    files_json, p.test_summary, p.log_tail, p.error, now
                ],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;

            conn.query_row("SELECT * FROM tasks WHERE id = ?1", params![p.task_id], row_to_task)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }
}

// -- Runners -----------------------------------------------------------------

fn row_to_runner(r: &rusqlite::Row<'_>) -> rusqlite::Result<RunnerRow> {
    let tools_str: String = r.get("tools")?;
    let tags_str: String = r.get("tags")?;
    let scope_str: String = r.get("scope_prefixes")?;
    let meta_str: String = r.get("metadata")?;
    let caps_str: String = r.get("capabilities").unwrap_or_else(|_| "{}".into());
    let drain_int: i64 = r.get("drain_requested")?;

    Ok(RunnerRow {
        runner_id: r.get("runner_id")?,
        public_key: r.get("public_key")?,
        hostname: r.get("hostname")?,
        os: r.get("os")?,
        arch: r.get("arch")?,
        state: r.get("state")?,
        runner_version: r.get("runner_version")?,
        protocol_version: r.get("protocol_version")?,
        max_concurrent: r.get("max_concurrent")?,
        tools: serde_json::from_str(&tools_str).unwrap_or(json!([])),
        tags: serde_json::from_str(&tags_str).unwrap_or(json!([])),
        scope_prefixes: serde_json::from_str(&scope_str).unwrap_or(json!([])),
        tenant: r.get("tenant")?,
        workspace_root: r.get("workspace_root")?,
        capabilities: serde_json::from_str(&caps_str).unwrap_or(json!({})),
        metadata: serde_json::from_str(&meta_str).unwrap_or(json!({})),
        drain_requested: drain_int != 0,
        last_heartbeat: r.get("last_heartbeat")?,
        first_seen: r.get("first_seen")?,
        last_nonce: r.get("last_nonce")?,
    })
}

#[async_trait]
impl RunnerStore for SqliteStore {
    async fn upsert_runner(&self, data: Value) -> StoreResult<RunnerRow> {
        let runner_id = data["runner_id"].as_str().ok_or_else(|| StoreError::Backend("missing runner_id".into()))?.to_owned();
        let public_key = data["public_key"].as_str().unwrap_or("").to_owned();
        let hostname = data["hostname"].as_str().unwrap_or("").to_owned();
        let os = data["os"].as_str().unwrap_or("").to_owned();
        let arch = data["arch"].as_str().unwrap_or("").to_owned();
        let cpu_model: Option<String> = data["cpu_model"].as_str().map(|s| s.to_owned());
        let cpu_count: Option<i64> = data["cpu_count"].as_i64();
        let ram_mb: Option<i64> = data["ram_mb"].as_i64();
        let gpu: Option<String> = data["gpu"].as_str().map(|s| s.to_owned());
        let tools = serde_json::to_string(&data["tools"]).unwrap_or_else(|_| "[]".into());
        let tags = serde_json::to_string(&data["tags"]).unwrap_or_else(|_| "[]".into());
        let scope_prefixes = serde_json::to_string(&data["scope_prefixes"]).unwrap_or_else(|_| "[]".into());
        let tenant: Option<String> = data["tenant"].as_str().map(|s| s.to_owned());
        let workspace_root: Option<String> = data["workspace_root"].as_str().map(|s| s.to_owned());
        let runner_version = data["runner_version"].as_str().unwrap_or("0.0.0").to_owned();
        let protocol_version = data["protocol_version"].as_i64().unwrap_or(2);
        let max_concurrent = data["max_concurrent"].as_i64().unwrap_or(1);
        let metadata = serde_json::to_string(data.get("metadata").unwrap_or(&json!({}))).unwrap_or_else(|_| "{}".into());
        let capabilities = serde_json::to_string(data.get("capabilities").unwrap_or(&json!({}))).unwrap_or_else(|_| "{}".into());

        let now = utc_now();

        self.with_conn(|conn| {
            // Prune ghost runners from same hostname
            if !hostname.is_empty() {
                let cutoff = utc_offset(-120);
                conn.execute(
                    "DELETE FROM runners WHERE hostname = ?1 AND runner_id != ?2 AND last_heartbeat < ?3",
                    params![hostname, runner_id, cutoff],
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
            }

            // Insert or update; reject if runner_id rebinds to different public_key
            // We do this as separate SELECT + upsert to stay compatible with rusqlite
            let existing_key: Option<String> = conn
                .query_row("SELECT public_key FROM runners WHERE runner_id = ?1", params![runner_id], |r| r.get(0))
                .ok();

            if let Some(ref existing) = existing_key {
                if existing != &public_key {
                    return Err(StoreError::PermissionDenied("runner_id is already bound to a different public_key".into()));
                }
                conn.execute(
                    "UPDATE runners SET hostname=?1, os=?2, arch=?3, cpu_model=?4, cpu_count=?5,
                     ram_mb=?6, gpu=?7, tools=?8, tags=?9, scope_prefixes=?10, tenant=?11,
                     workspace_root=?12, runner_version=?13, protocol_version=?14,
                     max_concurrent=?15, state='online', drain_requested=0, metadata=?16,
                     capabilities=?17, last_heartbeat=?18, claim_failures_consecutive=0, last_claim_error=NULL
                     WHERE runner_id=?19",
                    params![hostname, os, arch, cpu_model, cpu_count, ram_mb, gpu,
                            tools, tags, scope_prefixes, tenant, workspace_root,
                            runner_version, protocol_version, max_concurrent, metadata,
                            capabilities, now, runner_id],
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
            } else {
                conn.execute(
                    "INSERT INTO runners (runner_id, public_key, hostname, os, arch, cpu_model,
                     cpu_count, ram_mb, gpu, tools, tags, scope_prefixes, tenant, workspace_root,
                     runner_version, protocol_version, max_concurrent, state, drain_requested,
                     metadata, first_seen, last_heartbeat, capabilities)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,'online',0,?18,?19,?20,?21)",
                    params![runner_id, public_key, hostname, os, arch, cpu_model, cpu_count,
                            ram_mb, gpu, tools, tags, scope_prefixes, tenant, workspace_root,
                            runner_version, protocol_version, max_concurrent, metadata, now, now, capabilities],
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
            }

            conn.query_row("SELECT * FROM runners WHERE runner_id = ?1", params![runner_id], row_to_runner)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn get_runner(&self, runner_id: &str) -> StoreResult<RunnerRow> {
        self.with_conn(|conn| {
            conn.query_row("SELECT * FROM runners WHERE runner_id = ?1", params![runner_id], row_to_runner)
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("runner {runner_id}")),
                    other => StoreError::Backend(other.to_string()),
                })
        })
    }

    async fn list_runners(&self) -> StoreResult<Vec<RunnerRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT * FROM runners ORDER BY hostname, runner_id")
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let r = stmt.query_map([], row_to_runner)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(r)
        })
    }

    async fn runner_public_key(&self, runner_id: &str) -> StoreResult<Option<String>> {
        self.with_conn(|conn| {
            let key: Option<String> = conn
                .query_row("SELECT public_key FROM runners WHERE runner_id = ?1", params![runner_id], |r| r.get(0))
                .ok();
            Ok(key)
        })
    }

    async fn heartbeat_runner(&self, runner_id: &str, data: Value, now: &str) -> StoreResult<RunnerRow> {
        let nonce = data["nonce"].as_str().unwrap_or("").to_owned();
        let cpu_load_pct: Option<f64> = data["cpu_load_pct"].as_f64();
        let ram_free_mb: Option<i64> = data["ram_free_mb"].as_i64();
        let battery_pct: Option<i64> = data["battery_pct"].as_i64();
        let on_battery: i64 = if data["on_battery"].as_bool().unwrap_or(false) { 1 } else { 0 };
        let last_known_commit: Option<String> = data["last_known_commit"].as_str().map(|s| s.to_owned());
        let claim_failures_total: Option<i64> = data["claim_failures_total"].as_i64();
        let claim_failures_consecutive: Option<i64> = data["claim_failures_consecutive"].as_i64();
        let last_claim_error: Option<String> = data["last_claim_error"].as_str().map(|s| s.to_owned());
        let heartbeat_failures_total: Option<i64> = data["heartbeat_failures_total"].as_i64();

        self.with_conn(|conn| {
            let rows_changed = conn.execute(
                "UPDATE runners SET
                    last_heartbeat = ?1,
                    cpu_load_pct = ?2,
                    ram_free_mb = ?3,
                    battery_pct = ?4,
                    on_battery = ?5,
                    last_known_commit = COALESCE(?6, last_known_commit),
                    last_nonce = ?7,
                    claim_failures_total = COALESCE(?8, claim_failures_total),
                    claim_failures_consecutive = COALESCE(?9, claim_failures_consecutive),
                    last_claim_error = ?10,
                    heartbeat_failures_total = COALESCE(?11, heartbeat_failures_total),
                    state = CASE WHEN drain_requested = 1 THEN 'draining' ELSE 'online' END
                 WHERE runner_id = ?12 AND (last_nonce IS NULL OR last_nonce != ?7)",
                params![
                    now, cpu_load_pct, ram_free_mb, battery_pct, on_battery,
                    last_known_commit, nonce,
                    claim_failures_total, claim_failures_consecutive, last_claim_error,
                    heartbeat_failures_total,
                    runner_id
                ],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;

            if rows_changed == 0 {
                let exists: Option<i64> = conn
                    .query_row("SELECT 1 FROM runners WHERE runner_id = ?1", params![runner_id], |r| r.get(0))
                    .ok();
                return match exists {
                    None => Err(StoreError::NotFound(format!("runner {runner_id}"))),
                    Some(_) => Err(StoreError::PermissionDenied("nonce replay rejected".into())),
                };
            }

            conn.query_row("SELECT * FROM runners WHERE runner_id = ?1", params![runner_id], row_to_runner)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn request_drain(&self, runner_id: &str) -> StoreResult<RunnerRow> {
        self.with_conn(|conn| {
            let rows_changed = conn.execute(
                "UPDATE runners SET drain_requested = 1, state = 'draining' WHERE runner_id = ?1",
                params![runner_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            if rows_changed == 0 {
                return Err(StoreError::NotFound(format!("runner {runner_id}")));
            }
            conn.query_row("SELECT * FROM runners WHERE runner_id = ?1", params![runner_id], row_to_runner)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn request_undrain(&self, runner_id: &str) -> StoreResult<RunnerRow> {
        self.with_conn(|conn| {
            let rows_changed = conn.execute(
                "UPDATE runners SET drain_requested = 0,
                 state = CASE WHEN state = 'draining' THEN 'online' ELSE state END
                 WHERE runner_id = ?1",
                params![runner_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            if rows_changed == 0 {
                return Err(StoreError::NotFound(format!("runner {runner_id}")));
            }
            conn.query_row("SELECT * FROM runners WHERE runner_id = ?1", params![runner_id], row_to_runner)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn delete_runner(&self, runner_id: &str) -> StoreResult<RunnerRow> {
        self.with_conn(|conn| {
            let row = conn.query_row("SELECT * FROM runners WHERE runner_id = ?1", params![runner_id], row_to_runner)
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("runner {runner_id}")),
                    other => StoreError::Backend(other.to_string()),
                })?;
            conn.execute("DELETE FROM runners WHERE runner_id = ?1", params![runner_id])
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(row)
        })
    }
}

// -- Dispatchers -------------------------------------------------------------

fn row_to_dispatcher(r: &rusqlite::Row<'_>) -> rusqlite::Result<DispatcherRow> {
    let meta_str: String = r.get("metadata")?;
    Ok(DispatcherRow {
        dispatcher_id: r.get("dispatcher_id")?,
        public_key: r.get("public_key")?,
        label: r.get("label")?,
        hostname: r.get("hostname")?,
        metadata: serde_json::from_str(&meta_str).unwrap_or(json!({})),
        first_seen: r.get("first_seen")?,
        last_seen: r.get("last_seen")?,
    })
}

#[async_trait]
impl DispatcherStore for SqliteStore {
    async fn upsert_dispatcher(&self, data: Value) -> StoreResult<DispatcherRow> {
        let dispatcher_id = data["dispatcher_id"].as_str().ok_or_else(|| StoreError::Backend("missing dispatcher_id".into()))?.to_owned();
        let public_key = data["public_key"].as_str().unwrap_or("").to_owned();
        let label = data["label"].as_str().unwrap_or("").to_owned();
        let hostname: Option<String> = data["hostname"].as_str().map(|s| s.to_owned());
        let metadata = serde_json::to_string(data.get("metadata").unwrap_or(&json!({}))).unwrap_or_else(|_| "{}".into());
        let now = utc_now();

        self.with_conn(|conn| {
            let existing_key: Option<String> = conn
                .query_row("SELECT public_key FROM dispatchers WHERE dispatcher_id = ?1", params![dispatcher_id], |r| r.get(0))
                .ok();

            if let Some(ref existing) = existing_key {
                if existing != &public_key {
                    return Err(StoreError::PermissionDenied("dispatcher_id is already bound to a different public_key".into()));
                }
                conn.execute(
                    "UPDATE dispatchers SET label=?1, hostname=?2, metadata=?3, last_seen=?4 WHERE dispatcher_id=?5",
                    params![label, hostname, metadata, now, dispatcher_id],
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
            } else {
                conn.execute(
                    "INSERT INTO dispatchers (dispatcher_id, public_key, label, hostname, metadata, first_seen, last_seen)
                     VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![dispatcher_id, public_key, label, hostname, metadata, now, now],
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
            }

            conn.query_row("SELECT * FROM dispatchers WHERE dispatcher_id = ?1", params![dispatcher_id], row_to_dispatcher)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn get_dispatcher(&self, dispatcher_id: &str) -> StoreResult<DispatcherRow> {
        self.with_conn(|conn| {
            conn.query_row("SELECT * FROM dispatchers WHERE dispatcher_id = ?1", params![dispatcher_id], row_to_dispatcher)
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("dispatcher {dispatcher_id}")),
                    other => StoreError::Backend(other.to_string()),
                })
        })
    }

    async fn list_dispatchers(&self) -> StoreResult<Vec<DispatcherRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT * FROM dispatchers ORDER BY label, dispatcher_id")
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let r = stmt.query_map([], row_to_dispatcher)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(r)
        })
    }

    async fn dispatcher_public_key(&self, dispatcher_id: &str) -> StoreResult<Option<String>> {
        self.with_conn(|conn| {
            let key: Option<String> = conn
                .query_row("SELECT public_key FROM dispatchers WHERE dispatcher_id = ?1", params![dispatcher_id], |r| r.get(0))
                .ok();
            Ok(key)
        })
    }

    async fn delete_dispatcher(&self, dispatcher_id: &str) -> StoreResult<DispatcherRow> {
        self.with_conn(|conn| {
            let row = conn.query_row("SELECT * FROM dispatchers WHERE dispatcher_id = ?1", params![dispatcher_id], row_to_dispatcher)
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("dispatcher {dispatcher_id}")),
                    other => StoreError::Backend(other.to_string()),
                })?;
            let hostname: Option<String> = row.hostname.clone();
            conn.execute("DELETE FROM dispatchers WHERE dispatcher_id = ?1", params![dispatcher_id])
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            // If no other dispatchers on this hostname, remove the dispatch host_role
            if let Some(h) = hostname {
                let remaining: i64 = conn
                    .query_row("SELECT COUNT(*) FROM dispatchers WHERE hostname = ?1", params![h], |r| r.get(0))
                    .unwrap_or(0);
                if remaining == 0 {
                    conn.execute("DELETE FROM host_roles WHERE hostname = ?1 AND role = 'dispatch'", params![h])
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                }
            }
            Ok(row)
        })
    }
}

// -- Nonces ------------------------------------------------------------------

#[async_trait]
impl NonceStore for SqliteStore {
    async fn consume_dispatcher_nonce(&self, dispatcher_id: &str, nonce: &str, now: &str) -> StoreResult<()> {
        self.with_conn(|conn| {
            let rows_changed = conn.execute(
                "UPDATE dispatchers SET last_nonce = ?1, last_seen = ?2
                 WHERE dispatcher_id = ?3 AND (last_nonce IS NULL OR last_nonce != ?1)",
                params![nonce, now, dispatcher_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            if rows_changed == 0 {
                let exists: Option<i64> = conn
                    .query_row("SELECT 1 FROM dispatchers WHERE dispatcher_id = ?1", params![dispatcher_id], |r| r.get(0))
                    .ok();
                return match exists {
                    None => Err(StoreError::NotFound(format!("dispatcher {dispatcher_id}"))),
                    Some(_) => Err(StoreError::PermissionDenied("nonce replay rejected".into())),
                };
            }
            Ok(())
        })
    }

    async fn consume_runner_nonce(&self, runner_id: &str, nonce: &str, now: &str) -> StoreResult<()> {
        self.with_conn(|conn| {
            let rows_changed = conn.execute(
                "UPDATE runners SET last_nonce = ?1, last_heartbeat = ?2
                 WHERE runner_id = ?3 AND (last_nonce IS NULL OR last_nonce != ?1)",
                params![nonce, now, runner_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            if rows_changed == 0 {
                let exists: Option<i64> = conn
                    .query_row("SELECT 1 FROM runners WHERE runner_id = ?1", params![runner_id], |r| r.get(0))
                    .ok();
                return match exists {
                    None => Err(StoreError::NotFound(format!("runner {runner_id}"))),
                    Some(_) => Err(StoreError::PermissionDenied("nonce replay rejected".into())),
                };
            }
            Ok(())
        })
    }
}

// -- Streams -----------------------------------------------------------------

fn row_to_stream(r: &rusqlite::Row<'_>) -> rusqlite::Result<StreamLine> {
    Ok(StreamLine {
        id: r.get("id")?,
        task_id: r.get("task_id")?,
        seq: r.get("seq")?,
        channel: r.get("channel")?,
        line: r.get("line")?,
        created_at: r.get("created_at")?,
    })
}

#[async_trait]
impl StreamStore for SqliteStore {
    async fn append_stream(&self, task_id: i64, worker_id: &str, channel: &str, line: &str, now: &str) -> StoreResult<StreamLine> {
        self.with_conn(|conn| {
            // Ownership check
            let owner: Option<String> = conn
                .query_row("SELECT worker_id FROM tasks WHERE id = ?1", params![task_id], |r| r.get(0))
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("task {task_id}")),
                    other => StoreError::Backend(other.to_string()),
                })?;
            if owner.as_deref() != Some(worker_id) {
                return Err(StoreError::PermissionDenied(format!("worker mismatch on stream append")));
            }

            // Compute next seq from MAX
            let max_seq: i64 = conn
                .query_row("SELECT COALESCE(MAX(seq), 0) FROM task_streams WHERE task_id = ?1", params![task_id], |r| r.get(0))
                .unwrap_or(0);
            let next_seq = max_seq + 1;

            conn.execute(
                "INSERT INTO task_streams (task_id, seq, channel, line, created_at) VALUES (?1,?2,?3,?4,?5)",
                params![task_id, next_seq, channel, line, now],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            let id = conn.last_insert_rowid();

            Ok(StreamLine { id, task_id, seq: next_seq, channel: channel.to_owned(), line: line.to_owned(), created_at: now.to_owned() })
        })
    }

    async fn append_stream_bulk(&self, task_id: i64, worker_id: &str, entries: &[(String, String)], now: &str) -> StoreResult<Vec<StreamLine>> {
        if entries.is_empty() {
            return Ok(vec![]);
        }
        self.with_conn(|conn| {
            // Ownership check
            let owner: Option<String> = conn
                .query_row("SELECT worker_id FROM tasks WHERE id = ?1", params![task_id], |r| r.get(0))
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("task {task_id}")),
                    other => StoreError::Backend(other.to_string()),
                })?;
            if owner.as_deref() != Some(worker_id) {
                return Err(StoreError::PermissionDenied("worker mismatch on stream bulk append".into()));
            }

            let mut seq: i64 = conn
                .query_row("SELECT COALESCE(MAX(seq), 0) FROM task_streams WHERE task_id = ?1", params![task_id], |r| r.get(0))
                .unwrap_or(0);

            let mut result = Vec::with_capacity(entries.len());
            for (channel, line) in entries {
                seq += 1;
                conn.execute(
                    "INSERT INTO task_streams (task_id, seq, channel, line, created_at) VALUES (?1,?2,?3,?4,?5)",
                    params![task_id, seq, channel, line, now],
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
                let id = conn.last_insert_rowid();
                result.push(StreamLine {
                    id, task_id, seq,
                    channel: channel.clone(),
                    line: line.clone(),
                    created_at: now.to_owned(),
                });
            }
            Ok(result)
        })
    }

    async fn streams_since(&self, task_id: i64, after_seq: i64, limit: i64) -> StoreResult<Vec<StreamLine>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, task_id, seq, channel, line, created_at FROM task_streams
                 WHERE task_id = ?1 AND seq > ?2 ORDER BY seq ASC LIMIT ?3"
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            let r = stmt.query_map(params![task_id, after_seq, limit], row_to_stream)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(r)
        })
    }
}

// -- Progress ----------------------------------------------------------------

fn row_to_progress(r: &rusqlite::Row<'_>) -> rusqlite::Result<ProgressEntry> {
    let files_str: String = r.get("files_touched")?;
    Ok(ProgressEntry {
        id: r.get("id")?,
        task_id: r.get("task_id")?,
        seq: r.get("seq")?,
        message: r.get("message")?,
        files_touched: serde_json::from_str(&files_str).unwrap_or(json!([])),
        created_at: r.get("created_at")?,
    })
}

#[async_trait]
impl ProgressStore for SqliteStore {
    async fn append_progress(&self, task_id: i64, worker_id: &str, message: &str, files: Option<Vec<String>>, now: &str) -> StoreResult<ProgressEntry> {
        let files_json = serde_json::to_string(&files.unwrap_or_default()).unwrap_or_else(|_| "[]".into());
        self.with_conn(|conn| {
            // Ownership check via INSERT...SELECT (atomic ownership + seq)
            conn.execute(
                "INSERT INTO progress (task_id, seq, message, files_touched, created_at)
                 SELECT t.id,
                        COALESCE((SELECT MAX(seq) FROM progress WHERE task_id = t.id), 0) + 1,
                        ?1, ?2, ?3
                 FROM tasks t WHERE t.id = ?4 AND t.worker_id = ?5",
                params![message, files_json, now, task_id, worker_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;

            let id = conn.last_insert_rowid();
            // If no row inserted (0 rows), disambiguate
            if id == 0 {
                let exists: Option<String> = conn
                    .query_row("SELECT worker_id FROM tasks WHERE id = ?1", params![task_id], |r| r.get(0))
                    .ok();
                return match exists {
                    None => Err(StoreError::NotFound(format!("task {task_id}"))),
                    Some(_) => Err(StoreError::PermissionDenied("worker mismatch on progress".into())),
                };
            }

            conn.query_row(
                "SELECT id, task_id, seq, message, files_touched, created_at FROM progress WHERE id = ?1",
                params![id],
                row_to_progress,
            ).map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn progress_since(&self, task_id: i64, after_seq: i64) -> StoreResult<Vec<ProgressEntry>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, task_id, seq, message, files_touched, created_at FROM progress
                 WHERE task_id = ?1 AND seq > ?2 ORDER BY seq ASC"
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            let r = stmt.query_map(params![task_id, after_seq], row_to_progress)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(r)
        })
    }
}

// -- Approvals ---------------------------------------------------------------

fn row_to_approval(r: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRow> {
    let decision_str: String = r.get("decision_json")?;
    let scope_str: String = r.get("scope_globs_json")?;
    Ok(ApprovalRow {
        approval_id: r.get("approval_id")?,
        envelope_hash: r.get("envelope_hash")?,
        status: r.get("status")?,
        decision_json: serde_json::from_str(&decision_str).unwrap_or(json!({})),
        task_label: r.get("task_label")?,
        branch: r.get("branch")?,
        scope_globs_json: serde_json::from_str(&scope_str).unwrap_or(json!([])),
        dispatcher_id: r.get("dispatcher_id")?,
        approver: r.get("approver")?,
        reason: r.get("reason")?,
        created_at: r.get("created_at")?,
        resolved_at: r.get("resolved_at")?,
    })
}

#[async_trait]
impl ApprovalStore for SqliteStore {
    async fn create_or_get_pending_approval(&self, envelope_hash: &str, decision: Value, task_label: &str, branch: Option<&str>, scope_globs: Vec<String>, dispatcher_id: Option<&str>, now: &str) -> StoreResult<(String, bool)> {
        let decision_json = serde_json::to_string(&decision).unwrap_or_else(|_| "{}".into());
        let scope_json = serde_json::to_string(&scope_globs).unwrap_or_else(|_| "[]".into());

        self.with_conn(|conn| {
            // Check for existing pending row
            let existing: Option<String> = conn
                .query_row(
                    "SELECT approval_id FROM approvals WHERE envelope_hash = ?1 AND status = 'pending' LIMIT 1",
                    params![envelope_hash],
                    |r| r.get(0),
                )
                .ok();

            if let Some(id) = existing {
                return Ok((id, false));
            }

            let approval_id = generate_id();
            conn.execute(
                "INSERT INTO approvals (approval_id, envelope_hash, decision_json, task_label, branch, scope_globs_json, dispatcher_id, status, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,'pending',?8)",
                params![approval_id, envelope_hash, decision_json, task_label, branch, scope_json, dispatcher_id, now],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;

            Ok((approval_id, true))
        })
    }

    async fn consume_approval(&self, approval_id: &str, envelope_hash: &str) -> StoreResult<bool> {
        self.with_conn(|conn| {
            let rows_changed = conn.execute(
                "UPDATE approvals SET status = 'consumed' WHERE approval_id = ?1 AND envelope_hash = ?2 AND status = 'approved'",
                params![approval_id, envelope_hash],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(rows_changed > 0)
        })
    }

    async fn resolve_approval(&self, approval_id: &str, status: &str, approver: Option<&str>, reason: Option<&str>, now: &str) -> StoreResult<ApprovalRow> {
        self.with_conn(|conn| {
            let rows_changed = conn.execute(
                "UPDATE approvals SET status = ?1, approver = ?2, reason = ?3, resolved_at = ?4
                 WHERE approval_id = ?5 AND status = 'pending'",
                params![status, approver, reason, now, approval_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;

            if rows_changed == 0 {
                let row: Option<ApprovalRow> = conn
                    .query_row("SELECT * FROM approvals WHERE approval_id = ?1", params![approval_id], row_to_approval)
                    .ok();
                return match row {
                    None => Err(StoreError::NotFound(format!("approval {approval_id}"))),
                    Some(a) => Err(StoreError::Conflict(format!("approval already resolved: status={}", a.status))),
                };
            }

            conn.query_row("SELECT * FROM approvals WHERE approval_id = ?1", params![approval_id], row_to_approval)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn list_approvals(&self, status: Option<&str>, limit: i64) -> StoreResult<Vec<ApprovalRow>> {
        self.with_conn(|conn| {
            let rows: Vec<ApprovalRow> = if let Some(s) = status {
                let mut stmt = conn.prepare(
                    "SELECT * FROM approvals WHERE status = ?1 ORDER BY created_at DESC LIMIT ?2"
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
                let r = stmt.query_map(params![s, limit], row_to_approval)
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                r
            } else {
                let mut stmt = conn.prepare(
                    "SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?1"
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
                let r = stmt.query_map(params![limit], row_to_approval)
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                r
            };
            Ok(rows)
        })
    }

    async fn get_approval(&self, approval_id: &str) -> StoreResult<Option<ApprovalRow>> {
        self.with_conn(|conn| {
            let row = conn
                .query_row("SELECT * FROM approvals WHERE approval_id = ?1", params![approval_id], row_to_approval)
                .ok();
            Ok(row)
        })
    }
}

// -- Secrets -----------------------------------------------------------------

fn row_to_secret_metadata(r: &rusqlite::Row<'_>) -> rusqlite::Result<SecretMetadata> {
    Ok(SecretMetadata {
        name: r.get("name")?,
        version: r.get("version")?,
        created_at: r.get("created_at")?,
        last_rotated_at: r.get("last_rotated_at")?,
    })
}

#[async_trait]
impl SecretStore for SqliteStore {
    async fn put_secret(&self, name: &str, encrypted_value: &str, now: &str) -> StoreResult<SecretMetadata> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO secrets (name, encrypted_value, version, created_at) VALUES (?1,?2,1,?3)
                 ON CONFLICT(name) DO UPDATE SET encrypted_value = ?2, created_at = ?3",
                params![name, encrypted_value, now],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            conn.query_row("SELECT name, version, created_at, last_rotated_at FROM secrets WHERE name = ?1", params![name], row_to_secret_metadata)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn rotate_secret(&self, name: &str, encrypted_value: &str, now: &str) -> StoreResult<SecretMetadata> {
        self.with_conn(|conn| {
            let rows_changed = conn.execute(
                "UPDATE secrets SET encrypted_value = ?1, version = version + 1, last_rotated_at = ?2 WHERE name = ?3",
                params![encrypted_value, now, name],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            if rows_changed == 0 {
                return Err(StoreError::NotFound(format!("secret {name}")));
            }
            conn.query_row("SELECT name, version, created_at, last_rotated_at FROM secrets WHERE name = ?1", params![name], row_to_secret_metadata)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn list_secrets(&self) -> StoreResult<Vec<SecretMetadata>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT name, version, created_at, last_rotated_at FROM secrets ORDER BY name")
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let r = stmt.query_map([], row_to_secret_metadata)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(r)
        })
    }

    async fn resolve_secrets(&self, names: &[String]) -> StoreResult<HashMap<String, String>> {
        if names.is_empty() {
            return Ok(HashMap::new());
        }
        self.with_conn(|conn| {
            let mut out = HashMap::new();
            for name in names {
                let encrypted: Option<String> = conn
                    .query_row("SELECT encrypted_value FROM secrets WHERE name = ?1", params![name], |r| r.get(0))
                    .ok();
                if let Some(val) = encrypted {
                    out.insert(name.clone(), val);
                }
            }
            Ok(out)
        })
    }

    async fn delete_secret(&self, name: &str) -> StoreResult<bool> {
        self.with_conn(|conn| {
            let rows_changed = conn.execute("DELETE FROM secrets WHERE name = ?1", params![name])
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(rows_changed > 0)
        })
    }
}

// -- Labels ------------------------------------------------------------------

#[async_trait]
impl LabelStore for SqliteStore {
    async fn get_labels(&self) -> StoreResult<Value> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT key, value_json FROM labels")
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let rows: Vec<(String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            let mut hub_name = String::new();
            let mut runner_aliases = serde_json::Map::new();
            let mut host_aliases = serde_json::Map::new();

            for (k, v) in rows {
                let val: Value = serde_json::from_str(&v).unwrap_or(Value::String(v.clone()));
                let s = match &val { Value::String(s) => s.clone(), other => other.to_string() };
                if k == "hub_name" {
                    hub_name = s;
                } else if let Some(rid) = k.strip_prefix("runner_alias:") {
                    runner_aliases.insert(rid.to_owned(), Value::String(s));
                } else if let Some(h) = k.strip_prefix("host_alias:") {
                    host_aliases.insert(h.to_owned(), Value::String(s));
                }
            }

            Ok(json!({
                "hub_name": hub_name,
                "runner_aliases": runner_aliases,
                "host_aliases": host_aliases,
            }))
        })
    }

    async fn set_hub_name(&self, name: &str, by: Option<&str>, now: &str) -> StoreResult<()> {
        self.upsert_label("hub_name", name, by, now)
    }

    async fn set_runner_alias(&self, runner_id: &str, alias: &str, by: Option<&str>, now: &str) -> StoreResult<()> {
        let key = format!("runner_alias:{runner_id}");
        self.upsert_label(&key, alias, by, now)
    }

    async fn set_host_alias(&self, hostname: &str, alias: &str, by: Option<&str>, now: &str) -> StoreResult<()> {
        let key = format!("host_alias:{hostname}");
        self.upsert_label(&key, alias, by, now)
    }
}

impl SqliteStore {
    fn upsert_label(&self, key: &str, value: &str, updated_by: Option<&str>, now: &str) -> StoreResult<()> {
        let value_json = serde_json::to_string(&Value::String(value.to_owned())).unwrap_or_else(|_| format!("\"{}\"", value));
        self.with_conn(|conn| {
            if value.is_empty() {
                conn.execute("DELETE FROM labels WHERE key = ?1", params![key])
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
            } else {
                conn.execute(
                    "INSERT INTO labels (key, value_json, updated_by, updated_at) VALUES (?1,?2,?3,?4)
                     ON CONFLICT(key) DO UPDATE SET value_json = ?2, updated_by = ?3, updated_at = ?4",
                    params![key, value_json, updated_by, now],
                ).map_err(|e| StoreError::Backend(e.to_string()))?;
            }
            Ok(())
        })
    }
}

// -- Host roles --------------------------------------------------------------

fn row_to_host_role(r: &rusqlite::Row<'_>) -> rusqlite::Result<HostRoleRow> {
    let meta_str: String = r.get("metadata")?;
    let enabled_int: i64 = r.get("enabled")?;
    Ok(HostRoleRow {
        hostname: r.get("hostname")?,
        role: r.get("role")?,
        enabled: enabled_int != 0,
        status: r.get("status")?,
        metadata: serde_json::from_str(&meta_str).unwrap_or(json!({})),
        updated_at: r.get("updated_at")?,
    })
}

#[async_trait]
impl HostRoleStore for SqliteStore {
    async fn set_host_role(&self, hostname: &str, role: &str, enabled: bool, status: Option<&str>, metadata: Value, now: &str) -> StoreResult<HostRoleRow> {
        let meta_json = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".into());
        let enabled_int: i64 = if enabled { 1 } else { 0 };
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO host_roles (hostname, role, enabled, status, metadata, updated_at) VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(hostname, role) DO UPDATE SET enabled=?3, status=?4, metadata=?5, updated_at=?6",
                params![hostname, role, enabled_int, status, meta_json, now],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            conn.query_row("SELECT * FROM host_roles WHERE hostname = ?1 AND role = ?2", params![hostname, role], row_to_host_role)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
    }

    async fn get_host_role(&self, hostname: &str, role: &str) -> StoreResult<Option<HostRoleRow>> {
        self.with_conn(|conn| {
            let row = conn
                .query_row("SELECT * FROM host_roles WHERE hostname = ?1 AND role = ?2", params![hostname, role], row_to_host_role)
                .ok();
            Ok(row)
        })
    }

    async fn list_host_roles(&self) -> StoreResult<Vec<HostRoleRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT * FROM host_roles ORDER BY hostname, role")
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let r = stmt.query_map([], row_to_host_role)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(r)
        })
    }
}

impl FabricStore for SqliteStore {}

// -- Notes -------------------------------------------------------------------

#[async_trait]
impl NoteStore for SqliteStore {
    async fn post_note(&self, task_id: i64, author: &str, body: &str, now: &str) -> StoreResult<NoteRow> {
        self.with_conn(|conn| {
            let rows_changed = conn.execute(
                "INSERT INTO notes (task_id, author, body, created_at) SELECT t.id, ?1, ?2, ?3 FROM tasks t WHERE t.id = ?4",
                params![author, body, now, task_id],
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            if rows_changed == 0 {
                return Err(StoreError::NotFound(format!("task {task_id}")));
            }
            let id = conn.last_insert_rowid();
            Ok(NoteRow { id, task_id, author: author.to_owned(), body: body.to_owned(), created_at: now.to_owned() })
        })
    }

    async fn read_notes(&self, task_id: i64, after_id: i64) -> StoreResult<Vec<NoteRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, task_id, author, body, created_at FROM notes WHERE task_id = ?1 AND id > ?2 ORDER BY id ASC"
            ).map_err(|e| StoreError::Backend(e.to_string()))?;
            let r = stmt.query_map(params![task_id, after_id], |row| {
                Ok(NoteRow {
                    id: row.get("id")?,
                    task_id: row.get("task_id")?,
                    author: row.get("author")?,
                    body: row.get("body")?,
                    created_at: row.get("created_at")?,
                })
            }).map_err(|e| StoreError::Backend(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(r)
        })
    }
}

// -- Helpers -----------------------------------------------------------------

fn utc_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    epoch_secs_to_iso(d.as_secs() as i64)
}

fn utc_offset(offset_secs: i64) -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    epoch_secs_to_iso(d.as_secs() as i64 + offset_secs)
}

fn epoch_secs_to_iso(total_secs: i64) -> String {
    let secs = total_secs % 60;
    let mins = (total_secs / 60) % 60;
    let hours = (total_secs / 3600) % 24;
    let mut days = total_secs / 86400;
    let mut year = 1970i64;
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [31i64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md { month = i; break; }
        days -= md;
    }
    format!("{year:04}-{:02}-{:02} {hours:02}:{mins:02}:{secs:02}", month + 1, days + 1)
}

/// Generate a 32-hex-char random ID (matches Python's `uuid.uuid4().hex`).
fn generate_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Simple pseudo-random ID seeded from system time + thread ID
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut h);
    std::thread::current().id().hash(&mut h);
    let a = h.finish();
    // Mix in a second hash for more bits
    let mut h2 = DefaultHasher::new();
    a.hash(&mut h2);
    42u64.hash(&mut h2);
    let b = h2.finish();
    format!("{a:016x}{b:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn new_store() -> SqliteStore {
        let store = SqliteStore::open_in_memory().unwrap();
        store.init_schema().await.unwrap();
        store.run_additive_migrations().await.unwrap();
        store
    }

    #[tokio::test]
    async fn schema_init_and_version() {
        let store = new_store().await;
        let v = store.schema_version().await.unwrap();
        assert_eq!(v, 2);
    }

    #[tokio::test]
    async fn audit_chain_empty_returns_genesis() {
        let store = new_store().await;
        let tail = store.audit_chain_tail().await.unwrap();
        assert_eq!(tail, AUDIT_GENESIS_HASH);
    }

    #[tokio::test]
    async fn audit_append_and_verify() {
        let store = new_store().await;
        let payload = serde_json::json!({"task_id": 1, "title": "test"});
        let payload_json = serde_json::to_string(&payload).unwrap();
        let hash = audit_event_hash(AUDIT_GENESIS_HASH, "dispatch", &payload);
        let result = store.append_audit_event(AUDIT_GENESIS_HASH, &hash, AUDIT_GENESIS_HASH, "dispatch", Some(1), &payload_json, "2026-06-01 00:00:00").await.unwrap();
        assert!(matches!(result, AuditAppendResult::Ok(_)));
        let tail = store.audit_chain_tail().await.unwrap();
        assert_eq!(tail, hash);
    }

    #[tokio::test]
    async fn audit_tail_conflict() {
        let store = new_store().await;
        let p1 = serde_json::json!({"task_id": 1});
        let p1_json = serde_json::to_string(&p1).unwrap();
        let h1 = audit_event_hash(AUDIT_GENESIS_HASH, "dispatch", &p1);
        store.append_audit_event(AUDIT_GENESIS_HASH, &h1, AUDIT_GENESIS_HASH, "dispatch", Some(1), &p1_json, "2026-06-01 00:00:00").await.unwrap();
        let p2 = serde_json::json!({"task_id": 2});
        let p2_json = serde_json::to_string(&p2).unwrap();
        let h2 = audit_event_hash(AUDIT_GENESIS_HASH, "claim", &p2);
        let result = store.append_audit_event(AUDIT_GENESIS_HASH, &h2, AUDIT_GENESIS_HASH, "claim", Some(2), &p2_json, "2026-06-01 00:00:01").await.unwrap();
        assert!(matches!(result, AuditAppendResult::TailConflict { .. }));
    }

    #[tokio::test]
    async fn audit_chain_verification() {
        let store = new_store().await;
        let p1 = serde_json::json!({"task_id": 1, "title": "a"});
        let p1_json = serde_json::to_string(&p1).unwrap();
        let h1 = audit_event_hash(AUDIT_GENESIS_HASH, "dispatch", &p1);
        store.append_audit_event(AUDIT_GENESIS_HASH, &h1, AUDIT_GENESIS_HASH, "dispatch", Some(1), &p1_json, "2026-06-01 00:00:00").await.unwrap();
        let p2 = serde_json::json!({"task_id": 1, "worker_id": "r1"});
        let p2_json = serde_json::to_string(&p2).unwrap();
        let h2 = audit_event_hash(&h1, "claim", &p2);
        store.append_audit_event(&h1, &h2, &h1, "claim", Some(1), &p2_json, "2026-06-01 00:00:01").await.unwrap();
        let events = store.audit_events_for_task(1).await.unwrap();
        assert_eq!(events.len(), 2);
        let (ok, err) = store.verify_audit_chain(&events).await.unwrap();
        assert!(ok, "chain should verify: {err:?}");
    }

    #[tokio::test]
    async fn task_create_and_get() {
        let store = new_store().await;
        let p = CreateTaskParams {
            title: "Test task".into(),
            prompt: "Do the thing".into(),
            scope_globs: vec!["src/**".into()],
            base_commit: "abc123".into(),
            branch: "agent/test".into(),
            todo_id: Some("114".into()),
            timeout_minutes: 60,
            priority: 100,
            kind: "command".into(),
            metadata: serde_json::json!({}),
            required_tools: None,
            required_tags: None,
            tenant: None,
            workspace_root: None,
            require_base_commit: false,
            required_capabilities: None,
            secrets_needed: None,
            network_egress: None,
            dispatcher_id: None,
        };
        let task = store.create_task(p, "2026-06-01 00:00:00").await.unwrap();
        assert_eq!(task.title, "Test task");
        assert_eq!(task.status, "queued");
        assert_eq!(task.kind, "command");

        let fetched = store.get_task(task.id).await.unwrap();
        assert_eq!(fetched.id, task.id);
        assert_eq!(fetched.branch, "agent/test");
    }

    #[tokio::test]
    async fn task_list_and_claim() {
        let store = new_store().await;
        let make = |title: &str| CreateTaskParams {
            title: title.into(), prompt: "p".into(), scope_globs: vec![],
            base_commit: "a".into(), branch: "b".into(), todo_id: None,
            timeout_minutes: 60, priority: 100, kind: "command".into(),
            metadata: serde_json::json!({}), required_tools: None, required_tags: None,
            tenant: None, workspace_root: None, require_base_commit: false,
            required_capabilities: None, secrets_needed: None, network_egress: None,
            dispatcher_id: None,
        };
        store.create_task(make("t1"), "2026-06-01 00:00:00").await.unwrap();
        let t2 = store.create_task(make("t2"), "2026-06-01 00:00:01").await.unwrap();

        let all = store.list_tasks(None, 100).await.unwrap();
        assert_eq!(all.len(), 2);

        let claimed = store.claim_task(t2.id, "runner-1", "2026-06-01 00:01:00").await.unwrap();
        assert!(matches!(claimed, ClaimResult::Claimed(_)));

        // Can't claim again
        let again = store.claim_task(t2.id, "runner-2", "2026-06-01 00:01:01").await.unwrap();
        assert!(matches!(again, ClaimResult::AlreadyClaimed));
    }

    #[tokio::test]
    async fn runner_upsert_and_heartbeat() {
        let store = new_store().await;
        let data = serde_json::json!({
            "runner_id": "r-001", "public_key": "aabbcc", "hostname": "myhost",
            "os": "Windows", "arch": "x64", "runner_version": "0.5.0",
            "protocol_version": 3, "max_concurrent": 2,
            "tools": ["python"], "tags": ["gpu"], "scope_prefixes": ["/projects"],
        });
        let runner = store.upsert_runner(data).await.unwrap();
        assert_eq!(runner.runner_id, "r-001");
        assert_eq!(runner.state, "online");

        let hb = serde_json::json!({"nonce": "n1", "cpu_load_pct": 50.0});
        let updated = store.heartbeat_runner("r-001", hb, "2026-06-01 00:01:00").await.unwrap();
        assert_eq!(updated.runner_id, "r-001");

        // Replay same nonce → error
        let hb2 = serde_json::json!({"nonce": "n1"});
        let err = store.heartbeat_runner("r-001", hb2, "2026-06-01 00:01:01").await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn stream_append_and_read() {
        let store = new_store().await;
        let p = CreateTaskParams {
            title: "st".into(), prompt: "p".into(), scope_globs: vec![],
            base_commit: "a".into(), branch: "b".into(), todo_id: None,
            timeout_minutes: 60, priority: 100, kind: "command".into(),
            metadata: serde_json::json!({}), required_tools: None, required_tags: None,
            tenant: None, workspace_root: None, require_base_commit: false,
            required_capabilities: None, secrets_needed: None, network_egress: None,
            dispatcher_id: None,
        };
        let task = store.create_task(p, "2026-06-01 00:00:00").await.unwrap();
        // Claim so worker_id matches
        store.claim_task(task.id, "w1", "2026-06-01 00:00:01").await.unwrap();

        let line = store.append_stream(task.id, "w1", "stdout", "hello", "2026-06-01 00:00:02").await.unwrap();
        assert_eq!(line.seq, 1);

        let lines = store.streams_since(task.id, 0, 100).await.unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].line, "hello");
    }

    #[tokio::test]
    async fn labels_roundtrip() {
        let store = new_store().await;
        store.set_hub_name("my-hub", Some("admin"), "2026-06-01 00:00:00").await.unwrap();
        store.set_runner_alias("r-001", "primary", None, "2026-06-01 00:00:00").await.unwrap();
        let labels = store.get_labels().await.unwrap();
        assert_eq!(labels["hub_name"], "my-hub");
        assert_eq!(labels["runner_aliases"]["r-001"], "primary");
    }

    #[tokio::test]
    async fn host_roles_roundtrip() {
        let store = new_store().await;
        let row = store.set_host_role("host1", "hub_head", true, Some("active"), serde_json::json!({}), "2026-06-01 00:00:00").await.unwrap();
        assert!(row.enabled);
        assert_eq!(row.role, "hub_head");

        let got = store.get_host_role("host1", "hub_head").await.unwrap();
        assert!(got.is_some());

        let all = store.list_host_roles().await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn approval_workflow() {
        let store = new_store().await;
        let (id, created) = store.create_or_get_pending_approval(
            "hash123", serde_json::json!({}), "My task", Some("main"),
            vec!["src/**".into()], Some("d-001"), "2026-06-01 00:00:00"
        ).await.unwrap();
        assert!(created);

        // Same hash → reuse existing
        let (id2, created2) = store.create_or_get_pending_approval(
            "hash123", serde_json::json!({}), "My task", Some("main"),
            vec!["src/**".into()], Some("d-001"), "2026-06-01 00:00:01"
        ).await.unwrap();
        assert!(!created2);
        assert_eq!(id, id2);

        let resolved = store.resolve_approval(&id, "approved", Some("alice"), None, "2026-06-01 00:01:00").await.unwrap();
        assert_eq!(resolved.status, "approved");

        let consumed = store.consume_approval(&id, "hash123").await.unwrap();
        assert!(consumed);
    }
}
