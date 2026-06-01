//! SQLite backend for the ForgeWire Fabric store contract.
//!
//! Uses `rusqlite` with WAL mode. Schema initialization and additive
//! migrations match the Python oracle at `oracle/v2.7.0-baseline`.

#![deny(rust_2018_idioms)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use rusqlite::{params, Connection};
use serde_json::Value;
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
            // Read current tail
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
        for (i, event) in events.iter().enumerate() {
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

// Stub implementations for remaining traits so the crate compiles.
// Full implementations follow the same pattern as AuditStore above.

#[async_trait] impl TaskStore for SqliteStore {
    async fn create_task(&self, _params: CreateTaskParams, _now: &str) -> StoreResult<TaskRow> { todo!() }
    async fn get_task(&self, _id: i64) -> StoreResult<TaskRow> { todo!() }
    async fn list_tasks(&self, _status: Option<&str>, _limit: i64) -> StoreResult<Vec<TaskRow>> { todo!() }
    async fn claim_task(&self, _id: i64, _worker: &str, _now: &str) -> StoreResult<ClaimResult> { todo!() }
    async fn mark_running(&self, _id: i64, _now: &str) -> StoreResult<TaskRow> { todo!() }
    async fn cancel_task(&self, _id: i64, _now: &str) -> StoreResult<TaskRow> { todo!() }
    async fn count_tasks(&self) -> StoreResult<i64> { todo!() }
}

#[async_trait] impl ResultStore for SqliteStore {
    async fn submit_result(&self, _params: SubmitResultParams, _now: &str) -> StoreResult<TaskRow> { todo!() }
}

#[async_trait] impl RunnerStore for SqliteStore {
    async fn upsert_runner(&self, _data: Value) -> StoreResult<RunnerRow> { todo!() }
    async fn get_runner(&self, _id: &str) -> StoreResult<RunnerRow> { todo!() }
    async fn list_runners(&self) -> StoreResult<Vec<RunnerRow>> { todo!() }
    async fn runner_public_key(&self, _id: &str) -> StoreResult<Option<String>> { todo!() }
    async fn heartbeat_runner(&self, _id: &str, _data: Value, _now: &str) -> StoreResult<RunnerRow> { todo!() }
    async fn request_drain(&self, _id: &str) -> StoreResult<RunnerRow> { todo!() }
    async fn request_undrain(&self, _id: &str) -> StoreResult<RunnerRow> { todo!() }
    async fn delete_runner(&self, _id: &str) -> StoreResult<RunnerRow> { todo!() }
}

#[async_trait] impl DispatcherStore for SqliteStore {
    async fn upsert_dispatcher(&self, _data: Value) -> StoreResult<DispatcherRow> { todo!() }
    async fn get_dispatcher(&self, _id: &str) -> StoreResult<DispatcherRow> { todo!() }
    async fn list_dispatchers(&self) -> StoreResult<Vec<DispatcherRow>> { todo!() }
    async fn dispatcher_public_key(&self, _id: &str) -> StoreResult<Option<String>> { todo!() }
    async fn delete_dispatcher(&self, _id: &str) -> StoreResult<DispatcherRow> { todo!() }
}

#[async_trait] impl NonceStore for SqliteStore {
    async fn consume_dispatcher_nonce(&self, _id: &str, _nonce: &str, _now: &str) -> StoreResult<()> { todo!() }
    async fn consume_runner_nonce(&self, _id: &str, _nonce: &str, _now: &str) -> StoreResult<()> { todo!() }
}

#[async_trait] impl StreamStore for SqliteStore {
    async fn append_stream(&self, _tid: i64, _wid: &str, _ch: &str, _line: &str, _now: &str) -> StoreResult<StreamLine> { todo!() }
    async fn append_stream_bulk(&self, _tid: i64, _wid: &str, _entries: &[(String, String)], _now: &str) -> StoreResult<Vec<StreamLine>> { todo!() }
    async fn streams_since(&self, _tid: i64, _after: i64, _limit: i64) -> StoreResult<Vec<StreamLine>> { todo!() }
}

#[async_trait] impl ProgressStore for SqliteStore {
    async fn append_progress(&self, _tid: i64, _wid: &str, _msg: &str, _files: Option<Vec<String>>, _now: &str) -> StoreResult<ProgressEntry> { todo!() }
    async fn progress_since(&self, _tid: i64, _after: i64) -> StoreResult<Vec<ProgressEntry>> { todo!() }
}

#[async_trait] impl ApprovalStore for SqliteStore {
    async fn create_or_get_pending_approval(&self, _eh: &str, _d: Value, _tl: &str, _b: Option<&str>, _sg: Vec<String>, _di: Option<&str>, _now: &str) -> StoreResult<(String, bool)> { todo!() }
    async fn consume_approval(&self, _id: &str, _eh: &str) -> StoreResult<bool> { todo!() }
    async fn resolve_approval(&self, _id: &str, _status: &str, _approver: Option<&str>, _reason: Option<&str>, _now: &str) -> StoreResult<ApprovalRow> { todo!() }
    async fn list_approvals(&self, _status: Option<&str>, _limit: i64) -> StoreResult<Vec<ApprovalRow>> { todo!() }
    async fn get_approval(&self, _id: &str) -> StoreResult<Option<ApprovalRow>> { todo!() }
}

#[async_trait] impl SecretStore for SqliteStore {
    async fn put_secret(&self, _name: &str, _val: &str, _now: &str) -> StoreResult<SecretMetadata> { todo!() }
    async fn rotate_secret(&self, _name: &str, _val: &str, _now: &str) -> StoreResult<SecretMetadata> { todo!() }
    async fn list_secrets(&self) -> StoreResult<Vec<SecretMetadata>> { todo!() }
    async fn resolve_secrets(&self, _names: &[String]) -> StoreResult<std::collections::HashMap<String, String>> { todo!() }
    async fn delete_secret(&self, _name: &str) -> StoreResult<bool> { todo!() }
}

#[async_trait] impl LabelStore for SqliteStore {
    async fn get_labels(&self) -> StoreResult<Value> { todo!() }
    async fn set_hub_name(&self, _name: &str, _by: Option<&str>, _now: &str) -> StoreResult<()> { todo!() }
    async fn set_runner_alias(&self, _id: &str, _alias: &str, _by: Option<&str>, _now: &str) -> StoreResult<()> { todo!() }
    async fn set_host_alias(&self, _host: &str, _alias: &str, _by: Option<&str>, _now: &str) -> StoreResult<()> { todo!() }
}

#[async_trait] impl HostRoleStore for SqliteStore {
    async fn set_host_role(&self, _host: &str, _role: &str, _en: bool, _st: Option<&str>, _meta: Value, _now: &str) -> StoreResult<HostRoleRow> { todo!() }
    async fn get_host_role(&self, _host: &str, _role: &str) -> StoreResult<Option<HostRoleRow>> { todo!() }
    async fn list_host_roles(&self) -> StoreResult<Vec<HostRoleRow>> { todo!() }
}

impl FabricStore for SqliteStore {}

fn utc_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = d.as_secs();
    let secs = total_secs % 60;
    let mins = (total_secs / 60) % 60;
    let hours = (total_secs / 3600) % 24;
    let mut days = (total_secs / 86400) as i64;
    // Simple date computation from epoch days
    let mut year = 1970i64;
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md as i64 { month = i; break; }
        days -= md as i64;
    }
    format!("{year:04}-{:02}-{:02} {hours:02}:{mins:02}:{secs:02}", month + 1, days + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn schema_init_and_version() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.init_schema().await.unwrap();
        store.run_additive_migrations().await.unwrap();
        let v = store.schema_version().await.unwrap();
        assert_eq!(v, 2);
    }

    #[tokio::test]
    async fn audit_chain_empty_returns_genesis() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.init_schema().await.unwrap();
        let tail = store.audit_chain_tail().await.unwrap();
        assert_eq!(tail, AUDIT_GENESIS_HASH);
    }

    #[tokio::test]
    async fn audit_append_and_verify() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.init_schema().await.unwrap();

        let payload = serde_json::json!({"task_id": 1, "title": "test"});
        let payload_json = serde_json::to_string(&payload).unwrap();
        let hash = audit_event_hash(AUDIT_GENESIS_HASH, "dispatch", &payload);

        let result = store
            .append_audit_event(AUDIT_GENESIS_HASH, &hash, AUDIT_GENESIS_HASH, "dispatch", Some(1), &payload_json, "2026-06-01 00:00:00")
            .await
            .unwrap();

        assert!(matches!(result, AuditAppendResult::Ok(_)));

        let tail = store.audit_chain_tail().await.unwrap();
        assert_eq!(tail, hash);
    }

    #[tokio::test]
    async fn audit_tail_conflict() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.init_schema().await.unwrap();

        let p1 = serde_json::json!({"task_id": 1});
        let p1_json = serde_json::to_string(&p1).unwrap();
        let h1 = audit_event_hash(AUDIT_GENESIS_HASH, "dispatch", &p1);

        store
            .append_audit_event(AUDIT_GENESIS_HASH, &h1, AUDIT_GENESIS_HASH, "dispatch", Some(1), &p1_json, "2026-06-01 00:00:00")
            .await
            .unwrap();

        // Try to append with stale expected tail (genesis instead of h1)
        let p2 = serde_json::json!({"task_id": 2});
        let p2_json = serde_json::to_string(&p2).unwrap();
        let h2 = audit_event_hash(AUDIT_GENESIS_HASH, "claim", &p2);

        let result = store
            .append_audit_event(AUDIT_GENESIS_HASH, &h2, AUDIT_GENESIS_HASH, "claim", Some(2), &p2_json, "2026-06-01 00:00:01")
            .await
            .unwrap();

        assert!(matches!(result, AuditAppendResult::TailConflict { .. }));
    }

    #[tokio::test]
    async fn audit_chain_verification() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.init_schema().await.unwrap();

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
}
