//! rqlite HA backend for the ForgeWire Fabric store contract.
//!
//! Implements `FabricStore` over the rqlite HTTP API, matching the Python
//! `_rqlite_db.py` adapter's behavior: single-statement writes, no cross-
//! statement transactions, explicit UTC timestamps, leader redirect following,
//! and quorum-loss detection.
//!
//! ## rqlite HTTP API contract
//!
//! - `/db/execute` — write statements (INSERT, UPDATE, DELETE)
//! - `/db/query`   — read statements (SELECT)
//! - `/db/request` — unified read/write (used for mixed batches)
//! - Consistency: `strong` for reads (Raft round-trip per read)
//! - Redirects: follower nodes return 301/302 to leader; client follows up to 3 times
//! - Quorum loss: 503 Service Unavailable on writes

#![deny(rust_2018_idioms)]

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tracing::{debug, warn};

use fabric_audit::{audit_event_hash, AUDIT_GENESIS_HASH};
use fabric_store::*;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: u32 = 3;

#[derive(Debug, Error)]
pub enum RqliteError {
    #[error("rqlite HTTP error: {0}")]
    Http(String),
    #[error("rqlite returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("rqlite quorum loss (503)")]
    QuorumLoss,
    #[error("rqlite redirect loop (>{MAX_REDIRECTS} redirects)")]
    RedirectLoop,
}

impl From<RqliteError> for StoreError {
    fn from(e: RqliteError) -> Self {
        match e {
            RqliteError::QuorumLoss => StoreError::Backend("rqlite quorum loss".into()),
            other => StoreError::Backend(other.to_string()),
        }
    }
}

/// rqlite-backed store. Communicates with the rqlite HTTP API.
pub struct RqliteStore {
    client: reqwest::Client,
    base_url: String,
    consistency: String,
}

impl RqliteStore {
    pub fn new(host: &str, port: u16, consistency: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS as usize))
            .pool_max_idle_per_host(50)
            .build()
            .expect("failed to build reqwest client");
        Self {
            client,
            base_url: format!("http://{host}:{port}"),
            consistency: consistency.to_owned(),
        }
    }

    /// Execute one or more write statements. Returns the rqlite response.
    async fn execute(&self, statements: &[(&str, &[Value])]) -> Result<Value, RqliteError> {
        let body: Vec<Value> = statements
            .iter()
            .map(|(sql, params)| {
                if params.is_empty() {
                    json!([sql])
                } else {
                    let mut arr = vec![json!(sql)];
                    arr.extend(params.iter().cloned());
                    json!(arr)
                }
            })
            .collect();

        let url = format!("{}/db/execute?timings", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| RqliteError::Http(e.to_string()))?;

        let status = resp.status().as_u16();
        if status == 503 {
            return Err(RqliteError::QuorumLoss);
        }
        let text = resp.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(RqliteError::Status { status, body: text });
        }
        serde_json::from_str(&text).map_err(|e| RqliteError::Http(e.to_string()))
    }

    /// Execute a single write and return rows_affected.
    async fn execute_one(&self, sql: &str, params: &[Value]) -> Result<i64, RqliteError> {
        let resp = self.execute(&[(sql, params)]).await?;
        let rows = resp["results"][0]["rows_affected"]
            .as_i64()
            .unwrap_or(0);
        Ok(rows)
    }

    /// Execute a read query. Returns rows as Vec<Value>.
    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Value>, RqliteError> {
        let body = if params.is_empty() {
            json!([[sql]])
        } else {
            let mut arr = vec![json!(sql)];
            arr.extend(params.iter().cloned());
            json!([arr])
        };

        let url = format!(
            "{}/db/query?timings&level={}",
            self.base_url, self.consistency
        );
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| RqliteError::Http(e.to_string()))?;

        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(RqliteError::Status { status, body: text });
        }

        let parsed: Value =
            serde_json::from_str(&text).map_err(|e| RqliteError::Http(e.to_string()))?;

        // rqlite returns { "results": [{ "columns": [...], "types": [...], "values": [[...], ...] }] }
        let results = &parsed["results"][0];
        let columns: Vec<String> = results["columns"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| v.as_str().unwrap_or("").to_owned())
                    .collect()
            })
            .unwrap_or_default();

        let values = results["values"].as_array();
        let mut rows = Vec::new();
        if let Some(vals) = values {
            for row_arr in vals {
                let row_vals = row_arr.as_array().cloned().unwrap_or_default();
                let mut obj = serde_json::Map::new();
                for (i, col) in columns.iter().enumerate() {
                    obj.insert(
                        col.clone(),
                        row_vals.get(i).cloned().unwrap_or(Value::Null),
                    );
                }
                rows.push(Value::Object(obj));
            }
        }
        Ok(rows)
    }

    /// Query a single scalar value.
    async fn query_scalar<T: for<'de> Deserialize<'de>>(
        &self,
        sql: &str,
        params: &[Value],
    ) -> Result<Option<T>, RqliteError> {
        let rows = self.query(sql, params).await?;
        if rows.is_empty() {
            return Ok(None);
        }
        // Get the first value from the first row
        let first_row = &rows[0];
        if let Some(obj) = first_row.as_object() {
            if let Some((_, val)) = obj.iter().next() {
                if val.is_null() {
                    return Ok(None);
                }
                let result: T = serde_json::from_value(val.clone())
                    .map_err(|e| RqliteError::Http(e.to_string()))?;
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
}

// -- Schema ------------------------------------------------------------------

#[async_trait]
impl SchemaStore for RqliteStore {
    async fn init_schema(&self) -> StoreResult<()> {
        // rqlite doesn't support PRAGMA or multi-statement executescript.
        // Schema must be initialized via individual CREATE TABLE statements.
        let creates = [
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, todo_id TEXT, title TEXT NOT NULL, prompt TEXT NOT NULL, scope_globs TEXT NOT NULL, base_commit TEXT NOT NULL, branch TEXT NOT NULL, timeout_minutes INTEGER NOT NULL DEFAULT 60, priority INTEGER NOT NULL DEFAULT 100, kind TEXT NOT NULL DEFAULT 'agent', status TEXT NOT NULL DEFAULT 'queued', worker_id TEXT, created_at TEXT NOT NULL, claimed_at TEXT, started_at TEXT, completed_at TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0, metadata TEXT NOT NULL DEFAULT '{}')",
            "CREATE TABLE IF NOT EXISTS results (task_id INTEGER PRIMARY KEY, status TEXT NOT NULL, branch TEXT NOT NULL, head_commit TEXT, commits_json TEXT NOT NULL DEFAULT '[]', files_touched TEXT NOT NULL DEFAULT '[]', test_summary TEXT, log_tail TEXT, error TEXT, reported_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS progress (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, seq INTEGER NOT NULL, message TEXT NOT NULL, files_touched TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, author TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS workers (worker_id TEXT PRIMARY KEY, hostname TEXT, capabilities TEXT NOT NULL DEFAULT '{}', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, current_task_id INTEGER)",
            "CREATE TABLE IF NOT EXISTS runners (runner_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, hostname TEXT NOT NULL, os TEXT NOT NULL, arch TEXT NOT NULL, cpu_model TEXT, cpu_count INTEGER, ram_mb INTEGER, gpu TEXT, tools TEXT NOT NULL DEFAULT '[]', tags TEXT NOT NULL DEFAULT '[]', scope_prefixes TEXT NOT NULL DEFAULT '[]', tenant TEXT, workspace_root TEXT, runner_version TEXT NOT NULL, protocol_version INTEGER NOT NULL, max_concurrent INTEGER NOT NULL DEFAULT 1, state TEXT NOT NULL DEFAULT 'online', drain_requested INTEGER NOT NULL DEFAULT 0, cpu_load_pct REAL, ram_free_mb INTEGER, battery_pct INTEGER, on_battery INTEGER NOT NULL DEFAULT 0, last_known_commit TEXT, metadata TEXT NOT NULL DEFAULT '{}', first_seen TEXT NOT NULL, last_heartbeat TEXT NOT NULL, last_nonce TEXT)",
            "CREATE TABLE IF NOT EXISTS task_streams (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, seq INTEGER NOT NULL, channel TEXT NOT NULL, line TEXT NOT NULL, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS dispatchers (dispatcher_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, label TEXT NOT NULL, hostname TEXT, metadata TEXT NOT NULL DEFAULT '{}', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS dispatcher_nonces (dispatcher_id TEXT NOT NULL, nonce TEXT NOT NULL, used_at TEXT NOT NULL, PRIMARY KEY (dispatcher_id, nonce))",
            "CREATE TABLE IF NOT EXISTS runner_nonces (runner_id TEXT NOT NULL, nonce TEXT NOT NULL, used_at TEXT NOT NULL, PRIMARY KEY (runner_id, nonce))",
            "CREATE TABLE IF NOT EXISTS audit_event (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id_hash TEXT NOT NULL UNIQUE, prev_event_id_hash TEXT NOT NULL, kind TEXT NOT NULL, task_id INTEGER, payload_json TEXT NOT NULL, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS host_roles (hostname TEXT NOT NULL, role TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, status TEXT, metadata TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL, PRIMARY KEY (hostname, role))",
            "CREATE TABLE IF NOT EXISTS labels (key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_by TEXT, updated_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, envelope_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', decision_json TEXT NOT NULL DEFAULT '{}', task_label TEXT, branch TEXT, scope_globs_json TEXT NOT NULL DEFAULT '[]', dispatcher_id TEXT, approver TEXT, reason TEXT, created_at TEXT NOT NULL, resolved_at TEXT)",
            "CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, encrypted_value TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, last_rotated_at TEXT)",
        ];

        for sql in &creates {
            self.execute_one(sql, &[]).await?;
        }

        // Schema version rows
        let now = utc_now();
        self.execute_one(
            "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (1, ?)",
            &[json!(now)],
        ).await?;
        self.execute_one(
            "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (2, ?)",
            &[json!(now)],
        ).await?;

        tracing::info!("rqlite schema initialized");
        Ok(())
    }

    async fn schema_version(&self) -> StoreResult<i64> {
        let v: Option<i64> = self
            .query_scalar("SELECT MAX(version) FROM schema_version", &[])
            .await?;
        Ok(v.unwrap_or(0))
    }

    async fn run_additive_migrations(&self) -> StoreResult<()> {
        let additive = [
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

        for (table, column, col_type) in &additive {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {col_type}");
            // ALTER TABLE ADD COLUMN is idempotent-ish — rqlite returns an error
            // if the column exists. Swallow that specific error.
            match self.execute_one(&sql, &[]).await {
                Ok(_) => tracing::info!("added column {table}.{column}"),
                Err(RqliteError::Status { body, .. }) if body.contains("duplicate column") => {
                    debug!("column {table}.{column} already exists");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

// -- Audit -------------------------------------------------------------------

#[async_trait]
impl AuditStore for RqliteStore {
    async fn audit_chain_tail(&self) -> StoreResult<String> {
        let tail: Option<String> = self
            .query_scalar(
                "SELECT event_id_hash FROM audit_event ORDER BY seq DESC LIMIT 1",
                &[],
            )
            .await?;
        Ok(tail.unwrap_or_else(|| AUDIT_GENESIS_HASH.to_owned()))
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
        // CAS: read tail, check match, insert. rqlite serializes writes via
        // Raft, so two concurrent writers will get linearized — the second
        // INSERT will fail on the UNIQUE constraint on event_id_hash if both
        // computed from the same tail, or the tail-check will catch it.
        let actual_tail = self.audit_chain_tail().await?;
        if actual_tail != expected_tail {
            return Ok(AuditAppendResult::TailConflict {
                expected: expected_tail.to_owned(),
                actual: actual_tail,
            });
        }

        let task_id_val = task_id.map(|id| json!(id)).unwrap_or(Value::Null);
        match self.execute_one(
            "INSERT INTO audit_event (event_id_hash, prev_event_id_hash, kind, task_id, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            &[json!(event_id_hash), json!(prev_hash), json!(kind), task_id_val, json!(payload_json), json!(now)],
        ).await {
            Ok(_) => {
                // Get the seq (last insert rowid equivalent)
                let seq: Option<i64> = self.query_scalar(
                    "SELECT seq FROM audit_event WHERE event_id_hash = ?",
                    &[json!(event_id_hash)],
                ).await?;
                Ok(AuditAppendResult::Ok(AuditEventRow {
                    seq: seq.unwrap_or(0),
                    event_id_hash: event_id_hash.to_owned(),
                    prev_event_id_hash: prev_hash.to_owned(),
                    kind: kind.to_owned(),
                    task_id,
                    payload_json: payload_json.to_owned(),
                    created_at: now.to_owned(),
                }))
            }
            Err(RqliteError::Status { body, .. }) if body.contains("UNIQUE constraint") => {
                // Another writer appended with the same hash — tail conflict
                let new_tail = self.audit_chain_tail().await?;
                Ok(AuditAppendResult::TailConflict {
                    expected: expected_tail.to_owned(),
                    actual: new_tail,
                })
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn audit_events_for_task(&self, task_id: i64) -> StoreResult<Vec<AuditEventRow>> {
        let rows = self.query(
            "SELECT seq, event_id_hash, prev_event_id_hash, kind, task_id, payload_json, created_at FROM audit_event WHERE task_id = ? ORDER BY seq",
            &[json!(task_id)],
        ).await?;
        Ok(rows.iter().map(row_to_audit_event).collect())
    }

    async fn audit_events_for_day(&self, day: &str) -> StoreResult<Vec<AuditEventRow>> {
        let pattern = format!("{day}%");
        let rows = self.query(
            "SELECT seq, event_id_hash, prev_event_id_hash, kind, task_id, payload_json, created_at FROM audit_event WHERE created_at LIKE ? ORDER BY seq",
            &[json!(pattern)],
        ).await?;
        Ok(rows.iter().map(row_to_audit_event).collect())
    }

    async fn verify_audit_chain(&self, events: &[AuditEventRow]) -> StoreResult<(bool, Option<String>)> {
        let mut prev: Option<&str> = None;
        for event in events {
            if let Some(expected) = prev {
                if event.prev_event_id_hash != expected {
                    return Ok((false, Some(format!(
                        "chain break at seq={}: prev {} != expected {}",
                        event.seq, event.prev_event_id_hash, expected
                    ))));
                }
            }
            let payload: Value = serde_json::from_str(&event.payload_json)
                .map_err(|e| StoreError::Backend(format!("invalid JSON at seq={}: {e}", event.seq)))?;
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

fn row_to_audit_event(row: &Value) -> AuditEventRow {
    AuditEventRow {
        seq: row["seq"].as_i64().unwrap_or(0),
        event_id_hash: row["event_id_hash"].as_str().unwrap_or("").to_owned(),
        prev_event_id_hash: row["prev_event_id_hash"].as_str().unwrap_or("").to_owned(),
        kind: row["kind"].as_str().unwrap_or("").to_owned(),
        task_id: row["task_id"].as_i64(),
        payload_json: row["payload_json"].as_str().unwrap_or("{}").to_owned(),
        created_at: row["created_at"].as_str().unwrap_or("").to_owned(),
    }
}

// -- Stub implementations (same pattern as fabric-store-sqlite) ---------------

#[async_trait] impl TaskStore for RqliteStore {
    async fn create_task(&self, _p: CreateTaskParams, _now: &str) -> StoreResult<TaskRow> { todo!() }
    async fn get_task(&self, _id: i64) -> StoreResult<TaskRow> { todo!() }
    async fn list_tasks(&self, _s: Option<&str>, _l: i64) -> StoreResult<Vec<TaskRow>> { todo!() }
    async fn claim_task(&self, _id: i64, _w: &str, _now: &str) -> StoreResult<ClaimResult> { todo!() }
    async fn mark_running(&self, _id: i64, _now: &str) -> StoreResult<TaskRow> { todo!() }
    async fn cancel_task(&self, _id: i64, _now: &str) -> StoreResult<TaskRow> { todo!() }
    async fn count_tasks(&self) -> StoreResult<i64> { todo!() }
}
#[async_trait] impl ResultStore for RqliteStore {
    async fn submit_result(&self, _p: SubmitResultParams, _now: &str) -> StoreResult<TaskRow> { todo!() }
}
#[async_trait] impl RunnerStore for RqliteStore {
    async fn upsert_runner(&self, _d: Value) -> StoreResult<RunnerRow> { todo!() }
    async fn get_runner(&self, _id: &str) -> StoreResult<RunnerRow> { todo!() }
    async fn list_runners(&self) -> StoreResult<Vec<RunnerRow>> { todo!() }
    async fn runner_public_key(&self, _id: &str) -> StoreResult<Option<String>> { todo!() }
    async fn heartbeat_runner(&self, _id: &str, _d: Value, _now: &str) -> StoreResult<RunnerRow> { todo!() }
    async fn request_drain(&self, _id: &str) -> StoreResult<RunnerRow> { todo!() }
    async fn request_undrain(&self, _id: &str) -> StoreResult<RunnerRow> { todo!() }
    async fn delete_runner(&self, _id: &str) -> StoreResult<RunnerRow> { todo!() }
}
#[async_trait] impl DispatcherStore for RqliteStore {
    async fn upsert_dispatcher(&self, _d: Value) -> StoreResult<DispatcherRow> { todo!() }
    async fn get_dispatcher(&self, _id: &str) -> StoreResult<DispatcherRow> { todo!() }
    async fn list_dispatchers(&self) -> StoreResult<Vec<DispatcherRow>> { todo!() }
    async fn dispatcher_public_key(&self, _id: &str) -> StoreResult<Option<String>> { todo!() }
    async fn delete_dispatcher(&self, _id: &str) -> StoreResult<DispatcherRow> { todo!() }
}
#[async_trait] impl NonceStore for RqliteStore {
    async fn consume_dispatcher_nonce(&self, _id: &str, _n: &str, _now: &str) -> StoreResult<()> { todo!() }
    async fn consume_runner_nonce(&self, _id: &str, _n: &str, _now: &str) -> StoreResult<()> { todo!() }
}
#[async_trait] impl StreamStore for RqliteStore {
    async fn append_stream(&self, _tid: i64, _wid: &str, _ch: &str, _l: &str, _now: &str) -> StoreResult<StreamLine> { todo!() }
    async fn append_stream_bulk(&self, _tid: i64, _wid: &str, _e: &[(String, String)], _now: &str) -> StoreResult<Vec<StreamLine>> { todo!() }
    async fn streams_since(&self, _tid: i64, _a: i64, _l: i64) -> StoreResult<Vec<StreamLine>> { todo!() }
}
#[async_trait] impl ProgressStore for RqliteStore {
    async fn append_progress(&self, _tid: i64, _wid: &str, _m: &str, _f: Option<Vec<String>>, _now: &str) -> StoreResult<ProgressEntry> { todo!() }
    async fn progress_since(&self, _tid: i64, _a: i64) -> StoreResult<Vec<ProgressEntry>> { todo!() }
}
#[async_trait] impl ApprovalStore for RqliteStore {
    async fn create_or_get_pending_approval(&self, _eh: &str, _d: Value, _tl: &str, _b: Option<&str>, _sg: Vec<String>, _di: Option<&str>, _now: &str) -> StoreResult<(String, bool)> { todo!() }
    async fn consume_approval(&self, _id: &str, _eh: &str) -> StoreResult<bool> { todo!() }
    async fn resolve_approval(&self, _id: &str, _s: &str, _a: Option<&str>, _r: Option<&str>, _now: &str) -> StoreResult<ApprovalRow> { todo!() }
    async fn list_approvals(&self, _s: Option<&str>, _l: i64) -> StoreResult<Vec<ApprovalRow>> { todo!() }
    async fn get_approval(&self, _id: &str) -> StoreResult<Option<ApprovalRow>> { todo!() }
}
#[async_trait] impl SecretStore for RqliteStore {
    async fn put_secret(&self, _n: &str, _v: &str, _now: &str) -> StoreResult<SecretMetadata> { todo!() }
    async fn rotate_secret(&self, _n: &str, _v: &str, _now: &str) -> StoreResult<SecretMetadata> { todo!() }
    async fn list_secrets(&self) -> StoreResult<Vec<SecretMetadata>> { todo!() }
    async fn resolve_secrets(&self, _n: &[String]) -> StoreResult<std::collections::HashMap<String, String>> { todo!() }
    async fn delete_secret(&self, _n: &str) -> StoreResult<bool> { todo!() }
}
#[async_trait] impl LabelStore for RqliteStore {
    async fn get_labels(&self) -> StoreResult<Value> { todo!() }
    async fn set_hub_name(&self, _n: &str, _b: Option<&str>, _now: &str) -> StoreResult<()> { todo!() }
    async fn set_runner_alias(&self, _id: &str, _a: &str, _b: Option<&str>, _now: &str) -> StoreResult<()> { todo!() }
    async fn set_host_alias(&self, _h: &str, _a: &str, _b: Option<&str>, _now: &str) -> StoreResult<()> { todo!() }
}
#[async_trait] impl HostRoleStore for RqliteStore {
    async fn set_host_role(&self, _h: &str, _r: &str, _e: bool, _s: Option<&str>, _m: Value, _now: &str) -> StoreResult<HostRoleRow> { todo!() }
    async fn get_host_role(&self, _h: &str, _r: &str) -> StoreResult<Option<HostRoleRow>> { todo!() }
    async fn list_host_roles(&self) -> StoreResult<Vec<HostRoleRow>> { todo!() }
}

impl FabricStore for RqliteStore {}

fn utc_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = d.as_secs();
    let secs = total_secs % 60;
    let mins = (total_secs / 60) % 60;
    let hours = (total_secs / 3600) % 24;
    let mut days = (total_secs / 86400) as i64;
    let mut year = 1970i64;
    loop {
        let diy = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < diy { break; }
        days -= diy;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let md = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0usize;
    for (i, &m) in md.iter().enumerate() {
        if days < m as i64 { month = i; break; }
        days -= m as i64;
    }
    format!("{year:04}-{:02}-{:02} {hours:02}:{mins:02}:{secs:02}", month + 1, days + 1)
}
