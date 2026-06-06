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

mod dates;

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

    /// Execute multiple write statements atomically in a single rqlite
    /// transaction. Either all statements commit or none do — used where an
    /// insert and its derived accumulator updates must not drift (M2.5.3).
    async fn execute_tx(&self, statements: &[(&str, &[Value])]) -> Result<Value, RqliteError> {
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

        let url = format!("{}/db/execute?timings&transaction", self.base_url);
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
        let parsed: Value =
            serde_json::from_str(&text).map_err(|e| RqliteError::Http(e.to_string()))?;
        // rqlite reports per-statement errors inside the results array even on
        // HTTP 200; surface the first one so a failed transaction is not
        // silently treated as success.
        if let Some(results) = parsed["results"].as_array() {
            for r in results {
                if let Some(err) = r["error"].as_str() {
                    return Err(RqliteError::Status {
                        status: 200,
                        body: err.to_owned(),
                    });
                }
            }
        }
        Ok(parsed)
    }

    /// Execute a single write and return rows_affected.
    ///
    /// rqlite reports per-statement SQL errors inside `results[0].error` even on
    /// HTTP 200. Surface those instead of silently treating them as 0 rows —
    /// swallowing them once masked a missing-column bug that broke signed
    /// dispatch.
    async fn execute_one(&self, sql: &str, params: &[Value]) -> Result<i64, RqliteError> {
        let resp = self.execute(&[(sql, params)]).await?;
        if let Some(err) = resp["results"][0]["error"].as_str() {
            return Err(RqliteError::Status { status: 200, body: err.to_owned() });
        }
        let rows = resp["results"][0]["rows_affected"]
            .as_i64()
            .unwrap_or(0);
        Ok(rows)
    }

    /// Execute a single INSERT and return last_insert_id from the rqlite response.
    ///
    /// rqlite returns `last_insert_id` in the execute result directly — do NOT
    /// use `SELECT last_insert_rowid()` as a follow-up query; it always returns 0
    /// over HTTP because it rqlite uses a new
    /// connection per request.
    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64, RqliteError> {
        let resp = self.execute(&[(sql, params)]).await?;
        let id = resp["results"][0]["last_insert_id"]
            .as_i64()
            .ok_or_else(|| RqliteError::Http("INSERT returned no last_insert_id".into()))?;
        Ok(id)
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
            "CREATE TABLE IF NOT EXISTS dispatchers (dispatcher_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, label TEXT NOT NULL, hostname TEXT, metadata TEXT NOT NULL DEFAULT '{}', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_nonce TEXT)",
            "CREATE TABLE IF NOT EXISTS dispatcher_nonces (dispatcher_id TEXT NOT NULL, nonce TEXT NOT NULL, used_at TEXT NOT NULL, PRIMARY KEY (dispatcher_id, nonce))",
            "CREATE TABLE IF NOT EXISTS runner_nonces (runner_id TEXT NOT NULL, nonce TEXT NOT NULL, used_at TEXT NOT NULL, PRIMARY KEY (runner_id, nonce))",
            "CREATE TABLE IF NOT EXISTS audit_event (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id_hash TEXT NOT NULL UNIQUE, prev_event_id_hash TEXT NOT NULL, kind TEXT NOT NULL, task_id INTEGER, payload_json TEXT NOT NULL, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS host_roles (hostname TEXT NOT NULL, role TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, status TEXT, metadata TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL, PRIMARY KEY (hostname, role))",
            "CREATE TABLE IF NOT EXISTS labels (key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_by TEXT, updated_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, envelope_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', decision_json TEXT NOT NULL DEFAULT '{}', task_label TEXT, branch TEXT, scope_globs_json TEXT NOT NULL DEFAULT '[]', dispatcher_id TEXT, approver TEXT, reason TEXT, created_at TEXT NOT NULL, resolved_at TEXT)",
            "CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, encrypted_value TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, last_rotated_at TEXT)",
            // Cost ledger (M2.5.2). Columns mirror the Python hub schema.sql so the
            // Rust and Python hub paths read/write the same rqlite table. Previously
            // this table was only created by the Python hub, so a fresh Rust-only
            // install failed on the first record_cost — this closes that gap.
            "CREATE TABLE IF NOT EXISTS cost_ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL, dispatcher_id TEXT, runner_id TEXT, model_id TEXT NOT NULL DEFAULT '', prompt_tokens INTEGER NOT NULL DEFAULT 0, completion_tokens INTEGER NOT NULL DEFAULT 0, cost_usd REAL NOT NULL DEFAULT 0.0, wall_seconds REAL NOT NULL DEFAULT 0.0, runner_cpu_seconds REAL NOT NULL DEFAULT 0.0, created_at TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_cost_task ON cost_ledger (task_id)",
            "CREATE INDEX IF NOT EXISTS idx_cost_created ON cost_ledger (created_at)",
            "CREATE INDEX IF NOT EXISTS idx_cost_model ON cost_ledger (model_id, created_at)",
            // Budget accumulators (M2.5.3). One row per (scope, period_key); spend_usd
            // is intended to be updated atomically alongside each cost_ledger insert so
            // daily/weekly/per-dispatcher/per-model totals survive a hub restart without
            // a full cost_ledger re-aggregation. Tier-1 control-plane state (rqlite only).
            // NOTE: this creates the table only; the BudgetStore read/write accumulator
            // logic and Python BudgetEnforcer hydration are a follow-up M2.5.3 brief.
            "CREATE TABLE IF NOT EXISTS budget_state (scope TEXT NOT NULL, period_key TEXT NOT NULL, spend_usd REAL NOT NULL DEFAULT 0.0, updated_at TEXT NOT NULL, PRIMARY KEY (scope, period_key))",
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
        // v3: cost_ledger (+ indexes) and budget_state created in the Rust path.
        self.execute_one(
            "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (3, ?)",
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
            ("runners", "claim_failures_total", "INTEGER NOT NULL DEFAULT 0"),
            ("runners", "claim_failures_consecutive", "INTEGER NOT NULL DEFAULT 0"),
            ("runners", "last_claim_error", "TEXT"),
            ("runners", "last_claim_error_at", "TEXT"),
            ("runners", "heartbeat_failures_total", "INTEGER NOT NULL DEFAULT 0"),
            // dispatchers.last_nonce: consume_dispatcher_nonce updates it; absent
            // on older Rust-created schemas, which broke all signed dispatch.
            ("dispatchers", "last_nonce", "TEXT"),
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

// -- Row conversion helpers --------------------------------------------------

fn str_val(row: &Value, col: &str) -> String {
    row[col].as_str().unwrap_or("").to_owned()
}
fn opt_str(row: &Value, col: &str) -> Option<String> {
    row[col].as_str().map(|s| s.to_owned())
}
fn bool_val(row: &Value, col: &str) -> bool {
    row[col].as_i64().map(|v| v != 0).unwrap_or(false)
}
fn json_val(row: &Value, col: &str) -> Value {
    if let Some(s) = row[col].as_str() {
        serde_json::from_str(s).unwrap_or(Value::Null)
    } else {
        row[col].clone()
    }
}
fn json_arr(row: &Value, col: &str) -> Value {
    if let Some(s) = row[col].as_str() {
        serde_json::from_str(s).unwrap_or(json!([]))
    } else {
        json!([])
    }
}
fn json_obj(row: &Value, col: &str) -> Value {
    if let Some(s) = row[col].as_str() {
        serde_json::from_str(s).unwrap_or(json!({}))
    } else {
        json!({})
    }
}

fn row_to_task(row: &Value) -> TaskRow {
    TaskRow {
        id: row["id"].as_i64().unwrap_or(0),
        title: str_val(row, "title"),
        prompt: str_val(row, "prompt"),
        scope_globs: json_arr(row, "scope_globs"),
        base_commit: str_val(row, "base_commit"),
        branch: str_val(row, "branch"),
        status: str_val(row, "status"),
        kind: str_val(row, "kind"),
        worker_id: opt_str(row, "worker_id"),
        created_at: str_val(row, "created_at"),
        claimed_at: opt_str(row, "claimed_at"),
        started_at: opt_str(row, "started_at"),
        completed_at: opt_str(row, "completed_at"),
        cancel_requested: bool_val(row, "cancel_requested"),
        metadata: json_obj(row, "metadata"),
        todo_id: opt_str(row, "todo_id"),
        timeout_minutes: row["timeout_minutes"].as_i64().unwrap_or(60),
        priority: row["priority"].as_i64().unwrap_or(100),
        required_tools: if row["required_tools"].is_null() { None } else { Some(json_arr(row, "required_tools")) },
        required_tags: if row["required_tags"].is_null() { None } else { Some(json_arr(row, "required_tags")) },
        tenant: opt_str(row, "tenant"),
        workspace_root: opt_str(row, "workspace_root"),
        require_base_commit: bool_val(row, "require_base_commit"),
        required_capabilities: if row["required_capabilities"].is_null() { None } else { Some(json_arr(row, "required_capabilities")) },
        secrets_needed: if row["secrets_needed"].is_null() { None } else { Some(json_arr(row, "secrets_needed")) },
        network_egress: if row["network_egress"].is_null() { None } else { Some(json_val(row, "network_egress")) },
        dispatcher_id: opt_str(row, "dispatcher_id"),
    }
}

fn row_to_runner(row: &Value) -> RunnerRow {
    RunnerRow {
        runner_id: str_val(row, "runner_id"),
        public_key: str_val(row, "public_key"),
        hostname: str_val(row, "hostname"),
        os: str_val(row, "os"),
        arch: str_val(row, "arch"),
        state: str_val(row, "state"),
        runner_version: str_val(row, "runner_version"),
        protocol_version: row["protocol_version"].as_i64().unwrap_or(2),
        max_concurrent: row["max_concurrent"].as_i64().unwrap_or(1),
        tools: json_arr(row, "tools"),
        tags: json_arr(row, "tags"),
        scope_prefixes: json_arr(row, "scope_prefixes"),
        tenant: opt_str(row, "tenant"),
        workspace_root: opt_str(row, "workspace_root"),
        capabilities: json_obj(row, "capabilities"),
        metadata: json_obj(row, "metadata"),
        drain_requested: bool_val(row, "drain_requested"),
        last_heartbeat: str_val(row, "last_heartbeat"),
        first_seen: str_val(row, "first_seen"),
        last_nonce: opt_str(row, "last_nonce"),
    }
}

fn row_to_dispatcher(row: &Value) -> DispatcherRow {
    DispatcherRow {
        dispatcher_id: str_val(row, "dispatcher_id"),
        public_key: str_val(row, "public_key"),
        label: str_val(row, "label"),
        hostname: opt_str(row, "hostname"),
        metadata: json_obj(row, "metadata"),
        first_seen: str_val(row, "first_seen"),
        last_seen: str_val(row, "last_seen"),
    }
}

fn row_to_stream_line(row: &Value) -> StreamLine {
    StreamLine {
        id: row["id"].as_i64().unwrap_or(0),
        task_id: row["task_id"].as_i64().unwrap_or(0),
        seq: row["seq"].as_i64().unwrap_or(0),
        channel: str_val(row, "channel"),
        line: str_val(row, "line"),
        created_at: str_val(row, "created_at"),
    }
}

fn row_to_progress(row: &Value) -> ProgressEntry {
    ProgressEntry {
        id: row["id"].as_i64().unwrap_or(0),
        task_id: row["task_id"].as_i64().unwrap_or(0),
        seq: row["seq"].as_i64().unwrap_or(0),
        message: str_val(row, "message"),
        files_touched: json_arr(row, "files_touched"),
        created_at: str_val(row, "created_at"),
    }
}

fn row_to_approval(row: &Value) -> ApprovalRow {
    ApprovalRow {
        approval_id: str_val(row, "approval_id"),
        envelope_hash: str_val(row, "envelope_hash"),
        status: str_val(row, "status"),
        decision_json: json_obj(row, "decision_json"),
        task_label: opt_str(row, "task_label"),
        branch: opt_str(row, "branch"),
        scope_globs_json: json_arr(row, "scope_globs_json"),
        dispatcher_id: opt_str(row, "dispatcher_id"),
        approver: opt_str(row, "approver"),
        reason: opt_str(row, "reason"),
        created_at: str_val(row, "created_at"),
        resolved_at: opt_str(row, "resolved_at"),
    }
}

fn row_to_secret_metadata(row: &Value) -> SecretMetadata {
    SecretMetadata {
        name: str_val(row, "name"),
        version: row["version"].as_i64().unwrap_or(1),
        created_at: str_val(row, "created_at"),
        last_rotated_at: opt_str(row, "last_rotated_at"),
    }
}

fn row_to_host_role(row: &Value) -> HostRoleRow {
    HostRoleRow {
        hostname: str_val(row, "hostname"),
        role: str_val(row, "role"),
        enabled: bool_val(row, "enabled"),
        status: opt_str(row, "status"),
        metadata: json_obj(row, "metadata"),
        updated_at: str_val(row, "updated_at"),
    }
}

/// Generate a random 32-hex-char ID.
fn generate_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    let a = h.finish();
    let mut h2 = DefaultHasher::new();
    a.hash(&mut h2);
    99u64.hash(&mut h2);
    let b = h2.finish();
    format!("{a:016x}{b:016x}")
}

// -- Tasks -------------------------------------------------------------------

#[async_trait]
impl TaskStore for RqliteStore {
    async fn create_task(&self, p: CreateTaskParams, now: &str) -> StoreResult<TaskRow> {
        let scope_json = serde_json::to_string(&p.scope_globs).unwrap_or_else(|_| "[]".into());
        let meta_json = serde_json::to_string(&p.metadata).unwrap_or_else(|_| "{}".into());
        let tools_json = p.required_tools.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let tags_json = p.required_tags.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let caps_json = p.required_capabilities.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let secrets_json = p.secrets_needed.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let egress_json = p.network_egress.as_ref().map(|v| serde_json::to_string(v).unwrap_or_else(|_| "null".into()));
        let require_bc: i64 = if p.require_base_commit { 1 } else { 0 };

        let id = self.execute_insert(
            "INSERT INTO tasks (todo_id,title,prompt,scope_globs,base_commit,branch,timeout_minutes,priority,metadata,required_tools,required_tags,tenant,workspace_root,require_base_commit,dispatcher_id,required_capabilities,secrets_needed,network_egress,kind,created_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'queued')",
            &[json!(p.todo_id), json!(p.title), json!(p.prompt), json!(scope_json), json!(p.base_commit), json!(p.branch), json!(p.timeout_minutes), json!(p.priority), json!(meta_json), json!(tools_json), json!(tags_json), json!(p.tenant), json!(p.workspace_root), json!(require_bc), json!(p.dispatcher_id), json!(caps_json), json!(secrets_json), json!(egress_json), json!(p.kind), json!(now)],
        ).await.map_err(|e| StoreError::Backend(e.to_string()))?;
        self.get_task(id).await
    }

    async fn get_task(&self, id: i64) -> StoreResult<TaskRow> {
        let rows = self.query("SELECT * FROM tasks WHERE id = ?", &[json!(id)]).await?;
        rows.into_iter().next()
            .map(|r| row_to_task(&r))
            .ok_or_else(|| StoreError::NotFound(format!("task {id}")))
    }

    async fn list_tasks(&self, status: Option<&str>, limit: i64) -> StoreResult<Vec<TaskRow>> {
        let rows = if let Some(s) = status {
            self.query("SELECT * FROM tasks WHERE status = ? ORDER BY priority DESC, id ASC LIMIT ?", &[json!(s), json!(limit)]).await?
        } else {
            self.query("SELECT * FROM tasks ORDER BY priority DESC, id ASC LIMIT ?", &[json!(limit)]).await?
        };
        Ok(rows.iter().map(row_to_task).collect())
    }

    async fn claim_task(&self, task_id: i64, worker_id: &str, now: &str) -> StoreResult<ClaimResult> {
        let rows_changed = self.execute_one(
            "UPDATE tasks SET status='claimed', worker_id=?, claimed_at=? WHERE id=? AND status='queued' AND cancel_requested=0",
            &[json!(worker_id), json!(now), json!(task_id)],
        ).await?;
        if rows_changed == 0 {
            return Ok(ClaimResult::AlreadyClaimed);
        }
        Ok(ClaimResult::Claimed(self.get_task(task_id).await?))
    }

    async fn mark_running(&self, task_id: i64, now: &str) -> StoreResult<TaskRow> {
        self.execute_one(
            "UPDATE tasks SET status='running', started_at=COALESCE(started_at,?) WHERE id=? AND status IN ('claimed','running')",
            &[json!(now), json!(task_id)],
        ).await?;
        self.get_task(task_id).await
    }

    async fn cancel_task(&self, task_id: i64, now: &str) -> StoreResult<TaskRow> {
        self.execute_one("UPDATE tasks SET cancel_requested=1 WHERE id=?", &[json!(task_id)]).await?;
        self.execute_one(
            "UPDATE tasks SET status='cancelled', completed_at=? WHERE id=? AND status='queued'",
            &[json!(now), json!(task_id)],
        ).await?;
        self.get_task(task_id).await
    }

    async fn count_tasks(&self) -> StoreResult<i64> {
        let n: Option<i64> = self.query_scalar("SELECT COUNT(*) FROM tasks", &[]).await?;
        Ok(n.unwrap_or(0))
    }
}

// -- Results -----------------------------------------------------------------

#[async_trait]
impl ResultStore for RqliteStore {
    async fn submit_result(&self, p: SubmitResultParams, now: &str) -> StoreResult<TaskRow> {
        let commits_json = serde_json::to_string(&p.commits).unwrap_or_else(|_| "[]".into());
        let files_json = serde_json::to_string(&p.files_touched).unwrap_or_else(|_| "[]".into());

        let rows_changed = self.execute_one(
            "UPDATE tasks SET status=?, completed_at=? WHERE id=? AND worker_id=?",
            &[json!(p.status), json!(now), json!(p.task_id), json!(p.worker_id)],
        ).await?;

        if rows_changed == 0 {
            let rows = self.query("SELECT worker_id FROM tasks WHERE id=?", &[json!(p.task_id)]).await?;
            return match rows.first() {
                None => Err(StoreError::NotFound(format!("task {}", p.task_id))),
                Some(r) => Err(StoreError::PermissionDenied(format!(
                    "worker {} cannot report result for task owned by {}", p.worker_id, str_val(r, "worker_id")
                ))),
            };
        }

        self.execute_one(
            "INSERT OR REPLACE INTO results (task_id,status,branch,head_commit,commits_json,files_touched,test_summary,log_tail,error,reported_at) SELECT ?,?,branch,?,?,?,?,?,?,? FROM tasks WHERE id=?",
            &[json!(p.task_id), json!(p.status), json!(p.head_commit), json!(commits_json), json!(files_json), json!(p.test_summary), json!(p.log_tail), json!(p.error), json!(now), json!(p.task_id)],
        ).await?;

        self.get_task(p.task_id).await
    }
}

// -- Runners -----------------------------------------------------------------

#[async_trait]
impl RunnerStore for RqliteStore {
    async fn upsert_runner(&self, data: Value) -> StoreResult<RunnerRow> {
        let runner_id = data["runner_id"].as_str().ok_or_else(|| StoreError::Backend("missing runner_id".into()))?.to_owned();
        let public_key = data["public_key"].as_str().unwrap_or("").to_owned();
        let now = utc_now();

        // Prune ghost runners from same hostname
        if let Some(hostname) = data["hostname"].as_str() {
            if !hostname.is_empty() {
                let cutoff = utc_offset(-120);
                self.execute_one(
                    "DELETE FROM runners WHERE hostname=? AND runner_id!=? AND last_heartbeat<?",
                    &[json!(hostname), json!(runner_id), json!(cutoff)],
                ).await?;
            }
        }

        // Check existing key binding
        let existing_key_rows = self.query("SELECT public_key FROM runners WHERE runner_id=?", &[json!(runner_id)]).await?;
        if let Some(r) = existing_key_rows.first() {
            if str_val(r, "public_key") != public_key {
                return Err(StoreError::PermissionDenied("runner_id is already bound to a different public_key".into()));
            }
            let tools = serde_json::to_string(&data["tools"]).unwrap_or_else(|_| "[]".into());
            let tags = serde_json::to_string(&data["tags"]).unwrap_or_else(|_| "[]".into());
            let scope_prefixes = serde_json::to_string(&data["scope_prefixes"]).unwrap_or_else(|_| "[]".into());
            let metadata = serde_json::to_string(data.get("metadata").unwrap_or(&json!({}))).unwrap_or_else(|_| "{}".into());
            let capabilities = serde_json::to_string(data.get("capabilities").unwrap_or(&json!({}))).unwrap_or_else(|_| "{}".into());
            self.execute_one(
                "UPDATE runners SET hostname=?,os=?,arch=?,cpu_model=?,cpu_count=?,ram_mb=?,gpu=?,tools=?,tags=?,scope_prefixes=?,tenant=?,workspace_root=?,runner_version=?,protocol_version=?,max_concurrent=?,state='online',drain_requested=0,metadata=?,capabilities=?,last_heartbeat=?,claim_failures_consecutive=0,last_claim_error=NULL WHERE runner_id=?",
                &[json!(data["hostname"]), json!(data["os"]), json!(data["arch"]), json!(data["cpu_model"]), json!(data["cpu_count"]), json!(data["ram_mb"]), json!(data["gpu"]), json!(tools), json!(tags), json!(scope_prefixes), json!(data["tenant"]), json!(data["workspace_root"]), json!(data["runner_version"]), json!(data["protocol_version"]), json!(data["max_concurrent"]), json!(metadata), json!(capabilities), json!(now), json!(runner_id)],
            ).await?;
        } else {
            let tools = serde_json::to_string(&data["tools"]).unwrap_or_else(|_| "[]".into());
            let tags = serde_json::to_string(&data["tags"]).unwrap_or_else(|_| "[]".into());
            let scope_prefixes = serde_json::to_string(&data["scope_prefixes"]).unwrap_or_else(|_| "[]".into());
            let metadata = serde_json::to_string(data.get("metadata").unwrap_or(&json!({}))).unwrap_or_else(|_| "{}".into());
            let capabilities = serde_json::to_string(data.get("capabilities").unwrap_or(&json!({}))).unwrap_or_else(|_| "{}".into());
            self.execute_one(
                "INSERT INTO runners (runner_id,public_key,hostname,os,arch,cpu_model,cpu_count,ram_mb,gpu,tools,tags,scope_prefixes,tenant,workspace_root,runner_version,protocol_version,max_concurrent,state,drain_requested,metadata,first_seen,last_heartbeat,capabilities) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'online',0,?,?,?,?)",
                &[json!(runner_id), json!(public_key), json!(data["hostname"]), json!(data["os"]), json!(data["arch"]), json!(data["cpu_model"]), json!(data["cpu_count"]), json!(data["ram_mb"]), json!(data["gpu"]), json!(tools), json!(tags), json!(scope_prefixes), json!(data["tenant"]), json!(data["workspace_root"]), json!(data["runner_version"]), json!(data["protocol_version"]), json!(data["max_concurrent"]), json!(metadata), json!(now), json!(now), json!(capabilities)],
            ).await?;
        }

        self.get_runner(&runner_id).await
    }

    async fn get_runner(&self, runner_id: &str) -> StoreResult<RunnerRow> {
        let rows = self.query("SELECT * FROM runners WHERE runner_id=?", &[json!(runner_id)]).await?;
        rows.into_iter().next()
            .map(|r| row_to_runner(&r))
            .ok_or_else(|| StoreError::NotFound(format!("runner {runner_id}")))
    }

    async fn list_runners(&self) -> StoreResult<Vec<RunnerRow>> {
        let rows = self.query("SELECT * FROM runners ORDER BY hostname, runner_id", &[]).await?;
        Ok(rows.iter().map(row_to_runner).collect())
    }

    async fn runner_public_key(&self, runner_id: &str) -> StoreResult<Option<String>> {
        let key: Option<String> = self.query_scalar("SELECT public_key FROM runners WHERE runner_id=?", &[json!(runner_id)]).await?;
        Ok(key)
    }

    async fn heartbeat_runner(&self, runner_id: &str, data: Value, now: &str) -> StoreResult<RunnerRow> {
        let nonce = data["nonce"].as_str().unwrap_or("").to_owned();
        let rows_changed = self.execute_one(
            "UPDATE runners SET last_heartbeat=?,cpu_load_pct=?,ram_free_mb=?,battery_pct=?,on_battery=?,last_known_commit=COALESCE(?,last_known_commit),last_nonce=?,claim_failures_total=COALESCE(?,claim_failures_total),claim_failures_consecutive=COALESCE(?,claim_failures_consecutive),last_claim_error=?,heartbeat_failures_total=COALESCE(?,heartbeat_failures_total),state=CASE WHEN drain_requested=1 THEN 'draining' ELSE 'online' END WHERE runner_id=? AND (last_nonce IS NULL OR last_nonce!=?)",
            &[json!(now), json!(data["cpu_load_pct"]), json!(data["ram_free_mb"]), json!(data["battery_pct"]), json!(data["on_battery"].as_bool().map(|b| if b { 1 } else { 0 })), json!(data["last_known_commit"]), json!(nonce), json!(data["claim_failures_total"]), json!(data["claim_failures_consecutive"]), json!(data["last_claim_error"]), json!(data["heartbeat_failures_total"]), json!(runner_id), json!(nonce)],
        ).await?;
        if rows_changed == 0 {
            let exists = self.query("SELECT 1 FROM runners WHERE runner_id=?", &[json!(runner_id)]).await?;
            return if exists.is_empty() {
                Err(StoreError::NotFound(format!("runner {runner_id}")))
            } else {
                Err(StoreError::PermissionDenied("nonce replay rejected".into()))
            };
        }
        self.get_runner(runner_id).await
    }

    async fn request_drain(&self, runner_id: &str) -> StoreResult<RunnerRow> {
        let n = self.execute_one("UPDATE runners SET drain_requested=1,state='draining' WHERE runner_id=?", &[json!(runner_id)]).await?;
        if n == 0 { return Err(StoreError::NotFound(format!("runner {runner_id}"))); }
        self.get_runner(runner_id).await
    }

    async fn request_undrain(&self, runner_id: &str) -> StoreResult<RunnerRow> {
        let n = self.execute_one("UPDATE runners SET drain_requested=0,state=CASE WHEN state='draining' THEN 'online' ELSE state END WHERE runner_id=?", &[json!(runner_id)]).await?;
        if n == 0 { return Err(StoreError::NotFound(format!("runner {runner_id}"))); }
        self.get_runner(runner_id).await
    }

    async fn delete_runner(&self, runner_id: &str) -> StoreResult<RunnerRow> {
        let row = self.get_runner(runner_id).await?;
        self.execute_one("DELETE FROM runners WHERE runner_id=?", &[json!(runner_id)]).await?;
        Ok(row)
    }
}

// -- Dispatchers -------------------------------------------------------------

#[async_trait]
impl DispatcherStore for RqliteStore {
    async fn upsert_dispatcher(&self, data: Value) -> StoreResult<DispatcherRow> {
        let dispatcher_id = data["dispatcher_id"].as_str().ok_or_else(|| StoreError::Backend("missing dispatcher_id".into()))?.to_owned();
        let public_key = data["public_key"].as_str().unwrap_or("").to_owned();
        let now = utc_now();
        let metadata = serde_json::to_string(data.get("metadata").unwrap_or(&json!({}))).unwrap_or_else(|_| "{}".into());

        let existing = self.query("SELECT public_key FROM dispatchers WHERE dispatcher_id=?", &[json!(dispatcher_id)]).await?;
        if let Some(r) = existing.first() {
            if str_val(r, "public_key") != public_key {
                return Err(StoreError::PermissionDenied("dispatcher_id is already bound to a different public_key".into()));
            }
            self.execute_one(
                "UPDATE dispatchers SET label=?,hostname=?,metadata=?,last_seen=? WHERE dispatcher_id=?",
                &[json!(data["label"]), json!(data["hostname"]), json!(metadata), json!(now), json!(dispatcher_id)],
            ).await?;
        } else {
            self.execute_one(
                "INSERT INTO dispatchers (dispatcher_id,public_key,label,hostname,metadata,first_seen,last_seen) VALUES (?,?,?,?,?,?,?)",
                &[json!(dispatcher_id), json!(public_key), json!(data["label"]), json!(data["hostname"]), json!(metadata), json!(now), json!(now)],
            ).await?;
        }
        self.get_dispatcher(&dispatcher_id).await
    }

    async fn get_dispatcher(&self, dispatcher_id: &str) -> StoreResult<DispatcherRow> {
        let rows = self.query("SELECT * FROM dispatchers WHERE dispatcher_id=?", &[json!(dispatcher_id)]).await?;
        rows.into_iter().next()
            .map(|r| row_to_dispatcher(&r))
            .ok_or_else(|| StoreError::NotFound(format!("dispatcher {dispatcher_id}")))
    }

    async fn list_dispatchers(&self) -> StoreResult<Vec<DispatcherRow>> {
        let rows = self.query("SELECT * FROM dispatchers ORDER BY label, dispatcher_id", &[]).await?;
        Ok(rows.iter().map(row_to_dispatcher).collect())
    }

    async fn dispatcher_public_key(&self, dispatcher_id: &str) -> StoreResult<Option<String>> {
        let key: Option<String> = self.query_scalar("SELECT public_key FROM dispatchers WHERE dispatcher_id=?", &[json!(dispatcher_id)]).await?;
        Ok(key)
    }

    async fn delete_dispatcher(&self, dispatcher_id: &str) -> StoreResult<DispatcherRow> {
        let row = self.get_dispatcher(dispatcher_id).await?;
        let hostname = row.hostname.clone();
        self.execute_one("DELETE FROM dispatchers WHERE dispatcher_id=?", &[json!(dispatcher_id)]).await?;
        if let Some(h) = hostname {
            let n: Option<i64> = self.query_scalar("SELECT COUNT(*) FROM dispatchers WHERE hostname=?", &[json!(h)]).await?;
            if n.unwrap_or(0) == 0 {
                self.execute_one("DELETE FROM host_roles WHERE hostname=? AND role='dispatch'", &[json!(h)]).await?;
            }
        }
        Ok(row)
    }
}

// -- Nonces ------------------------------------------------------------------

#[async_trait]
impl NonceStore for RqliteStore {
    async fn consume_dispatcher_nonce(&self, dispatcher_id: &str, nonce: &str, now: &str) -> StoreResult<()> {
        let n = self.execute_one(
            "UPDATE dispatchers SET last_nonce=?,last_seen=? WHERE dispatcher_id=? AND (last_nonce IS NULL OR last_nonce!=?)",
            &[json!(nonce), json!(now), json!(dispatcher_id), json!(nonce)],
        ).await?;
        if n == 0 {
            let exists = self.query("SELECT 1 FROM dispatchers WHERE dispatcher_id=?", &[json!(dispatcher_id)]).await?;
            return if exists.is_empty() {
                Err(StoreError::NotFound(format!("dispatcher {dispatcher_id}")))
            } else {
                Err(StoreError::PermissionDenied("nonce replay rejected".into()))
            };
        }
        Ok(())
    }

    async fn consume_runner_nonce(&self, runner_id: &str, nonce: &str, now: &str) -> StoreResult<()> {
        let n = self.execute_one(
            "UPDATE runners SET last_nonce=?,last_heartbeat=? WHERE runner_id=? AND (last_nonce IS NULL OR last_nonce!=?)",
            &[json!(nonce), json!(now), json!(runner_id), json!(nonce)],
        ).await?;
        if n == 0 {
            let exists = self.query("SELECT 1 FROM runners WHERE runner_id=?", &[json!(runner_id)]).await?;
            return if exists.is_empty() {
                Err(StoreError::NotFound(format!("runner {runner_id}")))
            } else {
                Err(StoreError::PermissionDenied("nonce replay rejected".into()))
            };
        }
        Ok(())
    }
}

// -- Streams -----------------------------------------------------------------

#[async_trait]
impl StreamStore for RqliteStore {
    async fn append_stream(&self, task_id: i64, worker_id: &str, channel: &str, line: &str, now: &str) -> StoreResult<StreamLine> {
        let owner_rows = self.query("SELECT worker_id FROM tasks WHERE id=?", &[json!(task_id)]).await?;
        let owner = owner_rows.first().ok_or_else(|| StoreError::NotFound(format!("task {task_id}")))?;
        if opt_str(owner, "worker_id").as_deref() != Some(worker_id) {
            return Err(StoreError::PermissionDenied("worker mismatch on stream append".into()));
        }
        let max_seq: Option<i64> = self.query_scalar("SELECT COALESCE(MAX(seq),0) FROM task_streams WHERE task_id=?", &[json!(task_id)]).await?;
        let next_seq = max_seq.unwrap_or(0) + 1;
        let id = self.execute_insert(
            "INSERT INTO task_streams (task_id,seq,channel,line,created_at) VALUES (?,?,?,?,?)",
            &[json!(task_id), json!(next_seq), json!(channel), json!(line), json!(now)],
        ).await.map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(StreamLine { id, task_id, seq: next_seq, channel: channel.to_owned(), line: line.to_owned(), created_at: now.to_owned() })
    }

    async fn append_stream_bulk(&self, task_id: i64, worker_id: &str, entries: &[(String, String)], now: &str) -> StoreResult<Vec<StreamLine>> {
        if entries.is_empty() { return Ok(vec![]); }
        let owner_rows = self.query("SELECT worker_id FROM tasks WHERE id=?", &[json!(task_id)]).await?;
        let owner = owner_rows.first().ok_or_else(|| StoreError::NotFound(format!("task {task_id}")))?;
        if opt_str(owner, "worker_id").as_deref() != Some(worker_id) {
            return Err(StoreError::PermissionDenied("worker mismatch on stream bulk append".into()));
        }
        let max_seq: Option<i64> = self.query_scalar("SELECT COALESCE(MAX(seq),0) FROM task_streams WHERE task_id=?", &[json!(task_id)]).await?;
        let mut seq = max_seq.unwrap_or(0);
        let mut result = Vec::with_capacity(entries.len());
        for (channel, line) in entries {
            seq += 1;
            let id = self.execute_insert(
                "INSERT INTO task_streams (task_id,seq,channel,line,created_at) VALUES (?,?,?,?,?)",
                &[json!(task_id), json!(seq), json!(channel), json!(line), json!(now)],
            ).await.map_err(|e| StoreError::Backend(e.to_string()))?;
            result.push(StreamLine { id, task_id, seq, channel: channel.clone(), line: line.clone(), created_at: now.to_owned() });
        }
        Ok(result)
    }

    async fn streams_since(&self, task_id: i64, after_seq: i64, limit: i64) -> StoreResult<Vec<StreamLine>> {
        let rows = self.query("SELECT id,task_id,seq,channel,line,created_at FROM task_streams WHERE task_id=? AND seq>? ORDER BY seq ASC LIMIT ?", &[json!(task_id), json!(after_seq), json!(limit)]).await?;
        Ok(rows.iter().map(row_to_stream_line).collect())
    }
}

// -- Progress ----------------------------------------------------------------

#[async_trait]
impl ProgressStore for RqliteStore {
    async fn append_progress(&self, task_id: i64, worker_id: &str, message: &str, files: Option<Vec<String>>, now: &str) -> StoreResult<ProgressEntry> {
        let files_json = serde_json::to_string(&files.unwrap_or_default()).unwrap_or_else(|_| "[]".into());
        let owner_rows = self.query("SELECT worker_id FROM tasks WHERE id=?", &[json!(task_id)]).await?;
        let owner = owner_rows.first().ok_or_else(|| StoreError::NotFound(format!("task {task_id}")))?;
        if opt_str(owner, "worker_id").as_deref() != Some(worker_id) {
            return Err(StoreError::PermissionDenied("worker mismatch on progress".into()));
        }
        let max_seq: Option<i64> = self.query_scalar("SELECT COALESCE(MAX(seq),0) FROM progress WHERE task_id=?", &[json!(task_id)]).await?;
        let next_seq = max_seq.unwrap_or(0) + 1;
        let id = self.execute_insert(
            "INSERT INTO progress (task_id,seq,message,files_touched,created_at) VALUES (?,?,?,?,?)",
            &[json!(task_id), json!(next_seq), json!(message), json!(files_json), json!(now)],
        ).await.map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(ProgressEntry { id, task_id, seq: next_seq, message: message.to_owned(), files_touched: json!([]), created_at: now.to_owned() })
    }

    async fn progress_since(&self, task_id: i64, after_seq: i64) -> StoreResult<Vec<ProgressEntry>> {
        let rows = self.query("SELECT id,task_id,seq,message,files_touched,created_at FROM progress WHERE task_id=? AND seq>? ORDER BY seq ASC", &[json!(task_id), json!(after_seq)]).await?;
        Ok(rows.iter().map(row_to_progress).collect())
    }
}

// -- Approvals ---------------------------------------------------------------

#[async_trait]
impl ApprovalStore for RqliteStore {
    async fn create_or_get_pending_approval(&self, envelope_hash: &str, decision: Value, task_label: &str, branch: Option<&str>, scope_globs: Vec<String>, dispatcher_id: Option<&str>, now: &str) -> StoreResult<(String, bool)> {
        let rows = self.query("SELECT approval_id FROM approvals WHERE envelope_hash=? AND status='pending' LIMIT 1", &[json!(envelope_hash)]).await?;
        if let Some(r) = rows.first() {
            return Ok((str_val(r, "approval_id"), false));
        }
        let approval_id = generate_id();
        let decision_json = serde_json::to_string(&decision).unwrap_or_else(|_| "{}".into());
        let scope_json = serde_json::to_string(&scope_globs).unwrap_or_else(|_| "[]".into());
        self.execute_one(
            "INSERT INTO approvals (approval_id,envelope_hash,decision_json,task_label,branch,scope_globs_json,dispatcher_id,status,created_at) VALUES (?,?,?,?,?,?,?,'pending',?)",
            &[json!(approval_id), json!(envelope_hash), json!(decision_json), json!(task_label), json!(branch), json!(scope_json), json!(dispatcher_id), json!(now)],
        ).await?;
        Ok((approval_id, true))
    }

    async fn consume_approval(&self, approval_id: &str, envelope_hash: &str) -> StoreResult<bool> {
        let n = self.execute_one(
            "UPDATE approvals SET status='consumed' WHERE approval_id=? AND envelope_hash=? AND status='approved'",
            &[json!(approval_id), json!(envelope_hash)],
        ).await?;
        Ok(n > 0)
    }

    async fn resolve_approval(&self, approval_id: &str, status: &str, approver: Option<&str>, reason: Option<&str>, now: &str) -> StoreResult<ApprovalRow> {
        let n = self.execute_one(
            "UPDATE approvals SET status=?,approver=?,reason=?,resolved_at=? WHERE approval_id=? AND status='pending'",
            &[json!(status), json!(approver), json!(reason), json!(now), json!(approval_id)],
        ).await?;
        if n == 0 {
            let rows = self.query("SELECT * FROM approvals WHERE approval_id=?", &[json!(approval_id)]).await?;
            return match rows.first() {
                None => Err(StoreError::NotFound(format!("approval {approval_id}"))),
                Some(r) => Err(StoreError::Conflict(format!("approval already resolved: status={}", str_val(r, "status")))),
            };
        }
        let rows = self.query("SELECT * FROM approvals WHERE approval_id=?", &[json!(approval_id)]).await?;
        rows.into_iter().next()
            .map(|r| row_to_approval(&r))
            .ok_or_else(|| StoreError::NotFound(format!("approval {approval_id}")))
    }

    async fn list_approvals(&self, status: Option<&str>, limit: i64) -> StoreResult<Vec<ApprovalRow>> {
        let rows = if let Some(s) = status {
            self.query("SELECT * FROM approvals WHERE status=? ORDER BY created_at DESC LIMIT ?", &[json!(s), json!(limit)]).await?
        } else {
            self.query("SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?", &[json!(limit)]).await?
        };
        Ok(rows.iter().map(row_to_approval).collect())
    }

    async fn get_approval(&self, approval_id: &str) -> StoreResult<Option<ApprovalRow>> {
        let rows = self.query("SELECT * FROM approvals WHERE approval_id=?", &[json!(approval_id)]).await?;
        Ok(rows.first().map(row_to_approval))
    }
}

// -- Secrets -----------------------------------------------------------------

#[async_trait]
impl SecretStore for RqliteStore {
    async fn put_secret(&self, name: &str, encrypted_value: &str, now: &str) -> StoreResult<SecretMetadata> {
        self.execute_one(
            "INSERT INTO secrets (name,encrypted_value,version,created_at) VALUES (?,?,1,?) ON CONFLICT(name) DO UPDATE SET encrypted_value=?,created_at=?",
            &[json!(name), json!(encrypted_value), json!(now), json!(encrypted_value), json!(now)],
        ).await?;
        let rows = self.query("SELECT name,version,created_at,last_rotated_at FROM secrets WHERE name=?", &[json!(name)]).await?;
        rows.into_iter().next().map(|r| row_to_secret_metadata(&r)).ok_or_else(|| StoreError::Backend("secret not found after insert".into()))
    }

    async fn rotate_secret(&self, name: &str, encrypted_value: &str, now: &str) -> StoreResult<SecretMetadata> {
        let n = self.execute_one(
            "UPDATE secrets SET encrypted_value=?,version=version+1,last_rotated_at=? WHERE name=?",
            &[json!(encrypted_value), json!(now), json!(name)],
        ).await?;
        if n == 0 { return Err(StoreError::NotFound(format!("secret {name}"))); }
        let rows = self.query("SELECT name,version,created_at,last_rotated_at FROM secrets WHERE name=?", &[json!(name)]).await?;
        rows.into_iter().next().map(|r| row_to_secret_metadata(&r)).ok_or_else(|| StoreError::Backend("secret not found after update".into()))
    }

    async fn list_secrets(&self) -> StoreResult<Vec<SecretMetadata>> {
        let rows = self.query("SELECT name,version,created_at,last_rotated_at FROM secrets ORDER BY name", &[]).await?;
        Ok(rows.iter().map(row_to_secret_metadata).collect())
    }

    async fn resolve_secrets(&self, names: &[String]) -> StoreResult<std::collections::HashMap<String, String>> {
        if names.is_empty() { return Ok(std::collections::HashMap::new()); }
        let mut out = std::collections::HashMap::new();
        for name in names {
            if let Some(val) = self.query_scalar::<String>("SELECT encrypted_value FROM secrets WHERE name=?", &[json!(name)]).await? {
                out.insert(name.clone(), val);
            }
        }
        Ok(out)
    }

    async fn delete_secret(&self, name: &str) -> StoreResult<bool> {
        let n = self.execute_one("DELETE FROM secrets WHERE name=?", &[json!(name)]).await?;
        Ok(n > 0)
    }
}

// -- Labels ------------------------------------------------------------------

#[async_trait]
impl LabelStore for RqliteStore {
    async fn get_labels(&self) -> StoreResult<Value> {
        let rows = self.query("SELECT key, value_json FROM labels", &[]).await?;
        let mut hub_name = String::new();
        let mut runner_aliases = serde_json::Map::new();
        let mut host_aliases = serde_json::Map::new();
        for row in &rows {
            let k = str_val(row, "key");
            let raw = str_val(row, "value_json");
            let s = serde_json::from_str::<Value>(&raw)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_owned()))
                .unwrap_or(raw);
            if k == "hub_name" {
                hub_name = s;
            } else if let Some(rid) = k.strip_prefix("runner_alias:") {
                runner_aliases.insert(rid.to_owned(), json!(s));
            } else if let Some(h) = k.strip_prefix("host_alias:") {
                host_aliases.insert(h.to_owned(), json!(s));
            }
        }
        Ok(json!({"hub_name": hub_name, "runner_aliases": runner_aliases, "host_aliases": host_aliases}))
    }

    async fn set_hub_name(&self, name: &str, by: Option<&str>, now: &str) -> StoreResult<()> {
        self.upsert_label("hub_name", name, by, now).await
    }
    async fn set_runner_alias(&self, runner_id: &str, alias: &str, by: Option<&str>, now: &str) -> StoreResult<()> {
        self.upsert_label(&format!("runner_alias:{runner_id}"), alias, by, now).await
    }
    async fn set_host_alias(&self, hostname: &str, alias: &str, by: Option<&str>, now: &str) -> StoreResult<()> {
        self.upsert_label(&format!("host_alias:{hostname}"), alias, by, now).await
    }
}

impl RqliteStore {
    async fn upsert_label(&self, key: &str, value: &str, updated_by: Option<&str>, now: &str) -> StoreResult<()> {
        let value_json = serde_json::to_string(&Value::String(value.to_owned())).unwrap_or_else(|_| format!("\"{}\"", value));
        if value.is_empty() {
            self.execute_one("DELETE FROM labels WHERE key=?", &[json!(key)]).await?;
        } else {
            self.execute_one(
                "INSERT INTO labels (key,value_json,updated_by,updated_at) VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET value_json=?,updated_by=?,updated_at=?",
                &[json!(key), json!(value_json), json!(updated_by), json!(now), json!(value_json), json!(updated_by), json!(now)],
            ).await?;
        }
        Ok(())
    }
}

// -- Host roles --------------------------------------------------------------

#[async_trait]
impl HostRoleStore for RqliteStore {
    async fn set_host_role(&self, hostname: &str, role: &str, enabled: bool, status: Option<&str>, metadata: Value, now: &str) -> StoreResult<HostRoleRow> {
        let meta_json = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".into());
        let enabled_int: i64 = if enabled { 1 } else { 0 };
        self.execute_one(
            "INSERT INTO host_roles (hostname,role,enabled,status,metadata,updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(hostname,role) DO UPDATE SET enabled=?,status=?,metadata=?,updated_at=?",
            &[json!(hostname), json!(role), json!(enabled_int), json!(status), json!(meta_json), json!(now), json!(enabled_int), json!(status), json!(meta_json), json!(now)],
        ).await?;
        let rows = self.query("SELECT * FROM host_roles WHERE hostname=? AND role=?", &[json!(hostname), json!(role)]).await?;
        rows.into_iter().next()
            .map(|r| row_to_host_role(&r))
            .ok_or_else(|| StoreError::Backend("host_role not found after upsert".into()))
    }

    async fn get_host_role(&self, hostname: &str, role: &str) -> StoreResult<Option<HostRoleRow>> {
        let rows = self.query("SELECT * FROM host_roles WHERE hostname=? AND role=?", &[json!(hostname), json!(role)]).await?;
        Ok(rows.first().map(row_to_host_role))
    }

    async fn list_host_roles(&self) -> StoreResult<Vec<HostRoleRow>> {
        let rows = self.query("SELECT * FROM host_roles ORDER BY hostname, role", &[]).await?;
        Ok(rows.iter().map(row_to_host_role).collect())
    }
}

// -- Notes -------------------------------------------------------------------

#[async_trait]
impl NoteStore for RqliteStore {
    async fn post_note(&self, task_id: i64, author: &str, body: &str, now: &str) -> StoreResult<NoteRow> {
        // rqlite doesn't support INSERT...SELECT...RETURNING in the same way;
        // check task exists first, then insert.
        let exists = self.query("SELECT id FROM tasks WHERE id=?", &[json!(task_id)]).await?;
        if exists.is_empty() {
            return Err(StoreError::NotFound(format!("task {task_id}")));
        }
        let id = self.execute_insert(
            "INSERT INTO notes (task_id, author, body, created_at) VALUES (?,?,?,?)",
            &[json!(task_id), json!(author), json!(body), json!(now)],
        ).await.map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(NoteRow { id, task_id, author: author.to_owned(), body: body.to_owned(), created_at: now.to_owned() })
    }

    async fn read_notes(&self, task_id: i64, after_id: i64) -> StoreResult<Vec<NoteRow>> {
        let rows = self.query(
            "SELECT id,task_id,author,body,created_at FROM notes WHERE task_id=? AND id>? ORDER BY id ASC",
            &[json!(task_id), json!(after_id)],
        ).await?;
        Ok(rows.iter().map(|r| NoteRow {
            id: r["id"].as_i64().unwrap_or(0),
            task_id: r["task_id"].as_i64().unwrap_or(0),
            author: str_val(r, "author"),
            body: str_val(r, "body"),
            created_at: str_val(r, "created_at"),
        }).collect())
    }
}

#[async_trait]
impl CostStore for RqliteStore {
    async fn record_cost(
        &self,
        task_id: &str,
        dispatcher_id: Option<&str>,
        runner_id: Option<&str>,
        model_id: &str,
        prompt_tokens: i64,
        completion_tokens: i64,
        cost_usd: f64,
        wall_seconds: f64,
        runner_cpu_seconds: f64,
        now: &str,
    ) -> StoreResult<CostRow> {
        // Insert the immutable ledger row AND bump the daily/weekly spend
        // accumulators in one atomic transaction, so the accumulators can never
        // drift from the ledger across a crash, restart, or failover (M2.5.3).
        let insert_sql = "INSERT INTO cost_ledger \
            (task_id, dispatcher_id, runner_id, model_id, prompt_tokens, completion_tokens, \
             cost_usd, wall_seconds, runner_cpu_seconds, created_at) \
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        let insert_params = [
            serde_json::Value::String(task_id.to_owned()),
            dispatcher_id.map_or(serde_json::Value::Null, |v| serde_json::Value::String(v.to_owned())),
            runner_id.map_or(serde_json::Value::Null, |v| serde_json::Value::String(v.to_owned())),
            serde_json::Value::String(model_id.to_owned()),
            serde_json::json!(prompt_tokens),
            serde_json::json!(completion_tokens),
            serde_json::json!(cost_usd),
            serde_json::json!(wall_seconds),
            serde_json::json!(runner_cpu_seconds),
            serde_json::Value::String(now.to_owned()),
        ];

        // Atomic accumulator increment via UPSERT. Keyed by (scope, period_key).
        let upsert_sql = "INSERT INTO budget_state (scope, period_key, spend_usd, updated_at) \
            VALUES (?, ?, ?, ?) \
            ON CONFLICT(scope, period_key) DO UPDATE SET \
              spend_usd = spend_usd + excluded.spend_usd, \
              updated_at = excluded.updated_at";
        let day = dates::day_key(now);
        let week = dates::iso_week_key(now);
        let daily_params = [
            serde_json::Value::String("daily".to_owned()),
            serde_json::Value::String(day),
            serde_json::json!(cost_usd),
            serde_json::Value::String(now.to_owned()),
        ];
        let weekly_params = [
            serde_json::Value::String("weekly".to_owned()),
            serde_json::Value::String(week),
            serde_json::json!(cost_usd),
            serde_json::Value::String(now.to_owned()),
        ];

        let resp = self
            .execute_tx(&[
                (insert_sql, &insert_params[..]),
                (upsert_sql, &daily_params[..]),
                (upsert_sql, &weekly_params[..]),
            ])
            .await?;
        let id = resp["results"][0]["last_insert_id"]
            .as_i64()
            .ok_or_else(|| RqliteError::Http("cost INSERT returned no last_insert_id".into()))?;
        Ok(CostRow {
            id,
            task_id: task_id.to_owned(),
            dispatcher_id: dispatcher_id.map(str::to_owned),
            runner_id: runner_id.map(str::to_owned),
            model_id: model_id.to_owned(),
            prompt_tokens,
            completion_tokens,
            cost_usd,
            wall_seconds,
            runner_cpu_seconds,
            created_at: now.to_owned(),
        })
    }

    async fn query_cost(
        &self,
        since_iso: Option<&str>,
        limit: i64,
    ) -> StoreResult<Vec<CostRow>> {
        let rows = if let Some(since) = since_iso {
            let params = [serde_json::Value::String(since.to_owned()), serde_json::json!(limit)];
            self.query(
                "SELECT id, task_id, dispatcher_id, runner_id, model_id, \
                 prompt_tokens, completion_tokens, cost_usd, wall_seconds, \
                 runner_cpu_seconds, created_at \
                 FROM cost_ledger WHERE created_at >= ? \
                 ORDER BY created_at DESC LIMIT ?",
                &params,
            ).await?
        } else {
            let params = [serde_json::json!(limit)];
            self.query(
                "SELECT id, task_id, dispatcher_id, runner_id, model_id, \
                 prompt_tokens, completion_tokens, cost_usd, wall_seconds, \
                 runner_cpu_seconds, created_at \
                 FROM cost_ledger ORDER BY created_at DESC LIMIT ?",
                &params,
            ).await?
        };
        Ok(rows
            .iter()
            .filter_map(|r| {
                Some(CostRow {
                    id: r.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
                    task_id: r.get("task_id").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    dispatcher_id: r.get("dispatcher_id").and_then(|v| v.as_str()).map(str::to_owned),
                    runner_id: r.get("runner_id").and_then(|v| v.as_str()).map(str::to_owned),
                    model_id: r.get("model_id").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    prompt_tokens: r.get("prompt_tokens").and_then(|v| v.as_i64()).unwrap_or(0),
                    completion_tokens: r.get("completion_tokens").and_then(|v| v.as_i64()).unwrap_or(0),
                    cost_usd: r.get("cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    wall_seconds: r.get("wall_seconds").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    runner_cpu_seconds: r.get("runner_cpu_seconds").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    created_at: r.get("created_at").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                })
            })
            .collect())
    }
}

#[async_trait]
impl BudgetStore for RqliteStore {
    async fn add_spend(
        &self,
        scope: &str,
        period_key: &str,
        delta_usd: f64,
        now: &str,
    ) -> StoreResult<f64> {
        let sql = "INSERT INTO budget_state (scope, period_key, spend_usd, updated_at) \
            VALUES (?, ?, ?, ?) \
            ON CONFLICT(scope, period_key) DO UPDATE SET \
              spend_usd = spend_usd + excluded.spend_usd, \
              updated_at = excluded.updated_at";
        let params = [
            serde_json::Value::String(scope.to_owned()),
            serde_json::Value::String(period_key.to_owned()),
            serde_json::json!(delta_usd),
            serde_json::Value::String(now.to_owned()),
        ];
        self.execute_one(sql, &params).await?;
        self.get_spend(scope, period_key).await
    }

    async fn get_spend(&self, scope: &str, period_key: &str) -> StoreResult<f64> {
        let params = [
            serde_json::Value::String(scope.to_owned()),
            serde_json::Value::String(period_key.to_owned()),
        ];
        let total: Option<f64> = self
            .query_scalar(
                "SELECT spend_usd FROM budget_state WHERE scope = ? AND period_key = ?",
                &params,
            )
            .await?;
        Ok(total.unwrap_or(0.0))
    }

    async fn list_budget_state(&self) -> StoreResult<Vec<BudgetStateRow>> {
        let rows = self
            .query(
                "SELECT scope, period_key, spend_usd, updated_at FROM budget_state \
                 ORDER BY scope, period_key",
                &[],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| BudgetStateRow {
                scope: r.get("scope").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                period_key: r.get("period_key").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                spend_usd: r.get("spend_usd").and_then(|v| v.as_f64()).unwrap_or(0.0),
                updated_at: r.get("updated_at").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
            })
            .collect())
    }

    async fn current_budget(&self, now: &str) -> StoreResult<CurrentBudget> {
        let today = dates::day_key(now);
        let week = dates::iso_week_key(now);
        let daily_spend_usd = self.get_spend("daily", &today).await?;
        let weekly_spend_usd = self.get_spend("weekly", &week).await?;
        Ok(CurrentBudget {
            today,
            week,
            daily_spend_usd,
            weekly_spend_usd,
        })
    }
}

impl FabricStore for RqliteStore {}

// ---------------------------------------------------------------------------
// M2.5.3 — budget_state restart-persistence integration test
//
// Verifies the core invariant: N atomic cost inserts leave budget_state totals
// that equal the sum of those inserts, even when the store is reconstructed
// from scratch (simulating a hub restart). The test requires a live rqlite
// cluster; it is silently skipped when none is reachable so CI does not break
// on machines without rqlite.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use fabric_store::{BudgetStore, CostStore};

    fn test_store() -> Option<RqliteStore> {
        let host = std::env::var("RQLITE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port: u16 = std::env::var("RQLITE_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4001);
        // Quick TCP probe — return None if rqlite is not up.
        use std::net::TcpStream;
        if TcpStream::connect(format!("{host}:{port}")).is_err() {
            return None;
        }
        Some(RqliteStore::new(&host, port, "strong"))
    }

    #[tokio::test]
    async fn budget_state_persists_across_store_reconstruction() {
        let store = match test_store() {
            Some(s) => s,
            None => {
                eprintln!("SKIP budget_state restart test — rqlite not reachable");
                return;
            }
        };

        // Ensure schema exists (idempotent).
        store.init_schema().await.expect("init_schema");

        let now = utc_now();
        let day = dates::day_key(&now);
        let week = dates::iso_week_key(&now);

        // Fetch baseline so the test is additive (safe against a shared cluster).
        let baseline_day = store.get_spend("daily", &day).await.expect("baseline_day");
        let baseline_week = store.get_spend("weekly", &week).await.expect("baseline_week");

        // Insert 3 cost rows atomically — each bumps daily + weekly accumulators.
        let tid = format!("test-restart-{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
        for i in 0u32..3 {
            store
                .record_cost(
                    &format!("{tid}-{i}"),
                    None, None,
                    "test-model",
                    0, 0,
                    1.0,   // $1.00 each → $3.00 total
                    0.0, 0.0,
                    &now,
                )
                .await
                .expect("record_cost");
        }

        // Reconstruct the store — this simulates a hub restart (no in-memory state).
        let host = std::env::var("RQLITE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port: u16 = std::env::var("RQLITE_PORT")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(4001);
        let fresh = RqliteStore::new(&host, port, "strong");

        // budget_state point lookups must reflect all 3 inserts — not zero.
        let after_day = fresh.get_spend("daily", &day).await.expect("after_day");
        let after_week = fresh.get_spend("weekly", &week).await.expect("after_week");

        let delta_day = after_day - baseline_day;
        let delta_week = after_week - baseline_week;

        assert!(
            (delta_day - 3.0).abs() < 1e-6,
            "budget_state daily should have gained exactly $3.00 (got delta={delta_day})"
        );
        assert!(
            (delta_week - 3.0).abs() < 1e-6,
            "budget_state weekly should have gained exactly $3.00 (got delta={delta_week})"
        );
    }
}

fn utc_offset(offset_secs: i64) -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    epoch_secs_to_iso(d.as_secs() as i64 + offset_secs)
}

fn utc_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    epoch_secs_to_iso(d.as_secs() as i64)
}

fn epoch_secs_to_iso(total_secs: i64) -> String {
    let total_secs = total_secs as u64;
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
