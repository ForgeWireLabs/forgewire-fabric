//! Store trait definitions for ForgeWire Fabric hub persistence.
//!
//! These traits define the durable state contract for the rqlite backend
//! backends. The hub daemon programs against these traits; the backend is
//! selected at startup.
//!
//! ## Design rules
//!
//! - No transaction API. Atomic operations (claim CAS, audit-tail CAS) are
//!   modeled as single trait methods that return success/conflict explicitly.
//! - All timestamps are explicit UTC strings (`%Y-%m-%d %H:%M:%S`), never
//!   `datetime('now')` (which is backend-local).
//! - JSON columns are `serde_json::Value` at the trait boundary.
//! - Errors use a shared `StoreError` enum so the hub can match on conflict
//!   vs. transport vs. schema errors uniformly.

#![deny(rust_2018_idioms)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("schema error: {0}")]
    Schema(String),

    #[error("backend error: {0}")]
    Backend(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

// -- Task store --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTaskParams {
    pub title: String,
    pub prompt: String,
    pub scope_globs: Vec<String>,
    pub base_commit: String,
    pub branch: String,
    pub todo_id: Option<String>,
    pub timeout_minutes: i64,
    pub priority: i64,
    pub kind: String,
    pub metadata: Value,
    pub required_tools: Option<Vec<String>>,
    pub required_tags: Option<Vec<String>>,
    pub tenant: Option<String>,
    pub workspace_root: Option<String>,
    pub require_base_commit: bool,
    pub required_capabilities: Option<Vec<String>>,
    pub secrets_needed: Option<Vec<String>>,
    pub network_egress: Option<Value>,
    pub dispatcher_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRow {
    pub id: i64,
    pub title: String,
    pub prompt: String,
    pub scope_globs: Value,
    pub base_commit: String,
    pub branch: String,
    pub status: String,
    pub kind: String,
    pub worker_id: Option<String>,
    pub created_at: String,
    pub claimed_at: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub cancel_requested: bool,
    pub metadata: Value,
    pub todo_id: Option<String>,
    pub timeout_minutes: i64,
    pub priority: i64,
    pub required_tools: Option<Value>,
    pub required_tags: Option<Value>,
    pub tenant: Option<String>,
    pub workspace_root: Option<String>,
    pub require_base_commit: bool,
    pub required_capabilities: Option<Value>,
    pub secrets_needed: Option<Value>,
    pub network_egress: Option<Value>,
    pub dispatcher_id: Option<String>,
}

/// Atomic claim result — either the task was claimed or someone else got it.
pub enum ClaimResult {
    Claimed(TaskRow),
    AlreadyClaimed,
}

#[async_trait]
pub trait TaskStore: Send + Sync {
    async fn create_task(&self, params: CreateTaskParams, now: &str) -> StoreResult<TaskRow>;
    async fn get_task(&self, id: i64) -> StoreResult<TaskRow>;
    async fn list_tasks(&self, status_filter: Option<&str>, limit: i64) -> StoreResult<Vec<TaskRow>>;
    /// Atomic CAS: claim task only if status is still 'queued'.
    async fn claim_task(&self, task_id: i64, worker_id: &str, now: &str) -> StoreResult<ClaimResult>;
    async fn mark_running(&self, task_id: i64, now: &str) -> StoreResult<TaskRow>;
    async fn cancel_task(&self, task_id: i64, now: &str) -> StoreResult<TaskRow>;
    async fn count_tasks(&self) -> StoreResult<i64>;
}

// -- Result store ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResultParams {
    pub task_id: i64,
    pub worker_id: String,
    pub status: String,
    pub head_commit: Option<String>,
    pub commits: Vec<String>,
    pub files_touched: Vec<String>,
    pub test_summary: Option<String>,
    pub log_tail: Option<String>,
    pub error: Option<String>,
}

#[async_trait]
pub trait ResultStore: Send + Sync {
    async fn submit_result(&self, params: SubmitResultParams, now: &str) -> StoreResult<TaskRow>;
}

// -- Runner store ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerRow {
    pub runner_id: String,
    pub public_key: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub state: String,
    pub runner_version: String,
    pub protocol_version: i64,
    pub max_concurrent: i64,
    pub tools: Value,
    pub tags: Value,
    pub scope_prefixes: Value,
    pub tenant: Option<String>,
    pub workspace_root: Option<String>,
    pub capabilities: Value,
    pub metadata: Value,
    pub drain_requested: bool,
    pub last_heartbeat: String,
    pub first_seen: String,
    pub last_nonce: Option<String>,
}

#[async_trait]
pub trait RunnerStore: Send + Sync {
    async fn upsert_runner(&self, data: Value) -> StoreResult<RunnerRow>;
    async fn get_runner(&self, runner_id: &str) -> StoreResult<RunnerRow>;
    async fn list_runners(&self) -> StoreResult<Vec<RunnerRow>>;
    async fn runner_public_key(&self, runner_id: &str) -> StoreResult<Option<String>>;
    async fn heartbeat_runner(&self, runner_id: &str, data: Value, now: &str) -> StoreResult<RunnerRow>;
    async fn request_drain(&self, runner_id: &str) -> StoreResult<RunnerRow>;
    async fn request_undrain(&self, runner_id: &str) -> StoreResult<RunnerRow>;
    async fn delete_runner(&self, runner_id: &str) -> StoreResult<RunnerRow>;
}

// -- Dispatcher store --------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatcherRow {
    pub dispatcher_id: String,
    pub public_key: String,
    pub label: String,
    pub hostname: Option<String>,
    pub metadata: Value,
    pub first_seen: String,
    pub last_seen: String,
}

#[async_trait]
pub trait DispatcherStore: Send + Sync {
    async fn upsert_dispatcher(&self, data: Value) -> StoreResult<DispatcherRow>;
    async fn get_dispatcher(&self, dispatcher_id: &str) -> StoreResult<DispatcherRow>;
    async fn list_dispatchers(&self) -> StoreResult<Vec<DispatcherRow>>;
    async fn dispatcher_public_key(&self, dispatcher_id: &str) -> StoreResult<Option<String>>;
    async fn delete_dispatcher(&self, dispatcher_id: &str) -> StoreResult<DispatcherRow>;
}

// -- Nonce store (replay protection) -----------------------------------------

#[async_trait]
pub trait NonceStore: Send + Sync {
    async fn consume_dispatcher_nonce(&self, dispatcher_id: &str, nonce: &str, now: &str) -> StoreResult<()>;
    async fn consume_runner_nonce(&self, runner_id: &str, nonce: &str, now: &str) -> StoreResult<()>;
}

// -- Stream store ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamLine {
    pub id: i64,
    pub task_id: i64,
    pub seq: i64,
    pub channel: String,
    pub line: String,
    pub created_at: String,
}

#[async_trait]
pub trait StreamStore: Send + Sync {
    async fn append_stream(&self, task_id: i64, worker_id: &str, channel: &str, line: &str, now: &str) -> StoreResult<StreamLine>;
    async fn append_stream_bulk(&self, task_id: i64, worker_id: &str, entries: &[(String, String)], now: &str) -> StoreResult<Vec<StreamLine>>;
    async fn streams_since(&self, task_id: i64, after_seq: i64, limit: i64) -> StoreResult<Vec<StreamLine>>;
}

// -- Progress store ----------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEntry {
    pub id: i64,
    pub task_id: i64,
    pub seq: i64,
    pub message: String,
    pub files_touched: Value,
    pub created_at: String,
}

#[async_trait]
pub trait ProgressStore: Send + Sync {
    async fn append_progress(&self, task_id: i64, worker_id: &str, message: &str, files: Option<Vec<String>>, now: &str) -> StoreResult<ProgressEntry>;
    async fn progress_since(&self, task_id: i64, after_seq: i64) -> StoreResult<Vec<ProgressEntry>>;
}

// -- Audit store -------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventRow {
    pub seq: i64,
    pub event_id_hash: String,
    pub prev_event_id_hash: String,
    pub kind: String,
    pub task_id: Option<i64>,
    pub payload_json: String,
    pub created_at: String,
}

/// Result of an audit append with expected-tail CAS.
pub enum AuditAppendResult {
    Ok(AuditEventRow),
    TailConflict { expected: String, actual: String },
}

#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn audit_chain_tail(&self) -> StoreResult<String>;
    /// Append with expected-tail compare-and-swap. Returns `TailConflict`
    /// if another writer appended since we read the tail.
    async fn append_audit_event(
        &self,
        expected_tail: &str,
        event_id_hash: &str,
        prev_hash: &str,
        kind: &str,
        task_id: Option<i64>,
        payload_json: &str,
        now: &str,
    ) -> StoreResult<AuditAppendResult>;
    async fn audit_events_for_task(&self, task_id: i64) -> StoreResult<Vec<AuditEventRow>>;
    async fn audit_events_for_day(&self, day: &str) -> StoreResult<Vec<AuditEventRow>>;
    async fn verify_audit_chain(&self, events: &[AuditEventRow]) -> StoreResult<(bool, Option<String>)>;
}

// -- Approval store ----------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRow {
    pub approval_id: String,
    pub envelope_hash: String,
    pub status: String,
    pub decision_json: Value,
    pub task_label: Option<String>,
    pub branch: Option<String>,
    pub scope_globs_json: Value,
    pub dispatcher_id: Option<String>,
    pub approver: Option<String>,
    pub reason: Option<String>,
    pub created_at: String,
    pub resolved_at: Option<String>,
}

#[async_trait]
pub trait ApprovalStore: Send + Sync {
    async fn create_or_get_pending_approval(&self, envelope_hash: &str, decision: Value, task_label: &str, branch: Option<&str>, scope_globs: Vec<String>, dispatcher_id: Option<&str>, now: &str) -> StoreResult<(String, bool)>;
    async fn consume_approval(&self, approval_id: &str, envelope_hash: &str) -> StoreResult<bool>;
    async fn resolve_approval(&self, approval_id: &str, status: &str, approver: Option<&str>, reason: Option<&str>, now: &str) -> StoreResult<ApprovalRow>;
    async fn list_approvals(&self, status: Option<&str>, limit: i64) -> StoreResult<Vec<ApprovalRow>>;
    async fn get_approval(&self, approval_id: &str) -> StoreResult<Option<ApprovalRow>>;
}

// -- Secret store ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub name: String,
    pub version: i64,
    pub created_at: String,
    pub last_rotated_at: Option<String>,
}

#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn put_secret(&self, name: &str, encrypted_value: &str, now: &str) -> StoreResult<SecretMetadata>;
    async fn rotate_secret(&self, name: &str, encrypted_value: &str, now: &str) -> StoreResult<SecretMetadata>;
    async fn list_secrets(&self) -> StoreResult<Vec<SecretMetadata>>;
    async fn resolve_secrets(&self, names: &[String]) -> StoreResult<std::collections::HashMap<String, String>>;
    async fn delete_secret(&self, name: &str) -> StoreResult<bool>;
}

// -- Label store -------------------------------------------------------------

#[async_trait]
pub trait LabelStore: Send + Sync {
    async fn get_labels(&self) -> StoreResult<Value>;
    async fn set_hub_name(&self, name: &str, updated_by: Option<&str>, now: &str) -> StoreResult<()>;
    async fn set_runner_alias(&self, runner_id: &str, alias: &str, updated_by: Option<&str>, now: &str) -> StoreResult<()>;
    async fn set_host_alias(&self, hostname: &str, alias: &str, updated_by: Option<&str>, now: &str) -> StoreResult<()>;
}

// -- Host role store ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRoleRow {
    pub hostname: String,
    pub role: String,
    pub enabled: bool,
    pub status: Option<String>,
    pub metadata: Value,
    pub updated_at: String,
}

#[async_trait]
pub trait HostRoleStore: Send + Sync {
    async fn set_host_role(&self, hostname: &str, role: &str, enabled: bool, status: Option<&str>, metadata: Value, now: &str) -> StoreResult<HostRoleRow>;
    async fn get_host_role(&self, hostname: &str, role: &str) -> StoreResult<Option<HostRoleRow>>;
    async fn list_host_roles(&self) -> StoreResult<Vec<HostRoleRow>>;
}

// -- Schema management -------------------------------------------------------

#[async_trait]
pub trait SchemaStore: Send + Sync {
    async fn init_schema(&self) -> StoreResult<()>;
    async fn schema_version(&self) -> StoreResult<i64>;
    async fn run_additive_migrations(&self) -> StoreResult<()>;
}

// -- Note store (bidirectional task back-channel) ----------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteRow {
    pub id: i64,
    pub task_id: i64,
    pub author: String,
    pub body: String,
    pub created_at: String,
}

#[async_trait]
pub trait NoteStore: Send + Sync {
    async fn post_note(&self, task_id: i64, author: &str, body: &str, now: &str) -> StoreResult<NoteRow>;
    async fn read_notes(&self, task_id: i64, after_id: i64) -> StoreResult<Vec<NoteRow>>;
}

// -- Cost ledger (M2.5.2) ----------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CostRow {
    pub id: i64,
    pub task_id: String,
    pub dispatcher_id: Option<String>,
    pub runner_id: Option<String>,
    pub model_id: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cost_usd: f64,
    pub wall_seconds: f64,
    pub runner_cpu_seconds: f64,
    pub created_at: String,
}

#[async_trait]
pub trait CostStore: Send + Sync {
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
    ) -> StoreResult<CostRow>;

    async fn query_cost(
        &self,
        since_iso: Option<&str>,
        limit: i64,
    ) -> StoreResult<Vec<CostRow>>;
}

// -- Composite trait ---------------------------------------------------------

/// The full store contract. A backend implements all sub-traits.
#[async_trait]
pub trait FabricStore:
    TaskStore
    + ResultStore
    + RunnerStore
    + DispatcherStore
    + NonceStore
    + StreamStore
    + ProgressStore
    + AuditStore
    + ApprovalStore
    + SecretStore
    + LabelStore
    + HostRoleStore
    + NoteStore
    + SchemaStore
    + CostStore
    + Send
    + Sync
{
}
