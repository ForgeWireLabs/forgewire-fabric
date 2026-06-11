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
    /// Phase 2.8: agent-dispatch discriminator. NULL when kind=="command".
    /// One of "skill" | "tool" | "prompt" when kind=="agent". Backward-compat:
    /// missing on legacy briefs is backfilled to "prompt" by the hub.
    #[serde(default)]
    pub dispatch: Option<String>,
    /// Phase 2.8 (M2.8.2): skill name for dispatch="skill" briefs.
    #[serde(default)]
    pub skill: Option<String>,
    /// Phase 2.8 (M2.8.2): tool name for dispatch="tool" briefs.
    #[serde(default)]
    pub tool: Option<String>,
    /// M2.9.2: override the initial task status. `None` → "queued" (default).
    /// Only "held" is a valid non-default value; used when the dispatch gate
    /// returns `needs_approval`.
    #[serde(default)]
    pub initial_status: Option<String>,
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
    /// Phase 2.8: agent-dispatch discriminator. See `CreateTaskParams::dispatch`.
    #[serde(default)]
    pub dispatch: Option<String>,
    /// Phase 2.8 (M2.8.2): skill name for dispatch="skill" briefs.
    #[serde(default)]
    pub skill: Option<String>,
    /// Phase 2.8 (M2.8.2): tool name for dispatch="tool" briefs.
    #[serde(default)]
    pub tool: Option<String>,
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
    /// Phase 2.8: hard runner-kind property. JSON array of "agent" | "command".
    /// Backfilled to `["agent"]` for pre-2.8 rows. Replaces the tag-based
    /// `kind:<x>` filter at routing time.
    #[serde(default = "default_kinds")]
    pub kinds: Value,
    /// Phase 2.8: free-form agent type label (e.g. "claude-code", "vscode",
    /// "forgewire-orchestrator"). NULL for Loom-only runners.
    #[serde(default)]
    pub agent_type: Option<String>,
    /// Phase 2.8: full MCP manifest (tools / resources / prompts per server)
    /// introspected from the runner's MCPServerRegistry. NULL for Loom-only
    /// runners. See SPEC.md for the locked shape.
    #[serde(default)]
    pub mcp_manifest: Option<Value>,
    /// Phase 2.8: monotonically increasing on each manifest change.
    #[serde(default)]
    pub mcp_manifest_version: i64,
}

fn default_kinds() -> Value {
    serde_json::json!(["agent"])
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

// -- Budget accumulators (M2.5.3) --------------------------------------------

/// One persistent spend accumulator: total `spend_usd` for a (scope, period_key).
///
/// `scope` is e.g. `"daily"` or `"weekly"`; `period_key` is the day string
/// `"YYYY-MM-DD"` or the ISO week string `"YYYY-WNN"`. These rows let the
/// budget enforcer read current-period totals via point lookups and survive a
/// hub restart without re-aggregating the whole `cost_ledger`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudgetStateRow {
    pub scope: String,
    pub period_key: String,
    pub spend_usd: f64,
    pub updated_at: String,
}

/// Current-period spend totals for the instant the query is made, using the
/// store's own day/ISO-week period-key derivation (so the keys match the
/// accumulator writes exactly).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurrentBudget {
    pub today: String,
    pub week: String,
    pub daily_spend_usd: f64,
    pub weekly_spend_usd: f64,
}

#[async_trait]
pub trait BudgetStore: Send + Sync {
    /// Atomically add `delta_usd` to the (scope, period_key) accumulator,
    /// creating the row if absent. Returns the new total.
    async fn add_spend(
        &self,
        scope: &str,
        period_key: &str,
        delta_usd: f64,
        now: &str,
    ) -> StoreResult<f64>;

    /// Current total for a (scope, period_key); 0.0 if no row exists.
    async fn get_spend(&self, scope: &str, period_key: &str) -> StoreResult<f64>;

    /// All accumulator rows — used to hydrate an in-memory enforcer on startup.
    async fn list_budget_state(&self) -> StoreResult<Vec<BudgetStateRow>>;

    /// Current daily and weekly spend totals for the instant `now`, read from
    /// the accumulators (point lookups, no `cost_ledger` scan). `now` is a hub
    /// UTC timestamp string; the implementation derives the day and ISO-week
    /// period keys the same way the accumulator writes do.
    async fn current_budget(&self, now: &str) -> StoreResult<CurrentBudget>;
}

// -- Runner capability index (M2.8.1, Phase 2.8) -----------------------------

/// Normalized capability advertised by a Fabric runner. One row per
/// `(runner_id, capability_kind, name)` derived from the runner's
/// `mcp_manifest`. Used by the capability router to answer "which runners
/// advertise tool X / prompt Y / resource URI Z?".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunnerCapabilityRow {
    pub runner_id: String,
    /// One of "tool" | "resource" | "prompt".
    pub capability_kind: String,
    /// Tool name, resource URI, or prompt name.
    pub name: String,
    /// `server_id` from the manifest's `servers[]` entry that supplied this
    /// capability. Disambiguates multi-server manifests.
    pub source_server: String,
    pub description: Option<String>,
    /// JSON blob carrying per-kind extras: tool `input_schema`, resource
    /// `mime_type`, or prompt `arguments`.
    #[serde(default)]
    pub extra: Value,
}

#[async_trait]
pub trait RunnerCapabilityStore: Send + Sync {
    /// Atomically replace the full capability set for a runner. Pre-existing
    /// rows for `runner_id` are deleted and the supplied `rows` inserted in a
    /// single rqlite transaction. Used after `upsert_runner` so the index
    /// never lags the manifest.
    async fn replace_runner_capabilities(
        &self,
        runner_id: &str,
        rows: &[RunnerCapabilityRow],
        now: &str,
    ) -> StoreResult<()>;

    /// Capabilities currently advertised by `runner_id`.
    async fn runner_capabilities(
        &self,
        runner_id: &str,
    ) -> StoreResult<Vec<RunnerCapabilityRow>>;

    /// Runners that advertise `name` under `capability_kind`. The capability
    /// router intersects this set with the eligible-runner set when handling
    /// `dispatch ∈ {"skill","tool"}` and `target.required_resources`.
    async fn query_runners_by_capability(
        &self,
        capability_kind: &str,
        name: &str,
    ) -> StoreResult<Vec<String>>;

    /// Wipe all capability rows for a runner — invoked when a runner is
    /// deleted or transitions to Loom-only (`kinds = ["command"]`).
    async fn delete_runner_capabilities(&self, runner_id: &str) -> StoreResult<()>;
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
    + BudgetStore
    + RunnerCapabilityStore
    + Send
    + Sync
{
}
