//! Shared hub state — passed to all route handlers via axum State.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

use fabric_policy::{BudgetPolicy, DispatchGate};
use fabric_secrets::{SecretBroker, SecretError};
use fabric_store::FabricStore;
use fabric_streams::StreamBuffer;

/// In-memory queue of signed stdin batches per task.
/// Each entry is `(seq, lines)`. Flushed when a task completes.
pub type InputQueue = Mutex<HashMap<i64, Vec<(i64, Vec<String>)>>>;

pub struct HubState {
    pub store: Arc<dyn FabricStore>,
    pub secrets: SecretBroker,
    pub token: String,
    /// Optional shared secret required (alongside a loopback-only source
    /// address) to complete `POST /auth/bootstrap`. `None` means loopback
    /// alone is sufficient -- the plan's "local console proof" alternative
    /// to a one-time bootstrap secret.
    pub bootstrap_secret: Option<String>,
    /// The hub's WebAuthn relying-party instance (114C.6), built once at
    /// startup from `auth.passkeys` settings. `None` when passkeys are
    /// disabled, unconfigured, or every configured origin fails the
    /// secure-context check -- see `crate::webauthn::build_from_settings`.
    /// Never a startup failure: passkey routes fail closed with
    /// `AccountPolicyViolation` when this is `None`, the rest of the hub
    /// stays healthy.
    pub webauthn: Option<Arc<webauthn_rs::prelude::Webauthn>>,
    /// Step-up freshness window in minutes (114C.6,
    /// `auth.sessions.step_up_freshness_minutes`, default 10, schema-capped
    /// at 10). A session's step-up counts as "recent" only within this many
    /// minutes; the sensitive-action gate in `require_bearer` reads it.
    pub step_up_freshness_minutes: i64,
    pub started_at: Instant,
    pub started_at_unix: f64,
    pub gate: DispatchGate,
    /// Effective hub policy rendered for authenticated observer/reviewer clients.
    /// This is a startup snapshot of the same policy used to construct `gate`.
    pub effective_policy: serde_json::Value,
    /// Cost caps enforced natively on every dispatch, read from the persistent
    /// `budget_state` accumulators (M2.5.3). Empty = no caps configured.
    pub budget_caps: BudgetPolicy,
    pub host: String,
    pub port: u16,
    pub protocol_version: i64,
    pub package_version: String,
    pub sidecar_integrity: String,
    /// "rqlite" (only supported backend)
    pub backend: String,
    /// Bounded write buffer for task stream lines.
    pub stream_buffer: Arc<StreamBuffer>,
    /// M2.9.4 (F4): per-task signed stdin batches; populated by POST /tasks/{id}/input,
    /// drained by runners via GET /tasks/{id}/input?after_seq=N.
    pub input_queues: Arc<InputQueue>,
    /// Optional routing of HITL approvals to ForgeLink as the governed decision
    /// surface (work item 016 AGH-028; decision 0004). Disabled unless configured.
    pub forgelink: crate::forgelink::ForgeLinkConfig,
    /// Last optional Tier-2 exporter status. This is observational only and
    /// never participates in dispatch or hub availability decisions.
    pub history_status: Arc<Mutex<serde_json::Value>>,
}

impl HubState {
    pub async fn redact_text(&self, text: &str) -> Result<String, SecretError> {
        let envelopes = self
            .store
            .all_secret_envelopes()
            .await
            .map_err(|e| SecretError::ProviderIo(e.to_string()))?;
        self.secrets.redact_text(
            text,
            envelopes
                .iter()
                .map(|(name, envelope)| (name.as_str(), envelope.as_str())),
        )
    }

    pub async fn redact_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<serde_json::Value, SecretError> {
        let envelopes = self
            .store
            .all_secret_envelopes()
            .await
            .map_err(|e| SecretError::ProviderIo(e.to_string()))?;
        self.secrets.redact_value(
            value,
            envelopes
                .iter()
                .map(|(name, envelope)| (name.as_str(), envelope.as_str())),
        )
    }
}
