//! Typed HTTP client for the ForgeWire Fabric hub API.
//!
//! Shared by the runner daemon, CLI, tests, and optional adapters.
//! Every method maps 1:1 to a hub endpoint documented in ENDPOINT_AUTH_MATRIX.md.

#![deny(rust_2018_idioms)]

use std::collections::HashMap;
use std::time::Duration;

use fabric_identity::IdentityFile;
use fabric_protocol::{canonicalize, sign_envelope_hex, sign_payload_hex};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::debug;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u32 = 3;
const RETRY_BASE_MS: u64 = 500;

/// The wire codes `crates/fabric-hub/src/error.rs`'s `ApiError::account`
/// emits for `fabric_accounts::error::AccountsError` (114C.6 Slice 7's own
/// tests already cross-check the Rust source of truth,
/// `AccountsError::ALL_CODES`, against `packages/fabric-client-core/src/
/// authContracts.ts`'s `TYPED_AUTH_ERROR_CODES` via `tests/fixtures/
/// accounts/account_session_summary.json` -- this is a *third* independent
/// copy of the same 20-string wire contract, not a shared-crate dependency,
/// matching how the TS side is already an independent copy rather than a
/// `fabric-accounts` dependency. `fabric-client` deliberately does not
/// depend on `fabric-accounts`: it is a thin, general-purpose HTTP client
/// used by the CLI, the runner daemon, and (114C.7) the desktop Tauri
/// backend, none of which should need the account domain's own crypto/
/// storage dependency chain just to recognize a stable error string.
const KNOWN_AUTH_ERROR_CODES: &[&str] = &[
    "AuthenticationRequired",
    "InvalidCredentials",
    "SessionExpired",
    "SessionRevoked",
    "RefreshReplayDetected",
    "AccountDisabled",
    "AccountLocked",
    "RecoveryRequired",
    "StepUpRequired",
    "AssuranceTooLow",
    "AccountPolicyViolation",
    "LastAdministratorViolation",
    "UsernameConflict",
    "CredentialConflict",
    "BootstrapClosed",
    "BootstrapLocalOnly",
    "AuthServiceUnavailable",
    "RolePolicyViolation",
    "ChallengeInvalid",
    "CredentialReplaySuspected",
];

/// A recognized `{code, message}` pair from a 114C auth-route error
/// response. `Serialize` so it can cross the Tauri IPC boundary directly.
#[derive(Debug, Clone, Serialize)]
pub struct TypedAuthError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("hub returned {status}: {body}")]
    Hub { status: u16, body: String },

    #[error("transport error after {attempts} attempts: {message}")]
    Transport { attempts: u32, message: String },

    #[error("protocol error: {0}")]
    Protocol(String),
}

impl ClientError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Hub { status: 404, .. })
    }

    pub fn is_upgrade_required(&self) -> bool {
        matches!(self, Self::Hub { status: 426, .. })
    }

    /// True when the hub rejected an intent with a hard policy deny (403).
    pub fn is_policy_denied(&self) -> bool {
        matches!(self, Self::Hub { status: 403, .. })
    }

    /// True when the hub requires operator approval before continuing (428).
    pub fn is_approval_required(&self) -> bool {
        matches!(self, Self::Hub { status: 428, .. })
    }

    /// Extract the `approval_id` from a 428 response body JSON, if present.
    pub fn approval_id(&self) -> Option<String> {
        if let Self::Hub { status: 428, body } = self {
            serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|v| {
                    v.get("detail")
                        .and_then(|d| d.get("approval_id"))
                        .or_else(|| v.get("approval_id"))
                        .and_then(|id| id.as_str())
                        .map(|s| s.to_owned())
                })
        } else {
            None
        }
    }

    pub fn status_code(&self) -> u16 {
        match self {
            Self::Hub { status, .. } => *status,
            Self::Transport { .. } => 0,
            Self::Protocol(_) => 0,
        }
    }

    /// The hub's error shape (`ApiError::into_response` in `fabric-hub`) is
    /// always `{error:{code,message,remediation}}`. `None` here means
    /// exactly "do not show this body to anyone" -- either it isn't that
    /// shape at all, or `code` isn't one of `KNOWN_AUTH_ERROR_CODES` -- both
    /// cases a caller must treat as "something unexpected happened," never
    /// as license to fall back to displaying `self.to_string()` (which, for
    /// `Self::Hub`, includes the raw `body` verbatim -- precisely what this
    /// method exists to keep off of any 114C auth-route caller's UI).
    pub fn typed_auth_error(&self) -> Option<TypedAuthError> {
        let Self::Hub { body, .. } = self else {
            return None;
        };
        let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
        let code = parsed.get("error")?.get("code")?.as_str()?;
        if !KNOWN_AUTH_ERROR_CODES.contains(&code) {
            return None;
        }
        let message = parsed
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or(code);
        Some(TypedAuthError {
            code: code.to_owned(),
            message: message.to_owned(),
        })
    }
}

/// How a human-session request authenticates to the hub.
///
/// - `Bearer` sends the opaque `access_secret` as `Authorization: Bearer …`
///   (114C). Whoever holds the secret is the human — a reusable secret on the
///   wire.
/// - `Pop` (114E proof-of-possession) signs the canonical `session-request`
///   envelope with the session's bound Ed25519 private key and sends the
///   `X-Forgewire-{Session,Timestamp,Nonce,Signature}` headers instead — no
///   reusable secret crosses the wire. The session must have been key-bound at
///   login (`login(..., session_public_key)`); the hub verifies against the
///   stored public key. The two coexist: the hub takes the PoP path only when
///   the signature header is present.
#[derive(Clone, Copy)]
pub enum SessionCredential<'a> {
    Bearer(&'a str),
    Pop {
        session_id: &'a str,
        secret_key_hex: &'a str,
    },
}

/// Typed hub client. Holds a connection-pooled HTTP client and the bearer token.
pub struct HubClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl HubClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .pool_max_idle_per_host(20)
            .build()
            .expect("failed to build reqwest client");
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            token: token.trim().to_owned(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // -- Low-level request with retry ----------------------------------------

    async fn request_with_retry(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, ClientError> {
        let url = format!("{}{}", self.base_url, path);
        let mut last_err = String::new();

        for attempt in 1..=MAX_RETRIES {
            let mut req = self
                .http
                .request(method.clone(), &url)
                .header("Authorization", format!("Bearer {}", self.token));
            if let Some(b) = body {
                req = req.json(b);
            }
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    if (200..300).contains(&status) {
                        let val: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                        return Ok(val);
                    }
                    return Err(ClientError::Hub { status, body: text });
                }
                Err(e) => {
                    last_err = e.to_string();
                    if attempt < MAX_RETRIES {
                        let delay = RETRY_BASE_MS * 2u64.pow(attempt - 1);
                        debug!(attempt, delay_ms = delay, error = %e, "retrying hub request");
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                }
            }
        }
        Err(ClientError::Transport {
            attempts: MAX_RETRIES,
            message: last_err,
        })
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value, ClientError> {
        self.request_with_retry(reqwest::Method::POST, path, Some(body))
            .await
    }

    async fn get(&self, path: &str) -> Result<Value, ClientError> {
        self.request_with_retry(reqwest::Method::GET, path, None)
            .await
    }

    async fn put(&self, path: &str, body: &Value) -> Result<Value, ClientError> {
        self.request_with_retry(reqwest::Method::PUT, path, Some(body))
            .await
    }

    async fn delete(&self, path: &str) -> Result<Value, ClientError> {
        self.request_with_retry(reqwest::Method::DELETE, path, None)
            .await
    }

    async fn delete_with_body(&self, path: &str, body: &Value) -> Result<Value, ClientError> {
        self.request_with_retry(reqwest::Method::DELETE, path, Some(body))
            .await
    }

    // -- Tasks (auth) --------------------------------------------------------

    /// Fetch a single task's full record (the sealed brief fields + status).
    pub async fn get_task(&self, task_id: i64) -> Result<Value, ClientError> {
        self.get(&format!("/tasks/{task_id}")).await
    }

    /// Register a dispatcher identity with a stable client-specific label.
    /// Safe to call on every session bootstrap; the hub upserts by identity.
    pub async fn register_dispatcher(
        &self,
        identity: &IdentityFile,
        label: &str,
        hostname: &str,
        source: &str,
    ) -> Result<Value, ClientError> {
        let ts = unix_timestamp();
        let nonce = random_nonce();
        let envelope = json!({
            "op": "register-dispatcher",
            "dispatcher_id": identity.id,
            "public_key": identity.public_key_hex,
            "timestamp": ts,
            "nonce": nonce,
        });

        let signature = sign_envelope_hex(&identity.secret_key_hex, &envelope).map_err(|e| {
            ClientError::Transport {
                attempts: 0,
                message: format!("sign dispatcher registration: {e}"),
            }
        })?;
        self.post(
            "/dispatchers/register",
            &json!({
                "dispatcher_id": identity.id,
                "public_key": identity.public_key_hex,
                "label": label,
                "hostname": hostname,
                "metadata": { "source": source },
                "timestamp": ts,
                "nonce": nonce,
                "signature": signature,
            }),
        )
        .await
    }

    pub async fn list_runners(&self) -> Result<Value, ClientError> {
        self.get("/runners").await
    }

    pub async fn list_dispatchers(&self) -> Result<Value, ClientError> {
        self.get("/dispatchers").await
    }

    pub async fn list_tasks(&self, limit: u16) -> Result<Value, ClientError> {
        self.get(&format!("/tasks?limit={limit}")).await
    }

    pub async fn task_stream(
        &self,
        task_id: i64,
        after_seq: i64,
        limit: u16,
    ) -> Result<Value, ClientError> {
        self.get(&format!(
            "/tasks/{task_id}/stream?after_seq={after_seq}&limit={limit}"
        ))
        .await
    }

    pub async fn cancel_task(&self, task_id: i64) -> Result<Value, ClientError> {
        self.post(&format!("/tasks/{task_id}/cancel"), &json!({}))
            .await
    }

    pub async fn set_runner_drain(
        &self,
        runner_id: &str,
        drain: bool,
    ) -> Result<Value, ClientError> {
        let action = if drain { "drain" } else { "undrain" };
        self.post(
            &format!("/runners/{runner_id}/{action}-by-dispatcher"),
            &json!({}),
        )
        .await
    }

    pub async fn list_approvals(&self, status: &str, limit: u16) -> Result<Value, ClientError> {
        self.get(&format!("/approvals?status={status}&limit={limit}"))
            .await
    }

    pub async fn get_approval(&self, approval_id: &str) -> Result<Value, ClientError> {
        self.get(&format!("/approvals/{}", encode_path_segment(approval_id)))
            .await
    }

    pub async fn get_capability(&self, kind: &str, name: &str) -> Result<Value, ClientError> {
        self.get(&format!(
            "/capabilities/{}/{}",
            encode_path_segment(kind),
            encode_path_segment(name)
        ))
        .await
    }

    pub async fn decide_approval(
        &self,
        approval_id: &str,
        approve: bool,
        decision: &Value,
    ) -> Result<Value, ClientError> {
        let action = if approve { "approve" } else { "deny" };
        self.post(&format!("/approvals/{approval_id}/{action}"), decision)
            .await
    }

    pub async fn cost_budget(&self) -> Result<Value, ClientError> {
        self.get("/cost/budget").await
    }

    /// Return the effective hub policy and recent task decision evidence.
    pub async fn policy(&self) -> Result<Value, ClientError> {
        self.get("/policy").await
    }

    pub async fn settings(&self) -> Result<Value, ClientError> {
        self.get("/settings").await
    }

    pub async fn settings_schema(&self) -> Result<Value, ClientError> {
        self.get("/settings/schema").await
    }

    pub async fn set_setting(
        &self,
        key: &str,
        expected_revision: i64,
        value: Value,
    ) -> Result<Value, ClientError> {
        self.put(
            &format!("/settings/{}", encode_path_segment(key)),
            &json!({"expected_revision": expected_revision, "value": value}),
        )
        .await
    }

    pub async fn reset_setting(
        &self,
        key: &str,
        expected_revision: i64,
    ) -> Result<Value, ClientError> {
        self.delete_with_body(
            &format!("/settings/{}", encode_path_segment(key)),
            &json!({"expected_revision": expected_revision}),
        )
        .await
    }

    pub async fn history_status(&self) -> Result<Value, ClientError> {
        self.get("/history/status").await
    }

    pub async fn cost_summary(&self, since_days: u16) -> Result<Value, ClientError> {
        self.get(&format!("/cost/summary?since_days={since_days}"))
            .await
    }

    pub async fn cluster_health(&self) -> Result<Value, ClientError> {
        self.get("/cluster/health").await
    }

    /// `GET /whoami`: the installed credential's own subject, roles, and the
    /// `fabric.*.write` capability set the operator UI gates on. Uses the
    /// installed hub token (unlike [`Self::me`], which is human-session only).
    pub async fn whoami(&self) -> Result<Value, ClientError> {
        self.get("/whoami").await
    }

    pub async fn list_secrets(&self) -> Result<Value, ClientError> {
        self.get("/secrets").await
    }

    pub async fn put_or_rotate_secret(
        &self,
        name: &str,
        value: &str,
    ) -> Result<Value, ClientError> {
        self.post("/secrets", &json!({ "name": name, "value": value }))
            .await
    }

    pub async fn delete_secret(&self, name: &str) -> Result<Value, ClientError> {
        self.delete(&format!("/secrets/{}", encode_path_segment(name)))
            .await
    }

    pub async fn get_labels(&self) -> Result<Value, ClientError> {
        self.get("/labels").await
    }

    pub async fn set_hub_label(&self, name: &str, updated_by: &str) -> Result<Value, ClientError> {
        self.put(
            "/labels/hub",
            &json!({ "name": name, "updated_by": updated_by }),
        )
        .await
    }

    pub async fn set_host_label(
        &self,
        hostname: &str,
        alias: &str,
        updated_by: &str,
    ) -> Result<Value, ClientError> {
        self.put(
            &format!("/labels/hosts/{}", encode_path_segment(hostname)),
            &json!({ "alias": alias, "updated_by": updated_by }),
        )
        .await
    }

    pub async fn set_runner_label(
        &self,
        runner_id: &str,
        alias: &str,
        updated_by: &str,
    ) -> Result<Value, ClientError> {
        self.put(
            &format!("/labels/runners/{}", encode_path_segment(runner_id)),
            &json!({ "alias": alias, "updated_by": updated_by }),
        )
        .await
    }

    /// Dispatch a task via the signed POST /tasks/v2 path.
    ///
    /// `brief` carries the dispatch fields (title, prompt, scope_globs,
    /// base_commit, branch, and any optional routing/metadata). The dispatcher
    /// identity signs the canonical envelope over the protocol-v3 execution-semantics set
    /// the hub verifies; the signed envelope, nonce, and timestamp are attached
    /// to the request body. There is no unsigned dispatch path — every
    /// state-changing dispatch is ed25519-signed (hard rule #6).
    pub async fn dispatch_signed(
        &self,
        identity: &IdentityFile,
        brief: &Value,
    ) -> Result<Value, ClientError> {
        let ts = unix_timestamp();
        let nonce = random_nonce();

        // The hub verifies exactly this envelope (op + the brief's signed core
        // + timestamp + nonce). Keep field set and order identical to the hub's
        // POST /tasks/v2 verification in fabric-hub::routes::tasks.
        let mut envelope = json!({
            "op": "dispatch",
            "dispatcher_id": identity.id,
            "title": brief.get("title").cloned().unwrap_or(Value::Null),
            "prompt": brief.get("prompt").cloned().unwrap_or(Value::Null),
            "scope_globs": brief.get("scope_globs").cloned().unwrap_or_else(|| json!([])),
            "base_commit": brief.get("base_commit").cloned().unwrap_or(Value::Null),
            "branch": brief.get("branch").cloned().unwrap_or(Value::Null),
            "todo_id": brief.get("todo_id").cloned().unwrap_or(Value::Null),
            "timeout_minutes": brief.get("timeout_minutes").cloned().unwrap_or_else(|| json!(60)),
            "priority": brief.get("priority").cloned().unwrap_or_else(|| json!(100)),
            "metadata": brief.get("metadata").cloned().unwrap_or(Value::Null),
            "required_tools": brief.get("required_tools").cloned().unwrap_or(Value::Null),
            "required_tags": brief.get("required_tags").cloned().unwrap_or(Value::Null),
            "required_capabilities": brief.get("required_capabilities").cloned().unwrap_or(Value::Null),
            "secrets_needed": brief.get("secrets_needed").cloned().unwrap_or(Value::Null),
            "network_egress": brief.get("network_egress").cloned().unwrap_or(Value::Null),
            "tenant": brief.get("tenant").cloned().unwrap_or(Value::Null),
            "workspace_root": brief.get("workspace_root").cloned().unwrap_or(Value::Null),
            "require_base_commit": brief.get("require_base_commit").cloned().unwrap_or(json!(false)),
            "kind": brief.get("kind").cloned().unwrap_or(json!("agent")),
            "max_cost_usd": brief.get("max_cost_usd").cloned().unwrap_or(Value::Null),
            "timestamp": ts,
            "nonce": nonce,
        });

        // Command tasks carry executable semantics that the hub requires the
        // dispatcher to cover explicitly. Environment values are represented
        // by a canonical digest so secret-bearing values are authenticated
        // without being copied into the signed envelope.
        let mut command_env_digest = None;
        if brief.get("kind").and_then(Value::as_str) == Some("command") {
            let command = brief
                .get("command")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    ClientError::Protocol("command brief requires a command array".to_string())
                })?;
            let cwd = brief.get("cwd").and_then(Value::as_str).unwrap_or("");
            let env = brief.get("env").cloned().unwrap_or_else(|| json!({}));
            let env_object = env.as_object().ok_or_else(|| {
                ClientError::Protocol("command brief env must be an object".to_string())
            })?;
            if env_object.values().any(|value| !value.is_string()) {
                return Err(ClientError::Protocol(
                    "command brief env values must be strings".to_string(),
                ));
            }
            let mut env_keys: Vec<String> = env_object.keys().cloned().collect();
            env_keys.sort();
            let canonical = canonicalize(&env).map_err(|error| {
                ClientError::Protocol(format!("canonicalize command env: {error}"))
            })?;
            let digest = hex::encode(Sha256::digest(canonical));

            let object = envelope.as_object_mut().ok_or_else(|| {
                ClientError::Protocol("dispatch envelope must be an object".to_string())
            })?;
            object.insert("loom_command".into(), Value::Array(command.clone()));
            object.insert("loom_cwd".into(), json!(cwd));
            object.insert("loom_env_keys".into(), json!(env_keys));
            object.insert("loom_env_digest".into(), json!(digest));
            command_env_digest = Some(digest);
        }
        let signature = sign_envelope_hex(&identity.secret_key_hex, &envelope).map_err(|e| {
            ClientError::Transport {
                attempts: 0,
                message: format!("sign: {e}"),
            }
        })?;

        // Request body = the full brief (flattened) + dispatcher auth fields.
        let mut body = brief.clone();
        if let Some(obj) = body.as_object_mut() {
            obj.insert("dispatcher_id".into(), json!(identity.id));
            obj.insert("timestamp".into(), json!(ts));
            obj.insert("nonce".into(), json!(nonce));
            obj.insert("signature".into(), json!(signature));
            if let Some(digest) = command_env_digest {
                obj.insert("loom_env_digest".into(), json!(digest));
            }
        } else {
            return Err(ClientError::Protocol(
                "dispatch brief must be an object".to_string(),
            ));
        }
        self.post("/tasks/v2", &body).await
    }

    // -- Self-update (auth) --------------------------------------------------

    /// List role-separated bearer metadata. Credential values and hashes are
    /// never returned by the hub.
    pub async fn list_role_tokens(&self, include_revoked: bool) -> Result<Value, ClientError> {
        self.get(&format!(
            "/admin/role-tokens?include_revoked={include_revoked}"
        ))
        .await
    }

    /// Issue a new role token. The `token` field in the response is shown once.
    pub async fn issue_role_token(
        &self,
        label: &str,
        roles: &[String],
    ) -> Result<Value, ClientError> {
        self.post(
            "/admin/role-tokens",
            &json!({ "label": label, "roles": roles }),
        )
        .await
    }

    /// Import a pre-existing bearer into the role-token store. The hub hashes
    /// it immediately and never returns the raw value.
    pub async fn migrate_role_token(
        &self,
        token: &str,
        label: &str,
        roles: &[String],
    ) -> Result<Value, ClientError> {
        self.post(
            "/admin/role-tokens/migrate",
            &json!({ "token": token, "label": label, "roles": roles }),
        )
        .await
    }

    /// Split the installed legacy compatibility bundle into one random token
    /// for each role. Every credential value is returned exactly once.
    pub async fn split_legacy_role_tokens(&self, label_prefix: &str) -> Result<Value, ClientError> {
        self.post(
            "/admin/role-tokens/split",
            &json!({ "label_prefix": label_prefix }),
        )
        .await
    }

    pub async fn revoke_role_token(&self, token_id: &str) -> Result<Value, ClientError> {
        self.delete(&format!(
            "/admin/role-tokens/{}",
            encode_path_segment(token_id)
        ))
        .await
    }

    /// Fetch this hub's staged-binary manifest: `{version, files:[{name,sha256,size}]}`.
    pub async fn binaries_manifest(&self) -> Result<Value, ClientError> {
        self.get("/admin/binaries/manifest").await
    }

    /// Trigger this node's in-place self-update. `from_hub` is the hub to pull
    /// staged binaries from (None = use this node's local staged dir).
    pub async fn trigger_self_update(
        &self,
        from_hub: Option<&str>,
        include_vsix: bool,
    ) -> Result<Value, ClientError> {
        let body = json!({
            "from_hub": from_hub,
            "include_vsix": include_vsix,
        });
        self.post("/admin/update", &body).await
    }

    // -- Audit (auth) --------------------------------------------------------

    /// Fetch the audit events for a UTC day (`YYYY-MM-DD`) plus the hub's
    /// chain-verification verdict. Returns the raw `/audit/day/{day}` body.
    pub async fn audit_day(&self, day: &str) -> Result<Value, ClientError> {
        self.get(&format!("/audit/day/{day}")).await
    }

    /// Fetch the audit events for a single task plus chain verification.
    pub async fn audit_for_task(&self, task_id: i64) -> Result<Value, ClientError> {
        self.get(&format!("/audit/tasks/{task_id}")).await
    }

    /// Fetch the current audit chain tail hash.
    pub async fn audit_tail(&self) -> Result<Value, ClientError> {
        self.get("/audit/tail").await
    }

    // -- Cluster registry (auth) -----------------------------------------------

    /// Fabric agent registry: every runner with `kinds ∋ "agent"` plus its manifest.
    pub async fn list_agents(&self) -> Result<Value, ClientError> {
        self.get("/agents").await
    }

    /// Cluster host map: hosts with their runners, dispatchers, and roles.
    pub async fn list_hosts(&self) -> Result<Value, ClientError> {
        self.get("/hosts").await
    }

    // -- Healthz (no auth) ---------------------------------------------------

    pub async fn healthz(&self) -> Result<Value, ClientError> {
        let url = format!("{}/healthz", self.base_url);
        match self
            .http
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                let text = resp.text().await.unwrap_or_default();
                Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
            }
            Err(e) => Err(ClientError::Transport {
                attempts: 1,
                message: e.to_string(),
            }),
        }
    }

    // -- Human accounts (114C) -- self-service, no bearer required ----------

    /// `GET /auth/bootstrap/status`: `true` while the realm has no
    /// administrator yet.
    pub async fn bootstrap_status(&self) -> Result<Value, ClientError> {
        self.get("/auth/bootstrap/status").await
    }

    /// `GET /auth/webauthn/doctor` (114C.6 Slice 7): explains why passkeys
    /// are or are not ready on this hub -- disabled, unconfigured, every
    /// origin insecure, an RP ID matching none of them, or a config fix
    /// that is correct but not yet live because the hub needs a restart.
    pub async fn webauthn_doctor(&self) -> Result<Value, ClientError> {
        self.get("/auth/webauthn/doctor").await
    }

    /// `POST /auth/bootstrap`: create the realm's first administrator.
    /// Unlike every other request this client sends, no `Authorization`
    /// header is attached (there is no credential yet); the hub instead
    /// gates this route on the caller's source address (loopback-only by
    /// default) and, if configured, `bootstrap_secret` via a dedicated
    /// header -- never a bearer token.
    pub async fn bootstrap(
        &self,
        username: &str,
        display_name: &str,
        password: &str,
        bootstrap_secret: Option<&str>,
    ) -> Result<Value, ClientError> {
        let url = format!("{}/auth/bootstrap", self.base_url);
        let mut req = self.http.post(&url).json(&json!({
            "username": username,
            "display_name": display_name,
            "password": password,
        }));
        if let Some(secret) = bootstrap_secret {
            req = req.header("X-Forgewire-Bootstrap-Secret", secret);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                if (200..300).contains(&status) {
                    Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
                } else {
                    Err(ClientError::Hub { status, body: text })
                }
            }
            Err(e) => Err(ClientError::Transport {
                attempts: 1,
                message: e.to_string(),
            }),
        }
    }

    // -- Human accounts (114C.7 Slice 2): the remaining 23 directly-wireable
    // routes (Slice 1 proved the shape on bootstrap/status; `bootstrap` and
    // `bootstrap_status` above predate this slice). 4 of the remaining 6 --
    // register/login passkey options+verify -- are not wired here: they
    // carry a live WebAuthn ceremony this backend has no way to drive (no
    // `navigator.credentials` in a Tauri Rust process); Desktop's existing
    // `webauthn_bridge` module (114C.6 Slice 5d) already opens a browser to
    // run that ceremony end to end against those routes directly, never
    // through this client. The other 2 -- step-up options+verify -- *are*
    // wired below (114C.7 Slice 5b): unlike login/register, step-up only
    // needs the browser to relay a `credentials.get` assertion, so this
    // client (which already holds the session bearer) makes both
    // authenticated calls itself.
    //
    // Single-attempt, no retry, unlike `request_with_retry` above: an
    // account-mutation or session-issuing call silently retried after a
    // successful-but-slow response could double-spend a refresh secret or
    // double-submit a recovery code. `bootstrap()` above already made this
    // same choice for the same reason.
    async fn request_auth(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        cred: Option<SessionCredential<'_>>,
    ) -> Result<Value, ClientError> {
        let url = format!("{}{}", self.base_url, path);
        // Serialize the body exactly once. For the PoP path the hub authenticates
        // `body_sha256` over the raw request bytes, so the bytes we hash MUST be
        // byte-identical to the bytes we send — hence an explicit `to_vec` +
        // `.body(...)` rather than reqwest's `.json(...)` (which would serialize
        // a second, potentially different, copy).
        let body_bytes: Vec<u8> = match body {
            Some(b) => serde_json::to_vec(b)
                .map_err(|e| ClientError::Protocol(format!("serialize request body: {e}")))?,
            None => Vec::new(),
        };
        let mut req = self.http.request(method.clone(), &url);
        match cred {
            Some(SessionCredential::Bearer(token)) => {
                req = req.header("Authorization", format!("Bearer {token}"));
            }
            Some(SessionCredential::Pop {
                session_id,
                secret_key_hex,
            }) => {
                let ts = unix_timestamp();
                let nonce = random_nonce();
                // The hub reconstructs and verifies exactly this envelope in
                // `fabric_hub::auth::resolve_signed_session`. `method` is the
                // HTTP method string; `path` is the URI path WITHOUT query
                // (matching `req.uri().path()` hub-side); `body_sha256` binds the
                // body so a captured signature cannot be replayed with a
                // different payload; `timestamp` is a JSON number (i64).
                // The hub signs `req.uri().path()` -- the path WITHOUT any query
                // string -- so a request that carries a query (e.g.
                // `/auth/sessions?account_id=…`) must sign only the part before
                // `?`, or verification fails. The query is still sent on the
                // wire; it is simply outside the signed envelope (a documented
                // Slice-1 boundary: query params are not body-bound).
                let signed_path = path.split('?').next().unwrap_or(path);
                let envelope = session_request_envelope(
                    session_id,
                    method.as_str(),
                    signed_path,
                    &hex::encode(Sha256::digest(&body_bytes)),
                    ts,
                    &nonce,
                );
                let signature = sign_envelope_hex(secret_key_hex, &envelope)
                    .map_err(|e| ClientError::Protocol(format!("sign session request: {e}")))?;
                req = req
                    .header("x-forgewire-session", session_id)
                    .header("x-forgewire-timestamp", ts.to_string())
                    .header("x-forgewire-nonce", nonce)
                    .header("x-forgewire-signature", signature);
            }
            None => {}
        }
        if !body_bytes.is_empty() {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body_bytes);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                if (200..300).contains(&status) {
                    Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
                } else {
                    Err(ClientError::Hub { status, body: text })
                }
            }
            Err(e) => Err(ClientError::Transport {
                attempts: 1,
                message: e.to_string(),
            }),
        }
    }

    /// `POST /auth/login`: username+password sign-in. Public route -- the
    /// returned `access_secret`/`refresh_secret` are the credential the
    /// caller must persist in platform secure storage (Tauri keychain),
    /// never in this client's own state.
    ///
    /// `session_public_key` (114E) is an optional hex Ed25519 public key to
    /// bind the new session to for proof-of-possession. When supplied, the
    /// caller keeps the matching private key in secure storage and thereafter
    /// authenticates with [`SessionCredential::Pop`] instead of the bearer.
    /// Omitting it yields today's bearer-only session, unchanged.
    #[allow(clippy::too_many_arguments)]
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        client_kind: Option<&str>,
        client_label: Option<&str>,
        session_public_key: Option<&str>,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            "/auth/login",
            Some(&json!({
                "username": username, "password": password,
                "client_kind": client_kind, "client_label": client_label,
                "session_public_key": session_public_key,
            })),
            None,
        )
        .await
    }

    /// `GET /auth/me` via proof-of-possession (114E): authenticate the current
    /// session by *signing* the request with its bound Ed25519 private key
    /// instead of presenting the bearer `access_secret`. The session must have
    /// been key-bound at login. This is the canonical PoP self-service call the
    /// Desktop uses once it holds the session key in the OS keyring.
    pub async fn me_signed(
        &self,
        session_id: &str,
        secret_key_hex: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::GET,
            "/auth/me",
            None,
            Some(SessionCredential::Pop {
                session_id,
                secret_key_hex,
            }),
        )
        .await
    }

    /// `POST /auth/logout` via proof-of-possession: revoke the calling session,
    /// authenticated by signing with its bound key. `session_id` is both the
    /// signing session and the revocation target (self-logout).
    pub async fn logout_signed(
        &self,
        session_id: &str,
        secret_key_hex: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            "/auth/logout",
            Some(&json!({ "session_id": session_id })),
            Some(SessionCredential::Pop {
                session_id,
                secret_key_hex,
            }),
        )
        .await
    }

    /// `GET /auth/sessions` via proof-of-possession. `session_id`/`secret_key_hex`
    /// authenticate the caller; `account_id` is the optional admin filter.
    pub async fn list_auth_sessions_signed(
        &self,
        session_id: &str,
        secret_key_hex: &str,
        account_id: Option<&str>,
    ) -> Result<Value, ClientError> {
        let path = match account_id {
            Some(id) => format!("/auth/sessions?account_id={}", encode_path_segment(id)),
            None => "/auth/sessions".to_owned(),
        };
        self.request_auth(
            reqwest::Method::GET,
            &path,
            None,
            Some(SessionCredential::Pop {
                session_id,
                secret_key_hex,
            }),
        )
        .await
    }

    /// `DELETE /auth/sessions/{target}` via proof-of-possession. `session_id`/
    /// `secret_key_hex` authenticate the caller; `target_session_id` is the
    /// session to revoke (own session, or another when the caller is admin --
    /// enforced hub-side).
    pub async fn revoke_auth_session_signed(
        &self,
        session_id: &str,
        secret_key_hex: &str,
        target_session_id: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::DELETE,
            &format!("/auth/sessions/{}", encode_path_segment(target_session_id)),
            None,
            Some(SessionCredential::Pop {
                session_id,
                secret_key_hex,
            }),
        )
        .await
    }

    /// `POST /auth/refresh`: rotate a session's refresh secret.
    pub async fn refresh_session(
        &self,
        session_id: &str,
        refresh_secret: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            "/auth/refresh",
            Some(&json!({ "session_id": session_id, "refresh_secret": refresh_secret })),
            None,
        )
        .await
    }

    /// `POST /auth/logout`: revoke one session (self-service or admin;
    /// ownership enforced hub-side).
    pub async fn logout(
        &self,
        access_secret: &str,
        session_id: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            "/auth/logout",
            Some(&json!({ "session_id": session_id })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /auth/logout-all`: revoke every session for the caller's own
    /// account.
    pub async fn logout_all(&self, access_secret: &str) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            "/auth/logout-all",
            None,
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `GET /auth/me`: the caller's own account summary.
    pub async fn me(&self, access_secret: &str) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::GET,
            "/auth/me",
            None,
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `DELETE /auth/passkeys/{id}`: remove one of the caller's own
    /// passkeys. Registering a passkey goes through `webauthn_bridge`, not
    /// this method -- see the ceremony-routes note above.
    pub async fn remove_passkey(
        &self,
        access_secret: &str,
        credential_id: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::DELETE,
            &format!("/auth/passkeys/{}", encode_path_segment(credential_id)),
            None,
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `GET /auth-policy`: realm id, whether bootstrap is still open, and
    /// the full role vocabulary. NOT public -- `required_roles` in
    /// `fabric-hub/src/auth.rs` gates it on `observer`/`reviewer` like any
    /// other authenticated route. (Discovered live 2026-07-22: this method
    /// previously called it with no bearer at all via `request_auth(...,
    /// None)`, so it always 401'd; every caller's "does this hub advertise
    /// human_accounts" probe silently failed regardless of hub support.)
    /// Uses the installed automation token via `self.get`, same as
    /// [`Self::whoami`] -- any credential holding at least `observer`
    /// satisfies it, so the pre-existing automation token is sufficient
    /// context, no human session required.
    pub async fn auth_policy(&self) -> Result<Value, ClientError> {
        self.get("/auth-policy").await
    }

    /// `GET /auth/sessions`: the caller's own sessions, or (admin only)
    /// another account's when `account_id` is supplied.
    pub async fn list_auth_sessions(
        &self,
        access_secret: &str,
        account_id: Option<&str>,
    ) -> Result<Value, ClientError> {
        let path = match account_id {
            Some(id) => format!("/auth/sessions?account_id={}", encode_path_segment(id)),
            None => "/auth/sessions".to_owned(),
        };
        self.request_auth(
            reqwest::Method::GET,
            &path,
            None,
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `DELETE /auth/sessions/{id}`: revoke a session by id (self-service or
    /// admin; ownership enforced hub-side).
    pub async fn revoke_auth_session(
        &self,
        access_secret: &str,
        session_id: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::DELETE,
            &format!("/auth/sessions/{}", encode_path_segment(session_id)),
            None,
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    // -- Step-up (114C.7 Slice 5b). Mirrors VSIX `hubClient.ts`'s Slice
    // 4c-3a `stepUpOptions`/`stepUpVerify` methods exactly: this client
    // holds the session bearer and calls both authenticated ends itself;
    // only the WebAuthn assertion crosses through the browser bridge
    // (`webauthn_bridge` module in the desktop crate), never this client's
    // own secret.

    /// `POST /auth/step-up/options`: start a step-up ceremony for the
    /// caller's current session. No body; returns the WebAuthn request
    /// challenge.
    pub async fn step_up_options(&self, access_secret: &str) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            "/auth/step-up/options",
            Some(&json!({})),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /auth/step-up/verify`: complete step-up with the relayed
    /// assertion. Returns the elevated session's new (rotated) access
    /// secret.
    pub async fn step_up_verify(
        &self,
        access_secret: &str,
        challenge_id: &str,
        options_token: &str,
        credential: &Value,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            "/auth/step-up/verify",
            Some(&json!({
                "challenge_id": challenge_id,
                "options_token": options_token,
                "credential": credential,
            })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    // -- Account administration (all `admin`-role-gated; `access_secret`
    // must be an admin's own human-session access secret -- `admin` can
    // never be carried by the automation `self.token` this client also
    // holds, see `required_roles` in `crates/fabric-hub/src/auth.rs`) ------

    /// `GET /accounts`: paginated account list. Readable by `admin` or
    /// `reviewer`.
    pub async fn list_accounts(
        &self,
        access_secret: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::GET,
            &format!("/accounts?limit={limit}&offset={offset}"),
            None,
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /accounts`: create a new account with an initial password and
    /// role. `admin` only.
    pub async fn create_account(
        &self,
        access_secret: &str,
        username: &str,
        display_name: &str,
        password: &str,
        role: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            "/accounts",
            Some(&json!({
                "username": username, "display_name": display_name,
                "password": password, "role": role,
            })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `GET /accounts/{id}`. Readable by `admin` or `reviewer`.
    pub async fn get_account(
        &self,
        access_secret: &str,
        account_id: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::GET,
            &format!("/accounts/{}", encode_path_segment(account_id)),
            None,
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `PATCH /accounts/{id}`: the narrow status-transition route -- unlock
    /// or admin-forced recovery toggling, per `transition_allowed` in
    /// `accounts.rs`. Not for `active` <-> `disabled` (use
    /// `disable_account`/`enable_account`). `expected_revision` must be the
    /// account's current `revision` from a prior read -- this is a
    /// compare-and-set route.
    pub async fn update_account_status(
        &self,
        access_secret: &str,
        account_id: &str,
        status: &str,
        expected_revision: i64,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::PATCH,
            &format!("/accounts/{}", encode_path_segment(account_id)),
            Some(&json!({ "status": status, "expected_revision": expected_revision })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /accounts/{id}/membership`: grant a role. `admin` only.
    pub async fn grant_membership(
        &self,
        access_secret: &str,
        account_id: &str,
        role: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            &format!("/accounts/{}/membership", encode_path_segment(account_id)),
            Some(&json!({ "role": role })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `DELETE /accounts/{id}/membership/{role}`: revoke a role, protecting
    /// the realm's last enabled administrator. `admin` only.
    pub async fn revoke_membership(
        &self,
        access_secret: &str,
        account_id: &str,
        role: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::DELETE,
            &format!(
                "/accounts/{}/membership/{}",
                encode_path_segment(account_id),
                encode_path_segment(role)
            ),
            None,
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /accounts/{id}/disable`: protects the last enabled admin.
    /// `expected_revision` is a compare-and-set token, see
    /// `update_account_status`.
    pub async fn disable_account(
        &self,
        access_secret: &str,
        account_id: &str,
        expected_revision: i64,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            &format!("/accounts/{}/disable", encode_path_segment(account_id)),
            Some(&json!({ "expected_revision": expected_revision })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /accounts/{id}/enable`: only valid from `disabled`.
    pub async fn enable_account(
        &self,
        access_secret: &str,
        account_id: &str,
        expected_revision: i64,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            &format!("/accounts/{}/enable", encode_path_segment(account_id)),
            Some(&json!({ "expected_revision": expected_revision })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /accounts/{id}/recovery-codes`: generates and returns
    /// plaintext recovery codes exactly once -- caller must display and
    /// discard, never cache or log them. `admin` only.
    pub async fn generate_recovery_codes(
        &self,
        access_secret: &str,
        account_id: &str,
        count: i64,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            &format!(
                "/accounts/{}/recovery-codes",
                encode_path_segment(account_id)
            ),
            Some(&json!({ "count": count })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /accounts/{id}/recovery/complete`: redeem a recovery code and
    /// set a new password.
    pub async fn complete_recovery(
        &self,
        access_secret: &str,
        account_id: &str,
        code: &str,
        new_password: &str,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            &format!(
                "/accounts/{}/recovery/complete",
                encode_path_segment(account_id)
            ),
            Some(&json!({ "code": code, "new_password": new_password })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /accounts/{id}/delete`: step one of two-step deletion -- marks
    /// `deletion_pending`, revokes sessions, protects the last admin.
    /// `admin` only.
    pub async fn initiate_account_deletion(
        &self,
        access_secret: &str,
        account_id: &str,
        expected_revision: i64,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            &format!("/accounts/{}/delete", encode_path_segment(account_id)),
            Some(&json!({ "expected_revision": expected_revision })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /accounts/{id}/tombstone`: step two, irreversible. Requires
    /// the account already be `deletion_pending`. `admin` only.
    pub async fn complete_account_deletion(
        &self,
        access_secret: &str,
        account_id: &str,
        expected_revision: i64,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            &format!("/accounts/{}/tombstone", encode_path_segment(account_id)),
            Some(&json!({ "expected_revision": expected_revision })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `GET /accounts/{id}/security-history`: bounded recent login attempts
    /// and sessions. Readable by `admin` or `reviewer`.
    pub async fn account_security_history(
        &self,
        access_secret: &str,
        account_id: &str,
        limit: i64,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::GET,
            &format!(
                "/accounts/{}/security-history?limit={limit}",
                encode_path_segment(account_id)
            ),
            None,
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `GET /accounts/export` (114C.5): a redacted profile-only snapshot of
    /// every account in the realm. Step-up gated, `admin`/`reviewer`.
    pub async fn export_accounts(&self, access_secret: &str) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::GET,
            "/accounts/export",
            None,
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    /// `POST /accounts/import` (114C.5): preview (`dry_run: true`, the
    /// default) or apply (`dry_run: false`) a ForgeWire account-interchange
    /// `document`. Step-up gated, `admin` only. `document` is forwarded
    /// as-is -- this client does not validate its shape; the hub's own
    /// `deny_unknown_fields` parsing is the enforcement boundary.
    pub async fn import_accounts(
        &self,
        access_secret: &str,
        document: &Value,
        dry_run: bool,
    ) -> Result<Value, ClientError> {
        self.request_auth(
            reqwest::Method::POST,
            "/accounts/import",
            Some(&json!({ "document": document, "dry_run": dry_run })),
            Some(SessionCredential::Bearer(access_secret)),
        )
        .await
    }

    // -- Runner registration (signed) ----------------------------------------

    pub async fn register_runner(
        &self,
        identity: &IdentityFile,
        payload: &RegisterPayload,
    ) -> Result<Value, ClientError> {
        let ts = unix_timestamp();
        let nonce = random_nonce();

        let signed_fields = json!({
            "op": "register",
            "runner_id": identity.id,
            "public_key": identity.public_key_hex,
            "protocol_version": payload.protocol_version,
            "timestamp": ts,
            "nonce": nonce,
        });
        let canonical =
            canonicalize(&signed_fields).map_err(|e| ClientError::Protocol(e.to_string()))?;
        let signature = sign_payload_hex(&identity.secret_key_hex, &canonical)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;

        let mut body = json!({
            "runner_id": identity.id,
            "public_key": identity.public_key_hex,
            "protocol_version": payload.protocol_version,
            "runner_version": payload.runner_version,
            "hostname": payload.hostname,
            "os": payload.os,
            "arch": payload.arch,
            "tools": payload.tools,
            "tags": payload.tags,
            "kinds": payload.kinds,
            "agent_type": payload.agent_type,
            "mcp_manifest": payload.mcp_manifest,
            "scope_prefixes": payload.scope_prefixes,
            "max_concurrent": payload.max_concurrent,
            "capabilities": payload.capabilities,
            "metadata": payload.metadata,
            "timestamp": ts,
            "nonce": nonce,
            "signature": signature,
        });
        if let Some(ref t) = payload.tenant {
            body["tenant"] = json!(t);
        }
        if let Some(ref w) = payload.workspace_root {
            body["workspace_root"] = json!(w);
        }
        if let Some(ref m) = payload.cpu_model {
            body["cpu_model"] = json!(m);
        }
        if let Some(c) = payload.cpu_count {
            body["cpu_count"] = json!(c);
        }
        if let Some(r) = payload.ram_mb {
            body["ram_mb"] = json!(r);
        }
        if let Some(ref g) = payload.gpu {
            body["gpu"] = json!(g);
        }

        self.post("/runners/register", &body).await
    }

    // -- Heartbeat (signed) --------------------------------------------------

    pub async fn heartbeat(
        &self,
        identity: &IdentityFile,
        stats: &HeartbeatStats,
    ) -> Result<Value, ClientError> {
        let ts = unix_timestamp();
        let nonce = random_nonce();

        let signed_fields = json!({
            "op": "heartbeat",
            "runner_id": identity.id,
            "timestamp": ts,
            "nonce": nonce,
        });
        let canonical =
            canonicalize(&signed_fields).map_err(|e| ClientError::Protocol(e.to_string()))?;
        let signature = sign_payload_hex(&identity.secret_key_hex, &canonical)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;

        let body = json!({
            "runner_id": identity.id,
            "timestamp": ts,
            "nonce": nonce,
            "signature": signature,
            "cpu_load_pct": stats.cpu_load_pct,
            "ram_free_mb": stats.ram_free_mb,
            "battery_pct": stats.battery_pct,
            "on_battery": stats.on_battery,
            "last_known_commit": stats.last_known_commit,
            "claim_failures_total": stats.claim_failures_total,
            "claim_failures_consecutive": stats.claim_failures_consecutive,
            "last_claim_error": stats.last_claim_error,
            "heartbeat_failures_total": stats.heartbeat_failures_total,
        });

        self.post(&format!("/runners/{}/heartbeat", identity.id), &body)
            .await
    }

    /// Claim from the Loom (command-kind) queue via `/tasks/claim-loom`.
    pub async fn claim_loom(
        &self,
        identity: &IdentityFile,
        claim: &ClaimPayload,
    ) -> Result<ClaimResponse, ClientError> {
        let ts = unix_timestamp();
        let nonce = random_nonce();
        let signed_fields = json!({
            "op": "claim",
            "runner_id": identity.id,
            "timestamp": ts,
            "nonce": nonce,
        });
        let canonical =
            canonicalize(&signed_fields).map_err(|e| ClientError::Protocol(e.to_string()))?;
        let signature = sign_payload_hex(&identity.secret_key_hex, &canonical)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        let body = json!({
            "runner_id": identity.id,
            "timestamp": ts,
            "nonce": nonce,
            "signature": signature,
            "scope_prefixes": claim.scope_prefixes,
            "tools": claim.tools,
            "tags": claim.tags,
            "tenant": claim.tenant,
            "workspace_root": claim.workspace_root,
            "last_known_commit": claim.last_known_commit,
            "cpu_load_pct": claim.cpu_load_pct,
            "ram_free_mb": claim.ram_free_mb,
            "battery_pct": claim.battery_pct,
            "on_battery": claim.on_battery,
        });
        let val = self.post("/tasks/claim-loom", &body).await?;
        let task = if val["task"].is_null() {
            None
        } else {
            Some(val["task"].clone())
        };
        Ok(ClaimResponse {
            task,
            info: val.get("info").cloned().unwrap_or(Value::Null),
        })
    }

    // -- Task lifecycle (bearer-only, compat quarantine) ----------------------

    pub async fn mark_running(&self, task_id: i64) -> Result<Value, ClientError> {
        self.post(&format!("/tasks/{task_id}/start"), &json!({}))
            .await
    }

    /// M2.5.1 — POST an intent-to-do event and return the hub decision.
    ///
    /// Returns `Ok(value)` on 200 (allowed).
    /// Returns `Err(e)` where `e.is_policy_denied()` on 403 (hard deny).
    /// Returns `Err(e)` where `e.is_approval_required()` on 428; use
    /// `e.approval_id()` to retrieve the approval_id for the re-POST.
    #[allow(clippy::too_many_arguments)]
    pub async fn post_intent(
        &self,
        task_id: i64,
        worker_id: &str,
        kind: &str,
        paths: &[&str],
        hosts: &[&str],
        command: Option<&str>,
        workspace_root: Option<&str>,
        branch: Option<&str>,
        approval_id: Option<&str>,
    ) -> Result<Value, ClientError> {
        let body = json!({
            "worker_id": worker_id,
            "kind": kind,
            "paths": paths,
            "hosts": hosts,
            "command": command,
            "workspace_root": workspace_root,
            "branch": branch,
            "approval_id": approval_id,
        });
        self.post(&format!("/tasks/{task_id}/intent"), &body).await
    }

    pub async fn append_stream(
        &self,
        task_id: i64,
        worker_id: &str,
        channel: &str,
        line: &str,
    ) -> Result<Value, ClientError> {
        self.post(
            &format!("/tasks/{task_id}/stream"),
            &json!({
                "worker_id": worker_id,
                "channel": channel,
                "line": line,
            }),
        )
        .await
    }

    pub async fn append_progress_event(
        &self,
        task_id: i64,
        worker_id: &str,
        message: &str,
        event: &str,
        details: &Value,
    ) -> Result<Value, ClientError> {
        self.post(
            &format!("/tasks/{task_id}/progress"),
            &json!({
                "worker_id": worker_id,
                "message": message,
                "files_touched": [],
                "event": event,
                "details": details,
            }),
        )
        .await
    }

    pub async fn append_stream_bulk(
        &self,
        task_id: i64,
        worker_id: &str,
        entries: &[StreamEntry],
    ) -> Result<Value, ClientError> {
        let entries_json: Vec<Value> = entries
            .iter()
            .map(|e| json!({"channel": e.channel, "line": e.line}))
            .collect();
        self.post(
            &format!("/tasks/{task_id}/stream/bulk"),
            &json!({
                "worker_id": worker_id,
                "entries": entries_json,
            }),
        )
        .await
    }

    pub async fn submit_result(
        &self,
        task_id: i64,
        result: &TaskResult,
    ) -> Result<Value, ClientError> {
        let mut body = json!({
            "worker_id": result.worker_id,
            "status": result.status,
            "head_commit": result.head_commit,
            "commits": result.commits,
            "files_touched": result.files_touched,
            "test_summary": result.test_summary,
            "log_tail": result.log_tail,
            "error": result.error,
        });
        if let Some(rc) = result.exit_code {
            body["exit_code"] = json!(rc);
        }
        self.post(&format!("/tasks/{task_id}/result"), &body).await
    }

    // -- Drain (signed) ------------------------------------------------------

    pub async fn drain(&self, identity: &IdentityFile) -> Result<Value, ClientError> {
        let ts = unix_timestamp();
        let nonce = random_nonce();

        let signed_fields = json!({
            "op": "drain",
            "runner_id": identity.id,
            "timestamp": ts,
            "nonce": nonce,
        });
        let canonical =
            canonicalize(&signed_fields).map_err(|e| ClientError::Protocol(e.to_string()))?;
        let signature = sign_payload_hex(&identity.secret_key_hex, &canonical)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;

        let body = json!({
            "runner_id": identity.id,
            "timestamp": ts,
            "nonce": nonce,
            "signature": signature,
        });

        self.post(&format!("/runners/{}/drain", identity.id), &body)
            .await
    }

    /// M2.9.4 (F4): drain signed stdin batches with seq > after_seq.
    /// Called by runners to feed queued lines into the running process stdin.
    pub async fn get_task_input(&self, task_id: i64, after_seq: i64) -> Result<Value, ClientError> {
        self.get(&format!("/tasks/{task_id}/input?after_seq={after_seq}"))
            .await
    }
}

// -- Payload types -----------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPayload {
    pub protocol_version: i64,
    pub runner_version: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub cpu_model: Option<String>,
    pub cpu_count: Option<i64>,
    pub ram_mb: Option<i64>,
    pub gpu: Option<String>,
    pub tools: Vec<String>,
    pub tags: Vec<String>,
    pub scope_prefixes: Vec<String>,
    pub tenant: Option<String>,
    pub workspace_root: Option<String>,
    pub max_concurrent: i64,
    pub capabilities: HashMap<String, Value>,
    pub metadata: HashMap<String, Value>,
    /// Hard runner-kind property. ``["agent"]`` for Fabric runners,
    /// ``["command"]`` for Loom runners, ``["agent","command"]`` for combined.
    pub kinds: Vec<String>,
    /// Free-form agent type string. ``None`` for Loom-only runners.
    pub agent_type: Option<String>,
    /// MCP manifest blob. ``None`` for Loom-only runners.
    pub mcp_manifest: Option<Value>,
}

#[derive(Debug, Clone, Default)]
pub struct HeartbeatStats {
    pub cpu_load_pct: Option<f64>,
    pub ram_free_mb: Option<i64>,
    pub battery_pct: Option<i64>,
    pub on_battery: bool,
    pub last_known_commit: Option<String>,
    pub claim_failures_total: i64,
    pub claim_failures_consecutive: i64,
    pub last_claim_error: Option<String>,
    pub heartbeat_failures_total: i64,
}

#[derive(Debug, Clone)]
pub struct ClaimPayload {
    pub scope_prefixes: Vec<String>,
    pub tools: Vec<String>,
    pub tags: Vec<String>,
    pub tenant: Option<String>,
    pub workspace_root: Option<String>,
    pub last_known_commit: Option<String>,
    pub cpu_load_pct: Option<f64>,
    pub ram_free_mb: Option<i64>,
    pub battery_pct: Option<i64>,
    pub on_battery: bool,
}

#[derive(Debug, Clone)]
pub struct ClaimResponse {
    pub task: Option<Value>,
    pub info: Value,
}

#[derive(Debug, Clone)]
pub struct StreamEntry {
    pub channel: String,
    pub line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub worker_id: String,
    pub status: String,
    pub head_commit: Option<String>,
    pub commits: Vec<String>,
    pub files_touched: Vec<String>,
    pub test_summary: Option<String>,
    pub log_tail: Option<String>,
    pub error: Option<String>,
    /// Loom-only (command kind): process exit code. None for agent-kind results.
    pub exit_code: Option<i64>,
}

// -- Helpers -----------------------------------------------------------------

/// Build the canonical 114E `session-request` envelope a proof-of-possession
/// client signs and the hub (`fabric_hub::auth::resolve_signed_session`)
/// reconstructs and verifies. The field set, names, and value types
/// (`timestamp` is a JSON number, `nonce`/`body_sha256` are strings) must match
/// the hub exactly — `canonicalize` makes key order irrelevant, but a value
/// type or field mismatch would silently fail verification. Extracted (rather
/// than inlined into `request_auth`) purely so a unit test can pin the envelope
/// shape and a sign→verify round-trip without standing up a hub.
fn session_request_envelope(
    session_id: &str,
    method: &str,
    path: &str,
    body_sha256: &str,
    timestamp: i64,
    nonce: &str,
) -> Value {
    json!({
        "op": "session-request",
        "session_id": session_id,
        "method": method,
        "path": path,
        "body_sha256": body_sha256,
        "timestamp": timestamp,
        "nonce": nonce,
    })
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn random_nonce() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

// rand is needed for nonce generation
use rand as _;

#[cfg(test)]
mod tests {
    use super::*;
    use fabric_protocol::verify_envelope_hex;

    #[test]
    fn pop_session_request_envelope_signs_verifies_and_binds_every_field() {
        // The client signs with the session's private key; the hub verifies
        // against the bound public key over the byte-identical canonical
        // envelope. This proves the client and hub agree on the wire without
        // standing up a hub (fabric-hub's human_pop_session.rs proves the
        // server half against a real ephemeral node).
        let id = fabric_identity::generate("pop-session", fabric_types::KeyPurpose::Node);
        let body_sha = hex::encode(Sha256::digest(b"{\"role\":\"reviewer\"}"));
        let env = session_request_envelope(
            "sess-1",
            "POST",
            "/accounts/a-1/membership",
            &body_sha,
            1_700_000_000,
            "abcd",
        );
        let sig = sign_envelope_hex(&id.secret_key_hex, &env).expect("sign");

        // Correct signature verifies against the bound public key.
        assert!(verify_envelope_hex(&id.public_key_hex, &env, &sig).expect("verify"));

        // `timestamp` is a JSON *number*, not a string -- a mismatched value
        // type would silently fail hub-side verification.
        assert_eq!(env["timestamp"], serde_json::json!(1_700_000_000i64));
        assert!(env["timestamp"].is_number());

        // Tampering any signed field breaks verification (method, path, body,
        // nonce, timestamp).
        for tampered in [
            session_request_envelope(
                "sess-1",
                "GET",
                "/accounts/a-1/membership",
                &body_sha,
                1_700_000_000,
                "abcd",
            ),
            session_request_envelope(
                "sess-1",
                "POST",
                "/accounts/a-1/DISABLE",
                &body_sha,
                1_700_000_000,
                "abcd",
            ),
            session_request_envelope(
                "sess-1",
                "POST",
                "/accounts/a-1/membership",
                &hex::encode(Sha256::digest(b"{\"role\":\"admin\"}")),
                1_700_000_000,
                "abcd",
            ),
            session_request_envelope(
                "sess-1",
                "POST",
                "/accounts/a-1/membership",
                &body_sha,
                1_700_000_001,
                "abcd",
            ),
            session_request_envelope(
                "sess-1",
                "POST",
                "/accounts/a-1/membership",
                &body_sha,
                1_700_000_000,
                "eeee",
            ),
        ] {
            assert!(
                !verify_envelope_hex(&id.public_key_hex, &tampered, &sig).expect("verify"),
                "tampered envelope must not verify: {tampered}"
            );
        }

        // A different key does not verify.
        let other = fabric_identity::generate("other", fabric_types::KeyPurpose::Node);
        assert!(!verify_envelope_hex(&other.public_key_hex, &env, &sig).expect("verify"));
    }

    fn hub_error(status: u16, body: &str) -> ClientError {
        ClientError::Hub {
            status,
            body: body.to_owned(),
        }
    }

    #[test]
    fn recognizes_a_well_formed_typed_error() {
        let error = hub_error(
            401,
            r#"{"error":{"code":"InvalidCredentials","message":"invalid username or password","remediation":null}}"#,
        );
        let typed = error.typed_auth_error().expect("must recognize this shape");
        assert_eq!(typed.code, "InvalidCredentials");
        assert_eq!(typed.message, "invalid username or password");
    }

    #[test]
    fn falls_back_to_the_code_itself_when_message_is_missing() {
        let error = hub_error(401, r#"{"error":{"code":"SessionExpired"}}"#);
        let typed = error.typed_auth_error().expect("code alone is enough");
        assert_eq!(typed.message, "SessionExpired");
    }

    #[test]
    fn rejects_a_code_not_in_the_known_set() {
        // A hub bug or an intermediary could put anything here -- an
        // unrecognized code must be treated the same as no code at all,
        // never passed through as if it were meaningful.
        let error = hub_error(
            500,
            r#"{"error":{"code":"SomethingThatIsNotARealCode","message":"whatever"}}"#,
        );
        assert!(error.typed_auth_error().is_none());
    }

    #[test]
    fn rejects_bodies_that_are_not_the_expected_shape() {
        for body in [
            "not json at all",
            r#"{"unrelated":"shape"}"#,
            r#"{"error":"just a string, not an object"}"#,
            "",
        ] {
            let error = hub_error(500, body);
            assert!(error.typed_auth_error().is_none(), "must reject {body:?}");
        }
    }

    #[test]
    fn non_hub_errors_never_produce_a_typed_auth_error() {
        assert!(ClientError::Transport {
            attempts: 3,
            message: "timeout".to_owned()
        }
        .typed_auth_error()
        .is_none());
        assert!(ClientError::Protocol("bad envelope".to_owned())
            .typed_auth_error()
            .is_none());
    }

    #[test]
    fn known_codes_match_the_typescript_side_exactly() {
        // Pinned by hand against packages/fabric-client-core/src/
        // authContracts.ts's TYPED_AUTH_ERROR_CODES -- both sides are
        // independent copies of the same wire contract (see this module's
        // own doc comment on KNOWN_AUTH_ERROR_CODES for why there is no
        // shared-crate dependency instead), so a drift here is a drift a
        // human introduced, not something a shared type could catch.
        assert_eq!(
            KNOWN_AUTH_ERROR_CODES,
            [
                "AuthenticationRequired",
                "InvalidCredentials",
                "SessionExpired",
                "SessionRevoked",
                "RefreshReplayDetected",
                "AccountDisabled",
                "AccountLocked",
                "RecoveryRequired",
                "StepUpRequired",
                "AssuranceTooLow",
                "AccountPolicyViolation",
                "LastAdministratorViolation",
                "UsernameConflict",
                "CredentialConflict",
                "BootstrapClosed",
                "BootstrapLocalOnly",
                "AuthServiceUnavailable",
                "RolePolicyViolation",
                "ChallengeInvalid",
                "CredentialReplaySuspected",
            ]
        );
    }
}
