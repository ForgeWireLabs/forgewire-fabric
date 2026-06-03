//! Typed HTTP client for the ForgeWire Fabric hub API.
//!
//! Shared by the runner daemon, CLI, tests, and optional adapters.
//! Every method maps 1:1 to a hub endpoint documented in ENDPOINT_AUTH_MATRIX.md.

#![deny(rust_2018_idioms)]

use std::collections::HashMap;
use std::time::Duration;

use fabric_identity::IdentityFile;
use fabric_protocol::{canonicalize, sign_payload_hex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tracing::{debug, warn};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u32 = 3;
const RETRY_BASE_MS: u64 = 500;

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
                        let val: Value =
                            serde_json::from_str(&text).unwrap_or(Value::Null);
                        return Ok(val);
                    }
                    return Err(ClientError::Hub {
                        status,
                        body: text,
                    });
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

    // -- Healthz (no auth) ---------------------------------------------------

    pub async fn healthz(&self) -> Result<Value, ClientError> {
        let url = format!("{}/healthz", self.base_url);
        match self.http.get(&url).timeout(Duration::from_secs(5)).send().await {
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
        let canonical = canonicalize(&signed_fields)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
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
        let canonical = canonicalize(&signed_fields)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
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

        self.post(
            &format!("/runners/{}/heartbeat", identity.id),
            &body,
        )
        .await
    }

    // -- Claim v2 (signed) ---------------------------------------------------

    pub async fn claim_v2(
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
        let canonical = canonicalize(&signed_fields)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
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

        let val = self.post("/tasks/claim-v2", &body).await?;
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
        let body = json!({
            "worker_id": result.worker_id,
            "status": result.status,
            "head_commit": result.head_commit,
            "commits": result.commits,
            "files_touched": result.files_touched,
            "test_summary": result.test_summary,
            "log_tail": result.log_tail,
            "error": result.error,
        });
        self.post(&format!("/tasks/{task_id}/result"), &body).await
    }

    // -- Drain (signed) ------------------------------------------------------

    pub async fn drain(
        &self,
        identity: &IdentityFile,
    ) -> Result<Value, ClientError> {
        let ts = unix_timestamp();
        let nonce = random_nonce();

        let signed_fields = json!({
            "op": "drain",
            "runner_id": identity.id,
            "timestamp": ts,
            "nonce": nonce,
        });
        let canonical = canonicalize(&signed_fields)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        let signature = sign_payload_hex(&identity.secret_key_hex, &canonical)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;

        let body = json!({
            "runner_id": identity.id,
            "timestamp": ts,
            "nonce": nonce,
            "signature": signature,
        });

        self.post(
            &format!("/runners/{}/drain", identity.id),
            &body,
        )
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
}

// -- Helpers -----------------------------------------------------------------

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn random_nonce() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

// rand is needed for nonce generation
use rand as _;
