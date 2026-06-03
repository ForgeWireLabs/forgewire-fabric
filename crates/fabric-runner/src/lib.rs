//! ForgeWire Fabric native runner daemon.
//!
//! The runner is a long-lived process that:
//! 1. Registers with the hub (signed, with exponential backoff)
//! 2. Heartbeats every 20s (signed, re-registers on 404)
//! 3. Polls for tasks via claim-v2 (signed, re-registers on 404)
//! 4. Executes claimed tasks as subprocesses
//! 5. Streams stdout/stderr to the hub line-by-line
//! 6. Submits terminal results
//! 7. Drains on shutdown (signed)

#![deny(rust_2018_idioms)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fabric_client::{
    ClaimPayload, ClaimResponse, HeartbeatStats, HubClient, RegisterPayload,
    TaskResult,
};
use fabric_identity::IdentityFile;
use fabric_types::KeyPurpose;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
pub const PROTOCOL_VERSION: i64 = 3;
pub const RUNNER_VERSION: &str = "0.5.0";
const MAX_REGISTER_BACKOFF: Duration = Duration::from_secs(30);
const MAX_LOG_TAIL_LINES: usize = 50;

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub hub_url: String,
    pub token: String,
    pub workspace_root: PathBuf,
    pub identity_path: PathBuf,
    pub tools: Vec<String>,
    pub tags: Vec<String>,
    pub scope_prefixes: Vec<String>,
    pub tenant: Option<String>,
    pub max_concurrent: i64,
    pub poll_interval: Duration,
}

impl RunnerConfig {
    pub fn from_env() -> Result<Self, String> {
        let hub_url = std::env::var("FORGEWIRE_HUB_URL")
            .map_err(|_| "FORGEWIRE_HUB_URL not set")?;
        let token_file = std::env::var("FORGEWIRE_HUB_TOKEN_FILE")
            .unwrap_or_else(|_| {
                if cfg!(windows) {
                    r"C:\ProgramData\forgewire\hub.token".to_owned()
                } else {
                    "/var/lib/forgewire/hub.token".to_owned()
                }
            });
        let token = std::fs::read_to_string(&token_file)
            .map_err(|e| format!("cannot read token file {token_file}: {e}"))?
            .trim()
            .to_owned();
        let workspace_root = std::env::var("FORGEWIRE_RUNNER_WORKSPACE_ROOT")
            .map(PathBuf::from)
            .map_err(|_| "FORGEWIRE_RUNNER_WORKSPACE_ROOT not set")?;
        let identity_path = std::env::var("FORGEWIRE_RUNNER_IDENTITY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                if cfg!(windows) {
                    PathBuf::from(r"C:\ProgramData\forgewire\runner_identity.json")
                } else {
                    PathBuf::from("/var/lib/forgewire/runner_identity.json")
                }
            });
        let max_concurrent = std::env::var("FORGEWIRE_RUNNER_MAX_CONCURRENT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let poll_secs: f64 = std::env::var("FORGEWIRE_RUNNER_POLL_INTERVAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5.0);
        let tags: Vec<String> = std::env::var("FORGEWIRE_RUNNER_TAGS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        let scope_prefixes: Vec<String> = std::env::var("FORGEWIRE_RUNNER_SCOPE_PREFIXES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(Self {
            hub_url,
            token,
            workspace_root,
            identity_path,
            tools: detect_tools(),
            tags,
            scope_prefixes,
            tenant: std::env::var("FORGEWIRE_RUNNER_TENANT").ok(),
            max_concurrent,
            poll_interval: Duration::from_secs_f64(poll_secs),
        })
    }
}

pub fn load_or_create_identity(path: &Path) -> IdentityFile {
    match fabric_identity::load_with_purpose(path, KeyPurpose::Runner) {
        Ok(id) => {
            info!(runner_id = %id.id, "loaded existing runner identity");
            id
        }
        Err(fabric_identity::IdentityError::NotFound(_)) => {
            let id = fabric_identity::generate(
                &format!("{}-runner", gethostname()),
                KeyPurpose::Runner,
            );
            if let Err(e) = fabric_identity::save(path, &id) {
                error!("failed to save identity to {}: {e}", path.display());
            }
            info!(runner_id = %id.id, "generated new runner identity");
            id
        }
        Err(e) => {
            panic!(
                "identity file {} is corrupted: {e}. Remove it and restart.",
                path.display()
            );
        }
    }
}

pub async fn register_with_retries(
    client: &HubClient,
    identity: &IdentityFile,
    config: &RunnerConfig,
) {
    let payload = build_register_payload(config);
    let mut delay = Duration::from_secs(1);
    loop {
        match client.register_runner(identity, &payload).await {
            Ok(resp) => {
                let proto = resp
                    .get("hub_protocol_version")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                info!(runner_id = %identity.id, hub_protocol = proto, "registered with hub");
                return;
            }
            Err(e) => {
                warn!(error = %e, retry_in = ?delay, "registration failed, retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_REGISTER_BACKOFF);
            }
        }
    }
}

pub async fn heartbeat_loop(
    client: Arc<HubClient>,
    identity: Arc<IdentityFile>,
    config: Arc<RunnerConfig>,
    mut shutdown: watch::Receiver<bool>,
    stats: Arc<tokio::sync::Mutex<HeartbeatStats>>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(HEARTBEAT_INTERVAL) => {}
            _ = shutdown.changed() => { return; }
        }
        let current_stats = stats.lock().await.clone();
        match client.heartbeat(&identity, &current_stats).await {
            Ok(_) => {
                stats.lock().await.heartbeat_failures_total = 0;
            }
            Err(e) if e.is_not_found() => {
                warn!("hub 404 on heartbeat; re-registering");
                register_with_retries(&client, &identity, &config).await;
            }
            Err(e) => {
                let mut s = stats.lock().await;
                s.heartbeat_failures_total += 1;
                warn!(error = %e, failures = s.heartbeat_failures_total, "heartbeat failed");
            }
        }
    }
}

pub async fn claim_loop(
    client: Arc<HubClient>,
    identity: Arc<IdentityFile>,
    config: Arc<RunnerConfig>,
    mut shutdown: watch::Receiver<bool>,
    stats: Arc<tokio::sync::Mutex<HeartbeatStats>>,
) {
    let claim = build_claim_payload(&config);
    loop {
        if *shutdown.borrow() {
            return;
        }
        match client.claim_v2(&identity, &claim).await {
            Ok(ClaimResponse { task: Some(task), .. }) => {
                {
                    let mut s = stats.lock().await;
                    s.claim_failures_consecutive = 0;
                    s.last_claim_error = None;
                }
                let task_id = task["id"].as_i64().unwrap_or(0);
                info!(task_id, title = task["title"].as_str().unwrap_or("?"), "claimed task");
                run_one_task(client.clone(), identity.clone(), &config, &task).await;
            }
            Ok(ClaimResponse { task: None, info }) => {
                if let Some(reason) = info["reason"].as_str() {
                    debug!(reason, "no task available");
                }
            }
            Err(e) if e.is_not_found() => {
                warn!("hub 404 on claim; re-registering");
                register_with_retries(&client, &identity, &config).await;
            }
            Err(e) => {
                let mut s = stats.lock().await;
                s.claim_failures_total += 1;
                s.claim_failures_consecutive += 1;
                s.last_claim_error = Some(e.to_string());
                warn!(error = %e, consecutive = s.claim_failures_consecutive, "claim failed");
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(config.poll_interval) => {}
            _ = shutdown.changed() => { return; }
        }
    }
}

async fn run_one_task(
    client: Arc<HubClient>,
    identity: Arc<IdentityFile>,
    config: &RunnerConfig,
    task: &Value,
) {
    let task_id = task["id"].as_i64().unwrap_or(0);
    let prompt = task["prompt"].as_str().unwrap_or("").to_owned();
    let runner_id = identity.id.clone();

    if let Err(e) = client.mark_running(task_id).await {
        error!(task_id, error = %e, "failed to mark task running");
    }

    let (program, args) = if cfg!(windows) {
        ("cmd".to_owned(), vec!["/c".to_owned(), prompt])
    } else {
        ("bash".to_owned(), vec!["-lc".to_owned(), prompt])
    };

    let result = match Command::new(&program)
        .args(&args)
        .current_dir(&config.workspace_root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();

            let stdout_handle = {
                let c = client.clone();
                let rid = runner_id.clone();
                tokio::spawn(async move {
                    pump_stream(c, task_id, &rid, "stdout", stdout).await
                })
            };
            let stderr_handle = {
                let c = client.clone();
                let rid = runner_id.clone();
                tokio::spawn(async move {
                    pump_stderr(c, task_id, &rid, stderr).await
                })
            };

            let rc = child.wait().await.map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);

            let mut log_lines = Vec::new();
            if let Ok(lines) = stdout_handle.await {
                log_lines.extend(lines);
            }
            if let Ok(lines) = stderr_handle.await {
                log_lines.extend(lines);
            }

            let tail_start = log_lines.len().saturating_sub(MAX_LOG_TAIL_LINES);
            let tail = log_lines[tail_start..].join("\n");

            TaskResult {
                worker_id: runner_id,
                status: if rc == 0 { "done".into() } else { "failed".into() },
                head_commit: None,
                commits: vec![],
                files_touched: vec![],
                test_summary: None,
                log_tail: Some(tail),
                error: if rc == 0 { None } else { Some(format!("exit code {rc}")) },
            }
        }
        Err(e) => TaskResult {
            worker_id: runner_id,
            status: "failed".into(),
            head_commit: None,
            commits: vec![],
            files_touched: vec![],
            test_summary: None,
            log_tail: None,
            error: Some(format!("spawn failed: {e}")),
        },
    };

    info!(task_id, status = %result.status, "task completed");
    if let Err(e) = client.submit_result(task_id, &result).await {
        error!(task_id, error = %e, "failed to submit result");
    }
}

async fn pump_stream(
    client: Arc<HubClient>,
    task_id: i64,
    runner_id: &str,
    channel: &str,
    pipe: Option<tokio::process::ChildStdout>,
) -> Vec<String>
where
{
    let mut lines = Vec::new();
    let Some(pipe) = pipe else { return lines };
    // Safety: ChildStdout and ChildStderr are both AsyncRead.
    // We read from a BufReader line-by-line.
    let mut reader = BufReader::new(pipe).lines();
    while let Ok(Some(line)) = reader.next_line().await {
        if let Err(e) = client.append_stream(task_id, runner_id, channel, &line).await {
            warn!(task_id, channel, error = %e, "stream append failed");
        }
        lines.push(line);
    }
    lines
}

// Overload for stderr (ChildStderr is a different type)
async fn pump_stderr(
    client: Arc<HubClient>,
    task_id: i64,
    runner_id: &str,
    pipe: Option<tokio::process::ChildStderr>,
) -> Vec<String> {
    let mut lines = Vec::new();
    let Some(pipe) = pipe else { return lines };
    let mut reader = BufReader::new(pipe).lines();
    while let Ok(Some(line)) = reader.next_line().await {
        if let Err(e) = client.append_stream(task_id, runner_id, "stderr", &line).await {
            warn!(task_id, error = %e, "stderr stream append failed");
        }
        lines.push(line);
    }
    lines
}

pub async fn drain_and_shutdown(client: &HubClient, identity: &IdentityFile) {
    info!("draining runner before shutdown");
    match client.drain(identity).await {
        Ok(_) => info!("drain acknowledged by hub"),
        Err(e) => warn!(error = %e, "drain failed"),
    }
}

fn build_register_payload(config: &RunnerConfig) -> RegisterPayload {
    RegisterPayload {
        protocol_version: PROTOCOL_VERSION,
        runner_version: RUNNER_VERSION.to_owned(),
        hostname: gethostname(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        cpu_model: None,
        cpu_count: None,
        ram_mb: None,
        gpu: None,
        tools: config.tools.clone(),
        tags: {
            let mut tags = config.tags.clone();
            if !tags.iter().any(|t| t.starts_with("kind:")) {
                tags.push("kind:command".into());
            }
            tags
        },
        scope_prefixes: config.scope_prefixes.clone(),
        tenant: config.tenant.clone(),
        workspace_root: Some(config.workspace_root.display().to_string()),
        max_concurrent: config.max_concurrent,
        capabilities: HashMap::new(),
        metadata: {
            let mut m = HashMap::new();
            m.insert("flavor".into(), Value::String("forgewire-runner-rust".into()));
            m
        },
    }
}

fn build_claim_payload(config: &RunnerConfig) -> ClaimPayload {
    // Mirror the same kind: tag injection as build_register_payload so that
    // runner_kind_from_tags() on the hub resolves "command" not "agent".
    let mut tags = config.tags.clone();
    if !tags.iter().any(|t| t.starts_with("kind:")) {
        tags.push("kind:command".into());
    }
    ClaimPayload {
        scope_prefixes: config.scope_prefixes.clone(),
        tools: config.tools.clone(),
        tags,
        tenant: config.tenant.clone(),
        workspace_root: Some(config.workspace_root.display().to_string()),
        last_known_commit: None,
        cpu_load_pct: None,
        ram_free_mb: None,
        battery_pct: None,
        on_battery: false,
    }
}

fn detect_tools() -> Vec<String> {
    ["git", "python", "python3", "node", "npm", "cargo", "rustc"]
        .iter()
        .filter(|tool| {
            std::process::Command::new(tool)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok()
        })
        .map(|s| (*s).to_owned())
        .collect()
}

fn gethostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        })
        .unwrap_or_else(|_| "unknown".into())
}
