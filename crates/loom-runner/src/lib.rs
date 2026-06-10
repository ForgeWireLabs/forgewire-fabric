//! ForgeWire Loom runner — dumb shell executor for command-kind tasks.
//!
//! The Loom runner:
//! 1. Registers with the hub as `kinds: ["command"]`, `agent_type: null`, no manifest.
//! 2. Heartbeats every 20 s (re-registers on 404).
//! 3. Claims tasks from `/tasks/claim-loom` (signed).
//! 4. Executes claimed tasks as subprocesses via `tokio::process::Command`.
//! 5. Streams stdout/stderr line-by-line.
//! 6. Submits terminal result with `exit_code`.
//! 7. Drains on shutdown.
//!
//! No LLM. No MCP introspection. No worktree management. Pure shell execution.

#![deny(rust_2018_idioms)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fabric_client::{ClaimPayload, ClaimResponse, HeartbeatStats, HubClient, RegisterPayload, TaskResult};
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
pub const RUNNER_VERSION: &str = "0.7.0";
const MAX_REGISTER_BACKOFF: Duration = Duration::from_secs(30);
const MAX_LOG_TAIL_LINES: usize = 200;

#[derive(Debug, Clone)]
pub struct LoomConfig {
    pub hub_url: String,
    pub token: String,
    pub identity_path: PathBuf,
    pub tools: Vec<String>,
    pub tags: Vec<String>,
    pub scope_prefixes: Vec<String>,
    pub tenant: Option<String>,
    pub max_concurrent: i64,
    pub poll_interval: Duration,
    pub beacon_port: u16,
}

impl LoomConfig {
    pub fn from_env() -> Result<Self, String> {
        let hub_url = std::env::var("FORGEWIRE_HUB_URL").unwrap_or_default();
        let beacon_port = std::env::var("FORGEWIRE_BEACON_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(fabric_beacon::DEFAULT_BEACON_PORT);
        let token_file = std::env::var("FORGEWIRE_HUB_TOKEN_FILE").unwrap_or_else(|_| {
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
        let identity_path = std::env::var("FORGEWIRE_RUNNER_IDENTITY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                if cfg!(windows) {
                    PathBuf::from(r"C:\ProgramData\forgewire\loom_runner_identity.json")
                } else {
                    PathBuf::from("/var/lib/forgewire/loom_runner_identity.json")
                }
            });
        let max_concurrent = std::env::var("FORGEWIRE_RUNNER_MAX_CONCURRENT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        let poll_secs: f64 = std::env::var("FORGEWIRE_RUNNER_POLL_INTERVAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3.0);
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
            identity_path,
            tools: detect_tools(),
            tags,
            scope_prefixes,
            tenant: std::env::var("FORGEWIRE_RUNNER_TENANT").ok(),
            max_concurrent,
            poll_interval: Duration::from_secs_f64(poll_secs),
            beacon_port,
        })
    }
}

pub async fn resolve_hub_url(config: &LoomConfig) -> String {
    if !config.hub_url.is_empty() {
        let c = HubClient::new(&config.hub_url, &config.token);
        if c.healthz().await.is_ok() {
            return config.hub_url.clone();
        }
        warn!(hub = %config.hub_url, "configured hub unreachable -- falling back to LAN discovery");
    }
    let want = fabric_beacon::token_hash(&config.token);
    let port = config.beacon_port;
    let mut delay = Duration::from_secs(1);
    loop {
        let want2 = want.clone();
        let found = tokio::task::spawn_blocking(move || {
            fabric_beacon::discover(port, Duration::from_secs(3), Some(&want2)).unwrap_or_default()
        })
        .await
        .unwrap_or_default();
        if let Some(hub) = found.into_iter().next() {
            info!(hub = %hub.url, hub_id = %hub.hub_id, "discovered hub via LAN beacon");
            return hub.url;
        }
        warn!(retry_in = ?delay, "no hub discovered on the LAN -- retrying");
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(15));
    }
}

pub fn load_or_create_identity(path: &Path) -> IdentityFile {
    match fabric_identity::load_with_purpose(path, KeyPurpose::Runner) {
        Ok(id) => {
            info!(runner_id = %id.id, "loaded existing loom runner identity");
            id
        }
        Err(fabric_identity::IdentityError::NotFound(_)) => {
            let id = fabric_identity::generate(
                &format!("{}-loom-runner", gethostname()),
                KeyPurpose::Runner,
            );
            if let Err(e) = fabric_identity::save(path, &id) {
                error!("failed to save loom identity to {}: {e}", path.display());
            }
            info!(runner_id = %id.id, "generated new loom runner identity");
            id
        }
        Err(e) => {
            panic!(
                "loom identity file {} is corrupted: {e}. Remove it and restart.",
                path.display()
            );
        }
    }
}

pub async fn register_with_retries(
    client: &HubClient,
    identity: &IdentityFile,
    config: &LoomConfig,
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
                info!(runner_id = %identity.id, hub_protocol = proto, "loom runner registered with hub");
                return;
            }
            Err(e) => {
                warn!(error = %e, retry_in = ?delay, "loom registration failed, retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_REGISTER_BACKOFF);
            }
        }
    }
}

pub async fn heartbeat_loop(
    client: Arc<HubClient>,
    identity: Arc<IdentityFile>,
    config: Arc<LoomConfig>,
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
                warn!("hub 404 on heartbeat; re-registering loom runner");
                register_with_retries(&client, &identity, &config).await;
            }
            Err(e) => {
                let mut s = stats.lock().await;
                s.heartbeat_failures_total += 1;
                warn!(error = %e, failures = s.heartbeat_failures_total, "loom heartbeat failed");
            }
        }
    }
}

pub async fn claim_loop(
    client: Arc<HubClient>,
    identity: Arc<IdentityFile>,
    config: Arc<LoomConfig>,
    mut shutdown: watch::Receiver<bool>,
    stats: Arc<tokio::sync::Mutex<HeartbeatStats>>,
) {
    let claim = build_claim_payload(&config);
    loop {
        if *shutdown.borrow() {
            return;
        }
        match client.claim_loom(&identity, &claim).await {
            Ok(ClaimResponse {
                task: Some(task), ..
            }) => {
                {
                    let mut s = stats.lock().await;
                    s.claim_failures_consecutive = 0;
                    s.last_claim_error = None;
                }
                let task_id = task["id"].as_i64().unwrap_or(0);
                info!(
                    task_id,
                    title = task["title"].as_str().unwrap_or("?"),
                    "loom runner claimed task"
                );
                run_one_task(client.clone(), identity.clone(), &task).await;
            }
            Ok(ClaimResponse { task: None, info }) => {
                if let Some(reason) = info["reason"].as_str() {
                    debug!(reason, "loom: no command task available");
                }
            }
            Err(e) if e.is_not_found() => {
                warn!("hub 404 on loom claim; re-registering");
                register_with_retries(&client, &identity, &config).await;
            }
            Err(e) => {
                let mut s = stats.lock().await;
                s.claim_failures_total += 1;
                s.claim_failures_consecutive += 1;
                s.last_claim_error = Some(e.to_string());
                warn!(error = %e, consecutive = s.claim_failures_consecutive, "loom claim failed");
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(config.poll_interval) => {}
            _ = shutdown.changed() => { return; }
        }
    }
}

async fn run_one_task(client: Arc<HubClient>, identity: Arc<IdentityFile>, task: &Value) {
    let task_id = task["id"].as_i64().unwrap_or(0);
    let runner_id = identity.id.clone();

    if let Err(e) = client.mark_running(task_id).await {
        error!(task_id, error = %e, "failed to mark loom task running");
    }

    // The task brief carries `command` (argv array), `cwd`, `env`, `timeout_seconds`.
    // Fall back to running the `prompt` field via shell for backward compat.
    let (program, args, cwd, timeout_secs) = resolve_command(task);

    let mut cmd = Command::new(&program);
    cmd.args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    if !cwd.is_empty() {
        cmd.current_dir(&cwd);
    }

    // Inject env overrides from task brief.
    if let Some(env_obj) = task["env"].as_object() {
        for (k, v) in env_obj {
            if let Some(val) = v.as_str() {
                cmd.env(k, val);
            }
        }
    }

    let result = match cmd.spawn() {
        Ok(mut child) => {
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();

            let stdout_handle = {
                let c = client.clone();
                let rid = runner_id.clone();
                tokio::spawn(async move {
                    pump_pipe(c, task_id, &rid, "stdout", stdout).await
                })
            };
            let stderr_handle = {
                let c = client.clone();
                let rid = runner_id.clone();
                tokio::spawn(async move {
                    pump_pipe(c, task_id, &rid, "stderr", stderr).await
                })
            };

            let rc = if timeout_secs > 0 {
                let timeout = Duration::from_secs(timeout_secs);
                match tokio::time::timeout(timeout, child.wait()).await {
                    Ok(Ok(status)) => status.code().unwrap_or(-1),
                    Ok(Err(_)) => -1,
                    Err(_) => {
                        warn!(task_id, timeout_secs, "loom task timed out; killing");
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        -124 // SIGXCPU-like sentinel
                    }
                }
            } else {
                child.wait().await.map(|s| s.code().unwrap_or(-1)).unwrap_or(-1)
            };

            let mut log_lines = Vec::new();
            if let Ok(lines) = stdout_handle.await {
                log_lines.extend(lines);
            }
            if let Ok(lines) = stderr_handle.await {
                log_lines.extend(lines);
            }
            let tail_start = log_lines.len().saturating_sub(MAX_LOG_TAIL_LINES);
            let tail = log_lines[tail_start..].join("\n");

            let (status, error) = if rc == -124 {
                ("timed_out".into(), Some(format!("command timed out after {timeout_secs}s")))
            } else if rc == 0 {
                ("done".into(), None)
            } else {
                ("failed".into(), Some(format!("exit code {rc}")))
            };

            TaskResult {
                worker_id: runner_id,
                status,
                head_commit: None,
                commits: vec![],
                files_touched: vec![],
                test_summary: None,
                log_tail: Some(tail),
                error,
                exit_code: Some(rc as i64),
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
            exit_code: None,
        },
    };

    info!(task_id, status = %result.status, "loom task completed");
    if let Err(e) = client.submit_result(task_id, &result).await {
        error!(task_id, error = %e, "failed to submit loom task result");
    }
}

/// Extract argv, cwd, and timeout from a Loom task brief.
/// Returns `(program, args, cwd, timeout_seconds)`.
fn resolve_command(task: &Value) -> (String, Vec<String>, String, u64) {
    // New Loom wire format: command is an argv array.
    if let Some(arr) = task["command"].as_array() {
        let argv: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_owned()))
            .collect();
        if !argv.is_empty() {
            let cwd = task["cwd"].as_str().unwrap_or("").to_owned();
            let timeout = task["timeout_seconds"].as_u64().unwrap_or(0);
            let (prog, rest) = argv.split_first().unwrap();
            return (prog.clone(), rest.to_vec(), cwd, timeout);
        }
    }
    // Fallback: run `prompt` via shell (backward compat with prompt-dispatch tasks).
    let prompt = task["prompt"].as_str().unwrap_or("").to_owned();
    let cwd = task["cwd"].as_str().unwrap_or("").to_owned();
    let timeout = task["timeout_seconds"].as_u64().unwrap_or(0);
    if cfg!(windows) {
        ("cmd".to_owned(), vec!["/c".to_owned(), prompt], cwd, timeout)
    } else {
        ("sh".to_owned(), vec!["-c".to_owned(), prompt], cwd, timeout)
    }
}

async fn pump_pipe<R>(
    client: Arc<HubClient>,
    task_id: i64,
    runner_id: &str,
    channel: &str,
    pipe: Option<R>,
) -> Vec<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = Vec::new();
    let Some(pipe) = pipe else { return lines };
    let mut reader = BufReader::new(pipe).lines();
    while let Ok(Some(line)) = reader.next_line().await {
        if let Err(e) = client
            .append_stream(task_id, runner_id, channel, &line)
            .await
        {
            warn!(task_id, channel, error = %e, "loom stream append failed");
        }
        lines.push(line);
    }
    lines
}

pub async fn drain_and_shutdown(client: &HubClient, identity: &IdentityFile) {
    info!("draining loom runner before shutdown");
    match client.drain(identity).await {
        Ok(_) => info!("loom drain acknowledged by hub"),
        Err(e) => warn!(error = %e, "loom drain failed"),
    }
}

fn build_register_payload(config: &LoomConfig) -> RegisterPayload {
    use std::collections::HashMap;
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
        tags: config.tags.clone(),
        scope_prefixes: config.scope_prefixes.clone(),
        tenant: config.tenant.clone(),
        workspace_root: None, // Loom runners are not git-workspace-aware
        max_concurrent: config.max_concurrent,
        capabilities: HashMap::new(),
        metadata: {
            let mut m = HashMap::new();
            m.insert(
                "flavor".into(),
                serde_json::Value::String("forgewire-loom-runner-rust".into()),
            );
            m
        },
        kinds: vec!["command".to_owned()],
        agent_type: None,
        mcp_manifest: None,
    }
}

fn build_claim_payload(config: &LoomConfig) -> ClaimPayload {
    ClaimPayload {
        scope_prefixes: config.scope_prefixes.clone(),
        tools: config.tools.clone(),
        tags: config.tags.clone(),
        tenant: config.tenant.clone(),
        workspace_root: None,
        last_known_commit: None,
        cpu_load_pct: None,
        ram_free_mb: None,
        battery_pct: None,
        on_battery: false,
    }
}

pub fn detect_tools() -> Vec<String> {
    ["git", "python", "python3", "node", "npm", "cargo", "rustc", "pytest", "make"]
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
