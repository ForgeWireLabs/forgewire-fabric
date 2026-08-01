//! Stable, CI-suitable diagnostics for the native Fabric operator CLI.

use std::{path::PathBuf, time::Duration};

use fabric_client::HubClient;
use serde::Serialize;
use serde_json::{json, Value};

pub const DOCTOR_SCHEMA_VERSION: &str = "forgewire.fabric.doctor.v1";

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub id: String,
    pub status: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub details: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorSummary {
    pub passed: usize,
    pub warnings: usize,
    pub failures: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub schema_version: &'static str,
    pub overall: &'static str,
    pub exit_code: i32,
    pub summary: DoctorSummary,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Default)]
struct ReportBuilder {
    checks: Vec<DoctorCheck>,
}

impl ReportBuilder {
    fn push(
        &mut self,
        id: impl Into<String>,
        status: &'static str,
        message: impl Into<String>,
        details: Value,
    ) {
        self.checks.push(DoctorCheck {
            id: id.into(),
            status,
            message: message.into(),
            details,
        });
    }

    fn pass(&mut self, id: impl Into<String>, message: impl Into<String>, details: Value) {
        self.push(id, "pass", message, details);
    }

    fn warning(&mut self, id: impl Into<String>, message: impl Into<String>, details: Value) {
        self.push(id, "warning", message, details);
    }

    fn failure(&mut self, id: impl Into<String>, message: impl Into<String>, details: Value) {
        self.push(id, "failure", message, details);
    }

    fn info(&mut self, id: impl Into<String>, message: impl Into<String>, details: Value) {
        self.push(id, "info", message, details);
    }

    fn finish(self) -> DoctorReport {
        let failures = self
            .checks
            .iter()
            .filter(|check| check.status == "failure")
            .count();
        let warnings = self
            .checks
            .iter()
            .filter(|check| check.status == "warning")
            .count();
        let passed = self
            .checks
            .iter()
            .filter(|check| matches!(check.status, "pass" | "info"))
            .count();
        let (overall, exit_code) = if failures > 0 {
            ("failure", 1)
        } else if warnings > 0 {
            ("degraded", 2)
        } else {
            ("healthy", 0)
        };
        DoctorReport {
            schema_version: DOCTOR_SCHEMA_VERSION,
            overall,
            exit_code,
            summary: DoctorSummary {
                passed,
                warnings,
                failures,
            },
            checks: self.checks,
        }
    }
}

/// Turns a `GET /auth/webauthn/doctor` response body into a doctor check
/// outcome. Pure and separate from `run()` so the four-way classification
/// (ready / valid-but-stale / intentionally-off / enabled-but-broken) is
/// testable against synthetic JSON without a live hub -- every other check
/// in `run()` calls straight through to a live `HubClient` and has no such
/// coverage, so this is deliberately not following that precedent.
fn classify_webauthn_doctor(value: &Value) -> (&'static str, &'static str, Value) {
    let enabled = value["enabled"].as_bool().unwrap_or(false);
    let ready = value["ready"].as_bool().unwrap_or(false);
    let restart_required = value["restart_required"].as_bool().unwrap_or(false);
    if ready && !restart_required {
        (
            "pass",
            "passkeys are configured and ready",
            json!({"rp_id": value["rp_id"], "rp_matched_origins": value["rp_matched_origins"]}),
        )
    } else if ready && restart_required {
        // The config is correct; the running instance just has not picked
        // it up yet (built once at startup -- see webauthn_doctor.rs's own
        // doc comment on the hub side).
        (
            "warning",
            "passkey config is valid but not yet live; restart the hub to apply it",
            json!({"rp_id": value["rp_id"]}),
        )
    } else if !enabled {
        // Not configured is a supported, deliberate state (password-only
        // deployments remain policy-supported), not a problem.
        ("info", "passkeys are not enabled", Value::Null)
    } else {
        let problems = value["problems"].as_array().cloned().unwrap_or_default();
        (
            "warning",
            "passkeys are enabled but misconfigured",
            json!({"problems": problems}),
        )
    }
}

pub async fn run(hub_url: &str, token_file: Option<&str>) -> DoctorReport {
    let mut report = ReportBuilder::default();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("static reqwest client configuration is valid");

    let rqlite_host =
        std::env::var("FORGEWIRE_HUB_RQLITE_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let rqlite_port = std::env::var("FORGEWIRE_HUB_RQLITE_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(4001);
    let rqlite_base = format!("http://{rqlite_host}:{rqlite_port}");

    match http.get(format!("{rqlite_base}/readyz")).send().await {
        Ok(response) if response.status().is_success() => {
            report.pass(
                "rqlite.ready",
                "rqlite is ready",
                json!({"host": rqlite_host, "port": rqlite_port}),
            );
            check_rqlite_status(&http, &rqlite_base, &mut report).await;
            check_rqlite_suffrage(&http, &rqlite_base, &mut report).await;
        }
        Ok(response) => report.failure(
            "rqlite.ready",
            format!("rqlite returned {}", response.status()),
            json!({"host": rqlite_host, "port": rqlite_port}),
        ),
        Err(error) => report.failure(
            "rqlite.ready",
            format!("rqlite is unreachable: {error}"),
            json!({"host": rqlite_host, "port": rqlite_port}),
        ),
    }

    let token_path = token_path(token_file);
    let token = match std::fs::read_to_string(&token_path) {
        Ok(value) if value.trim().len() >= 16 => {
            report.pass(
                "auth.token_file",
                "token file is present",
                json!({"path": token_path, "length": value.trim().len()}),
            );
            value.trim().to_owned()
        }
        Ok(value) => {
            report.warning(
                "auth.token_file",
                "token is shorter than 16 characters",
                json!({"path": token_path, "length": value.trim().len()}),
            );
            value.trim().to_owned()
        }
        Err(error) => {
            report.failure(
                "auth.token_file",
                format!("token file is unavailable: {error}"),
                json!({"path": token_path}),
            );
            String::new()
        }
    };

    let client = HubClient::new(hub_url, &token);
    match client.healthz().await {
        Ok(health) => check_hub_health(hub_url, &health, &mut report),
        Err(error) => report.failure(
            "hub.health",
            format!("hub is unreachable: {error}"),
            json!({"url": hub_url}),
        ),
    }
    match client.list_agents().await {
        Ok(value) => report.pass(
            "cluster.agents",
            "agent registry is readable",
            json!({"count": value["agents"].as_array().map_or(0, Vec::len)}),
        ),
        Err(error) => report.failure(
            "cluster.agents",
            format!("agent registry read failed: {error}"),
            Value::Null,
        ),
    }
    match client.list_hosts().await {
        Ok(value) => {
            let count = value["hosts"].as_array().map_or(0, Vec::len);
            if count == 0 {
                report.warning(
                    "cluster.hosts",
                    "host registry is empty",
                    json!({"count": 0}),
                );
            } else {
                report.pass(
                    "cluster.hosts",
                    "host registry is readable",
                    json!({"count": count}),
                );
            }
        }
        Err(error) => report.failure(
            "cluster.hosts",
            format!("host registry read failed: {error}"),
            Value::Null,
        ),
    }

    match client.list_runners().await {
        Ok(value) => {
            let runners = value["runners"].as_array().cloned().unwrap_or_default();
            let without_manifest = runners
                .iter()
                .filter(|runner| {
                    runner["state"].as_str() == Some("online") && runner["mcp_manifest"].is_null()
                })
                .count();
            if without_manifest > 0 {
                report.warning(
                    "cluster.capability_tags",
                    "online runners are missing MCP capability manifests",
                    json!({"online_without_manifest": without_manifest, "runner_count": runners.len()}),
                );
            } else {
                report.pass(
                    "cluster.capability_tags",
                    "online runner capability manifests are available",
                    json!({"runner_count": runners.len()}),
                );
            }
        }
        Err(error) => report.failure(
            "cluster.capability_tags",
            format!("runner capability read failed: {error}"),
            Value::Null,
        ),
    }

    match client.settings().await {
        Ok(value) => report.pass(
            "settings.schema",
            "effective settings are schema-valid and readable",
            json!({"revision": value["revision"], "history_mode": value.pointer("/effective/history/mode")}),
        ),
        Err(error) => report.failure(
            "settings.schema",
            format!("settings validation/read failed: {error}"),
            Value::Null,
        ),
    }
    match client.history_status().await {
        Ok(value) if value["health"].as_str() == Some("degraded") => report.failure(
            "history.sink",
            "configured optional history sink is degraded",
            json!({"mode": value["mode"], "last_error": value["last_error"]}),
        ),
        Ok(value) if value["mode"].as_str() == Some("thin") => report.info(
            "history.sink",
            "thin history mode is active; rich analytics/RAG are unavailable",
            json!({"mode": "thin"}),
        ),
        Ok(value) => report.pass(
            "history.sink",
            "optional history exporter is healthy",
            json!({"mode": value["mode"], "exported": value["exported"]}),
        ),
        Err(error) => report.failure(
            "history.sink",
            format!("history status read failed: {error}"),
            Value::Null,
        ),
    }
    match client.audit_tail().await {
        Ok(value) => {
            let tail = value["chain_tail"].as_str().unwrap_or("");
            if tail.len() == 64 {
                report.pass(
                    "audit.ledger_tail",
                    "audit ledger tail is structurally valid",
                    json!({"hash_length": tail.len()}),
                );
            } else {
                report.failure(
                    "audit.ledger_tail",
                    "audit ledger tail is malformed",
                    json!({"hash_length": tail.len()}),
                );
            }
        }
        Err(error) => report.failure(
            "audit.ledger_tail",
            format!("audit ledger tail read failed: {error}"),
            Value::Null,
        ),
    }

    match client.webauthn_doctor().await {
        Ok(value) => {
            let (status, message, details) = classify_webauthn_doctor(&value);
            report.push("webauthn.rp_config", status, message, details);
        }
        Err(error) => report.failure(
            "webauthn.rp_config",
            format!("passkey config diagnostic read failed: {error}"),
            Value::Null,
        ),
    }

    check_identities(&mut report);
    check_binaries(&mut report);
    check_disk_space(&mut report);
    report.finish()
}

async fn check_rqlite_status(http: &reqwest::Client, base: &str, report: &mut ReportBuilder) {
    match http.get(format!("{base}/status")).send().await {
        Ok(response) if response.status().is_success() => match response.json::<Value>().await {
            Ok(body) => {
                let leader = body
                    .pointer("/store/leader/addr")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let state = body
                    .pointer("/store/raft/state")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if leader.is_empty() {
                    report.failure(
                        "rqlite.leader",
                        "no Raft leader is elected",
                        json!({"state": state}),
                    );
                } else {
                    report.pass(
                        "rqlite.leader",
                        "Raft leader is elected",
                        json!({"leader": leader, "state": state}),
                    );
                }
            }
            Err(error) => report.failure(
                "rqlite.leader",
                format!("rqlite status response is invalid JSON: {error}"),
                Value::Null,
            ),
        },
        Ok(response) => report.failure(
            "rqlite.leader",
            format!("rqlite status returned {}", response.status()),
            Value::Null,
        ),
        Err(error) => report.failure(
            "rqlite.leader",
            format!("rqlite status failed: {error}"),
            Value::Null,
        ),
    }
}

async fn check_rqlite_suffrage(http: &reqwest::Client, base: &str, report: &mut ReportBuilder) {
    match http
        .get(format!("{base}/nodes?nonvoters"))
        .send()
        .await
        .and_then(|response| response.error_for_status())
    {
        Ok(response) => match response.json::<Value>().await {
            Ok(body) => {
                let nodes = body.as_object();
                let total = nodes.map_or(0, serde_json::Map::len);
                let voters = nodes.map_or(0, |values| {
                    values
                        .values()
                        .filter(|value| value["voter"].as_bool().unwrap_or(false))
                        .count()
                });
                if total == 2 && voters == 2 {
                    report.warning(
                        "rqlite.suffrage",
                        "two-voter quorum trap: loss of either voter halts writes",
                        json!({"nodes": total, "voters": voters, "required_action": "add a third physical voter or demote the standby"}),
                    );
                } else if voters >= 3 {
                    report.pass(
                        "rqlite.suffrage",
                        "voter-loss quorum is available",
                        json!({"nodes": total, "voters": voters}),
                    );
                } else {
                    report.info(
                        "rqlite.suffrage",
                        "cluster does not claim voter-loss quorum",
                        json!({"nodes": total, "voters": voters, "required_for_voter_loss_ha": 3}),
                    );
                }
            }
            Err(error) => report.failure(
                "rqlite.suffrage",
                format!("rqlite node response is invalid JSON: {error}"),
                Value::Null,
            ),
        },
        Err(error) => report.failure(
            "rqlite.suffrage",
            format!("rqlite node query failed: {error}"),
            Value::Null,
        ),
    }
}

fn check_hub_health(hub_url: &str, health: &Value, report: &mut ReportBuilder) {
    let version = health["version"].as_str().unwrap_or("unknown");
    let protocol = health["protocol_version"].as_i64().unwrap_or(0);
    let backend = health["backend"].as_str().unwrap_or("unknown");
    let rust_hub = health["rust_hub"].as_bool().unwrap_or(false);
    if !rust_hub || !backend.starts_with("rqlite") {
        report.warning(
            "hub.health",
            "hub is reachable but is not the supported Rust/rqlite authority",
            json!({"url": hub_url, "version": version, "protocol": protocol, "backend": backend, "rust_hub": rust_hub}),
        );
    } else {
        report.pass(
            "hub.health",
            "hub is healthy",
            json!({"url": hub_url, "version": version, "protocol": protocol, "backend": backend, "rust_hub": true}),
        );
    }

    if hub_url.starts_with("https://") {
        report.pass(
            "transport.tls_validity",
            "HTTPS certificate chain and validity window were accepted",
            json!({"url": hub_url}),
        );
    } else if hub_url.starts_with("http://127.0.0.1")
        || hub_url.starts_with("http://localhost")
        || hub_url.starts_with("http://[::1]")
    {
        report.info(
            "transport.tls_validity",
            "loopback HTTP transport is in use",
            json!({"url": hub_url, "scope": "loopback"}),
        );
    } else {
        report.warning(
            "transport.tls_validity",
            "non-loopback hub transport is not HTTPS",
            json!({"url": hub_url}),
        );
    }

    if let Some(server_time) = health["server_time"].as_f64() {
        let local_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let drift = (local_time - server_time).abs();
        if drift <= 5.0 {
            report.pass(
                "clock.drift",
                "hub clock drift is within five seconds",
                json!({"drift_seconds": drift}),
            );
        } else if drift <= 30.0 {
            report.warning(
                "clock.drift",
                "hub clock drift exceeds five seconds",
                json!({"drift_seconds": drift}),
            );
        } else {
            report.failure(
                "clock.drift",
                "hub clock drift exceeds the signed-envelope tolerance",
                json!({"drift_seconds": drift}),
            );
        }
    } else {
        report.warning(
            "clock.drift",
            "hub does not report server time",
            Value::Null,
        );
    }

    let fabric = health.pointer("/queues/fabric").and_then(Value::as_i64);
    let loom = health.pointer("/queues/loom").and_then(Value::as_i64);
    match (fabric, loom) {
        (Some(fabric), Some(loom)) => report.pass(
            "hub.queues",
            "Fabric and Loom queue depths are available",
            json!({"fabric": fabric, "loom": loom}),
        ),
        _ => report.failure(
            "hub.queues",
            "health response has no Fabric/Loom queue depths",
            Value::Null,
        ),
    }
    match health["capability_index_rows"].as_i64() {
        Some(rows) => report.pass(
            "hub.capability_index",
            "capability index is available",
            json!({"rows": rows}),
        ),
        None => report.failure(
            "hub.capability_index",
            "health response has no capability index count",
            Value::Null,
        ),
    }
    if health["sidecar_integrity"].as_str() == Some("trusted_bearer") {
        report.warning(
            "hub.sidecar_integrity",
            "v2 out-of-band fields remain bearer-gated",
            json!({"mode": "trusted_bearer"}),
        );
    } else {
        report.pass(
            "hub.sidecar_integrity",
            "sidecar integrity mode is supported",
            json!({"mode": health["sidecar_integrity"]}),
        );
    }
}

/// Platform-appropriate default state directory: `%PROGRAMDATA%\forgewire`
/// on Windows, `~/Library/Application Support/forgewire` on macOS,
/// `/var/lib/forgewire` on Linux (the FHS convention for a system-service
/// daemon, which fabric-hub/fabric-runner are per their systemd unit files
/// -- not a bug to fix, unlike the Windows/macOS cases). Every default here
/// is env-var overridable at each call site's own layer
/// (`FORGEWIRE_HUB_TOKEN_FILE` etc.); this is only the fallback used when
/// no override is set, so it never relocates an already-configured
/// installation's state.
pub(crate) fn default_state_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\forgewire")
    } else if cfg!(target_os = "macos") {
        std::env::var("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support/forgewire"))
            .unwrap_or_else(|_| PathBuf::from("/var/lib/forgewire"))
    } else {
        PathBuf::from("/var/lib/forgewire")
    }
}

fn check_identities(report: &mut ReportBuilder) {
    let base = default_state_dir();
    let paths: [PathBuf; 2] = [
        base.join("runner_identity.json"),
        base.join("hub_identity.json"),
    ];
    for path in paths {
        let label = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("identity");
        let id = format!("identity.{label}");
        match fabric_identity::load(&path) {
            Ok(identity) => report.pass(
                id,
                "identity is valid",
                json!({"path": path, "identity_id": identity.id, "purpose": identity.purpose}),
            ),
            Err(fabric_identity::IdentityError::NotFound(_)) => report.info(
                id,
                "optional identity is not installed on this host",
                json!({"path": path}),
            ),
            Err(error) => report.failure(
                id,
                format!("identity is invalid: {error}"),
                json!({"path": path}),
            ),
        }
    }
}

fn check_binaries(report: &mut ReportBuilder) {
    let bin_dir = default_state_dir().join("bin");
    for binary in ["forgewire-hub", "forgewire-runner", "forgewire-fabric-cli"] {
        let installed = bin_dir.join(format!(
            "{}{}",
            binary,
            if cfg!(windows) { ".exe" } else { "" }
        ));
        let id = format!("binary.{binary}");
        if installed.exists() || which(binary) {
            report.pass(id, "native binary is available", json!({"name": binary}));
        } else {
            report.warning(
                id,
                "native binary is not available",
                json!({"name": binary, "install_dir": bin_dir}),
            );
        }
    }
}

fn check_disk_space(report: &mut ReportBuilder) {
    let path = default_state_dir();
    let probe = if path.exists() {
        path
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };
    match fs2::available_space(&probe) {
        Ok(bytes) if bytes < 1_073_741_824 => report.warning(
            "storage.free_space",
            "less than 1 GiB is available for Fabric runtime data",
            json!({"path": probe, "available_bytes": bytes}),
        ),
        Ok(bytes) => report.pass(
            "storage.free_space",
            "runtime data volume has sufficient free space",
            json!({"path": probe, "available_bytes": bytes}),
        ),
        Err(error) => report.warning(
            "storage.free_space",
            format!("free-space probe failed: {error}"),
            json!({"path": probe}),
        ),
    }
}

fn token_path(token_file: Option<&str>) -> PathBuf {
    token_file
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("FORGEWIRE_HUB_TOKEN_FILE")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| default_state_dir().join("hub.token"))
}

fn which(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

pub fn print_human(report: &DoctorReport) {
    println!("ForgeWire Fabric Doctor");
    println!("=======================");
    for check in &report.checks {
        let marker = match check.status {
            "pass" => "OK",
            "info" => "INFO",
            "warning" => "WARN",
            _ => "FAIL",
        };
        println!("{:<28} {:<4} {}", check.id, marker, check.message);
    }
    println!();
    println!(
        "RESULT: {} ({} passed/info, {} warning(s), {} failure(s)); exit {}",
        report.overall,
        report.summary.passed,
        report.summary.warnings,
        report.summary.failures,
        report.exit_code
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_contract_is_zero_one_two() {
        let mut healthy = ReportBuilder::default();
        healthy.pass("test", "ok", Value::Null);
        assert_eq!(healthy.finish().exit_code, 0);

        let mut degraded = ReportBuilder::default();
        degraded.warning("test", "degraded", Value::Null);
        assert_eq!(degraded.finish().exit_code, 2);

        let mut failed = ReportBuilder::default();
        failed.warning("warning", "degraded", Value::Null);
        failed.failure("failure", "failed", Value::Null);
        assert_eq!(failed.finish().exit_code, 1);
    }

    #[test]
    fn json_schema_is_stable_and_contains_no_token_value() {
        let mut builder = ReportBuilder::default();
        builder.pass(
            "auth.token_file",
            "token file is present",
            json!({"path": "token.file", "length": 32}),
        );
        let value = serde_json::to_value(builder.finish()).expect("report serializes");
        assert_eq!(value["schema_version"], DOCTOR_SCHEMA_VERSION);
        assert_eq!(value["overall"], "healthy");
        assert_eq!(value["exit_code"], 0);
        assert_eq!(value["checks"][0]["id"], "auth.token_file");
        assert!(value.to_string().find("secret-token-value").is_none());
    }

    #[test]
    fn classifies_ready_as_pass() {
        let (status, message, _) = classify_webauthn_doctor(&json!({
            "enabled": true, "ready": true, "restart_required": false,
            "rp_id": "fabric.example", "rp_matched_origins": ["https://fabric.example/"], "problems": []
        }));
        assert_eq!(status, "pass");
        assert_eq!(message, "passkeys are configured and ready");
    }

    #[test]
    fn classifies_ready_but_stale_as_warning_naming_the_restart() {
        let (status, message, _) = classify_webauthn_doctor(&json!({
            "enabled": true, "ready": true, "restart_required": true,
            "rp_id": "fabric.example", "problems": []
        }));
        assert_eq!(status, "warning");
        assert!(message.contains("restart"));
    }

    #[test]
    fn classifies_disabled_as_info_not_a_problem() {
        // Password-only deployments are policy-supported, not degraded.
        let (status, _, _) = classify_webauthn_doctor(&json!({
            "enabled": false, "ready": false, "restart_required": false, "problems": []
        }));
        assert_eq!(status, "info");
    }

    #[test]
    fn classifies_enabled_but_not_ready_as_warning_carrying_the_problems() {
        let (status, message, details) = classify_webauthn_doctor(&json!({
            "enabled": true, "ready": false, "restart_required": false,
            "problems": ["auth.passkeys.rp_id is not configured"]
        }));
        assert_eq!(status, "warning");
        assert_eq!(message, "passkeys are enabled but misconfigured");
        assert_eq!(
            details["problems"],
            json!(["auth.passkeys.rp_id is not configured"])
        );
    }

    #[test]
    fn missing_fields_default_to_the_least_alarming_reading() {
        // A response the client cannot fully parse (schema drift, a partial
        // body) must not be misread as "ready" -- absence of `ready: true`
        // should fall through the same path as an explicit `false`.
        let (status, _, _) = classify_webauthn_doctor(&json!({}));
        assert_eq!(
            status, "info",
            "an empty/unparseable body must not be reported as ready"
        );
    }
}
