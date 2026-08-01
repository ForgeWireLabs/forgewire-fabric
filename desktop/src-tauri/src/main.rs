#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri_plugin_updater::UpdaterExt;
use zeroize::Zeroize;

// 114C.6 Slice 5d: the only submodule in this crate. Everything else lives
// flat in this file by existing convention; broken out here because the
// bridge's pure logic + its own unit tests are substantial on their own
// (mirrors packages/fabric-client-core/src/webauthnBridge.ts field-for-field
// -- see that module's doc comment for why it is a second implementation
// rather than a shared one) and because fabric-hub's own equivalent code
// already lives in its own `routes/webauthn_bridge.rs`, which this matches.
mod webauthn_bridge;
// 114D D.3: native Windows Hello passkey enrollment via
// webauthn-authenticator-rs, the primary path once a realm exists;
// webauthn_bridge above stays the deliberate fallback. See its own module
// doc comment for the full rationale and the Windows/non-Windows split.
mod native_webauthn;

const UPDATER_PUBLIC_KEY: Option<&str> = option_env!("FORGEWIRE_UPDATER_PUBLIC_KEY");

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HubCandidate {
    url: String,
    label: Option<String>,
    priority: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuiConfig {
    hub_url: String,
    #[serde(default)]
    hub_candidates: Vec<HubCandidate>,
    #[serde(default)]
    hub_pin: Option<String>,
    #[serde(default = "default_refresh_interval_seconds")]
    refresh_interval_seconds: u16,
}

#[derive(Debug, Clone, Serialize)]
struct DispatcherIdentitySummary {
    id: String,
    purpose: String,
    public_key_hex: String,
    path: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DispatchBrief {
    title: String,
    prompt: String,
    scope_globs: Vec<String>,
    base_commit: String,
    branch: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    dispatch: Option<String>,
    #[serde(default)]
    required_tags: Vec<String>,
    #[serde(default)]
    required_capabilities: Vec<String>,
    #[serde(default)]
    skill: Option<String>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    command: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedDispatchRequest {
    hub_url: String,
    brief: DispatchBrief,
}

#[derive(Debug, Clone, Serialize)]
struct SignedDispatchResult {
    status: String,
    task_id: Option<i64>,
    approval_id: Option<String>,
    message: String,
    body: Value,
}

#[derive(Debug, Clone, Serialize)]
struct HubDiscoveryCandidate {
    url: String,
    label: String,
    status: String,
    version: Option<String>,
    priority: u16,
    reachable: bool,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FabricContext {
    hub_url: String,
    hub_source: String,
    token_present: bool,
    token_path: Option<String>,
    token_source: Option<String>,
    dispatcher_identity: Option<DispatcherIdentitySummary>,
    identity_path: Option<String>,
    identity_source: Option<String>,
    hub_candidates: Vec<HubDiscoveryCandidate>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct NativeSnapshotResult {
    snapshot: Value,
    errors: BTreeMap<String, String>,
    restrictions: BTreeMap<String, String>,
    active_hub: String,
    refreshed_at_ms: u64,
    /// The installed credential's `fabric.*.write` capabilities from
    /// `GET /whoami`, folded into the snapshot round-trip so the operator UI
    /// can gate commands without a second request. Empty when the hub predates
    /// `/whoami` or the credential is unauthorized -- the client fails closed.
    authorities: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DesktopUpdateStatus {
    configured: bool,
    current_version: String,
    available: bool,
    version: Option<String>,
    published_at: Option<String>,
    notes: Option<String>,
    message: String,
}

fn updater_is_configured() -> bool {
    UPDATER_PUBLIC_KEY.is_some_and(|key| !key.trim().is_empty())
}

#[tauri::command]
async fn check_for_desktop_update(app: tauri::AppHandle) -> Result<DesktopUpdateStatus, String> {
    let current_version = app.package_info().version.to_string();
    if !updater_is_configured() {
        return Ok(DesktopUpdateStatus {
            configured: false,
            current_version,
            available: false,
            version: None,
            published_at: None,
            notes: None,
            message: "Signed updater is unavailable in this build: release public-key metadata was not embedded.".to_string(),
        });
    }
    let update = app
        .updater()
        .map_err(|error| format!("initialize signed updater: {error}"))?
        .check()
        .await
        .map_err(|error| format!("check signed update channel: {error}"))?;
    Ok(match update {
        Some(update) => DesktopUpdateStatus {
            configured: true,
            current_version,
            available: true,
            version: Some(update.version),
            published_at: update.date.map(|date| date.to_string()),
            notes: update.body,
            message: "A signature-verified desktop update is available. Installation requires explicit confirmation.".to_string(),
        },
        None => DesktopUpdateStatus {
            configured: true,
            current_version,
            available: false,
            version: None,
            published_at: None,
            notes: None,
            message: "No newer signed desktop release is available.".to_string(),
        },
    })
}

#[tauri::command]
async fn install_verified_desktop_update(app: tauri::AppHandle) -> Result<String, String> {
    if !updater_is_configured() {
        return Err(
            "signed updater is unavailable: this build has no embedded release public key"
                .to_string(),
        );
    }
    let update = app
        .updater()
        .map_err(|error| format!("initialize signed updater: {error}"))?
        .check()
        .await
        .map_err(|error| format!("recheck signed update channel: {error}"))?
        .ok_or_else(|| "no newer signed desktop release is available".to_string())?;
    let version = update.version.clone();
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|error| format!("verify and install desktop update: {error}"))?;
    Ok(format!(
        "Signed update {version} installed. Restart ForgeWire Fabric Desktop to use it."
    ))
}

#[derive(Debug, Clone, Deserialize)]
struct ApprovalDecisionRequest {
    hub_url: String,
    approval_id: String,
    approve: bool,
    approver: String,
    reason: String,
}

#[derive(Debug, Clone, Deserialize)]
struct LabelMutationRequest {
    hub_url: String,
    target: String,
    #[serde(default)]
    target_id: Option<String>,
    label: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SecretMutationRequest {
    hub_url: String,
    action: String,
    name: String,
    #[serde(default)]
    value: Option<String>,
}

/// Outcome of resolving the hub token from the environment or installed token files.
#[derive(Debug, Clone, Default)]
struct LoadedHubToken {
    token: Option<String>,
    path: Option<String>,
    source: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct TokenStorageSummary {
    present: bool,
    path: String,
    source: String,
}

fn default_refresh_interval_seconds() -> u16 {
    10
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            hub_url: "http://127.0.0.1:8765".to_string(),
            hub_candidates: Vec::new(),
            hub_pin: None,
            refresh_interval_seconds: default_refresh_interval_seconds(),
        }
    }
}

#[tauri::command]
fn load_dispatcher_identity(path: String) -> Result<DispatcherIdentitySummary, String> {
    let path = normalize_existing_path(&path)?;
    dispatcher_identity_summary_from_path(path)
}

#[tauri::command]
fn load_or_create_dispatcher_identity() -> Result<DispatcherIdentitySummary, String> {
    let path = desktop_dispatcher_identity_path()?;
    if path.exists() {
        return dispatcher_identity_summary_from_path(path);
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid identity path {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create identity directory {}: {error}", parent.display()))?;
    let hostname = desktop_hostname();
    let identity = fabric_identity::generate(
        &format!(
            "desktop-dispatcher-{}",
            sanitize_identity_fragment(&hostname)
        ),
        fabric_types::KeyPurpose::Dispatcher,
    );
    fabric_identity::save(&path, &identity).map_err(|error| {
        format!(
            "save desktop dispatcher identity {}: {error}",
            path.display()
        )
    })?;
    dispatcher_identity_summary_from_path(path)
}

fn dispatcher_identity_summary_from_path(
    path: PathBuf,
) -> Result<DispatcherIdentitySummary, String> {
    let identity = fabric_identity::load(&path)
        .map_err(|error| format!("load dispatcher identity {}: {error}", path.display()))?;
    if identity.purpose != fabric_types::KeyPurpose::Dispatcher {
        return Err(format!(
            "identity {} has purpose {:?}; dispatcher identity is required",
            identity.id, identity.purpose
        ));
    }
    Ok(DispatcherIdentitySummary {
        id: identity.id,
        purpose: "dispatcher".to_string(),
        public_key_hex: identity.public_key_hex,
        path: path.display().to_string(),
    })
}

#[tauri::command]
async fn dispatch_signed_task(
    request: SignedDispatchRequest,
) -> Result<SignedDispatchResult, String> {
    let hub_url = sanitize_url(&request.hub_url)?;
    let brief = normalize_brief(request.brief)?;
    let (client, identity) = desktop_dispatch_client(&hub_url).await?;
    match client.dispatch_signed(&identity, &brief).await {
        Ok(body) => Ok(dispatch_result_from_body(body)),
        Err(error) => {
            let status = error.status_code();
            let body = match &error {
                fabric_client::ClientError::Hub { body, .. } => {
                    serde_json::from_str::<Value>(body).unwrap_or_else(|_| json!({ "raw": body }))
                }
                _ => json!({ "error": error.to_string() }),
            };
            Ok(SignedDispatchResult {
                status: if error.is_approval_required() {
                    "held".to_string()
                } else if error.is_policy_denied() {
                    "denied".to_string()
                } else {
                    "error".to_string()
                },
                task_id: None,
                approval_id: error.approval_id(),
                message: if status > 0 {
                    format!("hub returned {status}: {error}")
                } else {
                    error.to_string()
                },
                body,
            })
        }
    }
}

async fn desktop_dispatch_client(
    hub_url: &str,
) -> Result<(fabric_client::HubClient, fabric_identity::IdentityFile), String> {
    let identity_summary = load_or_create_dispatcher_identity()?;
    let identity_path = normalize_existing_path(&identity_summary.path)?;
    let identity = fabric_identity::load(&identity_path).map_err(|error| {
        format!(
            "load dispatcher identity {}: {error}",
            identity_path.display()
        )
    })?;
    if identity.purpose != fabric_types::KeyPurpose::Dispatcher {
        return Err(format!(
            "identity {} has purpose {:?}; dispatcher identity is required",
            identity.id, identity.purpose
        ));
    }
    let token = load_hub_token()?
        .token
        .ok_or_else(|| "hub token is not installed; configure it in Settings".to_string())?;
    let client = fabric_client::HubClient::new(hub_url, &token);
    let hostname = desktop_hostname();
    client
        .register_dispatcher(
            &identity,
            &format!("Desktop on {hostname}"),
            &hostname,
            "tauri-desktop",
        )
        .await
        .map_err(|error| format!("register desktop dispatcher: {error}"))?;
    Ok((client, identity))
}

#[tauri::command]
async fn discover_hubs(seed_urls: Vec<String>) -> Result<Vec<HubDiscoveryCandidate>, String> {
    let candidates = seed_urls
        .into_iter()
        .enumerate()
        .map(|(index, url)| HubCandidate {
            url,
            label: None,
            priority: Some(100u16.saturating_add(index as u16)),
        })
        .collect();
    discover_ranked_hub_candidates(candidates).await
}

async fn discover_ranked_hub_candidates(
    candidates: Vec<HubCandidate>,
) -> Result<Vec<HubDiscoveryCandidate>, String> {
    let candidates = hub_probe_candidates(candidates)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(900))
        .build()
        .map_err(|error| format!("build discovery client: {error}"))?;
    let mut results = Vec::new();
    for candidate in candidates {
        let url = candidate.url;
        let health_url = format!("{}/healthz", url.trim_end_matches('/'));
        let priority = candidate.priority.unwrap_or(100);
        let fallback_label = candidate.label.unwrap_or_else(|| {
            url.trim_start_matches("http://")
                .trim_start_matches("https://")
                .to_string()
        });
        match client.get(&health_url).send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.json::<Value>().await.unwrap_or(Value::Null);
                let version = body
                    .get("package_version")
                    .or_else(|| body.get("version"))
                    .and_then(|value| value.as_str())
                    .map(str::to_string);
                let status = body
                    .get("status")
                    .and_then(|value| value.as_str())
                    .unwrap_or("ok")
                    .to_string();
                results.push(HubDiscoveryCandidate {
                    url: url.clone(),
                    label: fallback_label,
                    status,
                    version,
                    priority,
                    reachable: true,
                    error: None,
                });
            }
            Ok(response) => results.push(HubDiscoveryCandidate {
                url,
                label: fallback_label,
                status: "unreachable".to_string(),
                version: None,
                priority,
                reachable: false,
                error: Some(format!("health probe returned {}", response.status())),
            }),
            Err(error) => results.push(HubDiscoveryCandidate {
                url,
                label: fallback_label,
                status: "unreachable".to_string(),
                version: None,
                priority,
                reachable: false,
                error: Some(error.to_string()),
            }),
        }
    }
    results.sort_by_key(|candidate| candidate.priority);
    Ok(results)
}

#[tauri::command]
fn load_gui_config() -> Result<GuiConfig, String> {
    read_gui_config()
}

#[tauri::command]
async fn load_fabric_context() -> Result<FabricContext, String> {
    let mut warnings = Vec::new();
    let gui_config = match read_gui_config() {
        Ok(config) => config,
        Err(error) => {
            warnings.push(error);
            GuiConfig::default()
        }
    };

    let env_hub = env::var("FORGEWIRE_HUB_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let mut hub_source = if env_hub.is_some() {
        "FORGEWIRE_HUB_URL".to_string()
    } else {
        "gui.toml/default".to_string()
    };
    let preferred_hub = env_hub.unwrap_or(gui_config.hub_url.clone());

    let mut ranked_candidates = Vec::new();
    if let Some(pin) = gui_config
        .hub_pin
        .clone()
        .filter(|value| !value.trim().is_empty())
    {
        hub_source = "gui.toml hub_pin".to_string();
        ranked_candidates.push(HubCandidate {
            url: pin,
            label: Some("Pinned hub".to_string()),
            priority: Some(0),
        });
    } else {
        ranked_candidates.extend(gui_config.hub_candidates.clone());
        ranked_candidates.push(HubCandidate {
            url: preferred_hub.clone(),
            label: Some("Preferred hub".to_string()),
            priority: Some(100),
        });
    }

    let hub_candidates = match discover_ranked_hub_candidates(ranked_candidates).await {
        Ok(candidates) => candidates,
        Err(error) => {
            warnings.push(format!("hub discovery failed: {error}"));
            Vec::new()
        }
    };
    let hub_url =
        if let Some(candidate) = hub_candidates.iter().find(|candidate| candidate.reachable) {
            hub_source = "live hub discovery".to_string();
            candidate.url.clone()
        } else {
            sanitize_url(&preferred_hub).unwrap_or_else(|_| GuiConfig::default().hub_url)
        };

    let hub_token = match load_hub_token() {
        Ok(result) => result,
        Err(error) => {
            warnings.push(error);
            LoadedHubToken::default()
        }
    };

    let (dispatcher_identity, identity_path, identity_source) =
        match load_or_create_dispatcher_identity() {
            Ok(summary) => (
                Some(summary.clone()),
                Some(summary.path),
                Some("desktop dedicated identity".to_string()),
            ),
            Err(error) => {
                warnings.push(error);
                (None, None, None)
            }
        };

    Ok(FabricContext {
        hub_url,
        hub_source,
        token_present: hub_token.token.is_some(),
        token_path: hub_token.path,
        token_source: hub_token.source,
        dispatcher_identity,
        identity_path,
        identity_source,
        hub_candidates,
        warnings,
    })
}

#[tauri::command]
async fn load_fabric_snapshot(hub_url: String) -> Result<NativeSnapshotResult, String> {
    let hub_url = sanitize_url(&hub_url)?;
    let client = hub_client(&hub_url)?;
    let mut snapshot = json!({
        "health": null,
        "cluster": null,
        "runners": [],
        "agents": [],
        "tasks": [],
        "approvals": [],
        "budget": null,
        "cost": null,
        "hosts": [],
        "audit": null,
        "secrets": [],
        "dispatchers": [],
        "hub_settings": null,
        "history": null
    });
    let mut errors = BTreeMap::new();
    let mut restrictions = BTreeMap::new();

    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "health",
        client.healthz().await,
        None,
        Value::Null,
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "cluster",
        client.cluster_health().await,
        None,
        Value::Null,
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "runners",
        client.list_runners().await,
        Some("runners"),
        json!([]),
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "hub_settings",
        client.settings().await,
        None,
        Value::Null,
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "history",
        client.history_status().await,
        None,
        Value::Null,
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "agents",
        client.list_agents().await,
        Some("agents"),
        json!([]),
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "tasks",
        client.list_tasks(80).await,
        Some("tasks"),
        json!([]),
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "approvals",
        client.list_approvals("pending", 80).await,
        Some("approvals"),
        json!([]),
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "budget",
        client.cost_budget().await,
        None,
        Value::Null,
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "cost",
        client.cost_summary(7).await,
        None,
        Value::Null,
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "hosts",
        client.list_hosts().await,
        Some("hosts"),
        json!([]),
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "audit",
        client.audit_tail().await,
        None,
        Value::Null,
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "secrets",
        client.list_secrets().await,
        Some("secrets"),
        json!([]),
    );
    record_snapshot_result(
        &mut snapshot,
        &mut errors,
        &mut restrictions,
        "dispatchers",
        client.list_dispatchers().await,
        Some("dispatchers"),
        json!([]),
    );

    // Best-effort: the caller's authoritative capability set. A failure here
    // (older hub without /whoami, or an unauthorized credential) must not fail
    // the whole snapshot -- the client simply gates every authority-bearing
    // command closed, which is the correct fail-safe posture.
    let authorities = match client.whoami().await {
        Ok(value) => value
            .get("authorities")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    Ok(NativeSnapshotResult {
        snapshot,
        errors,
        restrictions,
        active_hub: hub_url,
        refreshed_at_ms: now_millis(),
        authorities,
    })
}

#[tauri::command]
async fn load_task_stream(
    hub_url: String,
    task_id: i64,
    after_seq: i64,
    limit: u16,
) -> Result<Value, String> {
    hub_client(&sanitize_url(&hub_url)?)?
        .task_stream(task_id, after_seq.max(0), limit.clamp(1, 500))
        .await
        .map_err(client_error)
}

#[tauri::command]
async fn load_task_audit(hub_url: String, task_id: i64) -> Result<Value, String> {
    hub_client(&sanitize_url(&hub_url)?)?
        .audit_for_task(task_id)
        .await
        .map_err(client_error)
}

#[tauri::command]
async fn load_task_detail(hub_url: String, task_id: i64) -> Result<Value, String> {
    hub_client(&sanitize_url(&hub_url)?)?
        .get_task(task_id)
        .await
        .map_err(client_error)
}

#[tauri::command]
async fn load_approval_detail(hub_url: String, approval_id: String) -> Result<Value, String> {
    let approval_id = non_empty_identifier(&approval_id, "approval ID")?;
    hub_client(&sanitize_url(&hub_url)?)?
        .get_approval(&approval_id)
        .await
        .map_err(client_error)
}

#[tauri::command]
async fn load_capability_detail(
    hub_url: String,
    kind: String,
    name: String,
) -> Result<Value, String> {
    let kind = non_empty_identifier(&kind, "capability kind")?;
    let name = non_empty_identifier(&name, "capability name")?;
    hub_client(&sanitize_url(&hub_url)?)?
        .get_capability(&kind, &name)
        .await
        .map_err(client_error)
}

#[tauri::command]
async fn load_audit_day(hub_url: String, day: String) -> Result<Value, String> {
    let day = day.trim();
    if day.len() != 10
        || !day
            .chars()
            .enumerate()
            .all(|(index, character)| index == 4 || index == 7 || character.is_ascii_digit())
        || day.as_bytes()[4] != b'-'
        || day.as_bytes()[7] != b'-'
    {
        return Err("audit day must use YYYY-MM-DD".to_string());
    }
    hub_client(&sanitize_url(&hub_url)?)?
        .audit_day(day)
        .await
        .map_err(client_error)
}

#[tauri::command]
async fn cancel_task(hub_url: String, task_id: i64) -> Result<Value, String> {
    hub_client(&sanitize_url(&hub_url)?)?
        .cancel_task(task_id)
        .await
        .map_err(client_error)
}

/// `GET /auth/bootstrap/status` (114C.7 walking skeleton -- the first real
/// auth-route call from Desktop). Uses `hub_client_public`, not `hub_client`:
/// this route needs no bearer, and requiring an installed token first would
/// block exactly the case this exists to check (a fresh hub, nothing
/// configured yet).
#[tauri::command]
async fn auth_bootstrap_status(hub_url: String) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(match client.bootstrap_status().await {
        Ok(data) => AuthResult::ok(data),
        Err(error) => AuthResult::from_error(&error),
    })
}

// ---- 114C.7 Slice 2: the remaining 23 directly-wireable auth/account -----
// commands. Every one uses `hub_client_public` (an empty-token client), not
// `hub_client`: the bearer these routes need is a human session's own
// access secret (an explicit argument below, sourced from platform secure
// storage by the caller), never the installed automation hub token --
// `hub_client()`'s hard requirement for that token would also wrongly block
// `auth_bootstrap`/`auth_login` before any credential exists at all. The
// other 6 of the 30 total routes (passkey/step-up ceremonies) are not
// wired here -- see `webauthn_bridge` and the equivalent note in
// `vscode/src/hubClient.ts`.

#[tauri::command]
async fn auth_bootstrap(
    hub_url: String,
    username: String,
    display_name: String,
    password: String,
    bootstrap_secret: Option<String>,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .bootstrap(
                &username,
                &display_name,
                &password,
                bootstrap_secret.as_deref(),
            )
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn auth_login(
    hub_url: String,
    username: String,
    password: String,
    client_kind: Option<String>,
    client_label: Option<String>,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    // 114E: mint a per-session Ed25519 keypair and bind its public key to the
    // new session. The hub records the public key; we return the *private* key
    // to the caller so it can be persisted in the keyring next to the session
    // secrets (`SessionSecrets.session_signing_key`) and used to sign
    // subsequent requests (proof-of-possession) instead of replaying the
    // bearer. A hub too old to understand `session_public_key` simply ignores
    // it and issues a bearer-only session, so this is safe against either side.
    let session_key = fabric_identity::generate(
        &format!(
            "desktop-session-{}",
            sanitize_identity_fragment(&desktop_hostname())
        ),
        fabric_types::KeyPurpose::Node,
    );
    Ok(
        match client
            .login(
                &username,
                &password,
                client_kind.as_deref(),
                client_label.as_deref(),
                Some(&session_key.public_key_hex),
            )
            .await
        {
            Ok(mut data) => {
                // Attach the private key so the renderer can store it via
                // `save_session_secrets`; it is never sent to the hub.
                if let Some(obj) = data.as_object_mut() {
                    obj.insert(
                        "session_signing_key".to_string(),
                        serde_json::json!(session_key.secret_key_hex),
                    );
                }
                AuthResult::ok(data)
            }
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn auth_refresh(
    hub_url: String,
    session_id: String,
    refresh_secret: String,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client.refresh_session(&session_id, &refresh_secret).await {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn auth_logout(
    hub_url: String,
    access_secret: String,
    session_id: String,
    session_signing_key: Option<String>,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    // 114E: a key-bound session signs its logout; a bearer-only session (no
    // stored signing key) replays the access secret exactly as before.
    let result = match session_signing_key.as_deref() {
        Some(key) => client.logout_signed(&session_id, key).await,
        None => client.logout(&access_secret, &session_id).await,
    };
    Ok(match result {
        Ok(data) => AuthResult::ok(data),
        Err(error) => AuthResult::from_error(&error),
    })
}

#[tauri::command]
async fn auth_logout_all(hub_url: String, access_secret: String) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(match client.logout_all(&access_secret).await {
        Ok(data) => AuthResult::ok(data),
        Err(error) => AuthResult::from_error(&error),
    })
}

#[tauri::command]
async fn auth_me(
    hub_url: String,
    access_secret: String,
    session_id: Option<String>,
    session_signing_key: Option<String>,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    // 114E: prefer proof-of-possession when the session is key-bound (session_id
    // + signing key both present); otherwise fall back to the bearer secret.
    let result = match (session_id.as_deref(), session_signing_key.as_deref()) {
        (Some(sid), Some(key)) => client.me_signed(sid, key).await,
        _ => client.me(&access_secret).await,
    };
    Ok(match result {
        Ok(data) => AuthResult::ok(data),
        Err(error) => AuthResult::from_error(&error),
    })
}

#[tauri::command]
async fn auth_remove_passkey(
    hub_url: String,
    access_secret: String,
    credential_id: String,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client.remove_passkey(&access_secret, &credential_id).await {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

/// NOT a public route despite the name suggesting a bootstrap-style probe
/// -- `GET /auth-policy` requires `observer`/`reviewer` (`required_roles`
/// in `fabric-hub/src/auth.rs`), so this needs the installed automation
/// token like `healthz`/`whoami`, not `hub_client_public`. (Discovered live
/// 2026-07-22: using the public client meant this call always 401'd, so
/// `humanAccountsAdvertised` was never true regardless of hub support.)
/// If no token is installed yet, that is exactly "cannot tell if this hub
/// advertises human accounts" -- reported as `ok: false`, not a hard error,
/// matching every other caller's `.then(ok => ..., () => advertised=false)`
/// handling.
#[tauri::command]
async fn auth_policy(hub_url: String) -> Result<AuthResult, String> {
    let client = match hub_client(&sanitize_url(&hub_url)?) {
        Ok(client) => client,
        Err(message) => {
            return Ok(AuthResult {
                ok: false,
                data: None,
                code: None,
                message: Some(message),
            })
        }
    };
    Ok(match client.auth_policy().await {
        Ok(data) => AuthResult::ok(data),
        Err(error) => AuthResult::from_error(&error),
    })
}

#[tauri::command]
async fn list_auth_sessions(
    hub_url: String,
    access_secret: String,
    account_id: Option<String>,
    session_id: Option<String>,
    session_signing_key: Option<String>,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    let result = match (session_id.as_deref(), session_signing_key.as_deref()) {
        (Some(sid), Some(key)) => {
            client
                .list_auth_sessions_signed(sid, key, account_id.as_deref())
                .await
        }
        _ => {
            client
                .list_auth_sessions(&access_secret, account_id.as_deref())
                .await
        }
    };
    Ok(match result {
        Ok(data) => AuthResult::ok(data),
        Err(error) => AuthResult::from_error(&error),
    })
}

#[tauri::command]
async fn revoke_auth_session(
    hub_url: String,
    access_secret: String,
    session_id: String,
    auth_session_id: Option<String>,
    session_signing_key: Option<String>,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    // `session_id` is the revocation target; `auth_session_id` + signing key
    // authenticate the caller via PoP when present (else the bearer secret).
    let result = match (auth_session_id.as_deref(), session_signing_key.as_deref()) {
        (Some(sid), Some(key)) => {
            client
                .revoke_auth_session_signed(sid, key, &session_id)
                .await
        }
        _ => {
            client
                .revoke_auth_session(&access_secret, &session_id)
                .await
        }
    };
    Ok(match result {
        Ok(data) => AuthResult::ok(data),
        Err(error) => AuthResult::from_error(&error),
    })
}

#[tauri::command]
async fn list_accounts(
    hub_url: String,
    access_secret: String,
    limit: i64,
    offset: i64,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client.list_accounts(&access_secret, limit, offset).await {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn create_account(
    hub_url: String,
    access_secret: String,
    username: String,
    display_name: String,
    password: String,
    role: String,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .create_account(&access_secret, &username, &display_name, &password, &role)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn get_account(
    hub_url: String,
    access_secret: String,
    account_id: String,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client.get_account(&access_secret, &account_id).await {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn update_account_status(
    hub_url: String,
    access_secret: String,
    account_id: String,
    status: String,
    expected_revision: i64,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .update_account_status(&access_secret, &account_id, &status, expected_revision)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn grant_membership(
    hub_url: String,
    access_secret: String,
    account_id: String,
    role: String,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .grant_membership(&access_secret, &account_id, &role)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn revoke_membership(
    hub_url: String,
    access_secret: String,
    account_id: String,
    role: String,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .revoke_membership(&access_secret, &account_id, &role)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn disable_account(
    hub_url: String,
    access_secret: String,
    account_id: String,
    expected_revision: i64,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .disable_account(&access_secret, &account_id, expected_revision)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn enable_account(
    hub_url: String,
    access_secret: String,
    account_id: String,
    expected_revision: i64,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .enable_account(&access_secret, &account_id, expected_revision)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn generate_recovery_codes(
    hub_url: String,
    access_secret: String,
    account_id: String,
    count: i64,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .generate_recovery_codes(&access_secret, &account_id, count)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn complete_recovery(
    hub_url: String,
    access_secret: String,
    account_id: String,
    code: String,
    new_password: String,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .complete_recovery(&access_secret, &account_id, &code, &new_password)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn initiate_account_deletion(
    hub_url: String,
    access_secret: String,
    account_id: String,
    expected_revision: i64,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .initiate_account_deletion(&access_secret, &account_id, expected_revision)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn complete_account_deletion(
    hub_url: String,
    access_secret: String,
    account_id: String,
    expected_revision: i64,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .complete_account_deletion(&access_secret, &account_id, expected_revision)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn account_security_history(
    hub_url: String,
    access_secret: String,
    account_id: String,
    limit: i64,
) -> Result<AuthResult, String> {
    let client = hub_client_public(&sanitize_url(&hub_url)?);
    Ok(
        match client
            .account_security_history(&access_secret, &account_id, limit)
            .await
        {
            Ok(data) => AuthResult::ok(data),
            Err(error) => AuthResult::from_error(&error),
        },
    )
}

#[tauri::command]
async fn set_runner_drain(
    hub_url: String,
    runner_id: String,
    drain: bool,
) -> Result<Value, String> {
    let runner_id = non_empty_identifier(&runner_id, "runner ID")?;
    hub_client(&sanitize_url(&hub_url)?)?
        .set_runner_drain(&runner_id, drain)
        .await
        .map_err(client_error)
}

#[tauri::command]
async fn decide_approval(request: ApprovalDecisionRequest) -> Result<Value, String> {
    let approval_id = non_empty_identifier(&request.approval_id, "approval ID")?;
    let approver = non_empty_identifier(&request.approver, "approver")?;
    let reason = request.reason.trim();
    if !request.approve && reason.is_empty() {
        return Err("denial reason is required".to_string());
    }
    let decision = json!({
        "approver": approver,
        "reason": if reason.is_empty() { "Approved from Fabric Desktop" } else { reason },
    });
    hub_client(&sanitize_url(&request.hub_url)?)?
        .decide_approval(&approval_id, request.approve, &decision)
        .await
        .map_err(client_error)
}

#[tauri::command]
async fn rename_fabric_entity(request: LabelMutationRequest) -> Result<Value, String> {
    let label = request.label.trim();
    if label.len() > 80 {
        return Err("label must be at most 80 characters".to_string());
    }
    let client = hub_client(&sanitize_url(&request.hub_url)?)?;
    let actor = format!("Desktop on {}", desktop_hostname());
    match request.target.as_str() {
        "hub" => client.set_hub_label(label, &actor).await,
        "host" => {
            let target_id = non_empty_identifier(
                request.target_id.as_deref().unwrap_or_default(),
                "host name",
            )?;
            client.set_host_label(&target_id, label, &actor).await
        }
        "runner" => {
            let target_id = non_empty_identifier(
                request.target_id.as_deref().unwrap_or_default(),
                "runner ID",
            )?;
            client.set_runner_label(&target_id, label, &actor).await
        }
        _ => return Err("label target must be hub, host, or runner".to_string()),
    }
    .map_err(client_error)
}

#[tauri::command]
async fn govern_secret(request: SecretMutationRequest) -> Result<Value, String> {
    let name = non_empty_identifier(&request.name, "secret name")?;
    let client = hub_client(&sanitize_url(&request.hub_url)?)?;
    match request.action.as_str() {
        "put" | "rotate" => {
            let mut value = request.value.unwrap_or_default();
            if value.is_empty() {
                return Err("secret value is required".to_string());
            }
            let result = client.put_or_rotate_secret(&name, &value).await;
            value.zeroize();
            result.map_err(client_error)
        }
        "delete" => client.delete_secret(&name).await.map_err(client_error),
        _ => Err("secret action must be put, rotate, or delete".to_string()),
    }
}

#[tauri::command]
async fn redispatch_task(hub_url: String, task_id: i64) -> Result<SignedDispatchResult, String> {
    let hub_url = sanitize_url(&hub_url)?;
    let (client, identity) = desktop_dispatch_client(&hub_url).await?;
    let response = client.get_task(task_id).await.map_err(client_error)?;
    let task = response.get("task").unwrap_or(&response);
    let scope_globs = task
        .get("scope_globs")
        .cloned()
        .or_else(|| {
            task.get("scope_globs_json")
                .and_then(Value::as_str)
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
        })
        .unwrap_or_else(|| json!([]));
    let brief = json!({
        "title": task.get("title").cloned().unwrap_or_else(|| json!(format!("Redispatch task {task_id}"))),
        "prompt": task.get("prompt").cloned().unwrap_or_else(|| json!("Redispatched from Fabric Desktop")),
        "scope_globs": scope_globs,
        "base_commit": task.get("base_commit").cloned().unwrap_or_else(|| json!("origin/main")),
        "branch": task.get("branch").cloned().unwrap_or_else(|| json!(format!("agent/redispatch/{task_id}"))),
        "kind": task.get("kind").cloned().unwrap_or_else(|| json!("agent")),
        "dispatch": task.get("dispatch").cloned().unwrap_or_else(|| json!("prompt")),
        "priority": task.get("priority").cloned().unwrap_or_else(|| json!(100)),
        "timeout_minutes": task.get("timeout_minutes").cloned().unwrap_or_else(|| json!(60)),
        "require_base_commit": task.get("require_base_commit").cloned().unwrap_or(Value::Bool(false)),
    });
    match client.dispatch_signed(&identity, &brief).await {
        Ok(body) => Ok(dispatch_result_from_body(body)),
        Err(error) => Err(client_error(error)),
    }
}

#[tauri::command]
fn save_hub_token(token: String) -> Result<TokenStorageSummary, String> {
    let token = token.trim();
    if token.len() < 16 || token.chars().any(char::is_whitespace) {
        return Err("hub token must be at least 16 non-whitespace characters".to_string());
    }
    let path = user_forgewire_dir()?.join("hub.token");
    let parent = path
        .parent()
        .ok_or_else(|| "invalid hub token path".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create token directory {}: {error}", parent.display()))?;
    fs::write(&path, token.as_bytes())
        .map_err(|error| format!("write hub token {}: {error}", path.display()))?;
    restrict_secret_permissions(&path)?;
    Ok(TokenStorageSummary {
        present: true,
        path: path.display().to_string(),
        source: "~/.forgewire/hub.token".to_string(),
    })
}

#[tauri::command]
fn remove_hub_token() -> Result<TokenStorageSummary, String> {
    let path = user_forgewire_dir()?.join("hub.token");
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| format!("remove hub token {}: {error}", path.display()))?;
    }
    Ok(TokenStorageSummary {
        present: false,
        path: path.display().to_string(),
        source: "~/.forgewire/hub.token".to_string(),
    })
}

#[tauri::command]
fn set_hub_pin(pin: Option<String>) -> Result<GuiConfig, String> {
    let mut config = read_gui_config()?;
    config.hub_pin = pin
        .map(|value| sanitize_url(&value))
        .transpose()?
        .filter(|value| !value.is_empty());
    save_gui_config(config)
}

// ---- Human-session secrets (114C.6) -------------------------------------------
//
// Implements `SessionCredentialStore` (packages/fabric-client-core/src/
// contracts.ts) over the OS credential store, closing the still-open half of
// 114C.3's "protected session storage adapters for VSIX and Desktop"
// deliverable -- the VSIX half has an existing `SecretStorage` precedent,
// Desktop's had never been built.
//
// Deliberately NOT the `~/.forgewire/hub.token` plaintext-file pattern used
// for the static hub token above: session secrets rotate on every login and
// every step-up, so a frequently-rewritten plaintext file is a materially
// worse blast radius than a single static token. WebAuthn *private keys*
// never appear here at all -- they never leave the platform authenticator,
// which is what makes "private keys never enter Fabric storage or renderer
// state" true by construction rather than by discipline.

const SESSION_KEYRING_SERVICE: &str = "forgewire-fabric-desktop";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionSecrets {
    session_id: String,
    access_secret: String,
    refresh_secret: String,
    /// 114E proof-of-possession: the hex Ed25519 *private* key this session was
    /// bound to at login. Present only for key-bound (PoP) sessions; a bearer-
    /// only session (or a pre-114E stored entry) leaves it `None` and continues
    /// to authenticate with `access_secret`. Kept in the OS keyring next to the
    /// session secrets, never in renderer state.
    #[serde(default)]
    session_signing_key: Option<String>,
}

fn session_entry(profile_id: &str) -> Result<keyring::Entry, String> {
    let profile_id = profile_id.trim();
    if profile_id.is_empty() {
        return Err("profile id is required".to_string());
    }
    keyring::Entry::new(SESSION_KEYRING_SERVICE, profile_id)
        .map_err(|error| format!("open credential store entry: {error}"))
}

#[tauri::command]
fn save_session_secrets(profile_id: String, secrets: SessionSecrets) -> Result<(), String> {
    if secrets.session_id.trim().is_empty()
        || secrets.access_secret.trim().is_empty()
        || secrets.refresh_secret.trim().is_empty()
    {
        return Err("session_id, access_secret, and refresh_secret are all required".to_string());
    }
    let payload = serde_json::to_string(&secrets)
        .map_err(|error| format!("serialize session secrets: {error}"))?;
    session_entry(&profile_id)?
        .set_password(&payload)
        // The error is deliberately not interpolated with `payload`: a
        // keyring error message must never carry the secret it failed to
        // store.
        .map_err(|error| format!("store session secrets: {error}"))
}

#[tauri::command]
fn load_session_secrets(profile_id: String) -> Result<Option<SessionSecrets>, String> {
    match session_entry(&profile_id)?.get_password() {
        Ok(payload) => serde_json::from_str(&payload)
            .map(Some)
            // A corrupt/legacy entry reads as "no stored session" rather than
            // a hard error: the caller's correct response either way is to
            // sign in again, and failing loudly here would strand the user
            // with no in-app path to recover.
            .or(Ok(None)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("read session secrets: {error}")),
    }
}

#[tauri::command]
fn clear_session_secrets(profile_id: String) -> Result<(), String> {
    match session_entry(&profile_id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(format!("clear session secrets: {error}")),
    }
}

fn record_snapshot_result(
    snapshot: &mut Value,
    errors: &mut BTreeMap<String, String>,
    restrictions: &mut BTreeMap<String, String>,
    key: &str,
    result: Result<Value, fabric_client::ClientError>,
    nested_key: Option<&str>,
    fallback: Value,
) {
    match result {
        Ok(value) => {
            snapshot[key] = nested_key
                .and_then(|nested| value.get(nested).cloned())
                .unwrap_or(value);
        }
        Err(error) => {
            snapshot[key] = fallback;
            if let Some(message) = role_policy_restriction(&error) {
                restrictions.insert(key.to_string(), message);
            } else {
                errors.insert(key.to_string(), client_error(error));
            }
        }
    }
}

fn role_policy_restriction(error: &fabric_client::ClientError) -> Option<String> {
    let fabric_client::ClientError::Hub { status: 403, body } = error else {
        return None;
    };
    let body: Value = serde_json::from_str(body).ok()?;
    let detail = body.get("error").unwrap_or(&body);
    if detail.get("code").and_then(Value::as_str) != Some("RolePolicyViolation") {
        return None;
    }
    let roles = |key: &str| {
        detail
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let required = roles("required_roles");
    let granted = roles("granted_roles");
    Some(match (required.is_empty(), granted.is_empty()) {
        (false, false) => {
            format!("Requires {required} role access. Current token roles: {granted}.")
        }
        (false, true) => format!("Requires {required} role access."),
        _ => "The current role token does not grant access to this view.".to_string(),
    })
}

fn read_gui_config() -> Result<GuiConfig, String> {
    let path = gui_config_path()?;
    if !path.exists() {
        return Ok(GuiConfig::default());
    }
    let body =
        fs::read_to_string(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    toml::from_str::<GuiConfig>(&body).map_err(|error| format!("parse {}: {error}", path.display()))
}

#[tauri::command]
fn save_gui_config(config: GuiConfig) -> Result<GuiConfig, String> {
    let path = gui_config_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid config path {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;

    let sanitized = GuiConfig {
        hub_url: config.hub_url.trim().trim_end_matches('/').to_string(),
        hub_candidates: config
            .hub_candidates
            .into_iter()
            .map(|candidate| HubCandidate {
                url: candidate.url.trim().trim_end_matches('/').to_string(),
                label: candidate
                    .label
                    .map(|label| label.trim().to_string())
                    .filter(|label| !label.is_empty()),
                priority: candidate.priority,
            })
            .filter(|candidate| !candidate.url.is_empty())
            .collect(),
        hub_pin: config
            .hub_pin
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty()),
        refresh_interval_seconds: config.refresh_interval_seconds.clamp(2, 300),
    };
    let body = toml::to_string_pretty(&sanitized)
        .map_err(|error| format!("serialize gui config: {error}"))?;
    fs::write(&path, body).map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(sanitized)
}

fn gui_config_path() -> Result<PathBuf, String> {
    Ok(user_forgewire_dir()?.join("gui.toml"))
}

fn user_forgewire_dir() -> Result<PathBuf, String> {
    let home = env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
        .ok_or_else(|| "could not resolve user home directory".to_string())?;
    Ok(home.join(".forgewire"))
}

fn desktop_dispatcher_identity_path() -> Result<PathBuf, String> {
    Ok(user_forgewire_dir()?.join("desktop_dispatcher_identity.json"))
}

fn desktop_hostname() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

fn sanitize_identity_fragment(value: &str) -> String {
    let value: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    value.trim_matches('-').to_string()
}

#[cfg(unix)]
fn restrict_secret_permissions(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("set secret permissions {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn restrict_secret_permissions(_path: &std::path::Path) -> Result<(), String> {
    // The existing ~/.forgewire token path is the operator-approved Windows
    // credential source. Installer ACL hardening remains authoritative there.
    Ok(())
}

fn normalize_existing_path(path: &str) -> Result<PathBuf, String> {
    let trimmed = path.trim().trim_matches('"');
    if trimmed.is_empty() {
        return Err("identity path is required".to_string());
    }
    let path = PathBuf::from(trimmed);
    if !path.exists() {
        return Err(format!("identity file does not exist: {}", path.display()));
    }
    if !path.is_file() {
        return Err(format!("identity path is not a file: {}", path.display()));
    }
    Ok(path)
}

fn hub_probe_candidates(seed_candidates: Vec<HubCandidate>) -> Result<Vec<HubCandidate>, String> {
    let mut candidates: Vec<HubCandidate> = Vec::new();
    for mut candidate in seed_candidates {
        candidate.url = sanitize_url(&candidate.url)?;
        if let Some(index) = candidates
            .iter()
            .position(|existing| existing.url == candidate.url)
        {
            if candidate.priority.unwrap_or(100) < candidates[index].priority.unwrap_or(100) {
                candidates[index] = candidate;
            }
        } else {
            candidates.push(candidate);
        }
    }
    let local = HubCandidate {
        url: "http://127.0.0.1:8765".to_string(),
        label: Some("Local hub".to_string()),
        priority: Some(500),
    };
    if !candidates
        .iter()
        .any(|candidate| candidate.url == local.url)
    {
        candidates.push(local);
    }
    candidates.sort_by_key(|candidate| candidate.priority.unwrap_or(100));
    Ok(candidates)
}

fn sanitize_url(value: &str) -> Result<String, String> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("hub URL is required".to_string());
    }
    let normalized = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    Ok(normalized
        .replacen("http://localhost", "http://127.0.0.1", 1)
        .replacen("https://localhost", "https://127.0.0.1", 1))
}

fn hub_client(hub_url: &str) -> Result<fabric_client::HubClient, String> {
    let token = load_hub_token()?
        .token
        .ok_or_else(|| "hub token is not installed; configure it in Settings".to_string())?;
    Ok(fabric_client::HubClient::new(hub_url, &token))
}

/// 114C.7: public auth routes (bootstrap status, login, passkey-login
/// options/verify, ...) have no bearer to send -- there is no credential
/// before the first admin exists, or before the caller has signed in at
/// all. `hub_client` above hard-requires an installed token before it will
/// even construct a client, which is right for every other route but wrong
/// here: it would block a bootstrap-status check on a fresh, never-
/// configured hub, exactly the situation where checking matters most.
fn hub_client_public(hub_url: &str) -> fabric_client::HubClient {
    fabric_client::HubClient::new(hub_url, "")
}

fn client_error(error: fabric_client::ClientError) -> String {
    let status = error.status_code();
    if status > 0 {
        format!("hub returned {status}: {error}")
    } else {
        error.to_string()
    }
}

/// Response shape for 114C auth-route Tauri commands. Deliberately not
/// `Result<Value, String>` (the convention every other command here uses):
/// the hub's own error responses for these routes carry a stable typed code
/// a caller should switch on, and `client_error` above -- correct for every
/// non-auth route -- formats the *raw response body* into the string a
/// rejected promise would carry, which is exactly the leak this type exists
/// to avoid (see `fabric_client::ClientError::typed_auth_error`'s own doc
/// comment). `sanitize_url`/`hub_client` failures (bad input, no token
/// installed) still reject the promise normally via the outer
/// `Result<AuthResult, String>` -- only the *hub's own response* to a
/// well-formed request flows through this softer ok/code/message shape.
#[derive(Debug, Serialize)]
struct AuthResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl AuthResult {
    fn ok(data: Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            code: None,
            message: None,
        }
    }

    fn from_error(error: &fabric_client::ClientError) -> Self {
        match error.typed_auth_error() {
            Some(typed) => Self {
                ok: false,
                data: None,
                code: Some(typed.code),
                message: Some(typed.message),
            },
            None => Self {
                ok: false,
                data: None,
                code: None,
                message: Some("The hub returned an unexpected error. Try again.".to_string()),
            },
        }
    }

    /// A failure that never touched the hub at all (no stored session, the
    /// bridge could not open, an incomplete reply) -- as opposed to
    /// `from_error`, which classifies an actual hub HTTP response. Used by
    /// `webauthn_bridge::step_up`, whose failure modes span both.
    fn plain_error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            code: None,
            message: Some(message.into()),
        }
    }
}

fn non_empty_identifier(value: &str, label: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.contains('/') || value.contains('\\') {
        return Err(format!("invalid {label}"));
    }
    Ok(value.to_string())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn load_hub_token() -> Result<LoadedHubToken, String> {
    if let Ok(token) = env::var("FORGEWIRE_HUB_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok(LoadedHubToken {
                token: Some(token),
                path: None,
                source: Some("FORGEWIRE_HUB_TOKEN".to_string()),
            });
        }
    }

    let mut paths = Vec::new();
    if let Ok(path) = env::var("FORGEWIRE_HUB_TOKEN_FILE") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            paths.push((
                PathBuf::from(trimmed),
                "FORGEWIRE_HUB_TOKEN_FILE".to_string(),
            ));
        }
    }
    paths.extend(installed_token_paths());

    for (path, source) in paths {
        if !path.exists() {
            continue;
        }
        let token = fs::read_to_string(&path)
            .map_err(|error| format!("read hub token {}: {error}", path.display()))?
            .trim()
            .to_string();
        if !token.is_empty() {
            return Ok(LoadedHubToken {
                token: Some(token),
                path: Some(path.display().to_string()),
                source: Some(source),
            });
        }
    }
    Ok(LoadedHubToken::default())
}

fn installed_token_paths() -> Vec<(PathBuf, String)> {
    installed_base_dirs()
        .into_iter()
        .map(|(base, source)| (base.join("hub.token"), source))
        .collect()
}

fn installed_base_dirs() -> Vec<(PathBuf, String)> {
    let mut bases = Vec::new();
    if let Some(home) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) {
        bases.push((
            PathBuf::from(home).join(".forgewire"),
            "~/.forgewire".to_string(),
        ));
    }
    let program_data = env::var_os("ProgramData")
        .or_else(|| env::var_os("PROGRAMDATA"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    bases.push((
        program_data.join("forgewire"),
        "ProgramData/forgewire".to_string(),
    ));
    bases
}

fn normalize_brief(brief: DispatchBrief) -> Result<Value, String> {
    let title = brief.title.trim();
    let prompt = brief.prompt.trim();
    let base_commit = brief.base_commit.trim();
    let branch = brief.branch.trim();
    let kind = match brief.kind.trim() {
        "" => "agent",
        "agent" => "agent",
        "command" => "command",
        other => return Err(format!("kind must be agent or command, got {other}")),
    };
    let dispatch = brief.dispatch.as_deref().unwrap_or("prompt").trim();

    if title.is_empty() {
        return Err("title is required".to_string());
    }
    if prompt.is_empty() {
        return Err("prompt/brief is required".to_string());
    }
    if base_commit.is_empty() {
        return Err("base commit is required".to_string());
    }
    if branch.is_empty() {
        return Err("branch is required".to_string());
    }

    let scope_globs: Vec<String> = brief
        .scope_globs
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect();
    if scope_globs.is_empty() {
        return Err("at least one scope glob is required".to_string());
    }

    let required_tags: Vec<String> = brief
        .required_tags
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect();
    let required_capabilities: Vec<String> = brief
        .required_capabilities
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect();

    let mut body = json!({
        "title": title,
        "prompt": prompt,
        "scope_globs": scope_globs,
        "base_commit": base_commit,
        "branch": branch,
        "kind": kind,
        "dispatch": dispatch,
        "timeout_minutes": 60,
        "priority": 100,
        "require_base_commit": false,
    });
    let object = body.as_object_mut().expect("json object");
    if !required_tags.is_empty() {
        object.insert("required_tags".to_string(), json!(required_tags));
    }
    if !required_capabilities.is_empty() {
        object.insert(
            "required_capabilities".to_string(),
            json!(required_capabilities),
        );
    }
    if let Some(skill) = brief
        .skill
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        object.insert("skill".to_string(), json!(skill));
    }
    if let Some(tool) = brief
        .tool
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        object.insert("tool".to_string(), json!(tool));
    }
    if kind == "command" {
        let command: Vec<String> = brief
            .command
            .into_iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect();
        if command.is_empty() {
            return Err("command dispatch requires at least one command token".to_string());
        }
        object.insert("command".to_string(), json!(command));
    }
    Ok(body)
}

fn dispatch_result_from_body(body: Value) -> SignedDispatchResult {
    let task_id = body
        .get("task")
        .and_then(|task| task.get("id").or_else(|| task.get("task_id")))
        .and_then(|id| id.as_i64())
        .or_else(|| {
            body.get("id")
                .or_else(|| body.get("task_id"))
                .and_then(|id| id.as_i64())
        });
    let approval_id = body
        .get("approval_id")
        .and_then(|id| id.as_str())
        .map(str::to_string);
    let status = if approval_id.is_some() {
        "held"
    } else if task_id.is_some() {
        "queued"
    } else {
        "submitted"
    };
    SignedDispatchResult {
        status: status.to_string(),
        task_id,
        approval_id,
        message: match status {
            "held" => "dispatch is held for approval".to_string(),
            "queued" => "dispatch queued".to_string(),
            _ => "dispatch submitted".to_string(),
        },
        body,
    }
}

fn main() {
    let mut builder = tauri::Builder::default();
    if let Some(public_key) = UPDATER_PUBLIC_KEY.filter(|key| !key.trim().is_empty()) {
        builder = builder.plugin(
            tauri_plugin_updater::Builder::new()
                .pubkey(public_key)
                .build(),
        );
    }
    builder
        .setup(|_| {
            // Establish the client-specific audit identity before WebView
            // initialization. This keeps the desktop lifecycle valid during
            // slow, failed, or non-interactive WebView startup and makes
            // package validation independent of renderer timing.
            load_or_create_dispatcher_identity().map_err(std::io::Error::other)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            load_gui_config,
            load_fabric_context,
            load_fabric_snapshot,
            save_gui_config,
            save_hub_token,
            remove_hub_token,
            set_hub_pin,
            save_session_secrets,
            load_session_secrets,
            clear_session_secrets,
            webauthn_bridge::sign_in_with_passkey,
            webauthn_bridge::register_passkey,
            webauthn_bridge::step_up,
            native_webauthn::register_passkey_native,
            load_dispatcher_identity,
            load_or_create_dispatcher_identity,
            dispatch_signed_task,
            discover_hubs,
            load_task_stream,
            load_task_audit,
            load_task_detail,
            load_approval_detail,
            load_capability_detail,
            load_audit_day,
            cancel_task,
            auth_bootstrap_status,
            auth_bootstrap,
            auth_login,
            auth_refresh,
            auth_logout,
            auth_logout_all,
            auth_me,
            auth_remove_passkey,
            auth_policy,
            list_auth_sessions,
            revoke_auth_session,
            list_accounts,
            create_account,
            get_account,
            update_account_status,
            grant_membership,
            revoke_membership,
            disable_account,
            enable_account,
            generate_recovery_codes,
            complete_recovery,
            initiate_account_deletion,
            complete_account_deletion,
            account_security_history,
            redispatch_task,
            set_runner_drain,
            decide_approval,
            rename_fabric_entity,
            govern_secret,
            check_for_desktop_update,
            install_verified_desktop_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running ForgeWire Fabric Desktop");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updater_requires_embedded_public_key_metadata() {
        assert_eq!(
            updater_is_configured(),
            UPDATER_PUBLIC_KEY.is_some_and(|key| !key.trim().is_empty())
        );
    }

    #[test]
    fn local_hub_aliases_normalize_and_deduplicate() {
        let candidates = hub_probe_candidates(vec![
            HubCandidate {
                url: "http://localhost:8765/".to_string(),
                label: Some("alias".to_string()),
                priority: Some(200),
            },
            HubCandidate {
                url: "127.0.0.1:8765".to_string(),
                label: Some("preferred".to_string()),
                priority: Some(10),
            },
        ])
        .expect("candidate normalization");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].url, "http://127.0.0.1:8765");
        assert_eq!(candidates[0].priority, Some(10));
    }

    #[test]
    fn desktop_context_never_serializes_token_material() {
        let context = FabricContext {
            hub_url: "http://127.0.0.1:8765".to_string(),
            hub_source: "test".to_string(),
            token_present: true,
            token_path: Some("~/.forgewire/hub.token".to_string()),
            token_source: Some("test".to_string()),
            dispatcher_identity: None,
            identity_path: None,
            identity_source: None,
            hub_candidates: Vec::new(),
            warnings: Vec::new(),
        };
        let json = serde_json::to_value(context).expect("serialize context");
        assert_eq!(json["token_present"], true);
        assert!(json.get("token").is_none());
    }

    #[test]
    fn signed_dispatch_brief_keeps_agent_and_command_taxonomy() {
        let body = normalize_brief(DispatchBrief {
            title: "smoke".to_string(),
            prompt: "run smoke".to_string(),
            scope_globs: vec!["desktop/**".to_string()],
            base_commit: "origin/main".to_string(),
            branch: "agent/smoke".to_string(),
            kind: "command".to_string(),
            dispatch: Some("prompt".to_string()),
            required_tags: Vec::new(),
            required_capabilities: Vec::new(),
            skill: None,
            tool: None,
            command: vec!["npm".to_string(), "test".to_string()],
        })
        .expect("valid command brief");
        assert_eq!(body["kind"], "command");
        assert_eq!(body["command"], json!(["npm", "test"]));
    }

    #[test]
    fn role_policy_violation_is_a_domain_restriction_not_a_transport_error() {
        let error = fabric_client::ClientError::Hub {
            status: 403,
            body: json!({
                "error": {
                    "code": "RolePolicyViolation",
                    "granted_roles": ["dispatcher", "runner", "observer"],
                    "required_roles": ["reviewer"]
                }
            })
            .to_string(),
        };
        assert_eq!(
            role_policy_restriction(&error).as_deref(),
            Some(
                "Requires reviewer role access. Current token roles: dispatcher, runner, observer."
            )
        );
    }

    #[tokio::test]
    async fn live_installed_context_dashboard_reads_use_native_client() {
        if env::var("FORGEWIRE_114B_LIVE").as_deref() != Ok("1") {
            return;
        }
        let context = load_fabric_context()
            .await
            .expect("installed Fabric context");
        assert!(
            context.token_present,
            "installed Hub token must be available"
        );
        let result = load_fabric_snapshot(context.hub_url)
            .await
            .expect("native dashboard snapshot");
        assert!(
            result.errors.is_empty(),
            "native dashboard reads failed: {:?}",
            result.errors
        );
        assert_eq!(result.snapshot["health"]["status"], "ok");
    }

    #[tokio::test]
    async fn live_candidate_failover_reads_peer_when_preferred_hub_is_down() {
        let Ok(fallback_url) = env::var("FORGEWIRE_114B_FAILOVER_URL") else {
            return;
        };
        let primary_url = env::var("FORGEWIRE_114B_FAILOVER_PRIMARY")
            .unwrap_or_else(|_| "http://127.0.0.1:8765".to_string());
        let candidates = vec![
            HubCandidate {
                url: primary_url.clone(),
                label: Some("preferred Hub".to_string()),
                priority: Some(10),
            },
            HubCandidate {
                url: fallback_url.clone(),
                label: Some("real fallback".to_string()),
                priority: Some(20),
            },
        ];
        let discovered = discover_ranked_hub_candidates(candidates)
            .await
            .expect("candidate discovery");
        assert!(
            !discovered.iter().any(|candidate| candidate.url
                == sanitize_url(&primary_url).expect("primary URL")
                && candidate.reachable),
            "preferred candidate must be unavailable for the failover proof"
        );
        let elected = discovered
            .iter()
            .find(|candidate| candidate.reachable)
            .expect("real peer must be elected");
        assert_eq!(
            elected.url,
            sanitize_url(&fallback_url).expect("fallback URL")
        );
        let snapshot = load_fabric_snapshot(elected.url.clone())
            .await
            .expect("remote native snapshot");
        assert!(
            snapshot.errors.is_empty(),
            "remote failover reads failed: {:?}",
            snapshot.errors
        );
        assert_eq!(snapshot.snapshot["health"]["status"], "ok");
    }

    #[tokio::test]
    async fn live_agent_and_command_dispatches_preserve_taxonomy_and_audit() {
        if env::var("FORGEWIRE_114B_WORKFLOWS").as_deref() != Ok("1") {
            return;
        }
        let context = load_fabric_context()
            .await
            .expect("installed Fabric context");
        let hub_url = sanitize_url(&context.hub_url).expect("active Hub URL");
        let (client, identity) = desktop_dispatch_client(&hub_url)
            .await
            .expect("desktop dispatch client");
        let suffix = now_millis();
        let agent = client
            .dispatch_signed(
                &identity,
                &json!({
                    "title": format!("114B agent parity probe {suffix}"),
                    "prompt": "Parity probe only. Do not mutate files or external state.",
                    "scope_globs": ["work/active/114-forgewire-fabric/**"],
                    "base_commit": "origin/main",
                    "branch": format!("agent/114b-agent-probe/{suffix}"),
                    "kind": "agent",
                    "dispatch": "prompt",
                    "required_tags": [format!("114b-no-runner-{suffix}")],
                    "timeout_minutes": 5,
                    "priority": 900,
                    "require_base_commit": false,
                }),
            )
            .await
            .expect("signed Agent dispatch");
        let agent_id = dispatch_result_from_body(agent)
            .task_id
            .expect("Agent task ID");

        let command = client
            .dispatch_signed(
                &identity,
                &json!({
                    "title": format!("114B command parity probe {suffix}"),
                    "prompt": "Emit one inert parity marker.",
                    "scope_globs": ["work/active/114-forgewire-fabric/**"],
                    "base_commit": "origin/main",
                    "branch": format!("agent/114b-command-probe/{suffix}"),
                    "kind": "command",
                    "dispatch": "prompt",
                    "command": ["cmd.exe", "/d", "/c", "echo", "FORGEWIRE_114B_COMMAND_PROBE"],
                    "timeout_minutes": 5,
                    "priority": 100,
                    "require_base_commit": false,
                }),
            )
            .await
            .expect("signed Command dispatch");
        let command_id = dispatch_result_from_body(command)
            .task_id
            .expect("Command task ID");

        let agent_record = client.get_task(agent_id).await.expect("Agent task");
        let command_record = client.get_task(command_id).await.expect("Command task");
        let task_kind = |record: &Value| {
            record
                .get("task")
                .unwrap_or(record)
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        assert_eq!(task_kind(&agent_record), "agent");
        assert_eq!(task_kind(&command_record), "command");

        let _ = client.task_stream(command_id, 0, 200).await;
        let agent_audit = client
            .audit_for_task(agent_id)
            .await
            .expect("Agent audit evidence");
        let command_audit = client
            .audit_for_task(command_id)
            .await
            .expect("Command audit evidence");
        assert!(agent_audit
            .get("events")
            .and_then(Value::as_array)
            .is_some());
        assert!(command_audit
            .get("events")
            .and_then(Value::as_array)
            .is_some());

        client
            .cancel_task(agent_id)
            .await
            .expect("cancel unclaimed Agent parity probe");
        let command_status = client
            .get_task(command_id)
            .await
            .ok()
            .and_then(|record| {
                record
                    .get("task")
                    .unwrap_or(&record)
                    .get("status")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        if matches!(command_status.as_str(), "queued" | "claimed" | "running") {
            client
                .cancel_task(command_id)
                .await
                .expect("clean up Command parity probe");
        }
    }
}
