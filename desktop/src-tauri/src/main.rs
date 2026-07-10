#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
    token: String,
    identity_path: String,
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
}

#[derive(Debug, Clone, Serialize)]
struct FabricContext {
    hub_url: String,
    hub_source: String,
    token: Option<String>,
    token_path: Option<String>,
    token_source: Option<String>,
    dispatcher_identity: Option<DispatcherIdentitySummary>,
    identity_path: Option<String>,
    identity_source: Option<String>,
    hub_candidates: Vec<HubDiscoveryCandidate>,
    warnings: Vec<String>,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            hub_url: "http://127.0.0.1:8765".to_string(),
            hub_candidates: Vec::new(),
        }
    }
}

#[tauri::command]
fn load_dispatcher_identity(path: String) -> Result<DispatcherIdentitySummary, String> {
    let path = normalize_existing_path(&path)?;
    dispatcher_identity_summary_from_path(path)
}

fn dispatcher_identity_summary_from_path(path: PathBuf) -> Result<DispatcherIdentitySummary, String> {
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
async fn dispatch_signed_task(request: SignedDispatchRequest) -> Result<SignedDispatchResult, String> {
    let identity_path = normalize_existing_path(&request.identity_path)?;
    let identity = fabric_identity::load(&identity_path)
        .map_err(|error| format!("load dispatcher identity {}: {error}", identity_path.display()))?;
    if identity.purpose != fabric_types::KeyPurpose::Dispatcher {
        return Err(format!(
            "identity {} has purpose {:?}; dispatcher identity is required",
            identity.id, identity.purpose
        ));
    }

    let hub_url = sanitize_url(&request.hub_url)?;
    let token = request.token.trim();
    if token.is_empty() {
        return Err("hub token is required".to_string());
    }

    let brief = normalize_brief(request.brief)?;
    let client = fabric_client::HubClient::new(&hub_url, token);
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

#[tauri::command]
async fn discover_hubs(seed_urls: Vec<String>) -> Result<Vec<HubDiscoveryCandidate>, String> {
    discover_hub_candidates(seed_urls).await
}

async fn discover_hub_candidates(seed_urls: Vec<String>) -> Result<Vec<HubDiscoveryCandidate>, String> {
    let urls = hub_probe_urls(seed_urls)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(900))
        .build()
        .map_err(|error| format!("build discovery client: {error}"))?;
    let mut candidates = Vec::new();
    for url in urls {
        let health_url = format!("{}/healthz", url.trim_end_matches('/'));
        if let Ok(response) = client.get(&health_url).send().await {
            if response.status().is_success() {
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
                candidates.push(HubDiscoveryCandidate {
                    url: url.clone(),
                    label: format!("{} ({status})", url.trim_start_matches("http://").trim_start_matches("https://")),
                    status,
                    version,
                });
            }
        }
    }
    Ok(candidates)
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

    let mut seed_urls = Vec::new();
    seed_urls.push(preferred_hub.clone());
    for candidate in gui_config.hub_candidates {
        seed_urls.push(candidate.url);
    }

    let hub_candidates = match discover_hub_candidates(seed_urls).await {
        Ok(candidates) => candidates,
        Err(error) => {
            warnings.push(format!("hub discovery failed: {error}"));
            Vec::new()
        }
    };
    let hub_url = if let Some(candidate) = hub_candidates.first() {
        hub_source = "live hub discovery".to_string();
        candidate.url.clone()
    } else {
        sanitize_url(&preferred_hub).unwrap_or_else(|_| GuiConfig::default().hub_url)
    };

    let (token, token_path, token_source) = match load_hub_token() {
        Ok(result) => result,
        Err(error) => {
            warnings.push(error);
            (None, None, None)
        }
    };

    let mut identity_path = None;
    let mut identity_source = None;
    let mut dispatcher_identity = None;
    match find_dispatcher_identity_path() {
        Ok(Some((path, source))) => {
            identity_path = Some(path.display().to_string());
            identity_source = Some(source);
            match dispatcher_identity_summary_from_path(path) {
                Ok(summary) => dispatcher_identity = Some(summary),
                Err(error) => warnings.push(error),
            }
        }
        Ok(None) => warnings.push("no dispatcher identity file found in installed Fabric locations".to_string()),
        Err(error) => warnings.push(error),
    }

    Ok(FabricContext {
        hub_url,
        hub_source,
        token,
        token_path,
        token_source,
        dispatcher_identity,
        identity_path,
        identity_source,
        hub_candidates,
        warnings,
    })
}

fn read_gui_config() -> Result<GuiConfig, String> {
    let path = gui_config_path()?;
    if !path.exists() {
        return Ok(GuiConfig::default());
    }
    let body = fs::read_to_string(&path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    toml::from_str::<GuiConfig>(&body)
        .map_err(|error| format!("parse {}: {error}", path.display()))
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
                label: candidate.label.map(|label| label.trim().to_string()).filter(|label| !label.is_empty()),
                priority: candidate.priority,
            })
            .filter(|candidate| !candidate.url.is_empty())
            .collect(),
    };
    let body = toml::to_string_pretty(&sanitized)
        .map_err(|error| format!("serialize gui config: {error}"))?;
    fs::write(&path, body).map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(sanitized)
}

fn gui_config_path() -> Result<PathBuf, String> {
    let home = env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
        .ok_or_else(|| "could not resolve user home directory".to_string())?;
    Ok(home.join(".forgewire").join("gui.toml"))
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

fn hub_probe_urls(seed_urls: Vec<String>) -> Result<Vec<String>, String> {
    let mut urls = Vec::new();
    for url in seed_urls {
        let sanitized = sanitize_url(&url)?;
        if !urls.contains(&sanitized) {
            urls.push(sanitized);
        }
    }
    for url in ["http://127.0.0.1:8765", "http://localhost:8765"] {
        let url = url.to_string();
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    Ok(urls)
}

fn sanitize_url(value: &str) -> Result<String, String> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("hub URL is required".to_string());
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("http://{trimmed}"))
    }
}

fn load_hub_token() -> Result<(Option<String>, Option<String>, Option<String>), String> {
    if let Ok(token) = env::var("FORGEWIRE_HUB_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok((Some(token), None, Some("FORGEWIRE_HUB_TOKEN".to_string())));
        }
    }

    let mut paths = Vec::new();
    if let Ok(path) = env::var("FORGEWIRE_HUB_TOKEN_FILE") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            paths.push((PathBuf::from(trimmed), "FORGEWIRE_HUB_TOKEN_FILE".to_string()));
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
            return Ok((Some(token), Some(path.display().to_string()), Some(source)));
        }
    }
    Ok((None, None, None))
}

fn find_dispatcher_identity_path() -> Result<Option<(PathBuf, String)>, String> {
    if let Ok(path) = env::var("FORGEWIRE_DISPATCHER_IDENTITY_FILE") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if path.exists() {
                return Ok(Some((path, "FORGEWIRE_DISPATCHER_IDENTITY_FILE".to_string())));
            }
        }
    }

    for (path, source) in installed_identity_paths() {
        if path.exists() {
            return Ok(Some((path, source)));
        }
    }
    Ok(None)
}

fn installed_token_paths() -> Vec<(PathBuf, String)> {
    installed_base_dirs()
        .into_iter()
        .map(|(base, source)| (base.join("hub.token"), source))
        .collect()
}

fn installed_identity_paths() -> Vec<(PathBuf, String)> {
    installed_base_dirs()
        .into_iter()
        .map(|(base, source)| (base.join("dispatcher_identity.json"), source))
        .collect()
}

fn installed_base_dirs() -> Vec<(PathBuf, String)> {
    let mut bases = Vec::new();
    if let Some(home) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) {
        bases.push((PathBuf::from(home).join(".forgewire"), "~/.forgewire".to_string()));
    }
    let program_data = env::var_os("ProgramData")
        .or_else(|| env::var_os("PROGRAMDATA"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    bases.push((program_data.join("forgewire"), "ProgramData/forgewire".to_string()));
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
        object.insert("required_capabilities".to_string(), json!(required_capabilities));
    }
    if let Some(skill) = brief.skill.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()) {
        object.insert("skill".to_string(), json!(skill));
    }
    if let Some(tool) = brief.tool.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()) {
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
        .or_else(|| body.get("id").or_else(|| body.get("task_id")).and_then(|id| id.as_i64()));
    let approval_id = body.get("approval_id").and_then(|id| id.as_str()).map(str::to_string);
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
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            load_gui_config,
            load_fabric_context,
            save_gui_config,
            load_dispatcher_identity,
            dispatch_signed_task,
            discover_hubs
        ])
        .run(tauri::generate_context!())
        .expect("error while running ForgeWire Fabric Desktop");
}
