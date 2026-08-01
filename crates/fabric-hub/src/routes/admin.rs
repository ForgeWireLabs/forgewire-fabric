//! Self-update admin routes (M2.5.10).
//!
//! - `GET  /admin/binaries/manifest` — list the staged binaries with SHA-256.
//! - `GET  /admin/binaries/{name}`   — stream a staged binary.
//! - `POST /admin/update`            — launch this node's in-place self-update.
//!
//! The hub serves binaries an operator has staged into `…/bin/staged`, and can
//! trigger its own node to pull + swap them. The actual swap is done by the
//! detached `update-fabric.ps1` helper, launched via the Task Scheduler so it
//! runs OUTSIDE the hub's NSSM process tree and survives the hub restarting.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use fabric_store::RoleTokenRow;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

owned_router! {
    pub fn router, ROUTES {
        "GET" get "/admin/role-tokens" => list_role_tokens;
        "POST" post "/admin/role-tokens" => issue_role_token;
        "POST" post "/admin/role-tokens/split" => split_legacy_role_tokens;
        "POST" post "/admin/role-tokens/migrate" => migrate_role_token;
        "DELETE" delete "/admin/role-tokens/{token_id}" => revoke_role_token;
        "GET" get "/admin/binaries/manifest" => binaries_manifest;
        "GET" get "/admin/binaries/{name}" => binary_download;
        "POST" post "/admin/update" => trigger_update;
    }
}

use crate::auth::{normalize_roles, AuthContext};
use crate::state::HubState;
use crate::utils::{audit_append, utc_now};

#[derive(Debug, Deserialize)]
pub struct IssueRoleTokenRequest {
    pub label: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct MigrateRoleTokenRequest {
    /// Existing bearer value to import. It is hashed in the handler and is
    /// never persisted, returned, logged, or included in audit.
    pub token: String,
    pub label: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SplitLegacyRoleTokensRequest {
    #[serde(default)]
    pub label_prefix: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListRoleTokensQuery {
    #[serde(default)]
    pub include_revoked: bool,
}

pub async fn issue_role_token(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(request): Json<IssueRoleTokenRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let label = validate_token_label(&request.label)?;
    let roles =
        normalize_roles(&request.roles).map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    let raw_token = random_credential();
    let token_hash = hash_credential(&raw_token);
    let token_id = random_token_id();
    let now = utc_now();
    let row = state
        .store
        .create_role_token(
            &token_id,
            &token_hash,
            &label,
            &roles,
            &actor.subject,
            false,
            &now,
        )
        .await
        .map_err(|error| {
            (
                StatusCode::CONFLICT,
                format!("role token issue failed: {error}"),
            )
        })?;
    if let Err(error) = audit_append(
        &*state.store,
        &state.secrets,
        "auth.role_token_issued",
        None,
        &json!({
            "token_id": row.token_id,
            "label": row.label,
            "roles": row.roles,
            "created_by": actor.subject,
            "migrated": false,
        }),
    )
    .await
    {
        let _ = state.store.revoke_role_token(&row.token_id, &now).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("audit append failed; issued token revoked: {error}"),
        ));
    }

    Ok(Json(json!({
        "token": raw_token,
        "token_metadata": row,
        "warning": "the token value is shown once; store it in a protected token file",
    })))
}

pub async fn migrate_role_token(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(request): Json<MigrateRoleTokenRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let label = validate_token_label(&request.label)?;
    let roles =
        normalize_roles(&request.roles).map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    let raw = request.token.trim();
    if raw.len() < 16 || raw.len() > 4096 {
        return Err((
            StatusCode::BAD_REQUEST,
            "migrated bearer must be between 16 and 4096 characters".into(),
        ));
    }
    if hash_credential(raw) == hash_credential(&state.token) {
        return Err((
            StatusCode::CONFLICT,
            "the installed cluster bearer is already represented by the visible compatibility bundle".into(),
        ));
    }
    let token_hash = hash_credential(raw);
    let token_id = random_token_id();
    let now = utc_now();
    let row = state
        .store
        .create_role_token(
            &token_id,
            &token_hash,
            &label,
            &roles,
            &actor.subject,
            true,
            &now,
        )
        .await
        .map_err(|error| {
            (
                StatusCode::CONFLICT,
                format!("role token migration failed: {error}"),
            )
        })?;
    if let Err(error) = audit_append(
        &*state.store,
        &state.secrets,
        "auth.role_token_migrated",
        None,
        &json!({
            "token_id": row.token_id,
            "label": row.label,
            "roles": row.roles,
            "created_by": actor.subject,
            "migrated": true,
        }),
    )
    .await
    {
        let _ = state.store.revoke_role_token(&row.token_id, &now).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("audit append failed; migrated token revoked: {error}"),
        ));
    }
    Ok(Json(json!({ "token_metadata": row })))
}

/// Split the installed compatibility bundle into five independent random
/// credentials. The values are returned once; rqlite receives hashes only.
pub async fn split_legacy_role_tokens(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(request): Json<SplitLegacyRoleTokensRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let prefix = validate_token_label(
        request
            .label_prefix
            .as_deref()
            .unwrap_or("legacy compatibility split"),
    )?;
    let now = utc_now();
    let mut issued: Vec<(String, RoleTokenRow)> = Vec::new();
    for role in crate::auth::VALID_ROLES {
        let raw_token = random_credential();
        let token_hash = hash_credential(&raw_token);
        let token_id = random_token_id();
        let roles = vec![(*role).to_owned()];
        let row = match state
            .store
            .create_role_token(
                &token_id,
                &token_hash,
                &format!("{prefix}: {role}"),
                &roles,
                &actor.subject,
                false,
                &now,
            )
            .await
        {
            Ok(row) => row,
            Err(error) => {
                for (_, prior) in &issued {
                    let _ = state.store.revoke_role_token(&prior.token_id, &now).await;
                }
                return Err((
                    StatusCode::CONFLICT,
                    format!("role token split failed: {error}"),
                ));
            }
        };
        issued.push((raw_token, row));
    }

    let audit_tokens: Vec<Value> = issued
        .iter()
        .map(|(_, row)| json!({ "token_id": row.token_id, "roles": row.roles }))
        .collect();
    if let Err(error) = audit_append(
        &*state.store,
        &state.secrets,
        "auth.legacy_bundle_split",
        None,
        &json!({
            "tokens": audit_tokens,
            "created_by": actor.subject,
            "legacy_retirement": "pending explicit operator setting",
        }),
    )
    .await
    {
        for (_, row) in &issued {
            let _ = state.store.revoke_role_token(&row.token_id, &now).await;
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("audit append failed; split tokens revoked: {error}"),
        ));
    }

    Ok(Json(json!({
        "tokens": issued
            .into_iter()
            .map(|(token, token_metadata)| json!({
                "token": token,
                "token_metadata": token_metadata,
            }))
            .collect::<Vec<_>>(),
        "warning": "each token value is shown once; store each in a protected role-specific token file",
        "legacy_retirement": "the installed cluster bearer remains enabled until an explicit retirement setting is applied",
    })))
}

pub async fn list_role_tokens(
    State(state): State<Arc<HubState>>,
    Query(query): Query<ListRoleTokensQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let rows = state
        .store
        .list_role_tokens(query.include_revoked)
        .await
        .map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("role token list failed: {error}"),
            )
        })?;
    Ok(Json(json!({ "tokens": rows })))
}

pub async fn revoke_role_token(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(token_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if token_id.is_empty() || token_id.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "invalid token id".into()));
    }
    let row = state
        .store
        .revoke_role_token(&token_id, &utc_now())
        .await
        .map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("role token revoke failed: {error}"),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "active role token not found".into()))?;
    audit_append(
        &*state.store,
        &state.secrets,
        "auth.role_token_revoked",
        None,
        &json!({
            "token_id": row.token_id,
            "label": row.label,
            "roles": row.roles,
            "revoked_by": actor.subject,
        }),
    )
    .await
    .map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("audit append failed: {error}"),
        )
    })?;
    Ok(Json(json!({ "token_metadata": row })))
}

fn validate_token_label(label: &str) -> Result<String, (StatusCode, String)> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "role token label must be between 1 and 128 characters".into(),
        ));
    }
    Ok(label.to_owned())
}

fn random_credential() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("fwrt_{}", hex::encode(bytes))
}

fn random_token_id() -> String {
    let mut bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut bytes);
    format!("rt_{}", hex::encode(bytes))
}

fn hash_credential(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

const SERVED: &[&str] = &[
    "forgewire-hub.exe",
    "forgewire-runner.exe",
    "forgewire-fabric-cli.exe",
];

fn staged_dir() -> PathBuf {
    std::env::var("FORGEWIRE_HUB_STAGED_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\forgewire\bin\staged"))
}

fn data_dir() -> PathBuf {
    std::env::var("FORGEWIRE_HUB_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\forgewire"))
}

fn update_script() -> PathBuf {
    std::env::var("FORGEWIRE_HUB_UPDATE_SCRIPT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir().join("update-fabric.ps1"))
}

/// `{ version, files: [{ name, sha256, size }] }` for everything staged.
pub async fn binaries_manifest(
    State(_s): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let dir = staged_dir();
    let version = std::fs::read_to_string(dir.join("VERSION"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "staged".into());

    let mut names: Vec<String> = SERVED.iter().map(|s| s.to_string()).collect();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.ends_with(".vsix") {
                names.push(n);
            }
        }
    }

    let mut files = Vec::new();
    for name in names {
        if let Ok(bytes) = std::fs::read(dir.join(&name)) {
            let mut h = Sha256::new();
            h.update(&bytes);
            files.push(json!({
                "name": name,
                "sha256": hex::encode(h.finalize()),
                "size": bytes.len(),
            }));
        }
    }
    Ok(Json(json!({ "version": version, "files": files })))
}

/// Stream one staged binary. Name is validated to prevent path traversal.
pub async fn binary_download(
    State(_s): State<Arc<HubState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if name.contains('/') || name.contains('\\') || name.contains("..") || name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "invalid name".into()));
    }
    let bytes = std::fs::read(staged_dir().join(&name))
        .map_err(|_| (StatusCode::NOT_FOUND, "not staged".into()))?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes))
}

#[derive(Deserialize)]
pub struct UpdateReq {
    /// Pull the new binaries from this hub's manifest. If absent, apply from the
    /// local staged dir.
    #[serde(default)]
    pub from_hub: Option<String>,
    #[serde(default)]
    pub include_vsix: bool,
}

/// Launch this node's self-update. Returns 202-style immediately; the hub will
/// go down briefly while the detached helper swaps and restarts it.
pub async fn trigger_update(
    State(_s): State<Arc<HubState>>,
    Json(req): Json<UpdateReq>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let script = update_script();
    if !script.exists() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("update script not found at {}", script.display()),
        ));
    }

    // Resolve a PowerShell that is reliably available to the SYSTEM scheduled
    // task. `pwsh.exe` by bare name is not always on SYSTEM's PATH; use the
    // absolute PowerShell 7 path when present, else fall back to Windows
    // PowerShell (always in System32, always on PATH).
    let pwsh = r"C:\Program Files\PowerShell\7\pwsh.exe";
    let shell = if std::path::Path::new(pwsh).exists() {
        format!("\"{pwsh}\"")
    } else {
        "powershell.exe".to_string()
    };

    // Build the helper command into a .cmd file to avoid nested-quote hell when
    // passing it to schtasks /tr.
    let mut cmd_line = format!(
        "{shell} -NoProfile -ExecutionPolicy Bypass -File \"{}\"",
        script.display()
    );
    match req.from_hub.as_deref() {
        Some(h) if !h.is_empty() => cmd_line.push_str(&format!(" -FromHub \"{h}\"")),
        _ => cmd_line.push_str(&format!(" -StageDir \"{}\"", staged_dir().display())),
    }
    if req.include_vsix {
        cmd_line.push_str(" -IncludeVsix");
    }

    let cmd_path = data_dir().join("selfupdate.cmd");
    let cmd_body = format!("@echo off\r\n{cmd_line}\r\n");
    std::fs::write(&cmd_path, cmd_body)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("write cmd: {e}")))?;

    // One-shot SYSTEM scheduled task that runs the .cmd, then run it now. The
    // task lives outside the hub's NSSM job tree, so it survives the hub being
    // stopped during the binary swap.
    let task = "ForgeWireSelfUpdate";
    let create = std::process::Command::new("schtasks.exe")
        .args([
            "/create",
            "/tn",
            task,
            "/tr",
            &cmd_path.to_string_lossy(),
            "/sc",
            "ONCE",
            "/st",
            "00:00",
            "/ru",
            "SYSTEM",
            "/rl",
            "HIGHEST",
            "/f",
        ])
        .output()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("schtasks create: {e}"),
            )
        })?;
    if !create.status.success() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "schtasks create failed: {}",
                String::from_utf8_lossy(&create.stderr)
            ),
        ));
    }
    let run = std::process::Command::new("schtasks.exe")
        .args(["/run", "/tn", task])
        .output()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("schtasks run: {e}"),
            )
        })?;
    if !run.status.success() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "schtasks run failed: {}",
                String::from_utf8_lossy(&run.stderr)
            ),
        ));
    }

    tracing::info!("self-update launched (source: {:?})", req.from_hub);
    Ok(Json(json!({
        "status": "updating",
        "detail": "self-update launched; this hub will restart shortly"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_credentials_are_random_and_sha256_is_one_way_metadata() {
        let first = random_credential();
        let second = random_credential();
        assert!(first.starts_with("fwrt_"));
        assert_eq!(first.len(), 69);
        assert_ne!(first, second);
        let digest = hash_credential(&first);
        assert_eq!(digest.len(), 64);
        assert_ne!(digest, first);

        let row = RoleTokenRow {
            token_id: "rt_public".into(),
            label: "test".into(),
            roles: vec!["observer".into()],
            created_at: "2026-07-15 00:00:00".into(),
            created_by: "reviewer-token-id".into(),
            migrated: false,
            revoked_at: None,
        };
        let serialized = serde_json::to_string(&row).expect("serialize public metadata");
        assert!(!serialized.contains(&first));
        assert!(!serialized.contains(&digest));
        assert!(!serialized.contains("token_hash"));
    }
}
