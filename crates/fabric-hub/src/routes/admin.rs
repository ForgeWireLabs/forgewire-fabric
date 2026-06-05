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

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::HubState;

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
    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    ))
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

    // Build the helper command into a .cmd file to avoid nested-quote hell when
    // passing it to schtasks /tr.
    let mut cmd_line = format!(
        "pwsh.exe -NoProfile -ExecutionPolicy Bypass -File \"{}\"",
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
            "/create", "/tn", task, "/tr", &cmd_path.to_string_lossy(),
            "/sc", "ONCE", "/st", "00:00", "/ru", "SYSTEM", "/rl", "HIGHEST", "/f",
        ])
        .output()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("schtasks create: {e}")))?;
    if !create.status.success() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("schtasks create failed: {}", String::from_utf8_lossy(&create.stderr)),
        ));
    }
    let run = std::process::Command::new("schtasks.exe")
        .args(["/run", "/tn", task])
        .output()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("schtasks run: {e}")))?;
    if !run.status.success() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("schtasks run failed: {}", String::from_utf8_lossy(&run.stderr)),
        ));
    }

    tracing::info!("self-update launched (source: {:?})", req.from_hub);
    Ok(Json(json!({
        "status": "updating",
        "detail": "self-update launched; this hub will restart shortly"
    })))
}
