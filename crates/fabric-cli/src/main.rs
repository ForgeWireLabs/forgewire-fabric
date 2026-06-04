//! ForgeWire Fabric native operator CLI.
//!
//! Provides Python-free surfaces for setup, health, identity, audit, and doctor.
//! Replaces the Python `forgewire-fabric` CLI for the core operator workflows.
//!
//! Usage:
//!     forgewire-fabric-cli health [--hub-url URL]
//!     forgewire-fabric-cli identity generate [--purpose runner|dispatcher|hub|node] [--output PATH]
//!     forgewire-fabric-cli identity show [--path PATH]
//!     forgewire-fabric-cli audit tail [--hub-url URL]
//!     forgewire-fabric-cli audit verify --task-id ID [--hub-url URL]
//!     forgewire-fabric-cli audit export --day YYYY-MM-DD [--hub-url URL]
//!     forgewire-fabric-cli replay TASK_ID [--with-model M] [--on RUNNER] [--dry-run]
//!     forgewire-fabric-cli doctor [--hub-url URL]
//!     forgewire-fabric-cli version

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use fabric_client::HubClient;
use fabric_identity::IdentityFile;
use fabric_types::KeyPurpose;

#[derive(Parser)]
#[command(name = "forgewire-fabric-cli", version, about = "ForgeWire Fabric operator CLI (native Rust)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check hub health
    Health {
        #[arg(long, env = "FORGEWIRE_HUB_URL", default_value = "http://127.0.0.1:8765")]
        hub_url: String,
    },
    /// Identity management
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Audit log operations
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Run diagnostic checks
    Doctor {
        #[arg(long, env = "FORGEWIRE_HUB_URL", default_value = "http://127.0.0.1:8765")]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Replay a recorded task: reconstruct its sealed brief at the exact base
    /// commit and (unless --dry-run) re-dispatch it. With --dry-run it only
    /// prints the brief that would be re-issued.
    Replay {
        /// The task id to replay.
        task_id: i64,
        /// Pin a model override for the replay (records metadata.model_pin),
        /// e.g. for a cheaper-model A/B comparison.
        #[arg(long)]
        with_model: Option<String>,
        /// Record a preferred runner for the replay (metadata.replay_on).
        #[arg(long)]
        on: Option<String>,
        /// Reconstruct and print the brief without dispatching.
        #[arg(long)]
        dry_run: bool,
        #[arg(long, env = "FORGEWIRE_HUB_URL", default_value = "http://127.0.0.1:8765")]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Print version
    Version,
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new ed25519 identity
    Generate {
        #[arg(long, default_value = "runner")]
        purpose: String,
        #[arg(long, short)]
        output: Option<PathBuf>,
        #[arg(long)]
        id: Option<String>,
    },
    /// Show an existing identity file
    Show {
        #[arg(long, short)]
        path: PathBuf,
    },
    /// Validate an identity file
    Validate {
        #[arg(long, short)]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Show the current audit chain tail hash
    Tail {
        #[arg(long, env = "FORGEWIRE_HUB_URL", default_value = "http://127.0.0.1:8765")]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Verify the audit chain for a task
    Verify {
        #[arg(long)]
        task_id: i64,
        #[arg(long, env = "FORGEWIRE_HUB_URL", default_value = "http://127.0.0.1:8765")]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Export one UTC day's audit events as JSONL to stdout (self-verifying).
    ///
    /// Pipe to a compressor if desired, e.g.:
    ///   forgewire-fabric-cli audit export --day 2026-06-04 | zstd > audit.jsonl.zst
    /// Exits non-zero if the hub reports the chain does not verify.
    Export {
        /// UTC day to export, formatted YYYY-MM-DD.
        #[arg(long)]
        day: String,
        #[arg(long, env = "FORGEWIRE_HUB_URL", default_value = "http://127.0.0.1:8765")]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Replay { task_id, with_model, on, dry_run, hub_url, token_file } => {
            let token = load_token(token_file.as_deref());
            let client = HubClient::new(&hub_url, &token);

            // 1. Fetch the original task record (the sealed brief).
            let task = match client.get_task(task_id).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("could not fetch task {task_id}: {e}");
                    std::process::exit(1);
                }
            };

            // 2. Reconstruct the dispatch brief from the recorded fields. Strings
            //    and arrays are taken verbatim so the replay re-issues the exact
            //    prompt, scope, and base commit.
            let mut metadata = task.get("metadata").cloned().unwrap_or_else(|| json!({}));
            if !metadata.is_object() {
                metadata = json!({});
            }
            metadata["replay_of_task_id"] = json!(task_id);
            if let Some(model) = &with_model {
                metadata["model_pin"] = json!(model);
            }
            if let Some(runner) = &on {
                metadata["replay_on"] = json!(runner);
            }

            let mut brief = json!({
                "title": task.get("title").cloned().unwrap_or(Value::Null),
                "prompt": task.get("prompt").cloned().unwrap_or(Value::Null),
                "scope_globs": task.get("scope_globs").cloned().unwrap_or_else(|| json!([])),
                "base_commit": task.get("base_commit").cloned().unwrap_or(Value::Null),
                "branch": task.get("branch").cloned().unwrap_or(Value::Null),
                "kind": task.get("kind").cloned().unwrap_or_else(|| json!("agent")),
                "timeout_minutes": task.get("timeout_minutes").cloned().unwrap_or(json!(60)),
                "priority": task.get("priority").cloned().unwrap_or(json!(100)),
                "require_base_commit": json!(true),
                "metadata": metadata,
            });
            // Pass through optional routing fields when present.
            for key in ["required_tools", "required_tags", "required_capabilities",
                        "tenant", "workspace_root", "network_egress", "todo_id"] {
                if let Some(v) = task.get(key) {
                    if !v.is_null() {
                        brief[key] = v.clone();
                    }
                }
            }

            // 3. Show the reconstructed brief (to stderr so stdout can stay
            //    machine-readable on actual dispatch).
            eprintln!("Replay of task {task_id} — reconstructed brief:");
            eprintln!("{}", serde_json::to_string_pretty(&brief).unwrap_or_default());

            if dry_run {
                eprintln!("DRY RUN — not dispatched.");
                return;
            }

            // 4. Re-dispatch.
            match client.dispatch_unsigned(&brief).await {
                Ok(new_task) => {
                    let new_id = new_task.get("id").and_then(|v| v.as_i64());
                    match new_id {
                        Some(id) => println!("{id}"),
                        None => println!("{}", serde_json::to_string(&new_task).unwrap_or_default()),
                    }
                    eprintln!("replayed task {task_id} -> new task {}", new_id.map(|i| i.to_string()).unwrap_or_else(|| "?".into()));
                }
                Err(e) => {
                    eprintln!("replay dispatch failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Version => {
            println!("forgewire-fabric-cli {}", env!("CARGO_PKG_VERSION"));
            println!("protocol_version: 3");
            println!("runtime: native Rust");
        }

        Commands::Health { hub_url } => {
            let client = HubClient::new(&hub_url, "");
            match client.healthz().await {
                Ok(health) => {
                    println!("{}", serde_json::to_string_pretty(&health).unwrap_or_default());
                }
                Err(e) => {
                    eprintln!("hub unreachable at {hub_url}: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Identity { action } => match action {
            IdentityAction::Generate { purpose, output, id } => {
                let kp = match purpose.as_str() {
                    "runner" => KeyPurpose::Runner,
                    "dispatcher" => KeyPurpose::Dispatcher,
                    "hub" => KeyPurpose::Hub,
                    "node" => KeyPurpose::Node,
                    other => {
                        eprintln!("unknown purpose: {other} (use runner|dispatcher|hub|node)");
                        std::process::exit(1);
                    }
                };
                let hostname = std::env::var("COMPUTERNAME")
                    .or_else(|_| std::env::var("HOSTNAME"))
                    .unwrap_or_else(|_| "unknown".into());
                let identity_id = id.unwrap_or_else(|| format!("{hostname}-{purpose}"));
                let identity = fabric_identity::generate(&identity_id, kp);

                if let Some(path) = output {
                    fabric_identity::save(&path, &identity).unwrap_or_else(|e| {
                        eprintln!("failed to save identity: {e}");
                        std::process::exit(1);
                    });
                    println!("Identity saved to {}", path.display());
                    println!("  id:         {}", identity.id);
                    println!("  purpose:    {}", identity.purpose);
                    println!("  public_key: {}", identity.public_key_hex);
                } else {
                    println!("{}", serde_json::to_string_pretty(&identity).unwrap_or_default());
                }
            }
            IdentityAction::Show { path } => {
                let identity = fabric_identity::load(&path).unwrap_or_else(|e| {
                    eprintln!("failed to load {}: {e}", path.display());
                    std::process::exit(1);
                });
                println!("id:         {}", identity.id);
                println!("purpose:    {}", identity.purpose);
                println!("public_key: {}", identity.public_key_hex);
                if let Some(h) = &identity.hostname {
                    println!("hostname:   {h}");
                }
                if let Some(t) = &identity.created_at {
                    println!("created_at: {t}");
                }
            }
            IdentityAction::Validate { path } => {
                match fabric_identity::load(&path) {
                    Ok(id) => {
                        println!("VALID: {} (purpose={}, public_key={}...)", id.id, id.purpose, &id.public_key_hex[..16]);
                    }
                    Err(e) => {
                        eprintln!("INVALID: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },

        Commands::Audit { action } => {
            let (hub_url, token_file) = match &action {
                AuditAction::Tail { hub_url, token_file } => (hub_url.clone(), token_file.clone()),
                AuditAction::Verify { hub_url, token_file, .. } => (hub_url.clone(), token_file.clone()),
                AuditAction::Export { hub_url, token_file, .. } => (hub_url.clone(), token_file.clone()),
            };
            let token = load_token(token_file.as_deref());
            let client = HubClient::new(&hub_url, &token);

            match action {
                AuditAction::Tail { .. } => match client.audit_tail().await {
                    Ok(v) => println!("{}", v["chain_tail"].as_str().unwrap_or("(none)")),
                    Err(e) => {
                        eprintln!("audit tail failed: {e}");
                        std::process::exit(1);
                    }
                },
                AuditAction::Verify { task_id, .. } => match client.audit_for_task(task_id).await {
                    Ok(v) => {
                        let verified = v["verified"].as_bool().unwrap_or(false);
                        let count = v["events"].as_array().map_or(0, |a| a.len());
                        if verified {
                            println!("VERIFIED: task {task_id} chain intact ({count} events)");
                        } else {
                            let err = v["error"].as_str().unwrap_or("unknown");
                            eprintln!("BROKEN: task {task_id} chain failed verification: {err}");
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("audit verify failed: {e}");
                        std::process::exit(1);
                    }
                },
                AuditAction::Export { day, .. } => match client.audit_day(&day).await {
                    Ok(v) => {
                        // One JSON object per line to stdout (pipe to a compressor).
                        if let Some(events) = v["events"].as_array() {
                            for ev in events {
                                println!("{}", serde_json::to_string(ev).unwrap_or_default());
                            }
                            // Verification verdict goes to stderr so stdout stays
                            // clean JSONL. Non-zero exit if the chain is broken.
                            let verified = v["verified"].as_bool().unwrap_or(false);
                            if verified {
                                eprintln!(
                                    "exported {} event(s) for {day}; chain VERIFIED",
                                    events.len()
                                );
                            } else {
                                let err = v["error"].as_str().unwrap_or("unknown");
                                eprintln!("WARNING: chain did NOT verify for {day}: {err}");
                                std::process::exit(1);
                            }
                        } else {
                            eprintln!("unexpected response (no events array)");
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("audit export failed: {e}");
                        std::process::exit(1);
                    }
                },
            }
        }

        Commands::Doctor { hub_url, token_file } => {
            let mut failures = 0u32;
            let mut warnings = 0u32;

            println!("ForgeWire Fabric Doctor");
            println!("=======================");
            println!();

            // ── rqlite (must check FIRST — hub depends on it) ────────────────
            let rqlite_host = std::env::var("FORGEWIRE_HUB_RQLITE_HOST")
                .unwrap_or_else(|_| "127.0.0.1".into());
            let rqlite_port = std::env::var("FORGEWIRE_HUB_RQLITE_PORT")
                .ok().and_then(|v| v.parse::<u16>().ok()).unwrap_or(4001);
            let rqlite_status_url = format!("http://{rqlite_host}:{rqlite_port}/status");
            let rqlite_readyz_url = format!("http://{rqlite_host}:{rqlite_port}/readyz");

            print!("rqlite ({rqlite_host}:{rqlite_port}):  ");
            match reqwest::get(&rqlite_readyz_url).await {
                Ok(r) if r.status().is_success() => {
                    // Check leader status from /status
                    match reqwest::get(&rqlite_status_url).await {
                        Ok(sr) if sr.status().is_success() => {
                            if let Ok(body) = sr.json::<serde_json::Value>().await {
                                let leader_addr = body
                                    .pointer("/store/leader/addr")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let state = body
                                    .pointer("/store/raft/state")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");
                                if leader_addr.is_empty() {
                                    println!("FAIL — no Raft leader elected (state={state})");
                                    println!("  The rqlite cluster has no leader. Dispatch and claims will fail.");
                                    println!("  Fix: ensure at least 2 of 3 rqlite nodes are reachable.");
                                    println!("  Check: nssm status ForgeWireRqlite{}", if cfg!(windows) { "" } else { "" });
                                    failures += 1;
                                } else {
                                    println!("OK  (leader={leader_addr}, state={state})");
                                }
                            } else {
                                println!("OK  (readyz=200, status parse failed)");
                            }
                        }
                        _ => println!("OK  (readyz=200)"),
                    }
                }
                Ok(r) => {
                    println!("FAIL — rqlite returned {} (not ready)", r.status());
                    println!("  rqlite is running but not ready. Check rqlite logs.");
                    failures += 1;
                }
                Err(e) => {
                    println!("FAIL — rqlite not reachable: {e}");
                    println!("  rqlite must be running. Start with:");
                    if cfg!(windows) {
                        println!("    nssm start ForgeWireRqliteNode1");
                    } else {
                        println!("    systemctl start forgewire-rqlite");
                    }
                    failures += 1;
                }
            }

            // ── Hub connectivity ─────────────────────────────────────────────
            let token = load_token(token_file.as_deref());
            let client = HubClient::new(&hub_url, &token);
            print!("Hub ({hub_url}):  ");
            match client.healthz().await {
                Ok(health) => {
                    let version  = health["version"].as_str().unwrap_or("?");
                    let proto    = health["protocol_version"].as_i64().unwrap_or(0);
                    let sidecar  = health["sidecar_integrity"].as_str().unwrap_or("unknown");
                    let rust_hub = health["rust_hub"].as_bool().unwrap_or(false);
                    let backend  = health["backend"].as_str().unwrap_or("?");

                    if !rust_hub {
                        println!("WARN — Python hub detected (v{version}). Switch to Rust hub.");
                        warnings += 1;
                    } else if !backend.starts_with("rqlite") {
                        println!("WARN — hub backend is '{backend}', expected rqlite.");
                        warnings += 1;
                    } else {
                        println!("OK   (v{version}, proto={proto}, backend={backend}, runtime=rust)");
                    }
                    if sidecar == "trusted_bearer" {
                        println!("  WARN sidecar_integrity=trusted_bearer: out-of-band fields are bearer-gated only.");
                        println!("       Upgrade dispatchers to protocol v3 to close this gap (M2.7.7 expiry gate).");
                        warnings += 1;
                    }
                }
                Err(e) => {
                    println!("FAIL — {e}");
                    failures += 1;
                }
            }

            // ── Token file ───────────────────────────────────────────────────
            let token_path = token_file.as_deref().map(String::from).unwrap_or_else(|| {
                if cfg!(windows) { r"C:\ProgramData\forgewire\hub.token".into() }
                else { "/var/lib/forgewire/hub.token".into() }
            });
            print!("Token ({token_path}):  ");
            match std::fs::read_to_string(&token_path) {
                Ok(t) if t.trim().len() >= 16 => println!("OK   ({} chars)", t.trim().len()),
                Ok(t) => { println!("WARN — only {} chars (min 16)", t.trim().len()); warnings += 1; }
                Err(_) => { println!("FAIL — file not found"); failures += 1; }
            }

            // ── Identity files ───────────────────────────────────────────────
            let identity_paths: Vec<PathBuf> = if cfg!(windows) {
                vec![
                    r"C:\ProgramData\forgewire\runner_identity.json".into(),
                    r"C:\ProgramData\forgewire\hub_identity.json".into(),
                ]
            } else {
                vec![
                    "/var/lib/forgewire/runner_identity.json".into(),
                    "/var/lib/forgewire/hub_identity.json".into(),
                ]
            };
            for path in &identity_paths {
                let label = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                print!("Identity ({label}):  ");
                match fabric_identity::load(path) {
                    Ok(id) => println!("OK   ({}, purpose={}, pk={}...)", id.id, id.purpose, &id.public_key_hex[..16]),
                    Err(fabric_identity::IdentityError::NotFound(_)) => println!("not found (optional)"),
                    Err(e) => { println!("FAIL — {e}"); failures += 1; }
                }
            }

            // ── Native binaries ──────────────────────────────────────────────
            println!();
            println!("Native binaries:");
            let bin_dir = if cfg!(windows) { r"C:\ProgramData\forgewire\bin" } else { "/var/lib/forgewire/bin" };
            for bin in &["forgewire-hub", "forgewire-runner", "forgewire-fabric-cli"] {
                let path = PathBuf::from(bin_dir).join(format!("{}{}", bin, if cfg!(windows) { ".exe" } else { "" }));
                let found = path.exists() || which(bin);
                print!("  {bin:<26} ");
                if found { println!("OK"); } else { println!("not found in {bin_dir}"); warnings += 1; }
            }

            // ── Summary ──────────────────────────────────────────────────────
            println!();
            if failures > 0 {
                eprintln!("RESULT: {} failure(s), {} warning(s) — cluster is NOT healthy", failures, warnings);
                std::process::exit(1);
            } else if warnings > 0 {
                println!("RESULT: 0 failures, {} warning(s) — cluster is degraded", warnings);
            } else {
                println!("RESULT: all checks passed ✓");
            }
        }
    }
}

fn load_token(token_file: Option<&str>) -> String {
    let path = token_file
        .map(String::from)
        .or_else(|| std::env::var("FORGEWIRE_HUB_TOKEN_FILE").ok())
        .unwrap_or_else(|| {
            if cfg!(windows) {
                r"C:\ProgramData\forgewire\hub.token".into()
            } else {
                "/var/lib/forgewire/hub.token".into()
            }
        });
    std::fs::read_to_string(&path)
        .map(|t| t.trim().to_owned())
        .unwrap_or_default()
}

fn which(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}
