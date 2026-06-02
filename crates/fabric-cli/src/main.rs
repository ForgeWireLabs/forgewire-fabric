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
//!     forgewire-fabric-cli doctor [--hub-url URL]
//!     forgewire-fabric-cli version

use std::path::PathBuf;

use clap::{Parser, Subcommand};
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
            };
            let token = load_token(token_file.as_deref());
            let client = HubClient::new(&hub_url, &token);

            match action {
                AuditAction::Tail { .. } => {
                    match client.healthz().await {
                        Ok(_) => println!("(audit tail requires authenticated endpoint — use the hub API directly)"),
                        Err(e) => {
                            eprintln!("hub unreachable: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                AuditAction::Verify { task_id, .. } => {
                    println!("Verifying audit chain for task {task_id}...");
                    println!("(requires authenticated endpoint — use the hub API directly)");
                }
            }
        }

        Commands::Doctor { hub_url, token_file } => {
            println!("ForgeWire Fabric Doctor");
            println!("======================");
            println!();

            // Hub connectivity
            let client = HubClient::new(&hub_url, "");
            print!("Hub ({hub_url}): ");
            match client.healthz().await {
                Ok(health) => {
                    let version = health["version"].as_str().unwrap_or("?");
                    let proto = health["protocol_version"].as_i64().unwrap_or(0);
                    let sidecar = health["sidecar_integrity"].as_str().unwrap_or("unknown");
                    let rust_hub = health["rust_hub"].as_bool().unwrap_or(false);
                    println!("OK (v{version}, proto={proto}, runtime={})", if rust_hub { "rust" } else { "python" });

                    if sidecar == "trusted_bearer" {
                        println!("  WARNING: sidecar_integrity=trusted_bearer");
                        println!("    Out-of-band dispatch fields are bearer-gated only.");
                        println!("    Upgrade to protocol v3 to sign all execution-semantic fields.");
                    }
                }
                Err(e) => {
                    println!("UNREACHABLE ({e})");
                }
            }

            // Identity files
            let identity_paths = if cfg!(windows) {
                vec![
                    PathBuf::from(r"C:\ProgramData\forgewire\runner_identity.json"),
                    PathBuf::from(r"C:\ProgramData\forgewire\hub_identity.json"),
                ]
            } else {
                vec![
                    PathBuf::from("/var/lib/forgewire/runner_identity.json"),
                    PathBuf::from("/var/lib/forgewire/hub_identity.json"),
                ]
            };
            for path in &identity_paths {
                print!("Identity ({}): ", path.display());
                match fabric_identity::load(path) {
                    Ok(id) => println!("OK ({}, purpose={}, pk={}...)", id.id, id.purpose, &id.public_key_hex[..16]),
                    Err(fabric_identity::IdentityError::NotFound(_)) => println!("not found"),
                    Err(e) => println!("ERROR: {e}"),
                }
            }

            // Token file
            let token_path = token_file.unwrap_or_else(|| {
                if cfg!(windows) {
                    r"C:\ProgramData\forgewire\hub.token".into()
                } else {
                    "/var/lib/forgewire/hub.token".into()
                }
            });
            print!("Token ({token_path}): ");
            match std::fs::read_to_string(&token_path) {
                Ok(t) => {
                    let len = t.trim().len();
                    if len >= 16 {
                        println!("OK ({len} chars)");
                    } else {
                        println!("WARNING: only {len} chars (minimum 16)");
                    }
                }
                Err(e) => println!("ERROR: {e}"),
            }

            // rqlite
            print!("rqlite (127.0.0.1:4001): ");
            let rqlite_client = HubClient::new("http://127.0.0.1:4001", "");
            match rqlite_client.healthz().await {
                Ok(_) => println!("responding"),
                Err(_) => {
                    // Try readyz directly
                    match reqwest::get("http://127.0.0.1:4001/readyz").await {
                        Ok(r) if r.status().is_success() => println!("OK (readyz=200)"),
                        Ok(r) => println!("DEGRADED (readyz={})", r.status()),
                        Err(_) => println!("not running"),
                    }
                }
            }

            println!();
            println!("Native binaries:");
            println!("  forgewire-hub:    {}", if which("forgewire-hub") { "found on PATH" } else { "not on PATH" });
            println!("  forgewire-runner: {}", if which("forgewire-runner") { "found on PATH" } else { "not on PATH" });
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
