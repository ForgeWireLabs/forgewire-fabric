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
//!     forgewire-fabric-cli replay TASK_ID --identity KEY [--with-model M] [--on RUNNER] [--dry-run]
//!     forgewire-fabric-cli doctor [--hub-url URL]
//!     forgewire-fabric-cli version

use std::path::PathBuf;

mod doctor;

use clap::{Parser, Subcommand};
use fabric_client::HubClient;
use fabric_types::KeyPurpose;
use serde_json::{json, Value};

#[derive(Parser)]
#[command(
    name = "forgewire-fabric-cli",
    version,
    about = "ForgeWire Fabric operator CLI (native Rust)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check hub health
    Health {
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
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
    /// Role-separated bearer token lifecycle (reviewer authority required)
    RoleTokens {
        #[command(subcommand)]
        action: RoleTokenAction,
    },
    /// Read or mutate schema-validated hub settings.
    Settings {
        #[command(subcommand)]
        action: SettingsAction,
    },
    /// Human-account self-service authentication (114C).
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Account export/import tooling (114C.5). `admin`/`reviewer`, step-up
    /// gated hub-side -- these commands need an already-elevated human
    /// session's access secret (`--access-secret-file`), not a role token.
    Accounts {
        #[command(subcommand)]
        action: AccountsAction,
    },
    /// Show the optional Tier-2 history exporter status.
    HistoryStatus {
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Run diagnostic checks
    Doctor {
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
        /// Emit the stable machine-readable diagnostic schema.
        #[arg(long)]
        json: bool,
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
        /// Dispatcher identity file (ed25519 secret key). Required unless
        /// --dry-run; the replay is re-dispatched over the SIGNED /tasks/v2 path.
        #[arg(long, short)]
        identity: Option<PathBuf>,
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Discover ForgeWire hubs on the LAN via the UDP beacon (no config needed).
    Discover {
        /// Seconds to listen for beacon replies.
        #[arg(long, default_value = "3")]
        timeout: u64,
        /// Only show hubs matching this token file's cluster.
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
        /// Beacon UDP port.
        #[arg(long, default_value_t = fabric_beacon::DEFAULT_BEACON_PORT)]
        port: u16,
    },
    /// Roll a staged binary update across the cluster, one node at a time,
    /// health-gated. Stage binaries first with: update-fabric.ps1 -Stage <dir>.
    Update {
        /// Pull staged binaries from this hub (default: auto-detect the node
        /// that has binaries staged).
        #[arg(long)]
        from_hub: Option<String>,
        /// Update only the node at this hub URL (no cluster roll).
        #[arg(long)]
        only: Option<String>,
        /// Also install the staged VS Code extension on each node.
        #[arg(long)]
        include_vsix: bool,
        /// Seconds to wait for a node to come back healthy after its update.
        #[arg(long, default_value = "120")]
        node_timeout: u64,
        #[arg(long, default_value_t = fabric_beacon::DEFAULT_BEACON_PORT)]
        beacon_port: u16,
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
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Verify the audit chain for a task
    Verify {
        #[arg(long)]
        task_id: i64,
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
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
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
}

#[derive(Subcommand)]
enum RoleTokenAction {
    /// List role-token metadata (never credential values or hashes)
    List {
        #[arg(long)]
        include_revoked: bool,
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Issue a new role token; its credential is shown exactly once
    Issue {
        #[arg(long)]
        label: String,
        #[arg(long, value_delimiter = ',', required = true)]
        roles: Vec<String>,
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Split the legacy bundle, or import an existing bearer from a protected file
    Migrate {
        /// Split the installed legacy bundle into dispatcher, runner,
        /// observer, approver, and reviewer credentials.
        #[arg(long)]
        split: bool,
        #[arg(long, conflicts_with = "split")]
        from_token_file: Option<PathBuf>,
        #[arg(long, default_value = "legacy compatibility split")]
        label: String,
        #[arg(long, value_delimiter = ',', conflicts_with = "split")]
        roles: Vec<String>,
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Revoke a role token by its public token id
    Revoke {
        token_id: String,
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuthAction {
    /// `true` while the realm has no administrator yet.
    BootstrapStatus {
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
    },
    /// Create the realm's first administrator. The hub must be reachable at
    /// a loopback address (127.0.0.1/::1) by default -- run this on the hub
    /// machine itself, not remotely, unless the hub's `auth.bootstrap.
    /// local_only` setting has been explicitly disabled.
    Bootstrap {
        #[arg(long)]
        username: String,
        #[arg(long)]
        display_name: String,
        /// Prompted-equivalent: read from stdin if omitted, never taken as a
        /// bare positional/visible argument, so it cannot linger in shell
        /// history or a process listing.
        #[arg(long)]
        password: Option<String>,
        /// Only needed if the hub was started with
        /// FORGEWIRE_HUB_BOOTSTRAP_SECRET_FILE configured.
        #[arg(long, env = "FORGEWIRE_HUB_BOOTSTRAP_SECRET")]
        bootstrap_secret: Option<String>,
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
    },
}

#[derive(Subcommand)]
enum AccountsAction {
    /// `GET /accounts/export`: print a redacted profile-only snapshot of
    /// every account in the realm.
    Export {
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_ACCESS_SECRET_FILE")]
        access_secret_file: Option<String>,
    },
    /// `POST /accounts/import`: preview (default) or apply a ForgeWire
    /// account-interchange document read from `--file`. Preview never
    /// writes; pass `--apply` to actually create accounts.
    Import {
        /// Path to a JSON document matching the interchange schema
        /// (`{ "schema_version", "source", "accounts": [...] }`).
        #[arg(long)]
        file: PathBuf,
        /// Actually create accounts. Without this flag, only a preview is
        /// computed and nothing is written -- the safe default.
        #[arg(long)]
        apply: bool,
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_ACCESS_SECRET_FILE")]
        access_secret_file: Option<String>,
    },
}

#[derive(Subcommand)]
enum SettingsAction {
    /// Show the redacted effective/default/hub settings snapshot.
    List {
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Print the settings JSON Schema.
    Schema {
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Set one dotted key to a JSON value using revision compare-and-swap.
    Set {
        key: String,
        value: String,
        #[arg(long)]
        expected_revision: i64,
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
    /// Reset one dotted key to the lower settings tier.
    Reset {
        key: String,
        #[arg(long)]
        expected_revision: i64,
        #[arg(
            long,
            env = "FORGEWIRE_HUB_URL",
            default_value = "http://127.0.0.1:8765"
        )]
        hub_url: String,
        #[arg(long, env = "FORGEWIRE_HUB_TOKEN_FILE")]
        token_file: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Replay {
            task_id,
            with_model,
            on,
            dry_run,
            identity,
            hub_url,
            token_file,
        } => {
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
            for key in [
                "required_tools",
                "required_tags",
                "required_capabilities",
                "tenant",
                "workspace_root",
                "network_egress",
                "todo_id",
            ] {
                if let Some(v) = task.get(key) {
                    if !v.is_null() {
                        brief[key] = v.clone();
                    }
                }
            }

            // 3. Show the reconstructed brief (to stderr so stdout can stay
            //    machine-readable on actual dispatch).
            eprintln!("Replay of task {task_id} — reconstructed brief:");
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&brief).unwrap_or_default()
            );

            if dry_run {
                eprintln!("DRY RUN — not dispatched.");
                return;
            }

            // 4. Re-dispatch over the SIGNED path. A dispatcher identity is
            //    mandatory — there is no unsigned dispatch.
            let Some(identity_path) = identity else {
                eprintln!("--identity <dispatcher key file> is required to dispatch a replay (or use --dry-run)");
                std::process::exit(2);
            };
            let dispatcher = match fabric_identity::load(&identity_path) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!(
                        "failed to load dispatcher identity {}: {e}",
                        identity_path.display()
                    );
                    std::process::exit(1);
                }
            };
            match client.dispatch_signed(&dispatcher, &brief).await {
                Ok(new_task) => {
                    let new_id = new_task.get("id").and_then(|v| v.as_i64());
                    match new_id {
                        Some(id) => println!("{id}"),
                        None => {
                            println!("{}", serde_json::to_string(&new_task).unwrap_or_default());
                        }
                    }
                    eprintln!(
                        "replayed task {task_id} -> new task {}",
                        new_id.map(|i| i.to_string()).unwrap_or_else(|| "?".into())
                    );
                }
                Err(e) => {
                    eprintln!("replay dispatch failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Discover {
            timeout,
            token_file,
            port,
        } => {
            let want = token_file.as_deref().and_then(|tf| {
                std::fs::read_to_string(tf)
                    .ok()
                    .map(|t| fabric_beacon::token_hash(t.trim()))
            });
            eprintln!("listening for ForgeWire hubs on udp/{port} for {timeout}s...");
            let hubs = fabric_beacon::discover(
                port,
                std::time::Duration::from_secs(timeout),
                want.as_deref(),
            )
            .unwrap_or_default();
            if hubs.is_empty() {
                eprintln!("no hubs found (none on this LAN segment, or all firewalled)");
                std::process::exit(1);
            }
            for h in hubs {
                println!(
                    "{}\t{}\tproto={}\tcluster={}",
                    h.url, h.name, h.proto, h.token_hash
                );
            }
        }

        Commands::Update {
            from_hub,
            only,
            include_vsix,
            node_timeout,
            beacon_port,
            token_file,
        } => {
            let token = load_token(token_file.as_deref());
            if token.is_empty() {
                eprintln!("a hub token is required (set FORGEWIRE_HUB_TOKEN_FILE or --token-file)");
                std::process::exit(2);
            }

            // 1. Target nodes: a single --only URL, or all discovered hubs.
            let mut nodes: Vec<String> = if let Some(u) = &only {
                vec![u.trim_end_matches('/').to_owned()]
            } else {
                let want = fabric_beacon::token_hash(&token);
                let found = fabric_beacon::discover(
                    beacon_port,
                    std::time::Duration::from_secs(4),
                    Some(&want),
                )
                .unwrap_or_default();
                found.into_iter().map(|h| h.url).collect()
            };
            if nodes.is_empty() {
                eprintln!("no hubs found on the LAN (and no --only given)");
                std::process::exit(1);
            }

            // 2. Staging hub: explicit --from-hub, else the node whose manifest has files.
            let staging = if let Some(f) = &from_hub {
                f.trim_end_matches('/').to_owned()
            } else {
                let mut s = None;
                for n in &nodes {
                    let c = HubClient::new(n, &token);
                    if let Ok(m) = c.binaries_manifest().await {
                        let count = m
                            .get("files")
                            .and_then(|v| v.as_array())
                            .map_or(0, |a| a.len());
                        if count > 0 {
                            s = Some(n.clone());
                            break;
                        }
                    }
                }
                match s {
                    Some(s) => s,
                    None => {
                        eprintln!("no node has binaries staged. On one node run:\n  update-fabric.ps1 -Stage <dir>\nor copy new binaries into …\\bin\\staged");
                        std::process::exit(1);
                    }
                }
            };
            // Confirm staging manifest.
            match HubClient::new(&staging, &token).binaries_manifest().await {
                Ok(m) => {
                    let v = m.get("version").and_then(|x| x.as_str()).unwrap_or("?");
                    let n = m
                        .get("files")
                        .and_then(|x| x.as_array())
                        .map_or(0, |a| a.len());
                    eprintln!("staging hub: {staging}  (version {v}, {n} file(s))");
                }
                Err(e) => {
                    eprintln!("cannot read staging manifest from {staging}: {e}");
                    std::process::exit(1);
                }
            }

            // 3. A cluster roll updates every discovered peer first and the
            //    staging hub last so it remains available as the artifact
            //    source. `--only` is a strict single-node contract: the
            //    staging hub is a source, not an implicit second target.
            nodes = order_update_nodes(nodes, &staging, only.is_some());

            // 4. Roll, one node at a time, health-gated on started_at advancing.
            let mut ok = 0usize;
            for node in &nodes {
                let client = HubClient::new(node, &token);
                let pre = client
                    .healthz()
                    .await
                    .ok()
                    .and_then(|h| h.get("started_at").and_then(|v| v.as_f64()))
                    .unwrap_or(0.0);
                let from = if node == &staging {
                    None
                } else {
                    Some(staging.as_str())
                };
                eprintln!(
                    "--> updating {node} (from {}) ...",
                    from.unwrap_or("local stage")
                );
                if let Err(e) = client.trigger_self_update(from, include_vsix).await {
                    eprintln!("    trigger failed: {e}  (aborting roll)");
                    std::process::exit(1);
                }
                // Wait for the node to restart (started_at advances) and be healthy.
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(node_timeout);
                let mut healthy = false;
                while std::time::Instant::now() < deadline {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    if let Ok(h) = client.healthz().await {
                        let started = h.get("started_at").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let status_ok = h.get("status").and_then(|v| v.as_str()) == Some("ok");
                        if status_ok && started > pre {
                            healthy = true;
                            let ver = h.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                            eprintln!("    OK — back up, v{ver}");
                            break;
                        }
                    }
                }
                if !healthy {
                    eprintln!("    node did NOT return healthy within {node_timeout}s — aborting roll (remaining nodes untouched)");
                    std::process::exit(1);
                }
                ok += 1;
            }
            println!(
                "cluster update complete: {ok}/{} node(s) rolled",
                nodes.len()
            );
        }

        Commands::Version => {
            println!("forgewire-fabric-cli {}", env!("CARGO_PKG_VERSION"));
            println!("protocol_version: 4");
            println!("runtime: native Rust");
        }

        Commands::Health { hub_url } => {
            let client = HubClient::new(&hub_url, "");
            match client.healthz().await {
                Ok(health) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&health).unwrap_or_default()
                    );
                }
                Err(e) => {
                    eprintln!("hub unreachable at {hub_url}: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Identity { action } => match action {
            IdentityAction::Generate {
                purpose,
                output,
                id,
            } => {
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
                    println!("Identity saved (encrypted) to {}", path.display());
                    println!("  id:         {}", identity.id);
                    println!("  purpose:    {}", identity.purpose);
                    println!("  public_key: {}", identity.public_key_hex);
                } else {
                    // Never print the secret to stdout/terminal scrollback/shell
                    // history. Without --output there is nowhere encrypted to put
                    // it, so show only what Show/Validate already treat as safe.
                    println!("id:         {}", identity.id);
                    println!("purpose:    {}", identity.purpose);
                    println!("public_key: {}", identity.public_key_hex);
                    eprintln!(
                        "note: secret key not printed. Pass --output PATH to persist it \
                         to the encrypted identity vault."
                    );
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
            IdentityAction::Validate { path } => match fabric_identity::load(&path) {
                Ok(id) => {
                    println!(
                        "VALID: {} (purpose={}, public_key={}...)",
                        id.id,
                        id.purpose,
                        &id.public_key_hex[..16]
                    );
                }
                Err(e) => {
                    eprintln!("INVALID: {e}");
                    std::process::exit(1);
                }
            },
        },

        Commands::Audit { action } => {
            let (hub_url, token_file) = match &action {
                AuditAction::Tail {
                    hub_url,
                    token_file,
                } => (hub_url.clone(), token_file.clone()),
                AuditAction::Verify {
                    hub_url,
                    token_file,
                    ..
                } => (hub_url.clone(), token_file.clone()),
                AuditAction::Export {
                    hub_url,
                    token_file,
                    ..
                } => (hub_url.clone(), token_file.clone()),
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

        Commands::RoleTokens { action } => match action {
            RoleTokenAction::List {
                include_revoked,
                hub_url,
                token_file,
            } => {
                let client = HubClient::new(&hub_url, &load_token(token_file.as_deref()));
                match client.list_role_tokens(include_revoked).await {
                    Ok(value) => println!(
                        "{}",
                        serde_json::to_string_pretty(&value).unwrap_or_default()
                    ),
                    Err(error) => {
                        eprintln!("role-token list failed: {error}");
                        std::process::exit(1);
                    }
                }
            }
            RoleTokenAction::Issue {
                label,
                roles,
                hub_url,
                token_file,
            } => {
                let client = HubClient::new(&hub_url, &load_token(token_file.as_deref()));
                match client.issue_role_token(&label, &roles).await {
                    Ok(value) => {
                        eprintln!("credential shown once; move it immediately into a protected token file");
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&value).unwrap_or_default()
                        );
                    }
                    Err(error) => {
                        eprintln!("role-token issue failed: {error}");
                        std::process::exit(1);
                    }
                }
            }
            RoleTokenAction::Migrate {
                split,
                from_token_file,
                label,
                roles,
                hub_url,
                token_file,
            } => {
                let client = HubClient::new(&hub_url, &load_token(token_file.as_deref()));
                if split {
                    match client.split_legacy_role_tokens(&label).await {
                        Ok(value) => {
                            eprintln!("five credentials shown once; move each immediately into a protected role-specific token file");
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&value).unwrap_or_default()
                            );
                        }
                        Err(error) => {
                            eprintln!("legacy role-token split failed: {error}");
                            std::process::exit(1);
                        }
                    }
                    return;
                }
                let from_token_file = from_token_file.unwrap_or_else(|| {
                    eprintln!("--from-token-file is required unless --split is used");
                    std::process::exit(2);
                });
                if roles.is_empty() {
                    eprintln!("--roles is required unless --split is used");
                    std::process::exit(2);
                }
                let migrated = std::fs::read_to_string(&from_token_file)
                    .map(|value| value.trim().to_owned())
                    .unwrap_or_else(|error| {
                        eprintln!(
                            "cannot read migration token file {}: {error}",
                            from_token_file.display()
                        );
                        std::process::exit(1);
                    });
                match client.migrate_role_token(&migrated, &label, &roles).await {
                    Ok(value) => println!(
                        "{}",
                        serde_json::to_string_pretty(&value).unwrap_or_default()
                    ),
                    Err(error) => {
                        eprintln!("role-token migration failed: {error}");
                        std::process::exit(1);
                    }
                }
            }
            RoleTokenAction::Revoke {
                token_id,
                hub_url,
                token_file,
            } => {
                let client = HubClient::new(&hub_url, &load_token(token_file.as_deref()));
                match client.revoke_role_token(&token_id).await {
                    Ok(value) => println!(
                        "{}",
                        serde_json::to_string_pretty(&value).unwrap_or_default()
                    ),
                    Err(error) => {
                        eprintln!("role-token revoke failed: {error}");
                        std::process::exit(1);
                    }
                }
            }
        },

        Commands::Settings { action } => match action {
            SettingsAction::List {
                hub_url,
                token_file,
            } => {
                let client = HubClient::new(&hub_url, &load_token(token_file.as_deref()));
                print_api_result("settings read", client.settings().await);
            }
            SettingsAction::Schema {
                hub_url,
                token_file,
            } => {
                let client = HubClient::new(&hub_url, &load_token(token_file.as_deref()));
                print_api_result("settings schema read", client.settings_schema().await);
            }
            SettingsAction::Set {
                key,
                value,
                expected_revision,
                hub_url,
                token_file,
            } => {
                let value: Value = serde_json::from_str(&value).unwrap_or_else(|error| {
                    eprintln!("setting value must be JSON: {error}");
                    std::process::exit(64);
                });
                let client = HubClient::new(&hub_url, &load_token(token_file.as_deref()));
                print_api_result(
                    "settings mutation",
                    client.set_setting(&key, expected_revision, value).await,
                );
            }
            SettingsAction::Reset {
                key,
                expected_revision,
                hub_url,
                token_file,
            } => {
                let client = HubClient::new(&hub_url, &load_token(token_file.as_deref()));
                print_api_result(
                    "settings reset",
                    client.reset_setting(&key, expected_revision).await,
                );
            }
        },
        Commands::Auth { action } => match action {
            AuthAction::BootstrapStatus { hub_url } => {
                let client = HubClient::new(&hub_url, "");
                print_api_result("bootstrap status", client.bootstrap_status().await);
            }
            AuthAction::Bootstrap {
                username,
                display_name,
                password,
                bootstrap_secret,
                hub_url,
            } => {
                let password = password.unwrap_or_else(|| {
                    eprintln!("password: ");
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line).unwrap_or_else(|e| {
                        eprintln!("failed to read password from stdin: {e}");
                        std::process::exit(1);
                    });
                    line.trim().to_owned()
                });
                let client = HubClient::new(&hub_url, "");
                match client
                    .bootstrap(
                        &username,
                        &display_name,
                        &password,
                        bootstrap_secret.as_deref(),
                    )
                    .await
                {
                    Ok(value) => {
                        eprintln!(
                            "bootstrap complete -- realm's first administrator created. \
                             Sign in via POST /auth/login with this account's username \
                             and password."
                        );
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&value).unwrap_or_default()
                        );
                    }
                    Err(error) => {
                        eprintln!("bootstrap failed: {error}");
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Accounts { action } => match action {
            AccountsAction::Export {
                hub_url,
                access_secret_file,
            } => {
                let client = HubClient::new(&hub_url, "");
                let access_secret = load_access_secret(access_secret_file.as_deref());
                print_api_result(
                    "account export",
                    client.export_accounts(&access_secret).await,
                );
            }
            AccountsAction::Import {
                file,
                apply,
                hub_url,
                access_secret_file,
            } => {
                let text = std::fs::read_to_string(&file).unwrap_or_else(|e| {
                    eprintln!("cannot read {}: {e}", file.display());
                    std::process::exit(1);
                });
                let document: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| {
                    eprintln!("invalid JSON in {}: {e}", file.display());
                    std::process::exit(1);
                });
                let client = HubClient::new(&hub_url, "");
                let access_secret = load_access_secret(access_secret_file.as_deref());
                if !apply {
                    eprintln!("preview only -- pass --apply to actually create accounts");
                }
                print_api_result(
                    "account import",
                    client
                        .import_accounts(&access_secret, &document, !apply)
                        .await,
                );
            }
        },
        Commands::HistoryStatus {
            hub_url,
            token_file,
        } => {
            let client = HubClient::new(&hub_url, &load_token(token_file.as_deref()));
            print_api_result("history status", client.history_status().await);
        }
        Commands::Doctor {
            hub_url,
            token_file,
            json,
        } => {
            let report = doctor::run(&hub_url, token_file.as_deref()).await;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("doctor report serializes")
                );
            } else {
                doctor::print_human(&report);
            }
            if report.exit_code != 0 {
                std::process::exit(report.exit_code);
            }
        }
    }
}

fn print_api_result(operation: &str, result: Result<Value, fabric_client::ClientError>) {
    match result {
        Ok(value) => println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| "null".into())
        ),
        Err(error) => {
            eprintln!("{operation} failed: {error}");
            std::process::exit(1);
        }
    }
}

fn order_update_nodes(
    mut nodes: Vec<String>,
    staging: &str,
    single_node_only: bool,
) -> Vec<String> {
    nodes.sort();
    nodes.dedup();
    if !single_node_only {
        nodes.retain(|node| node != staging);
        nodes.push(staging.to_owned());
    }
    nodes
}

fn load_token(token_file: Option<&str>) -> String {
    let path = token_file
        .map(String::from)
        .or_else(|| std::env::var("FORGEWIRE_HUB_TOKEN_FILE").ok())
        .unwrap_or_else(|| {
            doctor::default_state_dir()
                .join("hub.token")
                .to_string_lossy()
                .into_owned()
        });
    std::fs::read_to_string(&path)
        .map(|t| t.trim().to_owned())
        .unwrap_or_default()
}

/// Same shape as [`load_token`], but for a human session's access secret
/// (`/accounts/export`/`/accounts/import`) rather than a role token --
/// deliberately no default OS path fallback (unlike a role token, there is
/// no standard deployment location for a personal, ephemeral human session
/// secret). An empty string on failure fails the request with a clear
/// hub-side 401 rather than panicking.
fn load_access_secret(access_secret_file: Option<&str>) -> String {
    let Some(path) = access_secret_file
        .map(String::from)
        .or_else(|| std::env::var("FORGEWIRE_ACCESS_SECRET_FILE").ok())
    else {
        return String::new();
    };
    std::fs::read_to_string(&path)
        .map(|t| t.trim().to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod role_token_cli_tests {
    use super::*;

    #[test]
    fn migrate_split_is_a_native_cli_path() {
        let cli = Cli::try_parse_from([
            "forgewire-fabric-cli",
            "role-tokens",
            "migrate",
            "--split",
            "--label",
            "two-machine cluster",
        ])
        .expect("parse role-token split");
        match cli.command {
            Commands::RoleTokens {
                action:
                    RoleTokenAction::Migrate {
                        split,
                        from_token_file,
                        roles,
                        ..
                    },
            } => {
                assert!(split);
                assert!(from_token_file.is_none());
                assert!(roles.is_empty());
            }
            _ => panic!("expected role-token migrate --split"),
        }
    }

    #[test]
    fn update_only_does_not_append_the_staging_hub() {
        let nodes = order_update_nodes(
            vec!["http://remote:8765".into()],
            "http://staging:8765",
            true,
        );
        assert_eq!(nodes, vec!["http://remote:8765"]);
    }

    #[test]
    fn cluster_update_keeps_the_staging_hub_last() {
        let nodes = order_update_nodes(
            vec![
                "http://staging:8765".into(),
                "http://peer-b:8765".into(),
                "http://peer-a:8765".into(),
                "http://peer-a:8765".into(),
            ],
            "http://staging:8765",
            false,
        );
        assert_eq!(
            nodes,
            vec![
                "http://peer-a:8765",
                "http://peer-b:8765",
                "http://staging:8765",
            ]
        );
    }
}
