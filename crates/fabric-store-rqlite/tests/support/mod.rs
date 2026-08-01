//! Provisions a throwaway single-node rqlite for Rust tests that write
//! `human_*` account state. This is the Rust-side counterpart to
//! `tests/ephemeral_rqlite.py` (used by the Python suite) -- the same
//! guarantees, re-derived here rather than shelled out to Python, because
//! `crates/fabric-store-rqlite`'s own test binaries need to spawn and tear
//! down rqlited directly.
//!
//! ## Why this exists (114C evidence plan, Rule 2)
//!
//! `crates/fabric-store-rqlite`'s existing tests default to `RQLITE_HOST`/
//! `RQLITE_PORT`, falling back to the **live shared cluster** at
//! `127.0.0.1:4001` (see `test_store()` in `src/lib.rs`). That is safe for
//! the existing tests because they are written baseline-diff style against a
//! cluster something else may be using concurrently. It is not safe for
//! anything that writes `human_*` rows: those rows are durable security
//! state (accounts, credentials, sessions, recovery codes) and nothing
//! cleans them from the live cluster. Every test that exercises the
//! `human_*` schema or the account/session/credential/membership
//! repositories uses [`EphemeralRqlite::provision`] instead, never the
//! default-port fallback.
//!
//! The node is standalone: it is never given `-join`, so it cannot enter the
//! real Raft cluster, and provisioning refuses outright to bind the live
//! cluster's ports even if a caller's free-port search somehow landed on one.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The live cluster. An ephemeral node must never bind or address these.
pub const LIVE_HTTP_PORT: u16 = 4001;
pub const LIVE_RAFT_PORT: u16 = 4002;

const DEFAULT_RQLITED: &str = r"C:\rqlite\rqlited.exe";
const LEADER_TIMEOUT: Duration = Duration::from_secs(30);

pub struct EphemeralRqlite {
    pub host: String,
    pub http_port: u16,
    // Not read by every test file that pulls in this shared support module --
    // kept for callers that need it (diagnostics, multi-node scenarios).
    #[allow(dead_code)]
    pub raft_port: u16,
    pub data_dir: PathBuf,
    child: Child,
}

impl EphemeralRqlite {
    pub fn base_url(&self) -> String {
        format!("http://{}:{}", self.host, self.http_port)
    }

    /// Locate rqlited, or `None` if it is not installed -- callers should
    /// skip (not fail) the test in that case, matching the existing
    /// `test_store()` skip-if-unreachable convention in `src/lib.rs`.
    fn rqlited_path() -> Option<PathBuf> {
        let default = PathBuf::from(DEFAULT_RQLITED);
        if default.exists() {
            return Some(default);
        }
        which_on_path("rqlited")
    }

    fn free_port() -> std::io::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?.port())
    }

    /// Spawn a throwaway node and wait for it to elect itself leader.
    /// Returns `Ok(None)` (not an error) if rqlited is not installed on this
    /// host -- tests should skip, not fail, in that case.
    pub async fn provision() -> Result<Option<Self>, String> {
        let Some(binary) = Self::rqlited_path() else {
            return Ok(None);
        };

        let http_port = Self::free_port().map_err(|e| e.to_string())?;
        let raft_port = Self::free_port().map_err(|e| e.to_string())?;

        // Belt-and-braces: the whole point of this module is that it cannot
        // collide with the real cluster.
        for port in [http_port, raft_port] {
            if port == LIVE_HTTP_PORT || port == LIVE_RAFT_PORT {
                return Err(format!("refusing to bind live cluster port {port}"));
            }
        }

        let data_dir = std::env::temp_dir().join(format!("fabric-ephemeral-rqlite-{http_port}"));
        std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;

        let child = Command::new(&binary)
            .arg("-node-id")
            .arg(format!("ephemeral-{http_port}"))
            .arg("-http-addr")
            .arg(format!("127.0.0.1:{http_port}"))
            .arg("-raft-addr")
            .arg(format!("127.0.0.1:{raft_port}"))
            // Deliberately no -join: a standalone node cannot enter the real
            // Raft cluster even by accident.
            .arg(&data_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to spawn rqlited: {e}"))?;

        let mut node = Self {
            host: "127.0.0.1".to_owned(),
            http_port,
            raft_port,
            data_dir,
            child,
        };
        node.await_leader().await?;
        Ok(Some(node))
    }

    async fn await_leader(&mut self) -> Result<(), String> {
        let client = reqwest::Client::new();
        let deadline = tokio::time::Instant::now() + LEADER_TIMEOUT;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(format!("rqlited exited with status {status}"));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!("no leader elected within {LEADER_TIMEOUT:?}"));
            }
            if let Ok(resp) = client
                .get(format!("{}/status", self.base_url()))
                .timeout(Duration::from_secs(1))
                .send()
                .await
            {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if body["store"]["leader"]["addr"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
                    {
                        return Ok(());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Direct SQL query against this node, bypassing `RqliteStore`, for
    /// tests that need to inspect raw stored rows (e.g. proving a database
    /// dump contains no plaintext secret) rather than going back through the
    /// repository abstraction under test. Shared general-purpose helper --
    /// not every test binary that pulls in this module happens to call it.
    #[allow(dead_code)]
    pub async fn raw_query(&self, sql: &str) -> Result<serde_json::Value, String> {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/db/query?level=strong", self.base_url()))
            .json(&serde_json::json!([[sql]]))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| e.to_string())
    }

    /// Direct SQL write against this node, bypassing `RqliteStore`, for
    /// tests that need to set up state no repository method exposes (e.g.
    /// backdating a row's timestamp to test rolling-window expiry). Shared
    /// general-purpose helper -- not every test binary that pulls in this
    /// module happens to call it.
    #[allow(dead_code)]
    pub async fn raw_execute(&self, sql: &str) -> Result<serde_json::Value, String> {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/db/execute", self.base_url()))
            .json(&serde_json::json!([[sql]]))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| e.to_string())
    }

    /// Shared general-purpose helper -- not every test binary that pulls in
    /// this module happens to call it.
    #[allow(dead_code)]
    pub async fn table_names(&self) -> Result<std::collections::BTreeSet<String>, String> {
        let result = self
            .raw_query("SELECT name FROM sqlite_master WHERE type='table'")
            .await?;
        let values = result["results"][0]["values"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        Ok(values
            .into_iter()
            .filter_map(|row| row.get(0).and_then(|v| v.as_str()).map(str::to_owned))
            .collect())
    }
}

impl Drop for EphemeralRqlite {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

fn which_on_path(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let exe_name = if cfg!(windows) {
        format!("{binary}.exe")
    } else {
        binary.to_owned()
    };
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(&exe_name))
        .find(|candidate| candidate.is_file())
}

/// Macro-free skip helper: tests call this and `return` early when `None`,
/// matching the existing `test_store()` skip-on-unreachable convention.
#[allow(dead_code)]
pub async fn provision_or_skip(test_name: &str) -> Option<EphemeralRqlite> {
    match EphemeralRqlite::provision().await {
        Ok(Some(node)) => Some(node),
        Ok(None) => {
            eprintln!("SKIP {test_name} — rqlited not installed");
            None
        }
        Err(e) => {
            eprintln!("SKIP {test_name} — ephemeral rqlite provisioning failed: {e}");
            None
        }
    }
}
