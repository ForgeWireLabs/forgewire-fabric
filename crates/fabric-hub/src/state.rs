//! Shared hub state — passed to all route handlers via axum State.

use std::sync::Arc;
use std::time::Instant;

use fabric_policy::DispatchGate;
use fabric_store_sqlite::SqliteStore;

pub struct HubState {
    pub store: Arc<SqliteStore>,
    pub token: String,
    pub started_at: Instant,
    pub started_at_unix: f64,
    pub gate: DispatchGate,
    pub host: String,
    pub port: u16,
    pub protocol_version: i64,
    pub package_version: String,
    pub sidecar_integrity: String,
}
