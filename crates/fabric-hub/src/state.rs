//! Shared hub state — passed to all route handlers via axum State.

use std::sync::Arc;
use std::time::Instant;

use fabric_policy::DispatchGate;
use fabric_store::FabricStore;
use fabric_streams::StreamBuffer;

pub struct HubState {
    pub store: Arc<dyn FabricStore>,
    pub token: String,
    pub started_at: Instant,
    pub started_at_unix: f64,
    pub gate: DispatchGate,
    pub host: String,
    pub port: u16,
    pub protocol_version: i64,
    pub package_version: String,
    pub sidecar_integrity: String,
    /// "rqlite" (only supported backend)
    pub backend: String,
    /// Bounded write buffer for task stream lines.
    pub stream_buffer: Arc<StreamBuffer>,
}
