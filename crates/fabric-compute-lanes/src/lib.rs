//! 114F.1B — backend-matrix-to-Loom capability projection.
//!
//! Takes the two static things a host can say about itself and projects them
//! into a redacted, Loom-safe capability view:
//!
//! ```text
//! ForgeCoreBackendMatrix   (108-owned, consumed unchanged from crates.io)
//!         +
//! ComputeTopologySnapshot  (114F.1A, fabric-topology)
//!         ↓
//! ComputeCapabilityProjection   ← this crate
//! ```
//!
//! Three rules from the 114F design doc shape everything here:
//!
//! - **No second device schema** (§3.1). `BackendKind`, `ComputeClass`,
//!   `MemoryModel`, and `DeviceDescriptor` come from [`forgewire_capability`]
//!   and are never redefined. This crate adds the *projection*, not a
//!   competing vocabulary.
//! - **Static capability and dynamic health are separate records** (§4.3). A
//!   transient fault must never rewrite hardware identity, so
//!   [`ComputeHealthOverlay`] is a distinct type keyed by device id rather than
//!   a field on the projected device.
//! - **Backend adapters are pluggable and unprivileged** (decision 0005).
//!   [`BackendAdapter`] is an open id plus backend list, deliberately not a
//!   closed enum, so llama.cpp, ONNX Runtime, `fc-kernels`, and a plain
//!   subprocess are all expressible with none structurally favored.
//!
//! This crate projects and redacts. It does not install lanes (114F.2), route
//! work (114F.4), or probe live health (114F.6).

#![deny(rust_2018_idioms)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use fabric_topology::ComputeTopologySnapshot;
use forgewire_capability::{
    BackendKind, ComputeClass, DeviceDescriptor, ForgeCoreBackendMatrix, MemoryModel,
};

mod redact;

pub use redact::{redact_field, RedactionOutcome};

/// Wire schema version for [`ComputeCapabilityProjection`].
pub const SCHEMA_VERSION: u32 = 1;

/// Errors from loading or validating capability inputs.
#[derive(Debug, thiserror::Error)]
pub enum ProjectionError {
    #[error("backend matrix snapshot is not valid JSON: {0}")]
    MalformedSnapshot(#[from] serde_json::Error),
    #[error("backend matrix snapshot could not be read: {0}")]
    UnreadableSnapshot(String),
    #[error("backend matrix schema version {found:?} is not supported (expected {expected:?})")]
    UnsupportedSchema { found: String, expected: String },
}

// ---------------------------------------------------------------------------
// Snapshot loading
// ---------------------------------------------------------------------------

/// A loaded `ForgeCoreBackendMatrix` plus the provenance 114F needs but the
/// frozen schema itself does not carry.
///
/// The matrix has no timestamp field, so freshness cannot be derived from its
/// contents. The loader records when it was observed instead, and
/// [`BackendMatrixSnapshot::is_stale`] applies a caller-supplied policy — this
/// crate does not invent a global freshness threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackendMatrixSnapshot {
    pub matrix: ForgeCoreBackendMatrix,
    /// SHA-256 of the matrix's own canonical JSON, computed by
    /// `forgewire-capability`, so a projection can be tied back to the exact
    /// matrix it came from.
    pub matrix_fingerprint: String,
    /// When this snapshot was observed (RFC3339, caller-supplied).
    pub observed_at: String,
    /// Age in seconds at observation, when the caller can determine it (e.g.
    /// from file mtime). `None` when unknown — unknown age is never silently
    /// treated as fresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<u64>,
}

impl BackendMatrixSnapshot {
    /// Parse a canonical matrix JSON document.
    pub fn from_json(
        json: &str,
        observed_at: &str,
        age_seconds: Option<u64>,
    ) -> Result<Self, ProjectionError> {
        let matrix = ForgeCoreBackendMatrix::from_canonical_json(json)?;
        Self::from_matrix(matrix, observed_at, age_seconds)
    }

    /// Wrap an already-parsed matrix, validating its schema version.
    pub fn from_matrix(
        matrix: ForgeCoreBackendMatrix,
        observed_at: &str,
        age_seconds: Option<u64>,
    ) -> Result<Self, ProjectionError> {
        if matrix.schema_version != forgewire_capability::SCHEMA_VERSION {
            return Err(ProjectionError::UnsupportedSchema {
                found: matrix.schema_version.clone(),
                expected: forgewire_capability::SCHEMA_VERSION.to_owned(),
            });
        }
        let matrix_fingerprint = matrix.fingerprint();
        Ok(Self {
            matrix,
            matrix_fingerprint,
            observed_at: observed_at.to_owned(),
            age_seconds,
        })
    }

    /// Read a snapshot from disk. Kept thin: all validation lives in
    /// [`BackendMatrixSnapshot::from_json`] so it stays testable without a
    /// filesystem.
    pub fn from_path(path: &std::path::Path, observed_at: &str) -> Result<Self, ProjectionError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ProjectionError::UnreadableSnapshot(e.to_string()))?;
        let age_seconds = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs());
        Self::from_json(&raw, observed_at, age_seconds)
    }

    /// Whether this snapshot exceeds `max_age_seconds`.
    ///
    /// Unknown age returns `true`: a snapshot whose freshness cannot be
    /// established is treated as stale rather than assumed current, so a
    /// missing timestamp can never silently advertise removed hardware.
    #[must_use]
    pub fn is_stale(&self, max_age_seconds: u64) -> bool {
        match self.age_seconds {
            Some(age) => age > max_age_seconds,
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Projected types
// ---------------------------------------------------------------------------

/// What kind of compute a projected device represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    Cpu,
    Gpu,
    Accelerator,
}

impl LaneKind {
    /// Derive the lane kind from the 108-owned compute class. This projects an
    /// existing vocabulary; it does not introduce a new classification.
    #[must_use]
    pub fn from_compute_class(class: ComputeClass) -> Self {
        match class {
            ComputeClass::CpuOnly => LaneKind::Cpu,
            ComputeClass::OpenvinoNpu => LaneKind::Accelerator,
            ComputeClass::ModernCuda
            | ComputeClass::LegacyCuda
            | ComputeClass::DiscreteVulkan
            | ComputeClass::IntegratedVulkan
            | ComputeClass::Metal
            | ComputeClass::DirectmlOnly => LaneKind::Gpu,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            LaneKind::Cpu => "cpu",
            LaneKind::Gpu => "gpu",
            LaneKind::Accelerator => "accelerator",
        }
    }
}

/// A runtime a lane may dispatch work to.
///
/// Deliberately an open `id` rather than a closed enum: decision 0005 makes
/// backend adapters pluggable and explicitly unprivileged, so `fc-kernels`,
/// llama.cpp, ONNX Runtime, and a plain subprocess are equally representable
/// and none is structurally favored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendAdapter {
    /// Stable adapter identifier, e.g. `"fc-kernels"`, `"llama.cpp"`,
    /// `"onnxruntime"`, `"subprocess"`.
    pub id: String,
    /// Backend kinds this adapter can drive on the device it is attached to.
    pub backends: Vec<BackendKind>,
}

impl BackendAdapter {
    #[must_use]
    pub fn new(id: &str, backends: Vec<BackendKind>) -> Self {
        Self {
            id: id.to_owned(),
            backends,
        }
    }

    fn to_canonical_value(&self) -> Value {
        let mut map: Map<String, Value> = Map::new();
        map.insert("id".into(), Value::String(self.id.clone()));
        map.insert(
            "backends".into(),
            Value::Array(
                self.backends
                    .iter()
                    .map(|b| Value::String(b.as_str().to_owned()))
                    .collect(),
            ),
        );
        Value::Object(map)
    }
}

/// Memory facts carried through from the matrix unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectedMemory {
    pub model: MemoryModel,
    pub dedicated_mb: i64,
    pub shared_mb: i64,
    pub host_visible_heap_mb: i64,
    pub supports_unified_addressing: bool,
    pub supports_pinned_host: bool,
}

impl ProjectedMemory {
    fn to_canonical_value(self) -> Value {
        let mut map: Map<String, Value> = Map::new();
        map.insert("dedicated_mb".into(), Value::from(self.dedicated_mb));
        map.insert(
            "host_visible_heap_mb".into(),
            Value::from(self.host_visible_heap_mb),
        );
        map.insert(
            "model".into(),
            Value::String(self.model.as_str().to_owned()),
        );
        map.insert("shared_mb".into(), Value::from(self.shared_mb));
        map.insert(
            "supports_pinned_host".into(),
            Value::Bool(self.supports_pinned_host),
        );
        map.insert(
            "supports_unified_addressing".into(),
            Value::Bool(self.supports_unified_addressing),
        );
        Value::Object(map)
    }
}

/// One device, projected into a form safe to advertise to the hub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectedDevice {
    /// Canonical device id, carried from the matrix so it stays stable and
    /// referenceable across hosts and restarts.
    pub device_id: String,
    pub lane_kind: LaneKind,
    pub vendor: String,
    pub name: String,
    pub compute_class: ComputeClass,
    pub supported_backends: Vec<BackendKind>,
    pub preferred_backend: BackendKind,
    pub memory: ProjectedMemory,
    /// Adapters permitted on this device. Empty means no adapter is registered
    /// yet — a device can be discovered before anything can drive it.
    #[serde(default)]
    pub adapters: Vec<BackendAdapter>,
    /// Fingerprint over this device's projected (post-redaction) content.
    pub fingerprint: String,
}

impl ProjectedDevice {
    fn to_canonical_value(&self) -> Value {
        let mut map: Map<String, Value> = Map::new();
        map.insert("device_id".into(), Value::String(self.device_id.clone()));
        map.insert(
            "lane_kind".into(),
            Value::String(self.lane_kind.as_str().to_owned()),
        );
        map.insert("vendor".into(), Value::String(self.vendor.clone()));
        map.insert("name".into(), Value::String(self.name.clone()));
        map.insert(
            "compute_class".into(),
            Value::String(self.compute_class.as_str().to_owned()),
        );
        map.insert(
            "supported_backends".into(),
            Value::Array(
                self.supported_backends
                    .iter()
                    .map(|b| Value::String(b.as_str().to_owned()))
                    .collect(),
            ),
        );
        map.insert(
            "preferred_backend".into(),
            Value::String(self.preferred_backend.as_str().to_owned()),
        );
        map.insert("memory".into(), self.memory.to_canonical_value());
        map.insert(
            "adapters".into(),
            Value::Array(
                self.adapters
                    .iter()
                    .map(BackendAdapter::to_canonical_value)
                    .collect(),
            ),
        );
        Value::Object(map)
    }

    /// Fingerprint of everything except the fingerprint field itself.
    fn compute_fingerprint(&self) -> String {
        let canonical = serde_json::to_string_pretty(&self.to_canonical_value())
            .expect("canonical projected device serializes");
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// CPU facts projected from [`ComputeTopologySnapshot`], summarized to what a
/// scheduler needs. The full topology remains available separately; this is
/// the advertised summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectedCpu {
    pub arch: String,
    pub processor_packages: u32,
    pub physical_cores: u32,
    pub logical_processors: u32,
    pub processor_groups: u32,
    pub numa_nodes: u32,
    /// True when any core exposes more than one logical processor.
    pub has_smt: bool,
    /// True when cores report differing efficiency classes (P/E-core hosts).
    pub heterogeneous_cores: bool,
    pub topology_fingerprint: String,
}

/// The full host capability projection: static, redacted, fingerprinted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComputeCapabilityProjection {
    pub schema_version: u32,
    pub host_id: String,
    pub cpu: ProjectedCpu,
    pub devices: Vec<ProjectedDevice>,
    pub available_runtimes: Vec<BackendKind>,
    pub backend_matrix_fingerprint: String,
    /// Warnings raised while projecting — partial discovery, redaction hits,
    /// stale inputs. Never silently dropped.
    #[serde(default)]
    pub projection_warnings: Vec<String>,
    pub projected_at: String,
}

impl ComputeCapabilityProjection {
    fn to_canonical_value(&self) -> Value {
        let mut map: Map<String, Value> = Map::new();
        map.insert("schema_version".into(), Value::from(self.schema_version));
        map.insert("host_id".into(), Value::String(self.host_id.clone()));
        map.insert(
            "cpu".into(),
            serde_json::to_value(&self.cpu).unwrap_or(Value::Null),
        );
        map.insert(
            "devices".into(),
            Value::Array(
                self.devices
                    .iter()
                    .map(ProjectedDevice::to_canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "available_runtimes".into(),
            Value::Array(
                self.available_runtimes
                    .iter()
                    .map(|b| Value::String(b.as_str().to_owned()))
                    .collect(),
            ),
        );
        map.insert(
            "backend_matrix_fingerprint".into(),
            Value::String(self.backend_matrix_fingerprint.clone()),
        );
        map.insert(
            "projection_warnings".into(),
            Value::Array(
                self.projection_warnings
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        map.insert(
            "projected_at".into(),
            Value::String(self.projected_at.clone()),
        );
        Value::Object(map)
    }

    /// Canonical JSON (sorted keys, two-space indent) — the same convention
    /// `ForgeCoreBackendMatrix` and `ComputeTopologySnapshot` use.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string_pretty(&self.to_canonical_value())
            .expect("canonical capability projection serializes")
    }

    /// Stable SHA-256 fingerprint of the canonical encoding.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.to_canonical_json().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Look up a projected device by canonical id.
    #[must_use]
    pub fn device(&self, device_id: &str) -> Option<&ProjectedDevice> {
        self.devices.iter().find(|d| d.device_id == device_id)
    }

    /// Devices of a given lane kind.
    #[must_use]
    pub fn devices_of_kind(&self, kind: LaneKind) -> Vec<&ProjectedDevice> {
        self.devices
            .iter()
            .filter(|d| d.lane_kind == kind)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Health overlay — dynamic, deliberately separate from static capability
// ---------------------------------------------------------------------------

/// Dynamic lane/device state. Per §4.3 this is a separate record from static
/// capability: a transient fault must never rewrite hardware identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Available,
    Busy,
    Degraded,
    Cooling,
    Drained,
    Quarantined,
    Unavailable,
}

/// Typed reason families from design-doc §6.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthReason {
    OperatorDrain,
    CapacityExhausted,
    MemoryPressure,
    ThermalThreshold,
    Throttling,
    DriverReset,
    DeviceLost,
    RepeatedProcessFailure,
    ProbeMismatch,
    MissingBackend,
    UnsupportedPlacement,
    StaleCapabilitySnapshot,
    IdentityConflict,
}

/// Dynamic state for one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeHealthOverlay {
    pub device_id: String,
    pub state: HealthState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<HealthReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub observed_at: String,
}

impl ComputeHealthOverlay {
    /// A healthy overlay for a device.
    #[must_use]
    pub fn available(device_id: &str, observed_at: &str) -> Self {
        Self {
            device_id: device_id.to_owned(),
            state: HealthState::Available,
            reason: None,
            detail: None,
            observed_at: observed_at.to_owned(),
        }
    }

    /// An unhealthy overlay with a typed reason.
    #[must_use]
    pub fn unhealthy(
        device_id: &str,
        state: HealthState,
        reason: HealthReason,
        observed_at: &str,
    ) -> Self {
        Self {
            device_id: device_id.to_owned(),
            state,
            reason: Some(reason),
            detail: None,
            observed_at: observed_at.to_owned(),
        }
    }

    /// Whether this device may accept new work. Quarantined, drained, cooling,
    /// and unavailable devices may not. Busy and degraded may — admission
    /// throttling is a routing concern (114F.4), not a capability one.
    #[must_use]
    pub fn admits_work(&self) -> bool {
        matches!(
            self.state,
            HealthState::Available | HealthState::Busy | HealthState::Degraded
        )
    }
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

/// Adapters a caller declares available on this host, keyed by the device id
/// they apply to. Callers with no adapters registered pass an empty map —
/// devices are still discovered and projected.
pub type AdapterRegistry = BTreeMap<String, Vec<BackendAdapter>>;

/// Project a backend matrix plus CPU topology into a redacted, Loom-safe
/// capability view.
///
/// Redaction runs over every free-form string carried from the matrix
/// (`vendor`, `name`). Anything redacted raises a projection warning rather
/// than being silently altered.
#[must_use]
pub fn project(
    host_id: &str,
    snapshot: &BackendMatrixSnapshot,
    topology: &ComputeTopologySnapshot,
    adapters: &AdapterRegistry,
    projected_at: &str,
    max_snapshot_age_seconds: u64,
) -> ComputeCapabilityProjection {
    let mut warnings: Vec<String> = Vec::new();

    if snapshot.is_stale(max_snapshot_age_seconds) {
        warnings.push(match snapshot.age_seconds {
            Some(age) => format!(
                "backend matrix snapshot is stale: {age}s old exceeds \
                 max_snapshot_age_seconds={max_snapshot_age_seconds}"
            ),
            None => "backend matrix snapshot age is unknown; treated as stale".to_owned(),
        });
    }

    // Carry the topology probe's own warnings through rather than dropping
    // them — partial CPU discovery is a capability-affecting fact.
    for w in &topology.probe_warnings {
        warnings.push(format!("cpu topology: {w}"));
    }

    if snapshot.matrix.devices.is_empty() {
        warnings.push("backend matrix declares no devices".to_owned());
    }

    let devices: Vec<ProjectedDevice> = snapshot
        .matrix
        .devices
        .iter()
        .map(|d| project_device(d, adapters, &mut warnings))
        .collect();

    ComputeCapabilityProjection {
        schema_version: SCHEMA_VERSION,
        host_id: host_id.to_owned(),
        cpu: project_cpu(topology),
        devices,
        available_runtimes: snapshot.matrix.available_runtimes.clone(),
        backend_matrix_fingerprint: snapshot.matrix_fingerprint.clone(),
        projection_warnings: warnings,
        projected_at: projected_at.to_owned(),
    }
}

fn project_device(
    device: &DeviceDescriptor,
    adapters: &AdapterRegistry,
    warnings: &mut Vec<String>,
) -> ProjectedDevice {
    let vendor = apply_redaction(&device.vendor, &device.id, "vendor", warnings);
    let name = apply_redaction(&device.name, &device.id, "name", warnings);

    // `driver_version` is deliberately NOT projected: it is the field most
    // likely to carry build/serial detail, it is not needed to select a
    // device, and capability advertisement is required to stay minimal.

    let mut projected = ProjectedDevice {
        device_id: device.id.clone(),
        lane_kind: LaneKind::from_compute_class(device.compute_class),
        vendor,
        name,
        compute_class: device.compute_class,
        supported_backends: device.supported_backends.clone(),
        preferred_backend: device.preferred_backend,
        memory: ProjectedMemory {
            model: device.memory.model,
            dedicated_mb: device.memory.dedicated_mb,
            shared_mb: device.memory.shared_mb,
            host_visible_heap_mb: device.memory.host_visible_heap_mb,
            supports_unified_addressing: device.memory.supports_unified_addressing,
            supports_pinned_host: device.memory.supports_pinned_host,
        },
        adapters: adapters.get(&device.id).cloned().unwrap_or_default(),
        fingerprint: String::new(),
    };

    if !device
        .supported_backends
        .contains(&device.preferred_backend)
    {
        warnings.push(format!(
            "device {}: preferred_backend {} is not in supported_backends",
            device.id,
            device.preferred_backend.as_str()
        ));
    }

    for adapter in &projected.adapters {
        if !adapter
            .backends
            .iter()
            .any(|b| device.supported_backends.contains(b))
        {
            warnings.push(format!(
                "device {}: adapter {} declares no backend this device supports",
                device.id, adapter.id
            ));
        }
    }

    projected.fingerprint = projected.compute_fingerprint();
    projected
}

fn apply_redaction(
    value: &str,
    device_id: &str,
    field: &str,
    warnings: &mut Vec<String>,
) -> String {
    match redact::redact_field(value) {
        RedactionOutcome::Clean(s) => s,
        RedactionOutcome::Redacted { value, reason } => {
            warnings.push(format!("device {device_id}: {field} redacted ({reason})"));
            value
        }
    }
}

fn project_cpu(topology: &ComputeTopologySnapshot) -> ProjectedCpu {
    let has_smt = topology
        .cores
        .iter()
        .any(|c| c.logical_processors.len() > 1);

    let mut classes: Vec<Option<u8>> = topology.cores.iter().map(|c| c.efficiency_class).collect();
    classes.sort_unstable();
    classes.dedup();
    let heterogeneous_cores = classes.len() > 1;

    ProjectedCpu {
        arch: topology.arch.clone(),
        processor_packages: topology.processor_packages,
        physical_cores: topology.physical_cores,
        logical_processors: topology.logical_processors,
        processor_groups: topology.processor_groups.len() as u32,
        numa_nodes: topology.numa_nodes.len() as u32,
        has_smt,
        heterogeneous_cores,
        topology_fingerprint: topology.fingerprint(),
    }
}

#[cfg(test)]
mod tests;
