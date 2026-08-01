//! Portable CPU topology discovery for ForgeWire Loom compute lanes.
//!
//! This crate is 114F's `ComputeTopologySnapshot` contract (114F.1A). It is a
//! host-local *supplement* to the frozen `ForgeCoreBackendMatrix` owned by
//! work item 108 — it does not describe GPUs, accelerators, or backend
//! kinds, and it introduces no competing device schema. See
//! `work/active/114-forgewire-fabric/114F-universal-compute-capability-lanes.md`
//! §6.1 for the target contract this crate implements, and
//! `114F-0-contract-inventory.md` §12 for why this is the second coded slice.
//!
//! Logical processors are addressed as `(group, index)` pairs rather than a
//! bare integer or bitmask. A single 64-bit mask cannot represent Windows
//! processor groups or hosts with more than 64 logical processors, and this
//! crate must never silently truncate either.
//!
//! This crate only *discovers* topology. It does not set CPU affinity or
//! enforce placement — that is 114F.3B, layered on top of this contract.

#![deny(rust_2018_idioms)]

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
mod unsupported;
#[cfg(target_os = "windows")]
mod windows;

/// Current wire schema version for [`ComputeTopologySnapshot`].
pub const SCHEMA_VERSION: u32 = 1;

/// A single logical processor, addressed by Windows processor group and
/// in-group index. Non-Windows probes always report `group: 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LogicalProcessorId {
    pub group: u16,
    pub index: u32,
}

impl LogicalProcessorId {
    #[must_use]
    pub fn new(group: u16, index: u32) -> Self {
        Self { group, index }
    }

    fn to_canonical_value(self) -> Value {
        let mut map: Map<String, Value> = Map::new();
        map.insert("group".into(), Value::from(self.group));
        map.insert("index".into(), Value::from(self.index));
        Value::Object(map)
    }
}

/// One physical core and the logical processors (SMT/HT siblings) it exposes.
/// `logical_processors.len() > 1` is how a hyper-threaded/SMT core is
/// represented — there is no separate, duplicated "sibling list" field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreTopology {
    pub core_id: u32,
    pub package_id: u32,
    pub logical_processors: Vec<LogicalProcessorId>,
    /// Heterogeneous performance/efficiency-core class, when the platform
    /// reports it (e.g. Windows `EfficiencyClass`). `None` when the platform
    /// has no such concept or the probe could not determine it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub efficiency_class: Option<u8>,
}

impl CoreTopology {
    fn to_canonical_value(&self) -> Value {
        let mut map: Map<String, Value> = Map::new();
        map.insert("core_id".into(), Value::from(self.core_id));
        map.insert("package_id".into(), Value::from(self.package_id));
        map.insert(
            "logical_processors".into(),
            Value::Array(
                self.logical_processors
                    .iter()
                    .copied()
                    .map(LogicalProcessorId::to_canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "efficiency_class".into(),
            self.efficiency_class
                .map_or(Value::Null, |v| Value::from(v)),
        );
        Value::Object(map)
    }
}

/// A Windows processor group and how many logical processors are active in
/// it. Always exactly one entry, `{ group: 0, .. }`, on non-Windows hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorGroup {
    pub group: u16,
    pub active_processor_count: u32,
}

impl ProcessorGroup {
    fn to_canonical_value(self) -> Value {
        let mut map: Map<String, Value> = Map::new();
        map.insert("group".into(), Value::from(self.group));
        map.insert(
            "active_processor_count".into(),
            Value::from(self.active_processor_count),
        );
        Value::Object(map)
    }
}

/// A NUMA node and the logical processors local to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaNode {
    pub node_id: u32,
    pub logical_processors: Vec<LogicalProcessorId>,
}

impl NumaNode {
    fn to_canonical_value(&self) -> Value {
        let mut map: Map<String, Value> = Map::new();
        map.insert("node_id".into(), Value::from(self.node_id));
        map.insert(
            "logical_processors".into(),
            Value::Array(
                self.logical_processors
                    .iter()
                    .copied()
                    .map(LogicalProcessorId::to_canonical_value)
                    .collect(),
            ),
        );
        Value::Object(map)
    }
}

/// Which probe produced a snapshot. A snapshot with `Unsupported` is still a
/// valid, honestly-typed result — never a fabricated topology for a platform
/// this crate cannot yet probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeSource {
    WindowsLogicalProcessorInformationEx,
    LinuxProcfsAndSysfs,
    Unsupported,
}

impl ProbeSource {
    fn as_str(self) -> &'static str {
        match self {
            ProbeSource::WindowsLogicalProcessorInformationEx => {
                "windows_logical_processor_information_ex"
            }
            ProbeSource::LinuxProcfsAndSysfs => "linux_procfs_and_sysfs",
            ProbeSource::Unsupported => "unsupported",
        }
    }
}

/// A host-local CPU topology snapshot. Supplements, but never replaces or
/// forks, the frozen `ForgeCoreBackendMatrix` owned by work item 108.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComputeTopologySnapshot {
    pub schema_version: u32,
    pub host_id: String,
    pub os: String,
    pub arch: String,
    pub processor_packages: u32,
    pub physical_cores: u32,
    pub logical_processors: u32,
    pub processor_groups: Vec<ProcessorGroup>,
    pub numa_nodes: Vec<NumaNode>,
    pub cores: Vec<CoreTopology>,
    pub probe_source: ProbeSource,
    #[serde(default)]
    pub probe_warnings: Vec<String>,
    pub captured_at: String,
}

impl ComputeTopologySnapshot {
    /// Build a canonical `serde_json::Value` for hashing/serialization.
    /// `serde_json::Map` is BTreeMap-backed by default, so key order here
    /// never matters — only the explicit array orderings below do.
    fn to_canonical_value(&self) -> Value {
        let mut map: Map<String, Value> = Map::new();
        map.insert("schema_version".into(), Value::from(self.schema_version));
        map.insert("host_id".into(), Value::String(self.host_id.clone()));
        map.insert("os".into(), Value::String(self.os.clone()));
        map.insert("arch".into(), Value::String(self.arch.clone()));
        map.insert(
            "processor_packages".into(),
            Value::from(self.processor_packages),
        );
        map.insert("physical_cores".into(), Value::from(self.physical_cores));
        map.insert(
            "logical_processors".into(),
            Value::from(self.logical_processors),
        );
        map.insert(
            "processor_groups".into(),
            Value::Array(
                self.processor_groups
                    .iter()
                    .copied()
                    .map(ProcessorGroup::to_canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "numa_nodes".into(),
            Value::Array(
                self.numa_nodes
                    .iter()
                    .map(NumaNode::to_canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "cores".into(),
            Value::Array(
                self.cores
                    .iter()
                    .map(CoreTopology::to_canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "probe_source".into(),
            Value::String(self.probe_source.as_str().to_owned()),
        );
        map.insert(
            "probe_warnings".into(),
            Value::Array(
                self.probe_warnings
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        map.insert(
            "captured_at".into(),
            Value::String(self.captured_at.clone()),
        );
        Value::Object(map)
    }

    /// Canonical JSON encoding (sorted keys, two-space indent) — the same
    /// convention `ForgeCoreBackendMatrix` uses in `fc-capability`, so
    /// snapshot fingerprints are reproducible across processes and hosts.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string_pretty(&self.to_canonical_value())
            .expect("canonical compute topology serializes")
    }

    /// Stable SHA-256 fingerprint of the canonical JSON encoding.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let canonical = self.to_canonical_json();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Capture a topology snapshot for the current host using the appropriate
/// platform probe. `host_id` should be a stable host identifier (e.g. the
/// hostname) supplied by the caller — this crate does not itself decide
/// runner/host identity.
#[must_use]
pub fn capture(host_id: &str, captured_at: &str) -> ComputeTopologySnapshot {
    #[cfg(target_os = "windows")]
    {
        windows::probe(host_id, captured_at)
    }
    #[cfg(target_os = "linux")]
    {
        linux::probe(host_id, captured_at)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        unsupported::probe(host_id, captured_at)
    }
}
