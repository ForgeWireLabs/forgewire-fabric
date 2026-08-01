//! Fallback probe for platforms this crate does not yet implement (e.g.
//! macOS). Returns a minimal, honestly-typed snapshot rather than a
//! fabricated topology — per the 114F design doc's non-goal: never claim
//! validation on a platform without physical hardware evidence.

use crate::{ComputeTopologySnapshot, ProbeSource, SCHEMA_VERSION};

pub(crate) fn probe(host_id: &str, captured_at: &str) -> ComputeTopologySnapshot {
    ComputeTopologySnapshot {
        schema_version: SCHEMA_VERSION,
        host_id: host_id.to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        processor_packages: 0,
        physical_cores: 0,
        logical_processors: 0,
        processor_groups: Vec::new(),
        numa_nodes: Vec::new(),
        cores: Vec::new(),
        probe_source: ProbeSource::Unsupported,
        probe_warnings: vec![format!(
            "no CPU topology probe implemented for target_os={}; \
             not validated on physical hardware, per 114F non-goals",
            std::env::consts::OS
        )],
        captured_at: captured_at.to_owned(),
    }
}
