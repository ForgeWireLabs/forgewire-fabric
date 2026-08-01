//! Golden canonical-encoding fixture, mirroring the pattern used by
//! `fc-capability`'s `backend_matrix.canonical.txt`/`.fingerprint.txt`
//! parity fixtures: a fixed, hand-built snapshot's canonical JSON and
//! fingerprint are checked into `tests/fixtures/` and compared byte-for-byte
//! on every run. Unlike `fc-capability` (which checks Rust/Python parity),
//! this crate has no parallel implementation to compare against yet — this
//! is a regression fixture, guarding the canonical encoding and fingerprint
//! against silent, unintended changes (field reordering, formatting drift).
//!
//! Built entirely from the public struct API (not the platform-gated
//! `windows`/`linux` probe modules) so it runs identically on every OS.

use fabric_topology::{
    ComputeTopologySnapshot, CoreTopology, LogicalProcessorId, NumaNode, ProbeSource,
    ProcessorGroup, SCHEMA_VERSION,
};

/// A fixed snapshot matching the Dell Precision 5520's real topology (4
/// physical cores, 8 logical processors, single package, single processor
/// group, HT pairs (0,1) (2,3) (4,5) (6,7)) — already documented in the
/// Bonsai handoff and confirmed live by this crate's Windows probe test.
fn precision_5520_fixture() -> ComputeTopologySnapshot {
    let cores: Vec<CoreTopology> = (0..4u32)
        .map(|core_id| CoreTopology {
            core_id,
            package_id: 0,
            logical_processors: vec![
                LogicalProcessorId::new(0, core_id * 2),
                LogicalProcessorId::new(0, core_id * 2 + 1),
            ],
            efficiency_class: Some(0),
        })
        .collect();

    ComputeTopologySnapshot {
        schema_version: SCHEMA_VERSION,
        host_id: "DESKTOP-228U8GL".into(),
        os: "windows".into(),
        arch: "x86_64".into(),
        processor_packages: 1,
        physical_cores: 4,
        logical_processors: 8,
        processor_groups: vec![ProcessorGroup {
            group: 0,
            active_processor_count: 8,
        }],
        numa_nodes: vec![NumaNode {
            node_id: 0,
            logical_processors: (0..8u32).map(|i| LogicalProcessorId::new(0, i)).collect(),
        }],
        cores,
        probe_source: ProbeSource::WindowsLogicalProcessorInformationEx,
        probe_warnings: Vec::new(),
        captured_at: "2026-07-28T00:00:00Z".into(),
    }
}

#[test]
fn canonical_json_matches_checked_in_fixture() {
    let expected = include_str!("fixtures/precision_5520.canonical.txt");
    let actual = precision_5520_fixture().to_canonical_json();
    assert_eq!(actual, expected, "canonical JSON encoding drifted");
}

#[test]
fn fingerprint_matches_checked_in_fixture() {
    let expected = include_str!("fixtures/precision_5520.fingerprint.txt").trim();
    let actual = precision_5520_fixture().fingerprint();
    assert_eq!(actual, expected, "fingerprint drifted");
}

#[test]
fn fingerprint_is_deterministic_across_independent_instances() {
    assert_eq!(
        precision_5520_fixture().fingerprint(),
        precision_5520_fixture().fingerprint()
    );
}

#[test]
fn serde_round_trip_preserves_all_fields() {
    let original = precision_5520_fixture();
    let json = serde_json::to_string(&original).expect("serialize");
    let restored: ComputeTopologySnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, restored);
}
