//! 114F.1B projection tests.
//!
//! Fixture coverage follows the design doc's §7 114F.1 exit criteria: CPU-only,
//! integrated GPU, discrete GPU, multiple GPU, legacy GPU, missing runtime, and
//! stale snapshot. Each case is built from the real
//! `forgewire_capability` types rather than hand-written JSON, so a schema
//! change upstream breaks these tests loudly instead of letting a stale fixture
//! pass.

use super::*;
use fabric_topology::{CoreTopology, LogicalProcessorId, NumaNode, ProbeSource, ProcessorGroup};
use forgewire_capability::MemoryDescriptor;

const NOW: &str = "2026-07-28T00:00:00Z";

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

fn device(
    id: &str,
    vendor: &str,
    name: &str,
    class: ComputeClass,
    supported: Vec<BackendKind>,
    preferred: BackendKind,
    memory: MemoryDescriptor,
) -> DeviceDescriptor {
    DeviceDescriptor {
        id: id.into(),
        vendor: vendor.into(),
        name: name.into(),
        driver_version: "551.86".into(),
        compute_class: class,
        supported_backends: supported,
        preferred_backend: preferred,
        memory,
        cuda_compute_capability: None,
    }
}

fn cpu_device() -> DeviceDescriptor {
    device(
        "cpu-0",
        "Intel",
        "Intel(R) Core(TM) i7-6820HQ",
        ComputeClass::CpuOnly,
        vec![BackendKind::CpuSimd],
        BackendKind::CpuSimd,
        MemoryDescriptor {
            model: MemoryModel::SharedSystemRam,
            dedicated_mb: 0,
            shared_mb: 32768,
            host_visible_heap_mb: 32768,
            supports_unified_addressing: false,
            supports_pinned_host: true,
        },
    )
}

fn discrete_gpu() -> DeviceDescriptor {
    device(
        "gpu-0",
        "NVIDIA",
        "NVIDIA GeForce RTX 4090",
        ComputeClass::ModernCuda,
        vec![BackendKind::Cuda, BackendKind::Directml],
        BackendKind::Cuda,
        MemoryDescriptor {
            model: MemoryModel::CudaManaged,
            dedicated_mb: 24576,
            shared_mb: 0,
            host_visible_heap_mb: 3072,
            supports_unified_addressing: false,
            supports_pinned_host: true,
        },
    )
}

fn integrated_gpu() -> DeviceDescriptor {
    device(
        "igpu-0",
        "Intel",
        "Intel(R) HD Graphics 530",
        ComputeClass::IntegratedVulkan,
        vec![BackendKind::Wgpu],
        BackendKind::Wgpu,
        MemoryDescriptor {
            model: MemoryModel::SharedSystemRam,
            dedicated_mb: 0,
            shared_mb: 8192,
            host_visible_heap_mb: 8192,
            supports_unified_addressing: true,
            supports_pinned_host: false,
        },
    )
}

/// The actual Quadro M1200 from the Bonsai experiment — a legacy GPU that is
/// real, still useful, and must not be conflated with a modern card.
fn legacy_gpu() -> DeviceDescriptor {
    device(
        "gpu-m1200",
        "NVIDIA",
        "NVIDIA Quadro M1200",
        ComputeClass::LegacyCuda,
        vec![BackendKind::Cuda, BackendKind::Wgpu],
        BackendKind::Wgpu,
        MemoryDescriptor {
            model: MemoryModel::Dedicated,
            dedicated_mb: 4096,
            shared_mb: 0,
            host_visible_heap_mb: 256,
            supports_unified_addressing: false,
            supports_pinned_host: true,
        },
    )
}

fn matrix(devices: Vec<DeviceDescriptor>, runtimes: Vec<BackendKind>) -> ForgeCoreBackendMatrix {
    ForgeCoreBackendMatrix {
        devices,
        available_runtimes: runtimes,
        ..Default::default()
    }
}

fn snapshot(matrix: ForgeCoreBackendMatrix, age_seconds: Option<u64>) -> BackendMatrixSnapshot {
    BackendMatrixSnapshot::from_matrix(matrix, NOW, age_seconds).expect("valid schema")
}

/// The Precision 5520's real topology: 4 cores, 8 logical, single package,
/// single group — the host every other slice tonight was validated against.
fn precision_topology() -> ComputeTopologySnapshot {
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
        schema_version: fabric_topology::SCHEMA_VERSION,
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
        captured_at: NOW.into(),
    }
}

fn project_fresh(
    snap: &BackendMatrixSnapshot,
    topo: &ComputeTopologySnapshot,
) -> ComputeCapabilityProjection {
    project(
        "DESKTOP-228U8GL",
        snap,
        topo,
        &AdapterRegistry::new(),
        NOW,
        3600,
    )
}

// ---------------------------------------------------------------------------
// Fixture case 1 — CPU-only host
// ---------------------------------------------------------------------------

#[test]
fn cpu_only_host_projects_and_registers_cleanly() {
    let snap = snapshot(
        matrix(vec![cpu_device()], vec![BackendKind::CpuSimd]),
        Some(10),
    );
    let projection = project_fresh(&snap, &precision_topology());

    assert_eq!(projection.devices.len(), 1);
    assert_eq!(projection.devices[0].lane_kind, LaneKind::Cpu);
    assert_eq!(projection.cpu.physical_cores, 4);
    assert_eq!(projection.cpu.logical_processors, 8);
    assert!(projection.cpu.has_smt);
    assert!(!projection.cpu.heterogeneous_cores);
    assert!(
        projection.projection_warnings.is_empty(),
        "unexpected warnings: {:?}",
        projection.projection_warnings
    );
}

// ---------------------------------------------------------------------------
// Fixture case 2/3/4 — iGPU, dGPU, multiple GPUs without conflation
// ---------------------------------------------------------------------------

#[test]
fn mixed_cpu_igpu_dgpu_advertises_all_devices_without_conflation() {
    // This is the design doc's own exit gate for 114F.1.
    let snap = snapshot(
        matrix(
            vec![cpu_device(), integrated_gpu(), discrete_gpu()],
            vec![BackendKind::Cuda, BackendKind::Wgpu, BackendKind::CpuSimd],
        ),
        Some(10),
    );
    let projection = project_fresh(&snap, &precision_topology());

    assert_eq!(projection.devices.len(), 3);
    assert_eq!(projection.devices_of_kind(LaneKind::Cpu).len(), 1);
    assert_eq!(projection.devices_of_kind(LaneKind::Gpu).len(), 2);

    // Each device keeps its own identity, class, and memory model.
    let igpu = projection.device("igpu-0").expect("igpu present");
    let dgpu = projection.device("gpu-0").expect("dgpu present");
    assert_eq!(igpu.compute_class, ComputeClass::IntegratedVulkan);
    assert_eq!(dgpu.compute_class, ComputeClass::ModernCuda);
    assert_eq!(igpu.memory.model, MemoryModel::SharedSystemRam);
    assert_eq!(dgpu.memory.model, MemoryModel::CudaManaged);

    // Distinct fingerprints — conflation would collapse these.
    assert_ne!(igpu.fingerprint, dgpu.fingerprint);
}

#[test]
fn multiple_gpus_receive_distinct_fingerprints() {
    let snap = snapshot(
        matrix(
            vec![discrete_gpu(), legacy_gpu()],
            vec![BackendKind::Cuda, BackendKind::Wgpu],
        ),
        Some(10),
    );
    let projection = project_fresh(&snap, &precision_topology());

    let a = projection.device("gpu-0").unwrap();
    let b = projection.device("gpu-m1200").unwrap();
    assert_ne!(a.fingerprint, b.fingerprint);
    assert_ne!(a.compute_class, b.compute_class);
}

// ---------------------------------------------------------------------------
// Fixture case 5 — legacy GPU
// ---------------------------------------------------------------------------

#[test]
fn legacy_gpu_is_projected_as_gpu_not_downgraded() {
    // The M1200 sustained 22-23 t/s in the Bonsai runs. "Legacy" must not mean
    // "discarded" — it is still a GPU lane.
    let snap = snapshot(
        matrix(vec![legacy_gpu()], vec![BackendKind::Wgpu]),
        Some(10),
    );
    let projection = project_fresh(&snap, &precision_topology());

    let gpu = projection.device("gpu-m1200").expect("legacy gpu present");
    assert_eq!(gpu.lane_kind, LaneKind::Gpu);
    assert_eq!(gpu.compute_class, ComputeClass::LegacyCuda);
    assert_eq!(gpu.preferred_backend, BackendKind::Wgpu);
}

// ---------------------------------------------------------------------------
// Fixture case 6 — missing runtime
// ---------------------------------------------------------------------------

#[test]
fn device_preferring_an_unavailable_runtime_is_still_projected_with_a_warning() {
    // The device advertises CUDA but the host reports no CUDA runtime. The
    // device must still appear (it exists!) and the mismatch must surface
    // rather than being silently dropped.
    let mut gpu = discrete_gpu();
    gpu.supported_backends = vec![BackendKind::Directml];
    gpu.preferred_backend = BackendKind::Cuda; // not in supported_backends

    let snap = snapshot(matrix(vec![gpu], vec![BackendKind::Directml]), Some(10));
    let projection = project_fresh(&snap, &precision_topology());

    assert_eq!(projection.devices.len(), 1);
    assert!(
        projection
            .projection_warnings
            .iter()
            .any(|w| w.contains("preferred_backend")),
        "expected a preferred_backend warning, got {:?}",
        projection.projection_warnings
    );
}

#[test]
fn empty_matrix_warns_but_still_projects_cpu_topology() {
    let snap = snapshot(matrix(vec![], vec![BackendKind::CpuSimd]), Some(10));
    let projection = project_fresh(&snap, &precision_topology());

    assert!(projection.devices.is_empty());
    assert!(projection
        .projection_warnings
        .iter()
        .any(|w| w.contains("no devices")));
    // CPU topology is independent of the matrix and must survive.
    assert_eq!(projection.cpu.physical_cores, 4);
}

// ---------------------------------------------------------------------------
// Fixture case 7 — stale snapshot
// ---------------------------------------------------------------------------

#[test]
fn stale_snapshot_raises_a_warning() {
    let snap = snapshot(
        matrix(vec![cpu_device()], vec![BackendKind::CpuSimd]),
        Some(7200),
    );
    let projection = project_fresh(&snap, &precision_topology()); // max age 3600

    assert!(
        projection
            .projection_warnings
            .iter()
            .any(|w| w.contains("stale")),
        "expected a staleness warning, got {:?}",
        projection.projection_warnings
    );
}

#[test]
fn unknown_snapshot_age_is_treated_as_stale() {
    // Fail closed: a snapshot whose freshness cannot be established must not
    // be assumed current, or removed hardware could be advertised forever.
    let snap = snapshot(matrix(vec![cpu_device()], vec![BackendKind::CpuSimd]), None);
    assert!(snap.is_stale(3600));

    let projection = project_fresh(&snap, &precision_topology());
    assert!(projection
        .projection_warnings
        .iter()
        .any(|w| w.contains("unknown")));
}

#[test]
fn fresh_snapshot_raises_no_staleness_warning() {
    let snap = snapshot(
        matrix(vec![cpu_device()], vec![BackendKind::CpuSimd]),
        Some(60),
    );
    let projection = project_fresh(&snap, &precision_topology());
    assert!(!projection
        .projection_warnings
        .iter()
        .any(|w| w.contains("stale")));
}

// ---------------------------------------------------------------------------
// Redaction integration
// ---------------------------------------------------------------------------

#[test]
fn device_names_containing_paths_are_redacted_with_a_warning() {
    let mut gpu = discrete_gpu();
    gpu.name = r"C:\Users\jerem\gpu-driver.dll".into();

    let snap = snapshot(matrix(vec![gpu], vec![BackendKind::Cuda]), Some(10));
    let projection = project_fresh(&snap, &precision_topology());

    let device = projection.device("gpu-0").unwrap();
    assert_eq!(device.name, "[redacted-path]");
    assert!(projection
        .projection_warnings
        .iter()
        .any(|w| w.contains("redacted")));
}

#[test]
fn driver_version_never_reaches_the_projection() {
    // driver_version is the field most likely to carry build/serial detail and
    // is not needed to select a device, so it is deliberately not projected.
    let snap = snapshot(
        matrix(vec![discrete_gpu()], vec![BackendKind::Cuda]),
        Some(10),
    );
    let projection = project_fresh(&snap, &precision_topology());

    let json = projection.to_canonical_json();
    assert!(
        !json.contains("551.86"),
        "driver_version leaked into the projection: {json}"
    );
    assert!(!json.contains("driver_version"));
}

// ---------------------------------------------------------------------------
// Backend adapters (decision 0005)
// ---------------------------------------------------------------------------

#[test]
fn adapters_attach_to_their_device_and_no_adapter_is_privileged() {
    let mut adapters = AdapterRegistry::new();
    adapters.insert(
        "gpu-0".into(),
        vec![
            BackendAdapter::new("llama.cpp", vec![BackendKind::Cuda]),
            BackendAdapter::new("fc-kernels", vec![BackendKind::Cuda]),
        ],
    );

    let snap = snapshot(
        matrix(vec![discrete_gpu(), cpu_device()], vec![BackendKind::Cuda]),
        Some(10),
    );
    let projection = project(
        "DESKTOP-228U8GL",
        &snap,
        &precision_topology(),
        &adapters,
        NOW,
        3600,
    );

    let gpu = projection.device("gpu-0").unwrap();
    assert_eq!(gpu.adapters.len(), 2);
    // Order is caller-declared, not reordered to favor any implementation.
    assert_eq!(gpu.adapters[0].id, "llama.cpp");
    assert_eq!(gpu.adapters[1].id, "fc-kernels");

    // A device with no registered adapter is still discovered.
    let cpu = projection.device("cpu-0").unwrap();
    assert!(cpu.adapters.is_empty());
}

#[test]
fn adapter_declaring_an_unsupported_backend_warns() {
    let mut adapters = AdapterRegistry::new();
    adapters.insert(
        "cpu-0".into(),
        vec![BackendAdapter::new("llama.cpp", vec![BackendKind::Cuda])],
    );

    let snap = snapshot(
        matrix(vec![cpu_device()], vec![BackendKind::CpuSimd]),
        Some(10),
    );
    let projection = project(
        "DESKTOP-228U8GL",
        &snap,
        &precision_topology(),
        &adapters,
        NOW,
        3600,
    );

    assert!(projection
        .projection_warnings
        .iter()
        .any(|w| w.contains("declares no backend this device supports")));
}

// ---------------------------------------------------------------------------
// Schema, encoding, fingerprint
// ---------------------------------------------------------------------------

#[test]
fn unsupported_matrix_schema_version_is_rejected() {
    let mut m = matrix(vec![cpu_device()], vec![BackendKind::CpuSimd]);
    m.schema_version = "99.0".into();

    let err = BackendMatrixSnapshot::from_matrix(m, NOW, Some(10))
        .expect_err("mismatched schema must be rejected");
    assert!(matches!(err, ProjectionError::UnsupportedSchema { .. }));
}

#[test]
fn malformed_snapshot_json_is_rejected() {
    let err = BackendMatrixSnapshot::from_json("{ not json", NOW, Some(10))
        .expect_err("malformed JSON must be rejected");
    assert!(matches!(err, ProjectionError::MalformedSnapshot(_)));
}

#[test]
fn matrix_round_trips_through_canonical_json() {
    let m = matrix(
        vec![cpu_device(), discrete_gpu()],
        vec![BackendKind::Cuda, BackendKind::CpuSimd],
    );
    let json = m.to_canonical_json();
    let snap = BackendMatrixSnapshot::from_json(&json, NOW, Some(10)).expect("round trip");
    assert_eq!(snap.matrix, m);
    assert_eq!(snap.matrix_fingerprint, m.fingerprint());
}

#[test]
fn projection_fingerprint_is_deterministic() {
    let snap = snapshot(
        matrix(vec![discrete_gpu()], vec![BackendKind::Cuda]),
        Some(10),
    );
    let topo = precision_topology();
    let a = project_fresh(&snap, &topo);
    let b = project_fresh(&snap, &topo);
    assert_eq!(a.fingerprint(), b.fingerprint());
}

#[test]
fn projection_fingerprint_changes_when_a_device_changes() {
    let topo = precision_topology();
    let base = project_fresh(
        &snapshot(
            matrix(vec![discrete_gpu()], vec![BackendKind::Cuda]),
            Some(10),
        ),
        &topo,
    );

    let mut altered_device = discrete_gpu();
    altered_device.memory.dedicated_mb = 12288;
    let altered = project_fresh(
        &snapshot(
            matrix(vec![altered_device], vec![BackendKind::Cuda]),
            Some(10),
        ),
        &topo,
    );

    assert_ne!(base.fingerprint(), altered.fingerprint());
}

#[test]
fn projection_serde_round_trips() {
    let snap = snapshot(
        matrix(vec![cpu_device(), discrete_gpu()], vec![BackendKind::Cuda]),
        Some(10),
    );
    let original = project_fresh(&snap, &precision_topology());
    let json = serde_json::to_string(&original).expect("serialize");
    let restored: ComputeCapabilityProjection = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, restored);
}

// ---------------------------------------------------------------------------
// Health overlay stays separate from static capability (§4.3)
// ---------------------------------------------------------------------------

#[test]
fn health_overlay_is_not_part_of_the_static_projection() {
    // A transient fault must never rewrite hardware identity: the projection's
    // fingerprint must be unaffected by health state entirely.
    let snap = snapshot(
        matrix(vec![discrete_gpu()], vec![BackendKind::Cuda]),
        Some(10),
    );
    let projection = project_fresh(&snap, &precision_topology());
    let before = projection.fingerprint();

    let _overlay = ComputeHealthOverlay::unhealthy(
        "gpu-0",
        HealthState::Quarantined,
        HealthReason::DriverReset,
        NOW,
    );

    assert_eq!(projection.fingerprint(), before);
    assert!(!projection.to_canonical_json().contains("quarantined"));
}

#[test]
fn health_states_gate_work_admission_correctly() {
    let admitting = [
        HealthState::Available,
        HealthState::Busy,
        HealthState::Degraded,
    ];
    let refusing = [
        HealthState::Cooling,
        HealthState::Drained,
        HealthState::Quarantined,
        HealthState::Unavailable,
    ];

    for state in admitting {
        let o = ComputeHealthOverlay {
            device_id: "gpu-0".into(),
            state,
            reason: None,
            detail: None,
            observed_at: NOW.into(),
        };
        assert!(o.admits_work(), "{state:?} should admit work");
    }
    for state in refusing {
        let o = ComputeHealthOverlay {
            device_id: "gpu-0".into(),
            state,
            reason: None,
            detail: None,
            observed_at: NOW.into(),
        };
        assert!(!o.admits_work(), "{state:?} should refuse work");
    }
}

#[test]
fn lane_kind_derives_from_compute_class_without_a_second_vocabulary() {
    assert_eq!(
        LaneKind::from_compute_class(ComputeClass::CpuOnly),
        LaneKind::Cpu
    );
    assert_eq!(
        LaneKind::from_compute_class(ComputeClass::OpenvinoNpu),
        LaneKind::Accelerator
    );
    for gpu_class in [
        ComputeClass::ModernCuda,
        ComputeClass::LegacyCuda,
        ComputeClass::DiscreteVulkan,
        ComputeClass::IntegratedVulkan,
        ComputeClass::Metal,
        ComputeClass::DirectmlOnly,
    ] {
        assert_eq!(LaneKind::from_compute_class(gpu_class), LaneKind::Gpu);
    }
}

#[test]
fn topology_probe_warnings_are_carried_into_the_projection() {
    let mut topo = precision_topology();
    topo.probe_warnings = vec!["missing topology attributes for logical cpu 6".into()];

    let snap = snapshot(
        matrix(vec![cpu_device()], vec![BackendKind::CpuSimd]),
        Some(10),
    );
    let projection = project_fresh(&snap, &topo);

    assert!(
        projection
            .projection_warnings
            .iter()
            .any(|w| w.starts_with("cpu topology:")),
        "topology warnings must not be dropped: {:?}",
        projection.projection_warnings
    );
}
