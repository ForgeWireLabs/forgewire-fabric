//! Linux CPU topology probe.
//!
//! The parsing logic (`topology_from_raw_cpus`) is a pure function over an
//! in-memory representation of `/sys/devices/system/cpu/cpu*/topology/*`, so
//! it is fully unit-tested on any host — this crate is developed and CI'd on
//! Windows, with no live Linux host available for this slice. Only the thin
//! filesystem-reading wrapper (`probe`) is Linux-specific and untestable
//! here; it is deliberately kept small and delegates all logic to the pure
//! function below.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::{
    ComputeTopologySnapshot, CoreTopology, LogicalProcessorId, NumaNode, ProbeSource,
    ProcessorGroup, SCHEMA_VERSION,
};

/// One logical CPU's raw topology facts, as read from
/// `/sys/devices/system/cpu/cpuN/topology/{physical_package_id,core_id}`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RawCpu {
    pub logical_index: u32,
    pub package_id: u32,
    pub core_id: u32,
}

/// Build a `ComputeTopologySnapshot` from raw per-CPU facts and NUMA
/// membership (`node_id -> [logical_index, ...]`). Linux has no processor
/// groups, so this always emits exactly one `ProcessorGroup { group: 0, .. }`.
pub(crate) fn topology_from_raw_cpus(
    host_id: &str,
    captured_at: &str,
    cpus: &[RawCpu],
    numa_membership: &[(u32, Vec<u32>)],
    warnings: Vec<String>,
) -> ComputeTopologySnapshot {
    // Group logical CPUs by (package_id, core_id) — SMT/HT siblings share a
    // core, so this is equivalent to (and simpler than) parsing
    // thread_siblings_list.
    let mut by_core: BTreeMap<(u32, u32), Vec<u32>> = BTreeMap::new();
    let mut packages: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for cpu in cpus {
        packages.insert(cpu.package_id);
        by_core
            .entry((cpu.package_id, cpu.core_id))
            .or_default()
            .push(cpu.logical_index);
    }

    let mut cores: Vec<CoreTopology> = by_core
        .into_iter()
        .map(|((package_id, core_id), mut logical_indices)| {
            logical_indices.sort_unstable();
            CoreTopology {
                core_id,
                package_id,
                logical_processors: logical_indices
                    .into_iter()
                    .map(|index| LogicalProcessorId::new(0, index))
                    .collect(),
                // Linux exposes heterogeneous perf/efficiency class via
                // cpu_capacity/cppc, not implemented in this slice.
                efficiency_class: None,
            }
        })
        .collect();
    cores.sort_by_key(|c| (c.package_id, c.core_id));

    let numa_nodes: Vec<NumaNode> = numa_membership
        .iter()
        .map(|(node_id, members)| {
            let mut sorted = members.clone();
            sorted.sort_unstable();
            NumaNode {
                node_id: *node_id,
                logical_processors: sorted
                    .into_iter()
                    .map(|index| LogicalProcessorId::new(0, index))
                    .collect(),
            }
        })
        .collect();

    ComputeTopologySnapshot {
        schema_version: SCHEMA_VERSION,
        host_id: host_id.to_owned(),
        os: "linux".to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        processor_packages: packages.len() as u32,
        physical_cores: cores.len() as u32,
        logical_processors: cpus.len() as u32,
        processor_groups: vec![ProcessorGroup {
            group: 0,
            active_processor_count: cpus.len() as u32,
        }],
        numa_nodes,
        cores,
        probe_source: ProbeSource::LinuxProcfsAndSysfs,
        probe_warnings: warnings,
        captured_at: captured_at.to_owned(),
    }
}

/// Read `/sys/devices/system/cpu/cpu*/topology/*` and
/// `/sys/devices/system/node/node*/cpulist` on a real Linux host. Not
/// exercised by this crate's tests (no Linux host available in this
/// session) — kept intentionally thin, with all real logic in the pure
/// function above.
pub(crate) fn probe(host_id: &str, captured_at: &str) -> ComputeTopologySnapshot {
    let mut warnings = Vec::new();
    let cpus = read_cpus(&mut warnings);
    let numa_membership = read_numa_membership(&mut warnings);
    topology_from_raw_cpus(host_id, captured_at, &cpus, &numa_membership, warnings)
}

fn read_cpus(warnings: &mut Vec<String>) -> Vec<RawCpu> {
    let cpu_root = Path::new("/sys/devices/system/cpu");
    let Ok(entries) = fs::read_dir(cpu_root) else {
        warnings.push(format!("could not read {}", cpu_root.display()));
        return Vec::new();
    };

    let mut cpus = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(index_str) = name.strip_prefix("cpu") else {
            continue;
        };
        let Ok(logical_index) = index_str.parse::<u32>() else {
            continue;
        };
        let topo_dir = entry.path().join("topology");
        let package_id = read_u32_file(&topo_dir.join("physical_package_id"));
        let core_id = read_u32_file(&topo_dir.join("core_id"));
        match (package_id, core_id) {
            (Some(package_id), Some(core_id)) => cpus.push(RawCpu {
                logical_index,
                package_id,
                core_id,
            }),
            _ => warnings.push(format!(
                "missing topology attributes for logical cpu {logical_index}"
            )),
        }
    }
    cpus.sort_by_key(|c| c.logical_index);
    cpus
}

fn read_numa_membership(warnings: &mut Vec<String>) -> Vec<(u32, Vec<u32>)> {
    let node_root = Path::new("/sys/devices/system/node");
    let Ok(entries) = fs::read_dir(node_root) else {
        warnings.push(format!(
            "could not read {} (no NUMA info available)",
            node_root.display()
        ));
        return Vec::new();
    };

    let mut nodes = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(id_str) = name.strip_prefix("node") else {
            continue;
        };
        let Ok(node_id) = id_str.parse::<u32>() else {
            continue;
        };
        let cpulist_path = entry.path().join("cpulist");
        match fs::read_to_string(&cpulist_path) {
            Ok(contents) => nodes.push((node_id, parse_cpu_list(contents.trim()))),
            Err(_) => warnings.push(format!("could not read {}", cpulist_path.display())),
        }
    }
    nodes.sort_by_key(|(id, _)| *id);
    nodes
}

/// Parse a Linux CPU list string such as `"0-3,8,10-11"` into individual
/// logical CPU indices.
fn parse_cpu_list(spec: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (start.parse::<u32>(), end.parse::<u32>()) {
                out.extend(start..=end);
            }
        } else if let Ok(value) = part.parse::<u32>() {
            out.push(value);
        }
    }
    out
}

fn read_u32_file(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_ranges_and_singletons() {
        assert_eq!(parse_cpu_list("0-3,8,10-11"), vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(parse_cpu_list("5"), vec![5]);
        assert_eq!(parse_cpu_list(""), Vec::<u32>::new());
    }

    fn precision_5520_like_cpus() -> Vec<RawCpu> {
        // Mirrors the actual Precision 5520 topology already documented in
        // the Bonsai handoff: 4 physical cores, 8 logical processors, single
        // package, HT pairs (0,1) (2,3) (4,5) (6,7).
        (0..8u32)
            .map(|logical_index| RawCpu {
                logical_index,
                package_id: 0,
                core_id: logical_index / 2,
            })
            .collect()
    }

    #[test]
    fn groups_smt_siblings_by_core() {
        let snapshot = topology_from_raw_cpus(
            "test-host",
            "2026-07-28T00:00:00Z",
            &precision_5520_like_cpus(),
            &[],
            Vec::new(),
        );
        assert_eq!(snapshot.processor_packages, 1);
        assert_eq!(snapshot.physical_cores, 4);
        assert_eq!(snapshot.logical_processors, 8);
        assert_eq!(snapshot.processor_groups.len(), 1);
        assert_eq!(snapshot.processor_groups[0].active_processor_count, 8);

        let core0 = &snapshot.cores[0];
        assert_eq!(core0.core_id, 0);
        assert_eq!(
            core0.logical_processors,
            vec![LogicalProcessorId::new(0, 0), LogicalProcessorId::new(0, 1)]
        );
    }

    #[test]
    fn numa_membership_maps_to_logical_processor_ids() {
        let snapshot = topology_from_raw_cpus(
            "test-host",
            "2026-07-28T00:00:00Z",
            &precision_5520_like_cpus(),
            &[(0, vec![0, 1, 2, 3, 4, 5, 6, 7])],
            Vec::new(),
        );
        assert_eq!(snapshot.numa_nodes.len(), 1);
        assert_eq!(snapshot.numa_nodes[0].node_id, 0);
        assert_eq!(snapshot.numa_nodes[0].logical_processors.len(), 8);
    }

    #[test]
    fn snapshot_fingerprint_is_stable_across_rebuilds() {
        let a = topology_from_raw_cpus(
            "test-host",
            "2026-07-28T00:00:00Z",
            &precision_5520_like_cpus(),
            &[(0, vec![0, 1, 2, 3, 4, 5, 6, 7])],
            Vec::new(),
        );
        let b = topology_from_raw_cpus(
            "test-host",
            "2026-07-28T00:00:00Z",
            &precision_5520_like_cpus(),
            &[(0, vec![0, 1, 2, 3, 4, 5, 6, 7])],
            Vec::new(),
        );
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    /// Live validation of `probe()` itself (real `/sys` reads, not the pure
    /// function above) against this actual host — a WSL2 Debian instance
    /// running on the same Dell Precision 5520 the Windows probe's live
    /// test validates against. Independently confirmed via manual `/sys`
    /// inspection before this test was written: cpu0/1, cpu2/3, cpu4/5,
    /// cpu6/7 each share a core_id (0-3 respectively), all physical_package_id
    /// 0, and /sys/devices/system/node/node0/cpulist is "0-7".
    #[test]
    fn live_probe_matches_this_host() {
        let snapshot = super::probe("live-wsl-host-test", "2026-07-28T00:00:00Z");
        assert!(
            snapshot.probe_warnings.is_empty(),
            "unexpected probe warnings: {:?}",
            snapshot.probe_warnings
        );
        assert_eq!(snapshot.processor_packages, 1);
        assert_eq!(snapshot.physical_cores, 4);
        assert_eq!(snapshot.logical_processors, 8);
        assert_eq!(snapshot.numa_nodes.len(), 1);
        assert_eq!(snapshot.numa_nodes[0].logical_processors.len(), 8);
        for core in &snapshot.cores {
            assert_eq!(core.logical_processors.len(), 2, "expected HT pairs");
        }
    }
}
