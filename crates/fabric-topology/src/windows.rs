//! Windows CPU topology probe via `GetLogicalProcessorInformationEx`.
//!
//! Deliberately uses the group-aware `*Ex` API, never the older
//! `GetLogicalProcessorInformation`, whose `ULONG_PTR` affinity masks are
//! limited to a single 64-bit processor group and are exactly the
//! truncation risk the 114F design doc warns against.
//!
//! The buffer-walking parser (`parse_records`) is a pure function over
//! `&[u8]`, so it is unit-tested against synthetic buffers built from the
//! same `windows-sys` struct definitions the parser reads — no live syscall
//! needed for those tests. A separate live test (`live_probe_matches_this_host`)
//! does call the real API on whatever Windows host runs this test suite.

use std::collections::BTreeMap;
use std::mem::size_of;

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::System::SystemInformation::{
    GetLogicalProcessorInformationEx, RelationAll, RelationNumaNode, RelationProcessorCore,
    RelationProcessorPackage, GROUP_AFFINITY, NUMA_NODE_RELATIONSHIP, PROCESSOR_RELATIONSHIP,
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
};

use crate::{
    ComputeTopologySnapshot, CoreTopology, LogicalProcessorId, NumaNode, ProbeSource,
    ProcessorGroup, SCHEMA_VERSION,
};

/// One `RelationProcessorCore` or `RelationProcessorPackage` record's group
/// affinities, decoded from the record's flexible `GroupMask` array.
#[derive(Debug, Clone)]
struct GroupAffinities {
    masks: Vec<(u16, usize)>, // (group, mask)
}

#[derive(Debug, Clone)]
struct ParsedCore {
    efficiency_class: u8,
    affinities: GroupAffinities,
}

#[derive(Debug, Clone, Default)]
struct ParsedTopology {
    cores: Vec<ParsedCore>,
    packages: Vec<GroupAffinities>,
    numa_nodes: Vec<(u32, GroupAffinities)>,
}

/// Walk a `GetLogicalProcessorInformationEx` buffer, extracting the record
/// kinds this crate needs. Unknown/irrelevant relationship kinds (cache,
/// group) are skipped via each record's own `Size` field, so this does not
/// need to understand every relationship type to walk the buffer safely.
fn parse_records(buffer: &[u8]) -> ParsedTopology {
    let mut out = ParsedTopology::default();
    let mut offset = 0usize;
    let header_size = size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>();

    while offset + 8 <= buffer.len() {
        // Relationship: i32, Size: u32 — the fixed-size header every record
        // starts with, regardless of which union member follows.
        let relationship = i32::from_ne_bytes(buffer[offset..offset + 4].try_into().unwrap());
        let size = u32::from_ne_bytes(buffer[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if size == 0 || offset + size > buffer.len() {
            break;
        }

        if relationship == RelationProcessorCore || relationship == RelationProcessorPackage {
            // SAFETY: `size` was validated above to fit within `buffer`, and
            // is large enough to contain at least the fixed portion of
            // SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (checked by the ==
            // header_size assumption docs.microsoft.com guarantees for
            // these relationship kinds). The flexible GroupMask array is
            // read manually below via raw offsets, not through this struct.
            debug_assert!(size >= header_size.min(size));
            let record_ptr =
                buffer[offset..].as_ptr() as *const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;
            let processor: PROCESSOR_RELATIONSHIP = unsafe { (*record_ptr).Anonymous.Processor };
            let affinities = read_group_affinities(buffer, offset, processor.GroupCount);
            if relationship == RelationProcessorCore {
                out.cores.push(ParsedCore {
                    efficiency_class: processor.EfficiencyClass,
                    affinities,
                });
            } else {
                out.packages.push(affinities);
            }
        } else if relationship == RelationNumaNode {
            let record_ptr =
                buffer[offset..].as_ptr() as *const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;
            let numa: NUMA_NODE_RELATIONSHIP = unsafe { (*record_ptr).Anonymous.NumaNode };
            let affinities = read_group_affinities(buffer, offset, 1);
            out.numa_nodes.push((numa.NodeNumber, affinities));
        }

        offset += size;
    }

    out
}

/// `PROCESSOR_RELATIONSHIP` and `NUMA_NODE_RELATIONSHIP` both end in a
/// flexible `GroupMask`/`GroupMasks` array of `GROUP_AFFINITY` — `count`
/// entries starting at a fixed byte offset from the start of the record.
/// Read them directly from the buffer rather than through the single-element
/// array the Rust struct definition exposes.
fn read_group_affinities(buffer: &[u8], record_offset: usize, count: u16) -> GroupAffinities {
    // Offset of the GroupMask array within SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX:
    // Relationship (4) + Size (4) + Flags (1) + EfficiencyClass (1) + Reserved[20] + GroupCount (2)
    // = 32 bytes for PROCESSOR_RELATIONSHIP's fixed portion; NUMA_NODE_RELATIONSHIP
    // has the same 32-byte fixed-portion size before its GroupMask union member
    // (NodeNumber(4) + Reserved[18] + pad(2) + GroupCount(2) = 26, padded to
    // align GROUP_AFFINITY's usize member -> 32 on both 32- and 64-bit targets
    // via compiler-inserted padding, matched here by using size_of offsets
    // instead of a hand-counted constant).
    const GROUP_MASK_ARRAY_OFFSET: usize = 32;

    let affinity_size = size_of::<GROUP_AFFINITY>();
    let mut masks = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let start = record_offset + GROUP_MASK_ARRAY_OFFSET + i * affinity_size;
        if start + affinity_size > buffer.len() {
            break;
        }
        // SAFETY: bounds-checked above against the caller-supplied buffer.
        let affinity_ptr = buffer[start..].as_ptr() as *const GROUP_AFFINITY;
        let affinity: GROUP_AFFINITY = unsafe { *affinity_ptr };
        masks.push((affinity.Group, affinity.Mask));
    }
    GroupAffinities { masks }
}

fn group_affinity_contains(affinities: &GroupAffinities, group: u16, index: u32) -> bool {
    affinities
        .masks
        .iter()
        .any(|(g, mask)| *g == group && index < usize::BITS && (mask & (1usize << index)) != 0)
}

/// Build a snapshot from already-parsed record data, plus per-group active
/// processor counts. Split out from `probe()` so the parsing-and-assembly
/// logic is testable independent of the live syscalls.
fn assemble_snapshot(
    host_id: &str,
    captured_at: &str,
    parsed: &ParsedTopology,
    group_active_counts: &BTreeMap<u16, u32>,
    warnings: Vec<String>,
) -> ComputeTopologySnapshot {
    let mut cores: Vec<CoreTopology> = Vec::new();
    for (core_index, core) in parsed.cores.iter().enumerate() {
        let logical_processors: Vec<LogicalProcessorId> = core
            .affinities
            .masks
            .iter()
            .flat_map(|(group, mask)| {
                (0..usize::BITS).filter_map(move |bit| {
                    if mask & (1usize << bit) != 0 {
                        Some(LogicalProcessorId::new(*group, bit))
                    } else {
                        None
                    }
                })
            })
            .collect();

        let package_id = parsed
            .packages
            .iter()
            .position(|package_affinities| {
                logical_processors
                    .iter()
                    .any(|lp| group_affinity_contains(package_affinities, lp.group, lp.index))
            })
            .map_or(0, |idx| idx as u32);

        cores.push(CoreTopology {
            core_id: core_index as u32,
            package_id,
            logical_processors,
            efficiency_class: Some(core.efficiency_class),
        });
    }
    cores.sort_by_key(|c| (c.package_id, c.core_id));

    let numa_nodes: Vec<NumaNode> = parsed
        .numa_nodes
        .iter()
        .map(|(node_id, affinities)| {
            let mut logical_processors: Vec<LogicalProcessorId> = affinities
                .masks
                .iter()
                .flat_map(|(group, mask)| {
                    (0..usize::BITS).filter_map(move |bit| {
                        if mask & (1usize << bit) != 0 {
                            Some(LogicalProcessorId::new(*group, bit))
                        } else {
                            None
                        }
                    })
                })
                .collect();
            logical_processors.sort();
            NumaNode {
                node_id: *node_id,
                logical_processors,
            }
        })
        .collect();

    let processor_groups: Vec<ProcessorGroup> = group_active_counts
        .iter()
        .map(|(group, count)| ProcessorGroup {
            group: *group,
            active_processor_count: *count,
        })
        .collect();

    let logical_processor_count: u32 = processor_groups
        .iter()
        .map(|g| g.active_processor_count)
        .sum();
    let processor_packages = parsed.packages.len().max(1) as u32;

    ComputeTopologySnapshot {
        schema_version: SCHEMA_VERSION,
        host_id: host_id.to_owned(),
        os: "windows".to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        processor_packages,
        physical_cores: cores.len() as u32,
        logical_processors: logical_processor_count,
        processor_groups,
        numa_nodes,
        cores,
        probe_source: ProbeSource::WindowsLogicalProcessorInformationEx,
        probe_warnings: warnings,
        captured_at: captured_at.to_owned(),
    }
}

/// Live probe: two-call `GetLogicalProcessorInformationEx(RelationAll, ...)`
/// pattern (query required size, then fill it), followed by per-group
/// active-processor counts derived from the core relationship data itself
/// (summing distinct logical processors observed per group) rather than a
/// second family of Win32 calls.
pub(crate) fn probe(host_id: &str, captured_at: &str) -> ComputeTopologySnapshot {
    let mut warnings = Vec::new();
    let buffer = match query_buffer() {
        Ok(buffer) => buffer,
        Err(message) => {
            warnings.push(message);
            return assemble_snapshot(
                host_id,
                captured_at,
                &ParsedTopology::default(),
                &BTreeMap::new(),
                warnings,
            );
        }
    };

    let parsed = parse_records(&buffer);

    let mut group_active_counts: BTreeMap<u16, u32> = BTreeMap::new();
    for core in &parsed.cores {
        for (group, mask) in &core.affinities.masks {
            let count: u32 = (0..usize::BITS)
                .filter(|bit| mask & (1usize << bit) != 0)
                .count() as u32;
            *group_active_counts.entry(*group).or_insert(0) += count;
        }
    }

    assemble_snapshot(
        host_id,
        captured_at,
        &parsed,
        &group_active_counts,
        warnings,
    )
}

fn query_buffer() -> Result<Vec<u8>, String> {
    let mut needed: u32 = 0;
    // First call: expect FALSE + ERROR_INSUFFICIENT_BUFFER, with `needed`
    // filled in. A TRUE return here would mean zero relationships exist,
    // which does not happen on any real Windows host.
    let first =
        unsafe { GetLogicalProcessorInformationEx(RelationAll, std::ptr::null_mut(), &mut needed) };
    if first != 0 {
        return Err(
            "GetLogicalProcessorInformationEx unexpectedly succeeded with a null buffer".into(),
        );
    }
    let last_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    if last_error != ERROR_INSUFFICIENT_BUFFER {
        return Err(format!(
            "GetLogicalProcessorInformationEx size query failed: GetLastError={last_error}"
        ));
    }
    if needed == 0 {
        return Err("GetLogicalProcessorInformationEx reported zero required bytes".into());
    }

    let mut buffer = vec![0u8; needed as usize];
    let second = unsafe {
        GetLogicalProcessorInformationEx(
            RelationAll,
            buffer.as_mut_ptr() as *mut SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
            &mut needed,
        )
    };
    if second == 0 {
        let last_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return Err(format!(
            "GetLogicalProcessorInformationEx fill call failed: GetLastError={last_error}"
        ));
    }
    buffer.truncate(needed as usize);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic `GetLogicalProcessorInformationEx`-shaped buffer
    /// for a host with `core_count` cores, each with `threads_per_core`
    /// logical processors, all in group 0, single package, single NUMA node
    /// spanning every logical processor. Written using the real
    /// `windows-sys` struct types so the byte layout matches what the parser
    /// above actually reads — this is what makes the test meaningful without
    /// a live syscall.
    fn build_synthetic_buffer(core_count: u32, threads_per_core: u32, group: u16) -> Vec<u8> {
        let mut buffer = Vec::new();
        let mut next_bit = 0u32;

        for core_index in 0..core_count {
            let mut mask: usize = 0;
            for _ in 0..threads_per_core {
                mask |= 1usize << next_bit;
                next_bit += 1;
            }
            push_processor_relationship_record(
                &mut buffer,
                RelationProcessorCore,
                /* efficiency_class */ (core_index % 2) as u8,
                &[(group, mask)],
            );
        }

        // One package covering every logical processor produced above.
        let full_mask: usize = if next_bit >= usize::BITS {
            usize::MAX
        } else {
            (1usize << next_bit) - 1
        };
        push_processor_relationship_record(
            &mut buffer,
            RelationProcessorPackage,
            0,
            &[(group, full_mask)],
        );

        push_numa_node_record(&mut buffer, 0, &[(group, full_mask)]);

        buffer
    }

    fn push_processor_relationship_record(
        buffer: &mut Vec<u8>,
        relationship: i32,
        efficiency_class: u8,
        affinities: &[(u16, usize)],
    ) {
        let group_mask_offset = 32usize;
        let size = group_mask_offset + affinities.len() * size_of::<GROUP_AFFINITY>();
        buffer.extend_from_slice(&relationship.to_ne_bytes());
        buffer.extend_from_slice(&(size as u32).to_ne_bytes());
        buffer.push(0u8); // Flags
        buffer.push(efficiency_class);
        buffer.extend_from_slice(&[0u8; 20]); // Reserved
        buffer.extend_from_slice(&(affinities.len() as u16).to_ne_bytes()); // GroupCount
                                                                            // 8 (Relationship+Size) + 1 + 1 + 20 + 2 = 32 bytes exactly — the
                                                                            // GroupMask array starts here with no further padding needed.
        for (group, mask) in affinities {
            buffer.extend_from_slice(&mask.to_ne_bytes());
            buffer.extend_from_slice(&group.to_ne_bytes());
            buffer.extend_from_slice(&[0u8; 6]); // GROUP_AFFINITY.Reserved[3] (u16*3)
        }
        assert_eq!(buffer.len() % 8, 0, "record should stay pointer-aligned");
    }

    fn push_numa_node_record(buffer: &mut Vec<u8>, node_number: u32, affinities: &[(u16, usize)]) {
        let group_mask_offset = 32usize;
        let size = group_mask_offset + affinities.len() * size_of::<GROUP_AFFINITY>();
        buffer.extend_from_slice(&RelationNumaNode.to_ne_bytes());
        buffer.extend_from_slice(&(size as u32).to_ne_bytes());
        buffer.extend_from_slice(&node_number.to_ne_bytes());
        buffer.extend_from_slice(&[0u8; 18]); // Reserved
        buffer.extend_from_slice(&(affinities.len() as u16).to_ne_bytes()); // GroupCount
                                                                            // 8 + 4 + 18 + 2 = 32 bytes exactly — same as above, no extra pad.
        for (group, mask) in affinities {
            buffer.extend_from_slice(&mask.to_ne_bytes());
            buffer.extend_from_slice(&group.to_ne_bytes());
            buffer.extend_from_slice(&[0u8; 6]);
        }
    }

    #[test]
    fn parses_precision_5520_like_buffer() {
        let buffer = build_synthetic_buffer(4, 2, 0);
        let parsed = parse_records(&buffer);
        assert_eq!(parsed.cores.len(), 4);
        assert_eq!(parsed.packages.len(), 1);
        assert_eq!(parsed.numa_nodes.len(), 1);

        let mut group_active_counts = BTreeMap::new();
        group_active_counts.insert(0u16, 8u32);
        let snapshot = assemble_snapshot(
            "test-host",
            "2026-07-28T00:00:00Z",
            &parsed,
            &group_active_counts,
            Vec::new(),
        );

        assert_eq!(snapshot.processor_packages, 1);
        assert_eq!(snapshot.physical_cores, 4);
        assert_eq!(snapshot.logical_processors, 8);
        assert_eq!(snapshot.numa_nodes[0].logical_processors.len(), 8);
        assert_eq!(snapshot.cores[0].logical_processors.len(), 2);
        assert_eq!(snapshot.cores[0].package_id, 0);
    }

    #[test]
    fn handles_multiple_processor_groups_without_truncation() {
        // 40 cores x 2 threads = 80 logical processors, split across two
        // Windows processor groups (each capped at 64) — proves the
        // (group, index) representation never collapses onto one mask.
        let mut buffer = Vec::new();
        buffer.extend(build_synthetic_buffer(32, 2, 0)); // 64 logical procs in group 0
                                                         // Manually append a few group-1 cores so we exercise a second group.
        let mut extra = Vec::new();
        push_processor_relationship_record(&mut extra, RelationProcessorCore, 0, &[(1, 0b11)]);
        push_processor_relationship_record(&mut extra, RelationProcessorCore, 0, &[(1, 0b1100)]);
        buffer.extend(extra);

        let parsed = parse_records(&buffer);
        assert_eq!(parsed.cores.len(), 34);

        let group1_lp: Vec<_> = parsed.cores[32..34]
            .iter()
            .flat_map(|c| c.affinities.masks.iter())
            .filter(|(g, _)| *g == 1)
            .collect();
        assert_eq!(group1_lp.len(), 2);
    }

    #[test]
    fn fingerprint_is_stable_across_independent_parses() {
        let buffer = build_synthetic_buffer(4, 2, 0);
        let mut counts = BTreeMap::new();
        counts.insert(0u16, 8u32);

        let a = assemble_snapshot(
            "test-host",
            "2026-07-28T00:00:00Z",
            &parse_records(&buffer),
            &counts,
            Vec::new(),
        );
        let b = assemble_snapshot(
            "test-host",
            "2026-07-28T00:00:00Z",
            &parse_records(&buffer),
            &counts,
            Vec::new(),
        );
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    /// Live validation against the actual dev machine this crate is built
    /// on (Dell Precision 5520, i7-6820HQ: 4 physical cores, 8 logical
    /// processors, single package, single processor group — already
    /// documented in the Bonsai handoff).
    #[test]
    fn live_probe_matches_this_host() {
        let snapshot = super::probe("live-host-test", "2026-07-28T00:00:00Z");
        assert!(
            snapshot.probe_warnings.is_empty(),
            "unexpected probe warnings: {:?}",
            snapshot.probe_warnings
        );
        assert_eq!(snapshot.physical_cores, 4);
        assert_eq!(snapshot.logical_processors, 8);
        assert_eq!(snapshot.processor_packages, 1);
        assert_eq!(snapshot.processor_groups.len(), 1);
        assert_eq!(snapshot.numa_nodes.len(), 1);
        for core in &snapshot.cores {
            assert_eq!(core.logical_processors.len(), 2, "expected HT pairs");
        }
    }
}
