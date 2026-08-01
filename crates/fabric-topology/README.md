# fabric-topology

Portable CPU topology discovery for ForgeWire Loom compute lanes (114F).

Captures a `ComputeTopologySnapshot` describing physical packages, cores, logical processors, SMT siblings, NUMA nodes, and processor groups — live-validated on Windows and Linux.

## What's here

- `ComputeTopologySnapshot::capture(host_id, captured_at)` — the entry point.
- `CoreTopology`, `LogicalProcessorId`, `ProcessorGroup`, `NumaNode` — the topology structs.
- `ProbeSource` — records which OS-native mechanism produced a snapshot, so a caller can distinguish a verified reading from a degraded fallback.

`forgewire-capability`'s hardware probe deliberately does **not** depend on this crate — the backend matrix's CPU device entry needs only device *identity* (vendor/brand/aggregate core counts), not full topology, and a cross-workspace path dependency would block that crate from publishing standalone. This crate remains the single source of truth for core/thread/NUMA/processor-group topology used by lane placement.

## License

Apache-2.0
