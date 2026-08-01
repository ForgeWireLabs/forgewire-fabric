# fabric-streams

Per-task stream sequence counters for ForgeWire Fabric: ordered, gap-free sequence numbers for task output/progress lines, plus a small in-memory buffer for batching writes.

## What's here

- `StreamCounter` — a per-task monotonic sequence counter.
- `StreamBuffer`, `PendingEntry` — buffers stream lines for a task before they're flushed to durable storage.
- `DurabilityProfile` — how aggressively buffered lines are flushed (trades write latency against loss window on crash).

## License

Apache-2.0
