# fabric-history

Optional, absence-tolerant Tier-2 history export for ForgeWire Fabric: an outbound sink for task/audit history that the hub feeds but never depends on.

## What's here

- `HistoryConfig`, `HistoryDsn` — how a history sink is configured (currently PostgreSQL via `tokio-postgres`).
- `ExportSource` / `HistoryTarget` traits — the source-of-record and destination sides of an export.
- `HistoryRecord`, `HistoryMode` — what gets exported and in what mode (e.g. full vs. incremental).
- `ExportHealth` — whether the sink is currently reachable; the hub degrades gracefully to thin-history mode when it isn't, per the two-tier database architecture (rqlite is the control-plane store; this sink is an optional operator-configured history archive).
- `HistoryError` — export/connection failures.

## License

Apache-2.0
