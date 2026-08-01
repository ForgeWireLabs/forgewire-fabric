# Optional Tier-2 history sink

rqlite is the only Tier-1 control-plane database. The optional PostgreSQL-
compatible sink stores long-term task history, cost events, and audit archive
for analytics. It is never in dispatch, consensus, authorization, or failover.

## Modes

- `thin`: no external database; Fabric remains fully functional.
- `external`: operator supplies a DSN for an existing database.
- `fabric-managed`: reserved for an explicitly provisioned optional sink.

The DSN is sensitive and must include `sslmode=require`. Connector and schema
errors are sanitized so credentials cannot appear in status or logs.
Autodetection is observational TCP probing only; it never supplies credentials
or auto-connects.

The exporter reads `tasks`, `cost`, and `audit` streams from rqlite, upserts
stable `task_history`, `cost_events`, and `audit_events_archive` views, then
commits a durable per-stream watermark only after the target write succeeds.
Target failure produces degraded history status and a retry delay; task
dispatch continues.

Check `/history/status` or doctor. Disconnecting the sink must not disrupt hub
health or task execution. If it does, the Tier-1/Tier-2 boundary has been
violated.

