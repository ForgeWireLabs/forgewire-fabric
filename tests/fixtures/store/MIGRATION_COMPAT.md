# Store Migration Compatibility Metadata

> **Oracle tag:** `oracle/v2.7.0-baseline`
> **Schema version at capture:** 2 (rows 1 and 2 in `schema_version` table)

## Reader/writer compatibility

| Scenario | Safe? | Notes |
|---|---|---|
| REMOVED — rqlite only since M2.7.3
| REMOVED — rqlite only since M2.7.3
| REMOVED — rqlite only since M2.7.3
| Rust hub reads schema_v1 (before additive columns) | ✅ Yes | Additive columns absent; Rust applies `ALTER TABLE ADD COLUMN IF NOT EXISTS` |

## Additive columns (applied at runtime by Python hub)

These columns are not in `schema.sql` but are added by Python `server.py` at startup
via `ALTER TABLE ADD COLUMN` (idempotent). The Rust `REMOVED-M2.7.3` crate must
apply the same migrations before first use.

### tasks table

| Column | Type | Default | Added for |
|---|---|---|---|
| `required_tools` | TEXT (JSON) | NULL | Runner capability routing |
| `required_tags` | TEXT (JSON) | NULL | Runner tag routing |
| `tenant` | TEXT | NULL | Tenant placement |
| `workspace_root` | TEXT | NULL | Workspace placement |
| `require_base_commit` | INTEGER | 0 | Commit precondition |
| `required_capabilities` | TEXT (JSON) | NULL | M2.5.4 structured caps |
| `secrets_needed` | TEXT (JSON) | NULL | M2.5.5a secret names |
| `network_egress` | TEXT (JSON) | NULL | M2.5.5b egress policy |
| `dispatcher_id` | TEXT | NULL | Dispatcher attribution |

### runners table

| Column | Type | Default | Added for |
|---|---|---|---|
| `capabilities` | TEXT (JSON) | '{}' | M2.5.4 capability blob |

## Rollback safety

Rolling back from Rust hub to Python hub after Rust writes is safe if:
1. No schema_version row beyond `2` was inserted by Rust.
2. No column was dropped or renamed by Rust.
3. Rust wrote valid UTF-8 JSON in all TEXT JSON columns.
4. Rust did not insert NULLs into NOT NULL columns.

**Before rolling back:** run `python -m forgewire_fabric.hub.server --check-schema` to
verify schema integrity.

## UTC timestamp contract

All `created_at`, `updated_at`, `applied_at`, and similar columns store ISO-8601 strings
in UTC, formatted as `%Y-%m-%d %H:%M:%S` (no timezone suffix, no fractional seconds).
The Python hub uses `datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")`.
The Rust hub must use the same format — not `datetime('now')` (SQLite local time) and
not RFC3339 with offset. Explicit UTC only.

## rqlite compatibility notes

The following SQLite patterns used by the Python hub are prohibited under rqlite:
- `SELECT` inside `BEGIN` / `COMMIT` (rqlite shim contract)
- Cross-statement transactions relying on statement ordering
- `datetime('now')` (SQLite-local, use explicit UTC string instead)
- Assumed auto-increment continuity across reconnects

Atomic claim operations and audit-tail reads are expressed as single-statement
compare-and-swap updates. See `store/rqlite_scenarios.json` for CAS fixtures.
