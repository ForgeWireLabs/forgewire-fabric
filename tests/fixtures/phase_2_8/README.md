# Phase 2.8 — M2.8.0 Cross-language fixtures

Frozen byte-exact contracts for the Loom/Fabric surface split. Every implementation milestone (M2.8.1+) must round-trip through these.

| File | Purpose |
|---|---|
| [SPEC.md](SPEC.md) | The locked spec: field names, enums, normalization rules, backfill matrix, audit-chain compat. |
| [registration_envelopes.json](registration_envelopes.json) | 4 registration envelopes covering Fabric-only, Loom-only, combined-kinds, and legacy-v3-no-kinds backfill. |
| [task_briefs.json](task_briefs.json) | 6 task briefs covering Loom command (2), Fabric skill, Fabric tool, Fabric prompt, and legacy-v3 backfill. |
| [capability_index.json](capability_index.json) | Manifest → normalized `runner_capabilities` rows. Pure-function projection contract for M2.8.1. |
| [routing_decisions.json](routing_decisions.json) | 17 capability-router decision cases covering skill match / tool match / drain interplay / tenant filter / agent_type pin / runner_id pin / resource intersect / Loom queue / kind mismatch / multi-runner tiebreak. |

## How implementations consume these

- **Rust (M2.8.1 store traits):** unit tests in `fabric-store-rqlite::tests::phase_2_8_*` load these JSON files at compile time via `include_str!` and round-trip them through `mcp_manifest::normalize_manifest_to_rows`. The store's `upsert_runner` + `runner_capabilities()` integration test (rqlite-required) uses `registration_envelopes.json` as input and verifies the persisted rows match `capability_index.json` expected rows byte-for-byte.
- **Rust (M2.8.2 router):** `fabric-claim-router::tests::phase_2_8_routing` loads `routing_decisions.json`, sets up the pre_state, evaluates each decision, and asserts the picked `runner_id` (or deny reason) matches.
- **Python (M2.8.0 audit-chain compat):** `tests/fixtures/phase_2_8/audit_compat.json` (sibling to `tests/fixtures/audit/`) verifies that adding the new keys to a v3 envelope does not change its canonical-JSON hash.

## Stability promise

These fixtures are part of the locked contract for Phase 2.8. Editing them requires:
1. A spec amendment in `phase-2.8-loom-fabric-surface-split.md`.
2. An audit-log entry in `todos/114-forgewire-fabric/README.md`.
3. Updated implementations in `fabric-store`, `fabric-store-rqlite`, `fabric-claim-router`, `fabric-hub`, and both Python MCP servers.

A drift between this fixture set and any of those implementations is a release-blocker.
