---
audience: @fabric-maintainers and audit reviewers
status: active
last_verified: 2026-06-05
source_of_truth: forgewire-fabric/AGENTS.md
---

# ForgeWire Fabric mirror audit workspace

This audit workspace records traceability for `forgewire-fabric` so the directory-level `AGENTS.md` guidance has a matching `_audit/` folder.

## Scope

- Keep the local `AGENTS.md` instructions aligned with the implementation and planning files in this subtree.
- Record ownership, review cadence, and drift findings in [`inventory.md`](./inventory.md) and [`alignment-report.md`](./alignment-report.md).
- Re-run `python scripts/validate_audit.py` from the ForgeWire repository root after audit metadata changes.

## Current review note

Bootstrap-only audit record for the in-tree Fabric subtree. Detailed implementation review remains governed by the subtree AGENTS instructions and Fabric validation commands.
