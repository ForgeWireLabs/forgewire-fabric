# Protocol v3 — Immutable Dispatch Envelope Specification

> **Status:** Design specification (M2.7.7). No implementation until v2 parity gates pass.
> **Author:** M2.7.7 design phase
> **Date:** 2026-06-01

---

## Purpose

Protocol v2 freezes a minimal signed payload (`op`, `dispatcher_id`, `title`, `prompt`, `scope_globs`, `base_commit`, `branch`, `timestamp`, `nonce`). All other execution-semantic fields — required capabilities, tenant, workspace, egress policy, secret names, cost caps, approval references, execution kind, sandbox profile — are out-of-band and bearer-gated only.

This was acceptable when the hub was a single-operator machine. It is not acceptable for the federated fleet (Phase 3) or any deployment where a bearer-token compromise must not alter execution semantics without invalidating the dispatcher signature.

Protocol v3 moves all execution-semantic fields under an immutable signed envelope.

---

## v3 Signed Envelope

```json
{
  "v": 3,
  "op": "dispatch",
  "dispatcher_id": "<str>",
  "title": "<str>",
  "prompt": "<str>",
  "scope_globs": ["<str>", ...],
  "base_commit": "<str>",
  "branch": "<str>",
  "timestamp": <int>,
  "nonce": "<str>",

  "kind": "agent" | "command",
  "tenant": "<str|null>",
  "workspace_root": "<str|null>",
  "require_base_commit": <bool>,
  "required_tools": ["<str>", ...],
  "required_tags": ["<str>", ...],
  "required_capabilities": ["<str>", ...],
  "secrets_needed": ["<str>", ...],
  "network_egress": { "allow": [...], "extra_hosts": [...] } | null,
  "cost_cap_usd": <float|null>,
  "approval_required": <bool>,
  "witness_required": <bool>,
  "sandbox_profile": "bare" | "container" | "vm",
  "timeout_minutes": <int>,
  "priority": <int>,
  "metadata": {}
}
```

All fields are immutable once signed. The signature covers the canonical JSON of the entire object (sorted keys, compact separators, UTF-8).

---

## Version Negotiation

### Dispatch path

1. Dispatcher sends `POST /tasks/v3` with the v3 envelope + signature.
2. Hub checks `v` field:
   - `v=3`: validate full signature, process all fields.
   - `v=2` on `/tasks/v2`: existing behavior (frozen v2 payload, out-of-band fields bearer-gated).
   - `v=3` on `/tasks/v2`: reject with 426 Upgrade Required.
   - `v=2` on `/tasks/v3`: reject with 400 Bad Request.
3. `/tasks` (unsigned, legacy): preserved during compat window only if `require_signed_dispatch=false`.

### Runner path

1. Runner claim-v2 is unchanged (runner signs `op=claim` with its own key).
2. Runner registration payload gains a `supported_protocol_versions: [2, 3]` field.
3. Hub-to-runner claim response includes the `v` field so the runner knows which envelope shape it received.

### Hub-to-hub (federated, Phase 3)

Hub-to-hub forwarding uses v3 exclusively. The originating hub's signature is preserved end-to-end. Relay hubs do not re-sign.

---

## Compatibility Matrix

| Dispatcher | Hub | Runner | Result |
|---|---|---|---|
| v2 | v2 | v2 | Current behavior (trusted-bearer compat) |
| v2 | v3 | v2 | Hub accepts v2 on `/tasks/v2`, processes with degraded integrity |
| v3 | v3 | v2 | Hub validates v3 signature, routes to v2 runner via existing claim contract |
| v3 | v3 | v3 | Full integrity: all fields signed, all fields verified |
| v3 | v2 | any | Hub rejects v3 (doesn't know the fields): dispatcher must fall back to v2 |

### Downgrade behavior

- A v3 dispatcher talking to a v2-only hub receives 404 on `/tasks/v3` and should fall back to `/tasks/v2` + out-of-band fields.
- A v3 hub never downgrades a v3 envelope to v2 internally — the full signed payload is stored and forwarded.
- `sidecar_integrity` in `/healthz` changes from `"trusted_bearer"` to `"signed_v3"` once the hub is running in v3 mode.

---

## Fields Moved Under Signature (v2 → v3)

| Field | v2 | v3 | Security impact |
|---|---|---|---|
| `kind` | out-of-band | **signed** | Prevents bearer-only routing class change |
| `tenant` | out-of-band | **signed** | Prevents cross-tenant dispatch injection |
| `workspace_root` | out-of-band | **signed** | Prevents workspace redirect |
| `require_base_commit` | out-of-band | **signed** | Prevents commit precondition bypass |
| `required_tools` | out-of-band | **signed** | Prevents tool requirement removal |
| `required_tags` | out-of-band | **signed** | Prevents tag requirement removal |
| `required_capabilities` | out-of-band | **signed** | Prevents capability gate bypass |
| `secrets_needed` | out-of-band | **signed** | Prevents secret injection (names only, never values) |
| `network_egress` | out-of-band | **signed** | Prevents egress allowlist manipulation |
| `cost_cap_usd` | new in v3 | **signed** | Per-task cost ceiling |
| `approval_required` | new in v3 | **signed** | Explicit approval gate |
| `witness_required` | new in v3 | **signed** | External witness co-sign requirement (Phase 5) |
| `sandbox_profile` | new in v3 | **signed** | Execution sandbox level |
| `timeout_minutes` | out-of-band | **signed** | Prevents timeout manipulation |
| `priority` | out-of-band | **signed** | Prevents priority escalation |
| `metadata` | out-of-band | **signed** | Forward-compat bag now tamper-evident |

---

## Audit Impact

- Audit event payloads include the `v` field so chain verification knows which fields were signed.
- v2 and v3 audit events coexist in the same chain. The hash formula is unchanged (`sha256(prev || "|" || kind || "|" || canonical_json(payload))`).
- v3 dispatch audit events include all signed fields in the payload. v2 events continue with the existing payload shape.

---

## Migration Plan

1. **Phase 1 (current):** v2 parity complete. `sidecar_integrity=trusted_bearer`.
2. **Phase 2:** Ship v3 endpoint (`POST /tasks/v3`) on the native Rust hub. Python hub gets a v3 adapter. `sidecar_integrity` reports `"v3_available"`.
3. **Phase 3:** Upgrade dispatchers to v3. Hub still accepts v2 on `/tasks/v2`.
4. **Phase 4:** Deprecate `/tasks/v2` (log warning). `sidecar_integrity=signed_v3`.
5. **Phase 5:** Remove `/tasks/v2` and unsigned `/tasks`. `sidecar_integrity=strict`.

The `trusted_bearer` compat window (M2.7.0 decision) closes at Phase 4.

---

## Golden Fixtures (to be added)

When v3 is implemented, add to `tests/fixtures/protocol/`:
- `envelope_v3.json`: canonical bytes, signatures, tamper rejection for the full v3 payload.
- `v2_v3_coexistence.json`: mixed-version audit chains, downgrade behavior, version negotiation.

---

## Open Questions (resolve at implementation time)

1. Should `metadata` be signed or remain extensible? **Decision: signed.** Metadata is forward-compat — better to have it tamper-evident and add new fields in future protocol bumps than to leave a hole.
2. Should `todo_id` be signed? **Decision: no.** It's a human-readable label with no execution semantics.
3. Should the v3 envelope include a `schema_version` field for future extensibility? **Decision: yes.** `"v": 3` serves this purpose.
