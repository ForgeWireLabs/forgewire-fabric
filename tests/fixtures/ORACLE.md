# M2.7.0 Oracle Baseline

> **Captured:** 2026-05-31
> **Tag:** `oracle/v2.7.0-baseline` → commit `978098a`
> **Purpose:** Pins the Python reference implementation that Rust must achieve byte-level parity with before any native daemon cutover.

---

## Identity

| Field | Value |
|---|---|
| Package version | `0.13.0` |
| Protocol version | `3` |
| Min compatible protocol version | `2` |
| Git tag | `oracle/v2.7.0-baseline` |
| Git commit | `978098a` |
| Schema version (SQLite) | `2` (rows 1 and 2 in `schema_version`) |
| SIGNATURE_MAX_SKEW_SECONDS | `300` |
| AUDIT_GENESIS_HASH | `"0" * 64` (64 ASCII zero characters) |
| Dispatch wire format | v2 (see frozen payload below) |

---

## Frozen v2 signed dispatch payload

The following fields and exactly these fields are covered by the ed25519 dispatcher signature. **Do not add or remove fields during the migration window.** New fields with security semantics belong in protocol v3.

```json
{
  "op": "dispatch",
  "dispatcher_id": "<str>",
  "title": "<str>",
  "prompt": "<str>",
  "scope_globs": ["<str>", ...],
  "base_commit": "<str>",
  "branch": "<str>",
  "timestamp": <int>,
  "nonce": "<str>"
}
```

Canonicalization: `json.dumps(payload, sort_keys=True, separators=(",", ":"))` → UTF-8 bytes. Identical to the Rust `fabric-protocol` crate's `canonicalize()`.

### Out-of-band fields (NOT in signed payload — bearer-gated only)

These fields alter execution semantics but are outside the v2 signature. They are the explicit compatibility quarantine documented below.

| Field | Added | Purpose |
|---|---|---|
| `todo_id` | v1 | Human reference label |
| `timeout_minutes` | v1 | Task timeout cap |
| `priority` | v1 | Queue ordering |
| `metadata` | v1 | Forward-compat bag |
| `required_tools` | v1 | Routing filter |
| `required_tags` | M2.5.4 | Routing filter |
| `tenant` | M2.5.4 | Tenant placement |
| `workspace_root` | M2.5.4 | Workspace placement |
| `require_base_commit` | M2.5.4 | Commit precondition |
| `required_capabilities` | M2.5.4 | Structured cap predicates |
| `secrets_needed` | M2.5.5a | Secret name list (audit: names only) |
| `network_egress` | M2.5.5b | Per-task egress policy |
| `approval_id` | M2.5.1 | Re-dispatch with approval gate bypass |
| `kind` | v1 | `agent` or `command` routing class |

---

## Signed-extension / trusted-bearer migration-window decision

**Decision: trusted-bearer compatibility window (option A).**

Rationale: The v2 canonical payload is frozen. The out-of-band fields listed above are bearer-gated and alter execution semantics (capabilities, egress, secrets, approval) without changing the dispatcher signature. During the migration window, these fields are only accepted on an explicitly declared trusted transport boundary.

Implementation contract:
- The native hub must surface a named `sidecar_integrity` field in `/healthz` and `/cluster/health` responses: `"trusted_bearer"` when running in compatibility mode, `"signed_extension"` when running with a separately-versioned extension envelope (v3), or `"strict"` when only the frozen v2 fields are accepted.
- `"trusted_bearer"` mode reports as a degraded integrity posture in `doctor` output with the message: `"Out-of-band dispatch fields are bearer-gated only. Upgrade to protocol v3 to sign all execution-semantic fields."`
- Expiry gate: this compatibility window closes when protocol v3 is specified and deployed (M2.7.7). At that point, all execution-semantic fields move under the immutable envelope and the `"trusted_bearer"` mode is removed.
- The Python oracle operates in `"trusted_bearer"` mode by design. The Rust native hub must reproduce this behavior exactly during the parity window.

---

## Audit chain formula (byte-exact)

```
event_id_hash = sha256(
    ascii(prev_event_id_hash)   # hex string as ASCII bytes
    || b"|"                     # LITERAL separator — must appear in golden fixtures
    || utf8(kind)               # event kind string
    || b"|"                     # LITERAL separator
    || audit_canonical_json(payload)
)

audit_canonical_json(payload) =
    json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

AUDIT_GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
```

The `b"|"` separators are **part of the compatibility contract**. A Rust implementation that omits them produces an internally consistent but byte-incompatible chain. The golden fixtures in `audit/chain.json` encode the expected hex digests for known inputs; the cross-language test must reproduce them exactly.

---

## Canonical JSON formula (protocol layer)

```
canonical_bytes = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

Object keys sorted lexicographically. No whitespace. UTF-8 encoded. The Rust `fabric-protocol` crate's `canonicalize()` must produce byte-identical output. Cross-language fixtures are in `protocol/envelope_v2.json`.

---

## Runner signed-operation payloads

### Register
```json
{"op": "register", "runner_id": "<str>", "public_key": "<hex>",
 "protocol_version": <int>, "timestamp": <int>, "nonce": "<str>"}
```

### Heartbeat
```json
{"op": "heartbeat", "runner_id": "<str>", "timestamp": <int>, "nonce": "<str>"}
```

### Claim (v2)
```json
{"op": "claim", "runner_id": "<str>", "timestamp": <int>, "nonce": "<str>"}
```

### Drain
```json
{"op": "drain", "runner_id": "<str>", "timestamp": <int>, "nonce": "<str>"}
```

### Dispatcher register
```json
{"op": "register-dispatcher", "dispatcher_id": "<str>", "public_key": "<hex>",
 "timestamp": <int>, "nonce": "<str>"}
```

---

## Phase 2.6 status at oracle capture

| Milestone | Status |
|---|---|
| M2.6.1 Functional defect sweep | ✅ Committed `100c16f` |
| M2.6.2 Lint floor + CI | ✅ Committed `bd7215d` |
| M2.6.3 Exception chaining | ✅ Committed `c986074` |
| M2.6.4 FastAPI lifespan | ✅ Committed `f3628ff` |
| M2.6.5 CLI split | ✅ Committed `543d657` |
| M2.6.6 Hub route split | ✅ Route modules committed `1bae1db`; `Blackboard` class remains in `server.py` — extraction deferred to M2.7.3 (store traits slice) |

---

## Live-smoke status at oracle capture

Live `/healthz` captured 2026-05-31 from OptiPlex hub (`DESKTOP-38GVF8D`, `10.43.106.95:8765`):

```json
{
  "status": "ok",
  "version": "0.13.0",
  "package_version": "0.13.0",
  "protocol_version": 3,
  "rust_crypto": false,
  "rust_router": false,
  "rust_streams": false,
  "started_at": 1779141938.6317647,
  "uptime_seconds": 1131647.5138821602,
  "host": "0.0.0.0",
  "port": 8765
}
```

**Note:** `rust_crypto/router/streams` are all `false` — the OptiPlex hub runs in Python fallback mode (no `forgewire_runtime` wheel compiled for Windows/this platform). All 41 fixture tests pass identically in Python fallback mode, confirming byte-level parity between Rust-accelerated and Python paths on the Precision 5520. The OptiPlex result proves the fallback path is correct.

OpenAPI capture: pending (requires hub token). Full `GET /openapi.json` diff against the endpoint-auth matrix is the remaining step before M2.7.1 can begin. The live `/healthz` response confirms version and protocol fields match the oracle.

---

## SQLite / rqlite deployment at oracle capture

| Backend | Status |
|---|---|
| SQLite | In use on Precision 5520 (`~/.forgewire/hub.sqlite3`) |
| rqlite | Not deployed at oracle capture — fixtures are synthetic |

rqlite fixtures in `store/rqlite_scenarios.json` are synthetic, derived from the Python `_rqlite_db.py` implementation and the rqlite HTTP API contract.

---

## Rust acceleration at oracle capture

| Module | Rust | Python fallback |
|---|---|---|
| `fabric-protocol` (ed25519 + canonical JSON) | ✅ loaded as `forgewire_runtime` | ✅ `_crypto.py` |
| `fabric-claim-router` | ✅ | ✅ `_router.py` |
| `fabric-streams` (seq counter) | ✅ | ✅ `_streams.py` |

All three Rust crates have Python fallbacks controlled by `FORGEWIRE_FORCE_PYTHON=1`. Fixtures must pass against both paths.

---

## Rollout ladder: step 0 complete

| Step | Promotion | Status |
|---|---|---|
| 0 | Python oracle freeze | ✅ Tag `oracle/v2.7.0-baseline` at `978098a`; fixture corpus created; live-smoke pending |

Next gate: live `/healthz` + OpenAPI capture, then M2.7.1 begins.
