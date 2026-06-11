# Endpoint-Auth Matrix — v2 Oracle Baseline

> **Oracle tag:** `oracle/v2.7.0-baseline` (commit `978098a`)
> **Captured:** 2026-05-31
> **Purpose:** Every route classified for auth shape. No unclassified mutation endpoint may exist when the Rust hub canary goes live. Routes marked `COMPAT_QUARANTINE` are the bearer-only mutation surface that must be declared as a trusted-bearer compatibility window in health/doctor output.

## Legend

| Column | Meaning |
|---|---|
| Method + Path | HTTP verb and path pattern |
| Shape | `read` = no state change; `write` = state change |
| Bearer | Required (✅), not required (–) |
| Disp-sig | Dispatcher ed25519 signature verified (✅), not required (–) |
| Runner-sig | Runner ed25519 signature verified (✅), not required (–) |
| Nonce | Replay-rejection nonce consumed (✅), not required (–) |
| Skew | Timestamp skew checked ±300 s (✅), not required (–) |
| Compat status | `SIGNED` = target posture met; `COMPAT_QUARANTINE` = bearer-only mutation (must surface in health); `READ_BEARER` = read-only bearer (acceptable) |
| Remediation | How this is resolved going forward |

---

## Cluster / health

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| GET /healthz | read | – | – | – | – | – | SIGNED | No auth on health probe — by design, preserve in Rust |
| GET /cluster/health | read | ✅ | – | – | – | – | READ_BEARER | Acceptable — read-only fleet status |

---

## Task dispatch

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| POST /tasks | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Legacy unsigned dispatch path. `require_signed_dispatch` config rejects this and forces `/tasks/v2`. Rust hub must: (1) preserve path for parity window; (2) reject when `require_signed_dispatch=true`; (3) surface as degraded integrity in health when active. Closes at protocol v3. |
| POST /tasks/v2 | write | ✅ | ✅ | – | ✅ | ✅ | SIGNED | Target posture. Dispatcher signs frozen v2 payload. |
| GET /tasks | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| GET /tasks/waiting | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| GET /tasks/{task_id} | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |

---

## Task lifecycle (runner-side mutations)

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| POST /tasks/claim | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Legacy v1 claim — no runner identity, no replay protection. Preserved for old runners during parity window. Rust hub must surface as degraded when active. The kind-specific signed claim routes are the target path. |
| POST /tasks/claim-loom | write | ✅ | – | ✅ | ✅ | ✅ | SIGNED | Target posture (command-kind queue). Runner signs claim with nonce + timestamp. M2.8.9 replaced the unified /tasks/claim-v2 alias with the kind-split routes. |
| POST /tasks/claim-fabric | write | ✅ | – | ✅ | ✅ | ✅ | SIGNED | Target posture (agent-kind queue). Runner signs claim with nonce + timestamp. |
| POST /tasks/{task_id}/start | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | No runner identity on start signal. Acceptable short-term because runner must hold a claimed task, but sign this in v3. |
| POST /tasks/{task_id}/cancel | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Bearer-only cancel. Anyone with the bearer token can cancel any task. Surface as degraded; v3 should restrict to dispatcher or operator role. |
| POST /tasks/{task_id}/progress | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | No runner identity on progress beat. Parity window: preserve. V3: runner-signed. |
| POST /tasks/{task_id}/stream | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | No runner identity on stream line. Parity window: preserve. V3: runner-signed or session-scoped. |
| POST /tasks/{task_id}/stream/bulk | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Same as single-line stream. |
| GET /tasks/{task_id}/stream | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| POST /tasks/{task_id}/result | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | No runner signature on terminal result. High-value mutation. V3: runner-signed with completion hash chain. |
| POST /tasks/{task_id}/notes | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Bearer-only note write. Low risk but unsigned. V3: author-attributed. |
| GET /tasks/{task_id}/notes | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| GET /tasks/{task_id}/events (SSE) | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |

---

## Runner registry

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| POST /runners/register | write | ✅ | – | ✅ (self-attest) | ✅ | ✅ | SIGNED | Runner self-attests public key. Target posture for registration. |
| GET /runners | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| POST /runners/{runner_id}/heartbeat | write | ✅ | – | ✅ | ✅ | ✅ | SIGNED | Runner-signed heartbeat. Target posture. |
| POST /runners/{runner_id}/drain | write | ✅ | – | ✅ | ✅ | ✅ | SIGNED | Runner-signed self-drain. Target posture. |
| POST /runners/{runner_id}/drain-by-dispatcher | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Operator/dispatcher drains runner by bearer only. V3: dispatcher-role token required. |
| POST /runners/{runner_id}/undrain-by-dispatcher | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Same as drain-by-dispatcher. |
| DELETE /runners/{runner_id} | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Bearer-only deregister. Acceptable short-term (test cleanup), but flag in health. V3: operator-role token. |

---

## Dispatcher registry

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| POST /dispatchers/register | write | ✅ | ✅ (self-attest) | – | ✅ | ✅ | SIGNED | Dispatcher self-attests public key. Target posture. |
| GET /dispatchers | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| DELETE /dispatchers/{dispatcher_id} | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Bearer-only deregister. V3: operator-role. |

---

## Labels

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| GET /labels | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| PUT /labels/hub | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Bearer-only display-name write. Low risk. V3: operator-role. |
| PUT /labels/runners/{runner_id} | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Same. |
| PUT /labels/hosts/{hostname} | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Same. |

---

## Hosts / roles

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| GET /hosts | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| POST /hosts/roles | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Bearer-only host-role assignment. V3: operator-role token. |

---

## Audit

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| GET /audit/tasks/{task_id} | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| GET /audit/day/{day} | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| GET /audit/tail | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |

---

## Approvals

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| GET /approvals | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| GET /approvals/{approval_id} | read | ✅ | – | – | – | – | READ_BEARER | Acceptable |
| POST /approvals/{approval_id}/approve | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Bearer-only approval decision. High-value: an approval bypasses the policy gate. V3: operator-role token required. |
| POST /approvals/{approval_id}/deny | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Same as approve. |

---

## Secrets

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| POST /secrets | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Bearer-only secret write/rotate. High-value mutation. V3: operator-role token. |
| GET /secrets | read | ✅ | – | – | – | – | READ_BEARER | Returns metadata (names + version), never values — acceptable. |
| DELETE /secrets/{name} | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Bearer-only secret delete. V3: operator-role token. |

---

## Admin (snapshot / import)

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| GET /state/snapshot | read | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Returns raw SQLite backup. High sensitivity — anyone with bearer token can exfiltrate the full database. V3: operator-role token + audit event. |
| POST /state/import | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Replaces entire database. Most destructive endpoint. V3: operator-role token + mandatory audit event + confirmation nonce. |

---

## Summary counts

| Category | Count |
|---|---|
| SIGNED (target posture met) | 7 |
| READ_BEARER (acceptable) | 17 |
| COMPAT_QUARANTINE (bearer-only mutation) | 22 |
| **Total routes** | **46** |

---

## Compat quarantine health contract

When the native Rust hub is running and any `COMPAT_QUARANTINE` route is reachable, `/healthz` and `/cluster/health` must include:

```json
{
  "sidecar_integrity": "trusted_bearer",
  "compat_quarantine_routes": [
    "POST /tasks",
    "POST /tasks/claim",
    "POST /tasks/{task_id}/start",
    ...
  ],
  "compat_expiry": "protocol_v3"
}
```

Doctor output must print a warning for each quarantined route that was invoked since last restart.

---

## Route auth matrix — open actions before M2.7.1

1. **Live OpenAPI capture:** Start hub, `GET /openapi.json`, diff against this matrix to catch any routes added after `978098a`.
2. **Confirm COMPAT_QUARANTINE visibility:** Verify `require_signed_dispatch` config correctly rejects `POST /tasks` when set.
3. **M2.7.4 gate:** Before Rust hub canary, confirm every `COMPAT_QUARANTINE` route surfaces in health output. No silent normalization.
