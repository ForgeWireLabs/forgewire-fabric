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
| Compat status | `SIGNED` = target posture met; `COMPAT_QUARANTINE` = bearer-only mutation (must surface in health); `READ_BEARER` = read-only bearer (acceptable); `HUMAN_SESSION` = gated by a signed-in human session's access secret (and, for admin routes, an account role), never by the dispatcher/runner ed25519 scheme this matrix otherwise classifies |
| Remediation | How this is resolved going forward |

> **114C addendum (2026-07-22):** the "Human accounts" section below was
> added when the 114C human-accounts feature's ~33 routes were found
> missing from this matrix entirely (114C.7 Slice 6 docs closeout). This
> addendum only adds those rows in the existing format; it does not re-run
> the "Live OpenAPI capture" audit item 1 under "Route auth matrix — open
> actions" below for the pre-existing ~46 rows.

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
| POST /tasks/claim | write | ✅ | – | – | – | – | **COMPAT_QUARANTINE** | Implemented in Rust 0.11.0 as explicitly degraded: runner-role bearer required; agent/plain tasks only; caller-supplied capabilities ignored; every use audited as `legacy_claim_degraded`; Warning response header. The kind-specific signed claim routes remain the target path. |
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
| POST /hosts/roles | write | ✅ | – | – | – | – | CLUSTER_PARTICIPANT | Host infra self-report; roles: runner/dispatcher/reviewer (same tier runner/dispatcher enrolment already writes host_roles under). Observer excluded. |

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
| GET /state/snapshot | read | ✅ | – | – | – | – | OPERATOR_AUDITED | Rust 0.11.0: admin/reviewer only; full snapshot access emits a mandatory `state_snapshot` audit event. |
| POST /state/import | write | ✅ | – | – | – | – | ADMIN_CONFIRMED | Rust 0.11.0: human admin only; requires `X-Forgewire-Import-Confirmation: sha256:<body digest>`, preserves non-empty-hub `X-Force: 1` guard, and emits mandatory requested/completed audit events. |

---

## Human accounts (auth/session/passkey/step-up)

114C human-accounts routes (`crates/fabric-hub/src/routes/{accounts,authn,webauthn_bridge,webauthn_doctor}.rs`,
confirmed against the route-manifest tests in `crates/fabric-hub/src/routes/mod.rs`).
None of these use the dispatcher/runner ed25519 scheme — Disp-sig/Runner-sig/
Nonce/Skew are "–" throughout. "Bearer" here means either the installed
automation token *or* a human session's access secret (`resolve_human_session`
tries the human session first); admin-only routes additionally require the
signed-in human hold the `admin` account role, which no automation token can
ever carry.

| Method + Path | Shape | Bearer | Disp-sig | Runner-sig | Nonce | Skew | Compat status | Remediation |
|---|---|---|---|---|---|---|---|---|
| GET /auth/bootstrap/status | read | – | – | – | – | – | HUMAN_SESSION | Public — true before the realm has any administrator. |
| POST /auth/bootstrap | write | – | – | – | – | – | HUMAN_SESSION | Public, but gated on source address (loopback by default) and an optional bootstrap secret header, never a bearer. Creates the realm's first admin exactly once. |
| POST /auth/login | write | – | – | – | – | – | HUMAN_SESSION | Public (username+password is the credential). Returns `access_secret`/`refresh_secret`; callers must persist them in a platform credential store, never client state. |
| POST /auth/refresh | write | – | – | – | – | – | HUMAN_SESSION | Public (the refresh secret itself is the credential). Rotates the refresh secret. |
| GET /auth-policy | read | – | – | – | – | – | HUMAN_SESSION | Public — realm id, whether bootstrap is open, and the assignable-role vocabulary clients read rather than hardcoding. |
| GET /auth/sessions | read | ✅ | – | – | – | – | HUMAN_SESSION | Self-service; admin may pass `account_id` to read another account's sessions. |
| DELETE /auth/sessions/{session_id} | write | ✅ | – | – | – | – | HUMAN_SESSION | Self-service or admin; ownership enforced handler-side. |
| POST /auth/logout | write | ✅ | – | – | – | – | HUMAN_SESSION | Self-service; revokes the caller's own session. |
| POST /auth/logout-all | write | ✅ | – | – | – | – | HUMAN_SESSION | Self-service; revokes every session on the caller's own account. |
| GET /auth/me | read | ✅ | – | – | – | – | HUMAN_SESSION | Self-service account summary. |
| POST /auth/passkeys/options | write | – | – | – | – | – | HUMAN_SESSION | Public — login-ceremony WebAuthn request options (no session exists yet). |
| POST /auth/passkeys/verify | write | – | – | – | – | – | HUMAN_SESSION | Public — completes passkey login, issues a session. |
| POST /auth/passkeys/register/options | write | ✅ | – | – | – | – | HUMAN_SESSION | Registration-ceremony creation options for a signed-in session. |
| POST /auth/passkeys/register/verify | write | ✅ | – | – | – | – | HUMAN_SESSION | Completes passkey registration for the caller's own session. |
| DELETE /auth/passkeys/{credential_id} | write | ✅ | – | – | – | – | HUMAN_SESSION | Self-service — removes one of the caller's own passkeys. |
| POST /auth/step-up/options | write | ✅ | – | – | – | – | HUMAN_SESSION | Self-service; starts the in-place step-up ceremony for the caller's current session. |
| POST /auth/step-up/verify | write | ✅ | – | – | – | – | HUMAN_SESSION | Completes step-up with a relayed WebAuthn assertion; elevates the session to `aal2` and rotates its access secret. |
| GET /auth/webauthn/bridge | read | – | – | – | – | – | HUMAN_SESSION | Public — serves the browser-relay bridge page used by both clients for every WebAuthn ceremony (neither has an in-process, hub-reachable WebAuthn context). |
| GET /auth/webauthn/bridge.js | read | – | – | – | – | – | HUMAN_SESSION | Public — the bridge page's JS, runs `navigator.credentials` and relays the result to a client-owned loopback listener. |
| GET /auth/webauthn/doctor | read | – | – | – | – | – | HUMAN_SESSION | Public by design (114C.6 Slice 7) — reports RP id / allowed-origins configuration, which is routing information, not a secret. |
| GET /setup/status | read | – | – | – | – | – | HUMAN_SESSION | Public (114D D.2) — drives the client setup FSM (`bootstrap_open`/`realm_established`/`sealing`); no credential exists yet in the pre-genesis window. |
| POST /setup/complete | write | – | – | – | – | – | HUMAN_SESSION | Public, but gated exactly like `/auth/bootstrap` (loopback by default, optional bootstrap secret header, never a bearer) (114D D.2). Atomically establishes the realm identity and the Master account/credential/admin-membership/recovery codes, then issues a session — reachable only in the `bootstrap_open ∧ ¬realm_established` window. |
| GET /accounts | read | ✅ | – | – | – | – | HUMAN_SESSION | `admin` or `reviewer` role. |
| POST /accounts | write | ✅ | – | – | – | – | HUMAN_SESSION | `admin` only. Creates an account with an initial password and role. |
| GET /accounts/{account_id} | read | ✅ | – | – | – | – | HUMAN_SESSION | `admin` or `reviewer` role. |
| PATCH /accounts/{account_id} | write | ✅ | – | – | – | – | HUMAN_SESSION | `admin` only. Narrow status-transition route (unlock, admin-forced recovery) — not for active↔disabled, see the dedicated routes below. Compare-and-set on `revision`. |
| POST /accounts/{account_id}/membership | write | ✅ | – | – | – | – | HUMAN_SESSION | `admin` only. Grants a role. |
| DELETE /accounts/{account_id}/membership/{role} | write | ✅ | – | – | – | – | HUMAN_SESSION | `admin` only. Revokes a role; protects the realm's last enabled administrator. |
| POST /accounts/{account_id}/disable | write | ✅ | – | – | – | – | HUMAN_SESSION | `admin` only. Protects the last enabled admin. Compare-and-set on `revision`. |
| POST /accounts/{account_id}/enable | write | ✅ | – | – | – | – | HUMAN_SESSION | `admin` only. Valid only from `disabled`. |
| POST /accounts/{account_id}/recovery-codes | write | ✅ | – | – | – | – | HUMAN_SESSION | `admin` only. Generates plaintext recovery codes shown exactly once — never cached or logged. |
| POST /accounts/{account_id}/recovery/complete | write | ✅ | – | – | – | – | HUMAN_SESSION | Redeems a recovery code and sets a new password. No client UI exists for this route on either platform yet (pre-existing gap, not introduced here). |
| POST /accounts/{account_id}/delete | write | ✅ | – | – | – | – | HUMAN_SESSION | `admin` only. Step one of two-step deletion — marks `deletion_pending`, revokes sessions, protects the last admin. Both clients additionally require a fresh client-side step-up before calling this (hub-side step-up enforcement is tracked separately, issue #1900). |
| POST /accounts/{account_id}/tombstone | write | ✅ | – | – | – | – | HUMAN_SESSION | `admin` only. Step two, irreversible — requires the account already be `deletion_pending`. Same client-side step-up requirement as `/delete`. |
| GET /accounts/{account_id}/security-history | read | ✅ | – | – | – | – | HUMAN_SESSION | `admin` or `reviewer` role. Bounded recent login attempts and sessions. |

---

## Summary counts

| Category | Count |
|---|---|
| SIGNED (target posture met) | 7 |
| READ_BEARER (acceptable) | 17 |
| COMPAT_QUARANTINE (bearer-only mutation) | 22 |
| HUMAN_SESSION (human-session/account authority, see addendum above) | 33 |
| **Total routes** | **79** |

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
