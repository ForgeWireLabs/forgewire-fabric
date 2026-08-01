# Changelog

All notable changes to **forgewire-fabric** are tracked here. Format roughly
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [semantic versioning](https://semver.org/spec/v2.0.0.html) for the Python
package. The VSIX (`vscode/`) is versioned independently.

## [Unreleased]

### Changed

- **Rust-authoritative hub consolidation (WI-128)**: `fabric-hub` 0.11.0 now
  owns the last parity routes: capability waiting diagnostics, true task SSE,
  operator-audited rqlite snapshot/import, and the explicitly degraded legacy
  claim quarantine. The duplicate FastAPI/rqlite/policy implementation and
  its closed-app re-export shims are removed; Python 0.19.0 is now strictly
  the HTTP client, MCP, CLI, discovery, and runner-side integration layer.
  `forgewire-fabric hub start` launches the installed native binary.

### Added

- **Proof-of-possession client (114E Slice 2)** (`fabric-client`, `desktop`):
  the client half of key-bound human sessions, coexisting with bearer.
  - `fabric-client`: a `SessionCredential` enum (`Bearer` | `Pop { session_id,
    secret_key_hex }`); `request_auth` signs the canonical `session-request`
    envelope with the bound Ed25519 key and sends `X-Forgewire-*` headers (body
    serialized once and hashed over the exact bytes sent; path signed without
    query, byte-identical to the hub's `resolve_signed_session`). `login` gains
    `session_public_key`; `me_signed`/`logout_signed`/`list_auth_sessions_signed`
    /`revoke_auth_session_signed` PoP variants; a sign→verify round-trip unit
    test mirrors `fabric-hub::human_pop_session`.
  - Desktop: a new **password sign-in** on the Account page establishes a human
    session (the first-session on-ramp a passkey-only client lacked) and, because
    the hub binds a per-session Ed25519 keypair at login, a proof-of-possession
    session — the private key is stored in the OS keyring
    (`SessionSecrets.sessionSigningKey`) and the renderer signs its self-service
    requests (`authMe`/`authLogout`/`listAuthSessions`/`revokeAuthSession`) with
    it instead of replaying the bearer. Bearer-only sessions are unaffected
    (the key is optional throughout). Verified end-to-end live against both
    cluster hubs (login → key-bound session → signed `/auth/me` → 200; wrong key
    rejected). Passkey-login PoP binding remains a follow-up.

### Fixed

- **Windows runner identity compatibility** (`installer`, `fabric-runner`,
  `loom-runner`): NSSM runner installation and the Python-to-Rust migration
  path now export both `FORGEWIRE_RUNNER_IDENTITY` and
  `FORGEWIRE_RUNNER_IDENTITY_PATH` to the same machine-scoped identity file.
  This preserves Python-runner compatibility while preventing native Rust
  runners from silently falling back to the shared default identity. Also
  corrects the Loom discovery-port documentation to the compiled default
  `48765`.


- **First-admin self-service lockout** (`fabric-hub`): the self-service routes
  (`/auth/me`, `/auth/sessions*`, `/auth/logout`, `/auth/logout-all`,
  `/auth/step-up/*`, `/auth/passkeys/*`, `/auth-policy`) were gated on
  `OBSERVE = [observer, reviewer]`, which excludes `admin`. Because bootstrap
  grants the first administrator only `admin`, a fresh first admin was `403`'d
  out of viewing itself, managing its sessions, logging out, stepping up, and
  — most damaging — **registering a passkey** (an `approver`- or
  `dispatcher`-only human was equally locked out). These are now gated on a
  `SELF_SERVICE` set of every human-assignable role; per-caller ownership is
  still enforced in the handler via `AuthContext.human_principal`. Completes the
  114D first-admin deadlock fix (which covered settings reads) for the
  session/credential surface. Found during the 114C.8 live closeout drills.

- **Host-role self-report authorization** (`fabric-hub`): `POST /hosts/roles` was
  gated at `reviewer`, so a node reporting its own infrastructure roles at
  install/enrolment time on the legacy cluster bearer (a `dispatcher/runner/observer`
  bundle) failed closed with `403`. It is now gated at the cluster-participant tier
  (`runner`, `dispatcher`, `reviewer`) — the same tier under which runner and
  dispatcher enrolment already write `host_roles` (`POST /runners/register`,
  `POST /dispatchers/register`), so it grants no new capability. Read-only
  `observer` still cannot write; the reviewer-gated `/labels/*` rename/relabel
  operations are unchanged. Baseline fixture and endpoint-auth matrix updated.

### Added

- **ForgeLink HITL routing** (`fabric-hub`): when ForgeLink is configured and
  reachable, a held approval is automatically routed to ForgeLink as the governed
  decision surface — an evidence-bearing `agent-governance-v1` approval request on
  ForgeLink's agent channel (ForgeLink work item 016, AGH-028; decision 0004).
  - New `forgelink` module: `ForgeLinkConfig::from_env()` reads `FORGELINK_BASE_URL`,
    `FORGELINK_CHANNEL_ID` (default `forgewire`), and `FORGELINK_CHANNEL_TOKEN`;
    `FORGELINK_HITL=off|0|false|disabled` is the operator opt-out.
  - Routing is **best-effort and time-bounded** (3s): on any failure — ForgeLink
    absent, unreachable, or opted out — the hub **falls back silently** to Fabric's
    built-in approval pane with no loss of function. ForgeLink is never a hard
    dependency.
  - The held-dispatch response includes `forgelink_routed` (the ForgeLink request
    id when routed), and the audit trail records `forgelink_routed` /
    `forgelink_unavailable`.
  - **Decision write-back:** `GET /approvals/{id}` reconciles a pending,
    ForgeLink-routed approval by polling ForgeLink's status (`fabric-<approval_id>`)
    and resolving it (approved/denied) exactly as Fabric's built-in approve/deny
    would, so the dispatcher's poll observes the governed decision and the held task
    proceeds. Needs `FORGELINK_MCP_TOKEN` (the status route is MCP-safe); best-effort,
    leaving the approval pending on any failure. Audit records
    `forgelink_decision_synced`.
  - 6 new `fabric-hub` unit tests (config/opt-out/reconcile gating, kind→authority
    mapping, the agent-governance-v1 request body, and decision classification).

- **Human accounts, sessions, and passkey sign-in** (114C): a Rust/rqlite human-principal,
  session, and administration authority, exposed through a matching self-service and admin
  UI on both clients (`vscode/` and `desktop/`).
  - **Self-service** (both clients): passkey sign-in/registration via a hub-served WebAuthn
    bridge page opened in the system browser; profile + active-session list; per-session
    revoke; sign-out (best-effort hub revoke, then an unconditional local credential clear);
    and an in-place step-up ceremony (`POST /auth/step-up/options` + `/verify`) that elevates
    a session to `aal2` and rotates its access secret — the WebAuthn assertion is the only
    thing that ever crosses into the browser, never the session's own bearer.
  - **Administration** (`admin` role only, both clients): account list, Create Account (role
    choices read from the hub's own `auth-policy`, never hardcoded), Disable/Enable
    (compare-and-set on account revision), Grant/Revoke Role, and two-step account deletion
    (`delete` → `deletion_pending` → `tombstone`) — deletion additionally requires a fresh
    step-up first on both clients, even though the hub does not yet enforce that itself
    (tracked in #1900).
  - Human-account roles gate client UI through a `requiresHumanRole` command descriptor,
    distinct from the pre-existing dispatcher/automation `fabric.*.write` authority set — an
    automation credential can never satisfy it.
  - `114B-parity-ledger.json`'s auth/account rows are all `"parity"`; see
    `work/active/114-forgewire-fabric/114C-human-accounts-sessions-operator-identity.md`.
  - Passkey credentials now capture WebAuthn backup eligibility/state (BE/BS
    flags) at registration and refresh them on every login/step-up —
    recorded metadata only, not a trust decision.
  - New `GET /accounts/export` / `POST /accounts/import` routes (`admin`/
    `reviewer`, step-up gated): a redacted profile-only account export, and
    a preview-by-default ForgeWire account-interchange import (`dry_run`
    defaults to `true`; imported accounts start `Invited` with no
    credential and a fresh batch of recovery codes, never `admin`/`runner`).
    Operator interface: `fabric-cli accounts export` / `accounts import
    --file <path> [--apply]`.
  - Authentication policy is now admin territory: a human `admin` can read
    hub settings and write the `auth.*` subtree (`auth.passkeys`,
    `auth.sessions`, `auth.bootstrap`) without first holding `reviewer`.
    This resolves the first-admin passkey-setup deadlock (a freshly
    bootstrapped admin previously could not enable passkeys because that
    required `reviewer`, which required a passkey — 114D groundwork). Every
    other settings key stays `reviewer`-only.
  - **Proof-of-possession human sessions** (114E Slice 1, server-side): a
    login may now bind a client-generated Ed25519 `session_public_key`, after
    which the client can authenticate requests by **signature** — four
    `X-Forgewire-*` headers over a canonical `{op,session_id,method,path,
    body_sha256,timestamp,nonce}` envelope verified against the session's
    bound key — instead of presenting the opaque bearer secret. No reusable
    secret crosses the wire. Fully **additive/coexisting**: bearer sessions
    (114C) still work unchanged, and the signed path only buffers the body
    when its header is present, so dispatch/stream routes are untouched.
    Clients keep using bearer until later slices flip them over.

## [0.5.0] - 2026-06-02  *(Rust workspace — see version note)*

> **Version note:** The Rust workspace tracks its own semver independently of the Python package.
> The Python package remains at 0.14.0 (last bump: M2.6.7). The Rust binaries (`forgewire-hub`,
> `forgewire-runner`, `forgewire-fabric-cli`) are at 0.5.0.

### Added

- **Stream bounded write buffer + named durability profiles** (`fabric-streams`, `fabric-hub`):
  - `DurabilityProfile` enum: `Strict` (every line written before HTTP response — default),
    `Balanced` (flush every 50 lines), `Throughput` (flush every 200 lines).
  - `StreamBuffer`: per-task bounded `VecDeque` with threshold-based flush and hard backpressure
    cap (500 lines / 2000 lines). `push()` returns `Some(batch)` at threshold; `push_bulk()`
    handles bulk appends. `flush_task()` force-drains before terminal state.
  - Hub wired end-to-end: `append_stream` and `append_stream_bulk` routes route through the
    buffer; `submit_result` force-flushes all pending lines before writing terminal state so
    no lines are lost at task completion regardless of profile.
  - `FORGEWIRE_HUB_STREAM_PROFILE` env var selects the profile at startup (default: `strict`).
  - `/healthz` now reports `stream_profile`, `stream_buffered_tasks`, `stream_buffered_lines`.
  - 17 new `fabric-streams` tests (counter + profile + buffer, including concurrency test).
  - OptiPlex hub (`forgewire-hub` 0.5.0, FORGEWIRE-HUB:8765) updated and verified live.

### Internal

- `fabric-hub/src/state.rs`: `HubState` gains `stream_buffer: Arc<StreamBuffer>`.
- `fabric-hub/src/routes/streams.rs`: strict path bypasses buffer (write-through); balanced/throughput
  paths accumulate and flush; `flush_batch()` helper groups by `worker_id` for bulk store writes.
- `fabric-hub/src/routes/health.rs`: buffer diagnostic counters added to healthz JSON.
- `fabric-hub/src/main.rs`: `FORGEWIRE_HUB_STREAM_PROFILE` parsed at startup; logged at info level.
- `todos/114-forgewire-fabric/phase-2.7-rust-first-runtime.md`: stream-buffering gate item
  checked off; definition-of-done at 8/10.

---

## [0.13.0] - 2026-05-13

### Added

- **Secret broker end-to-end** on the hub:
  - `POST /secrets`, `GET /secrets`, `DELETE /secrets/{name}` — auth-gated
    put/rotate/list/delete. Put-or-rotate is path-collapsed: existing names
    rotate, new names create. Values are never echoed; list returns metadata
    only (`name`, `version`, `created_at`, `last_rotated_at`).
  - Per-task `secrets_needed` column in the tasks schema. Dispatch records
    the requested secret **names** (never values) in the audit log.
  - `claim-v2` flow resolves `secrets_needed` against the broker and injects
    resolved values into the runner-side claim payload.
  - **Redaction** in `submit_result` / stream-append / progress paths:
    `log_tail` and `error` fields are scanned for secret values and replaced
    with `***SECRET:<name>***` markers before persistence.
  - `BlackboardClient` gained `put_secret`, `rotate_secret`, `list_secrets`,
    `delete_secret`, `resolve_secrets`.
  - CLI `forgewire-fabric secrets {put,rotate,list,delete}` group.
- **Live smoke script** `scripts/live_smoke_secrets.py` covering put → rotate
  → list-redaction → dispatch-with-secret → submit-with-redaction → cleanup.
  Validated against the OptiPlex 7050 hub (192.0.2.10:8765) on 2026-05-13.

### Internal

- `tests/hub/test_secret_broker.py` — 21 tests covering put/rotate/delete
  semantics, redaction substring matching, name-only audit recording,
  unknown-secret rejection at claim time, and version monotonicity.
- Full suite: **208 passed, 12 skipped** (0.12.0 baseline: 71 passed; the
  delta reflects expanded coverage across secret broker + adjacent paths
  that were previously thinner).
- `ops(install): resync bundled nssm-install-runner.ps1 with canonical script`
  — drift caught by `test_installer_assets_in_sync`; bundled installer asset
  now matches `scripts/install/nssm-install-runner.ps1` at commit `7a2b346`.

## [0.12.0] - 2026-05-13

### Added

- **Deregister endpoints** on the hub:
  - `DELETE /runners/{runner_id}` — removes a runner registration. Tasks with
    a dangling `worker_id` are intentionally preserved for audit replay.
  - `DELETE /dispatchers/{dispatcher_id}` — removes a dispatcher registration
    and also clears the `host_roles[dispatch]` row when no other dispatcher
    remains on that hostname. Prevents ghost host rows in `/hosts`.
  - Both endpoints are auth-gated and idempotent (re-delete returns 404).
- **`kind:agent` runner** + interactive approval roundtrip (`a59f303`). Adds a
  self-driving runner kind that participates in the claim → start → progress
  → result cycle while gated on approval, plus the live smoke harness at
  `scripts/live_smoke_approvals.py` exercising both `kind:agent` and
  `kind:command` end-to-end.
- **`ForgeWireAgentRunner` NSSM service installer** (`b3057e4`) and a remote
  wrapper (`4704361`) so a single command stands up the agent-runner kind
  on a Windows host alongside the existing command runner.
- **`package_version`** field on `/healthz` as an explicit alias for the
  existing `version` field. Clients can now read the hub's package version
  without guessing what `version` refers to.

### Changed

- **Routes package split** (`1bae1db`): hub HTTP routes moved from
  `forgewire_fabric.hub.server` into per-domain `forgewire_fabric.hub.routes.*`
  `APIRouter` modules (`admin`, `approvals`, `audit`, `auth`, `cluster`,
  `runners`, `secrets`, `streams`, `tasks`). The public route surface is
  byte-identical and pinned by `tests/hub/test_routes_layout.py`.
- **NSSM start-loop hardening** (`7a2b346`): runner services no longer
  thrash when the hub is briefly unreachable on boot.
- **`live_smoke_approvals.py`** now deregisters its own ephemeral runner +
  dispatcher in `_cleanup`, so repeated runs no longer accumulate ghost
  host rows.

### Fixed

- Ghost host rows (`live-approval-smoke`, `live-agent-approval-smoke`) that
  accumulated on every smoke run because the hub had no deregister path.
  Existing rows on long-lived hubs can now be removed with
  `DELETE /runners/{id}` and `DELETE /dispatchers/{id}`.

### Internal

- `Blackboard.delete_runner` and `Blackboard.delete_dispatcher` added to the
  persistence layer with the host-roles cleanup invariant noted above.
- 4 new tests in `tests/hub/test_host_summaries.py` cover the deregister
  paths (success, idempotency, auth, host-row cleanup).

---

## [0.11.6] and earlier

Pre-changelog releases — see `git log` for full history. Notable milestones:

- `0.11.6` — `c986074` `fix(hub): M2.6.3 preserve exception causes`
- `M2.6.4` — `f3628ff` startup migrated to FastAPI `lifespan`
- `M2.6.2` — `bd7215d` ruff floor added
- Earlier: dispatcher host-role registration, host-role summaries,
  machine-label promotion, rqlite cluster path, runner v2 protocol.


