# Changelog

All notable changes to **forgewire-fabric** are tracked here. Format roughly
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [semantic versioning](https://semver.org/spec/v2.0.0.html) for the Python
package. The VSIX (`vscode/`) is versioned independently.

## [Unreleased]

### Changed

- **Managed deployment clones and durable operator overlays**: standalone clone
  refreshes now archive dirty work to a host-specific branch and external Git
  bundle before a fast-forward. Consumer-owned NSSM services, identities, and
  binaries are registered under `C:\ProgramData\forgewire-operator`, cached,
  and replayed after install/redeploy without storing secret values in source.
  The Python integration/installer surface is now 0.20.0.

- **Rust-authoritative hub consolidation (WI-128)**: `fabric-hub` 0.11.0 now
  owns the last parity routes: capability waiting diagnostics, true task SSE,
  operator-audited rqlite snapshot/import, and the explicitly degraded legacy
  claim quarantine. The duplicate FastAPI/rqlite/policy implementation and
  its closed-app re-export shims are removed; Python 0.19.0 is now strictly
  the HTTP client, MCP, CLI, discovery, and runner-side integration layer.
  `forgewire-fabric hub start` launches the installed native binary.
### Security

- **A bare `reviewer`-role token could mint or revoke role tokens, including
  a fresh `dispatcher`/`runner`/`approver` token for itself (privilege
  escalation)** (`fabric-hub`): `required_roles`'s generic `/admin/*` ->
  `["reviewer"]` catch-all covered `/admin/role-tokens` and its
  `/split`/`/migrate` and `DELETE .../{id}` siblings too, so any caller
  holding only `reviewer` -- a role with no other special standing over
  `dispatcher`/`runner`/`approver` anywhere else in this route table -- could
  call `POST /admin/role-tokens` and hand itself a brand-new token carrying
  any of those roles, or revoke another automation credential outright.
  Caught live 2026-07-28 during a 114C.8 drill re-run: a probe of a real
  installed reviewer token's boundaries, expected to fail, succeeded instead
  (reverted immediately, no lasting effect). Fixed by carving
  `/admin/role-tokens*` out of the generic catch-all into its own branch,
  mirroring `/accounts`'s existing read/write split: listing (`GET`) stays
  reviewer-readable alongside `admin`, but issuing, splitting, migrating, and
  revoking now require `admin` -- a role no role token or the legacy bearer
  can ever hold, by construction (`admin` is deliberately absent from
  `VALID_ROLES`). The legacy bearer's own narrow three-path bootstrap
  exception (letting a fresh install split/migrate its compatibility bundle
  before any role token or human admin account exists) is untouched -- it
  bypasses this route table entirely via its own dedicated check. New
  regression test (`a_bare_reviewer_token_cannot_mint_or_revoke_role_tokens`)
  proves the exact escalation path is closed while `GET`/legacy-bootstrap
  behavior is unchanged; both route-policy baseline fixtures
  (`role_policy_baseline.json`'s machine-surface guard rejects `admin`
  outright, so the new pinned rows live in
  `human_account_route_policy_baseline.json` instead, alongside `/accounts`
  and `/settings`'s identical human-only-role carve-outs) and
  `admin_only_routes_reject_every_machine_role`'s hardcoded route list were
  updated to cover the four newly-admin-gated paths. Deployed to both live
  cluster nodes the same session via the existing self-update mechanism
  (`forgewire-fabric-cli update`), verified live on each afterward (same
  installed reviewer bearer that previously succeeded now correctly denied).
  **Operational note**: any existing tooling that relied on a bare
  `reviewer`-scoped automation token to manage the role-token fleet now
  needs a real, signed-in human `admin` session for that instead --
  reviewer's remaining role-token access is read-only (`GET`/list).

### Fixed

- **Genesis-minted accounts couldn't sign in after the seal (114D D.2)**
  (`fabric-accounts`, `fabric-store-rqlite`, `fabric-hub`): `complete_genesis`
  minted the Master's `human_accounts`/`human_memberships` rows under the
  freshly-generated `realm_identity` UUID, but every pre-existing 114C route
  (`/auth/login`, passkey login/registration, admin account routes,
  `require_bearer`'s own session resolution) is hardcoded to
  `fabric_hub::auth::DEFAULT_REALM_ID` (`"default"`) when scoping account
  lookups. The two values never matched. `/setup/complete`'s own embedded
  post-seal login worked (it used the matching value internally), but every
  *subsequent* `/auth/login` attempt failed with the same non-enumerating
  `InvalidCredentials` a wrong password produces -- indistinguishable without
  direct database inspection. Caught live during a genuine two-machine
  clean-slate reinstall and real Desktop sign-in attempt; not caught by the
  prior automated test suite, which had (unknowingly) baked the identical
  conflation into its own assertions (fixed alongside this: three tests now
  assert against the production-matching realm value, plus a new explicit
  `realm_identity_id != DEFAULT_REALM_ID` regression guard).
  `complete_genesis` now takes an explicit `account_realm_id` parameter,
  kept distinct from the realm identity's own freshly-minted id. Both live
  nodes were patched immediately (direct SQL) and then redeployed on the
  fixed binary, reverified with a real end-to-end login against the
  redeployed hub.

- **Desktop's restriction banner conflated the signed-in human's account role
  with the installed automation token's role (114C.7)** (`desktop`): the
  "Hub and fleet" dashboard (tasks/approvals/secrets/audit) authenticates
  exclusively through the installed, machine-level automation credential
  (`hub_client()`/`load_hub_token()`), a categorically different, deliberately
  separate credential from the signed-in human session used only for
  account self-service (confirmed intentional -- see `accountMe`'s doc
  comment in `main.tsx` and `command-availability-live-wiring-handoff.md`'s
  "Explicitly out of scope" note). The restriction banner shown when that
  automation token lacks a required role (e.g. "Requires reviewer role
  access. Current token roles: dispatcher, runner, observer.") named only the
  automation token's roles, with nothing distinguishing it from the caller's
  own account role -- so a signed-in `admin` reasonably read the message as
  describing *their own* access, not a separate machine credential. Caught
  live 2026-07-28 when a genesis-minted admin (freshly signed in after the
  realm-id fix above) saw the banner and could not tell why "admin" did not
  mean "full access." Fixed by appending the signed-in account's own role(s)
  to the restriction message wherever one is shown (the aggregate
  `RestrictionStrip` and the per-page Secrets/Approvals/Audit banners),
  extracted into a new, independently testable `restrictionMessages.ts`
  (mirroring the earlier `AccountPage` extraction, since `main.tsx` cannot be
  imported directly by a test). No credential or authorization logic
  changed -- display only. Separately (an operational fix, not a code
  change): minted a `reviewer`-authority role token via the legacy bearer's
  self-authorizing `POST /admin/role-tokens` bootstrap path and installed it
  as the Desktop's automation token, which is the actual, already-designed
  mechanism for extending the dashboard's authority (per `role-tokens
  migrate`/`issue` and `auth.rs`'s `legacy_bundle_is_narrow_and_only_
  bootstraps_role_tokens` test).

- **Desktop's browser-based WebAuthn bridge could never succeed against the
  default IP-literal hub URL (114C.6)** (`desktop`): `webauthn_bridge::
  build_bridge_url` opened the hub-served passkey bridge page at whatever
  literal host form `hub_url` carried, verbatim. `sanitize_url`/
  `normalizeHubUrl` actively rewrite a user's `localhost` hub URL *to*
  `127.0.0.1` for transport (the `GuiConfig` default), so the bridge page
  opened at an IP-literal origin -- which the WebAuthn spec forbids from
  ever satisfying any rp_id, including the realm's own default of
  `"localhost"`. Every passkey login and registration through the browser
  bridge failed with the browser's own `SecurityError` (seen live in Chrome
  as "This is an invalid domain.") before any authenticator prompt could
  even run. `native_webauthn::derive_loopback_origin` had already solved the
  identical problem for the native Windows Hello ceremony; the browser-bridge
  path never received the equivalent fix, and none of its existing tests
  exercised a `127.0.0.1` `hub_url` to catch it. Fixed with a new
  `normalize_bridge_host`, which rewrites a loopback `hub_url`'s host
  (`127.0.0.1`, `localhost`, or any `.localhost` subdomain) to the literal
  `"localhost"` before the bridge URL is built, leaving a remote (non-
  loopback) hub's `hub_url` untouched since that realm's rp_id is whatever it
  configured. A prior gap the same defect would also affect (the VSIX's
  TypeScript `buildBridgeUrl` in `packages/fabric-client-core/src/
  webauthnBridge.ts` mirrors this function field-for-field and has the
  identical bug against its own auto-discovered `http://127.0.0.1:<port>`
  local hub) is intentionally not touched by this change -- out of this
  fix's scope, tracked separately.

- **The VSIX's WebAuthn bridge had the identical IP-literal-origin bug as
  Desktop's, above (114C.6)** (`fabric-client-core`): `buildBridgeUrl` in
  `packages/fabric-client-core/src/webauthnBridge.ts` mirrors Desktop's
  `webauthn_bridge::build_bridge_url` field-for-field, and had mirrored its
  bug too -- it built the bridge page URL from `options.hubUrl` verbatim. The
  VS Code extension's `hubClient.ts` auto-discovers a local hub at the
  literal `http://127.0.0.1:<port>` (`vscode/src/hubClient.ts:447`), and the
  realm's WebAuthn `rp_id` defaults to `"localhost"` (114D sec 5); per the
  WebAuthn spec an IP-literal origin can never satisfy any non-empty
  `rp_id`, so the browser would refuse every `navigator.credentials.get`/
  `create()` call from that origin, exactly as reproduced live on Desktop.
  Fixed with a new `normalizeBridgeHost`, mirroring Desktop's
  `normalize_bridge_host`: it rewrites a loopback `hubUrl`'s host
  (`127.0.0.1`, `localhost`, or any `.localhost` subdomain) to the literal
  `"localhost"` before the bridge URL is built, leaving a remote (non-
  loopback) hub's `hubUrl` untouched. Hand-parsed via regex rather than the
  WHATWG `URL` constructor, since this package compiles with no DOM and no
  Node lib types and `URL` is unavailable to its source files -- confirmed
  by `test_client_core_architecture.py`'s no-DOM/no-node purity contract
  staying green. 4 new regression tests added mirroring the Rust side's
  `build_bridge_url`-level cases. `npm run build --workspace
  @forgewire/fabric-client-core`, `npx vitest run --root
  packages/fabric-client-core` (71 passed), `npx vitest run --root desktop`
  (58 passed), and `npm run compile --workspace forgewire`
  (typecheck/bundle/verify:bundle) all green. Not verified against a live
  browser passkey ceremony in VS Code itself this session.

### Added

- **Dual human/client audit attribution wired across the full route surface
  (114C.4, AC-114C-2)** (`fabric-hub`): the 2026-07-18 dual-attribution audit
  run left this at 1 of 25 tracked `audit_append` call sites carrying
  `attribution()`. Re-surveying the actual current surface (rather than
  trusting that stale count) found it had grown to 52 sites -- the original
  count never included `routes/accounts.rs`, `routes/setup.rs`, or the two
  denial-audit sites in `auth.rs` proper, and `routes/authn.rs` had grown
  from 2 to 10 sites since passkey routes landed. 30 of the 52 already
  carried `attribution()` from prior, uncounted work; this change wires the
  remaining 14 that had a real, already-authenticated `AuthContext`
  available but weren't using it: all 4 role-token admin routes
  (`admin.rs`), both authentication-denial audit paths (`auth.rs`, with a
  structural fix distinguishing "no actor ever resolved" -- a rejected or
  missing bearer -- from "known automation, no human", which previously
  collapsed to the same shape), `approvals.rs`'s ForgeLink-decision sync (new
  actor extraction on `get_approval`), the step-up-path passkey
  replay-suspected event (`authn.rs`), both secret rotation/deletion routes
  (`secrets.rs`, new actor extraction on both handlers), the settings-change
  event (`settings.rs`, upgraded from a bare subject string to the full
  shape), the egress-denied event (`streams.rs`, new actor extraction on
  `append_progress`), and the runtime intent gate (`tasks.rs`, new actor
  extraction on `evaluate_intent`). The remaining 8 sites are structurally
  out of scope, not a gap: 5 are pre-authentication routes (bootstrap, login,
  refresh-replay, login-time passkey-replay, genesis completion) where no
  `AuthContext` exists yet -- the audited event *is* the act of establishing
  or failing to establish one -- and 1 (`stdin_input`) authenticates via
  Ed25519 dispatcher-signature verification, a categorically different,
  already-cryptographically-verified identity model with no `AuthContext` on
  that path at all. Also closes a separately-recorded gap from the same
  2026-07-18 run ("no test... asserts a secret's absence from" a persisted
  audit event): a new `dual_attribution_leak_scanner.rs` integration test
  seals a real secret, appends a payload nesting an `attribution()`-shaped
  actor object beside the secret's plaintext through the real
  `audit_append`, and asserts against the persisted row that the plaintext
  is redacted while the actor object survives intact -- mutation-verified by
  temporarily removing `audit_append`'s redaction call and confirming the
  test fails with the plaintext visible before restoring it. Does not close
  AC-114C-2: role-token/Ed25519 identity preservation is architecturally
  untouched (only audit payload content changed) and was already
  live-verified separately; recovery remains backend-only with no client UI
  or live redemption drill; and the three step-up/passkey-gated live drills
  114C.8 deferred (disable-account, role grant/revoke, interactive
  dispatch+approval) still need to be re-run against the real cluster now
  that the WebAuthn bridge fix above removes their blocker.

- **Native Windows Hello passkey enrollment backend (114D D.3)** (`fabric-client`,
  `desktop`): partial progress toward AC-114D-3 -- the hard technical risk
  (does the native Windows WebAuthn API genuinely force Hello, not a USB key)
  is retired and evidenced. UI wiring and native login remain; live human
  verification is now done -- a deliberately-watched run on the real
  Precision machine (2026-07-28) produced a real credential (confirmed
  against `human_credentials`: 795 bytes of genuine public key material) via
  an actual completed Windows Hello ceremony. The one-off manual test that
  drove it (`live_manual_register_native_against_the_local_hub`) is deleted
  per its own doc comment now that the result is recorded in the evidence
  run.
  - `fabric-client`: `HubClient::register_passkey_options`/`register_passkey_verify`,
    mirroring `step_up_options`/`step_up_verify`'s session-bearer-authenticated
    shape -- closes half of the "register/login passkey options+verify are not
    wired here" gap this crate's own doc comment named (login stays unwired;
    no session exists yet to authenticate that call with).
  - `desktop`: new Windows-only `native_webauthn` module drives
    `webauthn-authenticator-rs`'s `Win10` backend directly -- no system browser,
    no webview-origin problem (there is no webview in this path at all).
    `force_platform_attachment` sets `authenticator_attachment: Platform` +
    `user_verification: Required` before every ceremony, overriding rather than
    only filling any pre-existing hint; verified against the actual
    `webauthn-authenticator-rs` source (not assumed) that this genuinely
    reaches the real `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS::dwAuthenticatorAttachment`
    Windows API parameter, and two of the new tests actually ran the real logic
    on Windows. `derive_loopback_origin` forces the ceremony origin's host to
    `localhost` (matching 114D's `rp_id` default) and refuses outright for a
    non-loopback `hub_url`, matching 114D sec 5's own accepted scope (native
    ceremonies only work against a local hub). A fixture test locks in the
    real (source-verified) double-nested wire shape
    `{"public_key":{"publicKey":{...}}}` the hub's response actually has --
    the exact shape a prior browser-bridge bug got wrong. Registration only
    (matching AC-114D-3's "enrollment" framing); the `Win10` backend's
    `do_authentication` half for native login is a natural follow-up, not
    built here. `#[cfg(not(windows))]` returns a typed "not supported" error
    so the Tauri command exists cross-platform even though only Windows
    implements it.
  - `cargo test --workspace` green (2 new transport tests; 9 new
    `native_webauthn` tests, including the Windows-only attachment-forcing
    ones actually executing on this machine). clippy clean.
    `scripts/validate_local.ps1` green end to end (needed several re-runs
    purely due to the documented live-cluster `settings_cas_..._on_real_rqlite`
    quorum-loss flake, confirmed environmental -- the local rqlite node had
    just restarted).
  - No frontend/UI change: `register_passkey_native` is a registered,
    invokable Tauri command, but nothing in the existing Account page calls
    it yet, so an operator's actual enrollment experience is unchanged by
    this slice.
- **Genesis setup backend (114D D.2)** (`fabric-accounts`, `fabric-store-rqlite`,
  `fabric-hub`): closes AC-114D-2 -- the slice that mints the real Master.
  - `fabric-accounts`: `AccountOrchestration::complete_genesis` -- a new
    `GenesisOutcome { realm, account, recovery_codes }` orchestration method
    atomically establishing the realm's founding identity AND the Master's
    account/password-credential/admin-membership/durable recovery codes in
    one SQL transaction, alongside `bootstrap_first_administrator`.
  - `fabric-store-rqlite`: the transaction inserts into *two* singleton
    tables (`realm_identity`, `human_bootstrap_state`) in one batch, so a new
    `realm_or_bootstrap_conflict` helper reads SQLite's own constraint-error
    message to disambiguate which one a losing caller lost to --
    `RealmAlreadyEstablished` vs `BootstrapClosed` -- rather than collapsing
    both into one generic conflict. Genesis recovery codes are durable
    (`expires_at` NULL), unlike `generate_recovery_codes`'s 72-hour
    admin-assisted-recovery TTL -- verified redeemable through the existing
    `complete_recovery_with_code` flow.
  - `fabric-hub`: new `routes::setup` module -- `GET /setup/status` (reports
    `bootstrap_open`/`realm_established`/`sealing`, the last always `false`
    in this increment since one SQL transaction has no partial-commit window
    for it to observe) and `POST /setup/complete`, gated by the *same*
    loopback + `bootstrap_open` primitive `/auth/bootstrap` already uses
    (`bootstrap_source_allowed`, widened to `pub(crate)` and reused
    verbatim, not reimplemented). `/setup/complete` composes
    `complete_genesis` with `authenticate_and_issue_session` (the same call
    `/auth/login` makes) so the response lands the operator signed-in,
    optionally proof-of-possession-bound (114E) via `session_public_key` --
    two separate calls, not one bigger transaction, so a session-issuance
    hiccup after a successful seal leaves a real Master retryable via normal
    login rather than a broken realm. Both routes are public (unreachable
    behind `require_bearer` by construction -- no credential exists yet).
  - Recovery-code minting is password-anchored in this increment (matching
    the design's own no-authenticator fallback, 114D sec 14.4) -- native
    passkey enrollment (D.3) and the high-security root-credential set
    (sec 19) compose afterward via the already-existing, now
    `admin`-reachable `/auth/passkeys/register/*` routes, since the minted
    Master already holds `admin` the instant genesis seals.
  - `cargo test --workspace` green throughout: 6 new store-layer tests
    (concurrent-genesis race, weak-password-rejects-before-writing, durable
    recovery-code redemption) and 8 new HTTP-level tests (loopback gating,
    empty-origins rejection, the legacy-admin-no-realm precondition, and an
    end-to-end proof that the genesis-issued session authenticates a real
    request with the admin role). clippy -D warnings clean;
    `scripts/validate_local.ps1`'s full 13-step gate green end to end.
- **Realm-identity store + WebAuthn rewiring (114D D.1, increments 2-3)**
  (`fabric-store-rqlite`, `fabric-store`, `fabric-hub`): closes AC-114D-1 --
  every node's WebAuthn verifier now reads `rp_id`/`origins` from the
  replicated realm identity instead of a local settings document, the
  per-node relying-party trap (114D sec 5).
  - `fabric-store-rqlite`: a `realm_identity` singleton table
    (`id INTEGER PRIMARY KEY CHECK (id = 1)`, the same CAS shape as
    `human_bootstrap_state`) added to `init_human_accounts_schema`; a
    `RealmRepository for RqliteStore` impl whose `establish_realm_identity`
    is a single-statement compare-and-set insert -- a second genesis hits
    the PRIMARY KEY conflict and maps to `RealmAlreadyEstablished` with no
    partial state, proving the concurrent-genesis guard (114D sec 15.1).
    `origins` persists as a JSON array, order preserved.
  - `fabric-store`: `FabricStore`'s supertrait list gains `RealmRepository`
    (mirroring how `AccountRepository`/`SessionRepository`/etc. were added
    in 114C), so both hub startup and the doctor route can read the realm
    identity through the single `Arc<dyn FabricStore>` handle they already
    hold.
  - `fabric-hub`: `webauthn::build_from_realm_or_settings` prefers the
    realm identity when established, falling back to legacy
    `auth.passkeys` settings for a pre-114D deployment or a node that
    hasn't run genesis; `diagnose_realm_or_settings` mirrors the same
    precedence so `GET /auth/webauthn/doctor`'s `ready` field can never
    disagree with what the running instance was actually built from (the
    existing `diagnose_ready_always_agrees_with_build_from_settings`
    invariant, now also proven across the realm branch). Both are wired
    into `main.rs` startup and the doctor route.
  - `cargo test --workspace` green throughout (fabric-store-rqlite's full
    suite against ephemeral rqlite, fabric-hub's 80 lib tests including 7
    new realm-path webauthn tests, 3 new realm_identity store-integration
    tests proving the CAS race). No client change (backend only, matching
    D.1's stated scope).
- **Realm-identity port layer (114D D.1, increment 1)** (`fabric-accounts`): the
  domain contract for the realm's founding cryptographic identity — a
  `RealmIdentity` record (`realm_id`, `name`, `rp_id`, `origins[]`, `created_at`,
  `genesis_node`, `key_alg`) and a `RealmRepository` port with
  `get_realm_identity` + a compare-and-set `establish_realm_identity` singleton.
  A new typed error `RealmAlreadyEstablished` (distinct from `BootstrapClosed`)
  lets genesis (D.2) detect a lost concurrent-genesis race and convert to join;
  it rippled through the Rust `ALL_CODES`, the TypeScript
  `TYPED_AUTH_ERROR_CODES`, and the shared `account_session_summary.json`
  fixture in the same change, keeping the cross-language error contract in sync.
  Port only — the rqlite `realm_identity` table/CAS impl and the WebAuthn
  rewiring land in the next D.1 increments.
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


