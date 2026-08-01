//! Repository traits: the domain layer's contract for durable storage.
//! Implementations (rqlite-backed, per the crate-boundary lock) live in
//! `fabric-store`/`fabric-store-rqlite` starting at 114C.2. Nothing in this
//! crate implements these traits -- that is the point of the boundary:
//! "Store implementations depend on domain contracts; domain policy does not
//! depend on HTTP or a client renderer."
//!
//! Method sets here are deliberately not exhaustive of the full 114C API
//! surface (bulk operations, pruning, retention) -- they cover the
//! operations whose *shape* is load-bearing for later milestones' invariants,
//! most importantly `count_enabled_admins`, which the last-administrator
//! compare-and-set protection (114C.5) is built on and which is seeded here
//! so the trait boundary doesn't have to be revisited to add it later.

use async_trait::async_trait;

use crate::domain::{
    Account, AccountId, AccountStatus, ClientKind, Credential, CredentialId, Membership,
    MembershipId, RealmId, RealmIdentity, Role, Session, SessionId,
};
use crate::dto::LoginAttemptDto;
use crate::error::AccountsResult;
use crate::secret::SecretString;

/// The realm's founding-identity authority (114D D.1). Read on every hub
/// startup to configure the WebAuthn verifier from the replicated realm
/// record (114D sec 15.1); written exactly once, at genesis (114D D.2).
#[async_trait]
pub trait RealmRepository: Send + Sync {
    /// The established realm identity, or `None` if no realm exists yet
    /// (a fresh, pre-genesis cluster). Drives the `¬realm_established` branch
    /// of the setup FSM (114D sec 14.1) and lets the WebAuthn builder fall
    /// back to legacy `auth.passkeys` settings on a pre-114D hub.
    async fn get_realm_identity(&self) -> AccountsResult<Option<RealmIdentity>>;

    /// Establish the realm's founding identity as a compare-and-set singleton:
    /// the insert is guarded so exactly one caller wins under concurrent
    /// genesis, and every loser gets [`crate::error::AccountsError::RealmAlreadyEstablished`]
    /// with no partial state (114D sec 15.1). Returns the stored record on
    /// success. `origins` is persisted verbatim (order preserved); the store
    /// is not responsible for secure-context filtering -- that stays in the
    /// hub's WebAuthn builder where it already lives.
    async fn establish_realm_identity(
        &self,
        realm: &RealmIdentity,
    ) -> AccountsResult<RealmIdentity>;
}

#[async_trait]
pub trait AccountRepository: Send + Sync {
    async fn create_account(&self, account: Account) -> AccountsResult<Account>;
    async fn get_account(&self, account_id: &AccountId) -> AccountsResult<Account>;
    async fn find_by_username(
        &self,
        realm_id: &RealmId,
        username_normalized: &str,
    ) -> AccountsResult<Option<Account>>;
    /// Compare-and-set on `revision`, per the plan's "one-statement atomic
    /// writes or explicit compare-and-set revision checks" write discipline.
    async fn update_status(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
        new_status: AccountStatus,
    ) -> AccountsResult<Account>;
    async fn list_accounts(
        &self,
        realm_id: &RealmId,
        limit: i64,
        offset: i64,
    ) -> AccountsResult<Vec<Account>>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn add_credential(&self, credential: Credential) -> AccountsResult<Credential>;
    async fn get_active_for_account(
        &self,
        account_id: &AccountId,
    ) -> AccountsResult<Vec<Credential>>;
    async fn mark_compromised(
        &self,
        credential_id: &CredentialId,
        now: &str,
    ) -> AccountsResult<Credential>;
    async fn revoke(&self, credential_id: &CredentialId, now: &str) -> AccountsResult<Credential>;
    /// Replace a credential's verifier in place -- "support rehash-on-success
    /// when the configured work factor increases." Added in 114C.3 once a
    /// concrete caller (login orchestration) existed to need it; the trait
    /// was deliberately not exhaustive of the full CRUD surface from the
    /// start (see this file's module doc comment).
    async fn rehash_secret(
        &self,
        credential_id: &CredentialId,
        new_secret_verifier: crate::secret::SecretString,
        new_algorithm: &str,
        new_algorithm_params: Option<serde_json::Value>,
        new_version: i64,
    ) -> AccountsResult<Credential>;
}

#[async_trait]
pub trait MembershipRepository: Send + Sync {
    /// Implementations must reject a `Role::Runner` membership the same way
    /// [`crate::domain::Membership::for_human`] does at the domain layer --
    /// this is the store-side half of the double-enforced invariant the name
    /// lock describes ("the store rejects `runner` membership for a human
    /// account").
    async fn grant(&self, membership: Membership) -> AccountsResult<Membership>;
    async fn revoke(&self, membership_id: &MembershipId, now: &str) -> AccountsResult<Membership>;
    async fn list_for_account(&self, account_id: &AccountId) -> AccountsResult<Vec<Membership>>;
    /// The read the last-administrator invariant is checked against before
    /// any mutation that could remove the last one. Counts only active
    /// (non-revoked) `admin` memberships on enabled accounts.
    async fn count_enabled_admins(&self, realm_id: &RealmId) -> AccountsResult<i64>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn issue(&self, session: Session) -> AccountsResult<Session>;
    /// Read a session by ID without mutating it or checking expiry/revocation
    /// -- needed so a caller can verify ownership *before* performing a
    /// mutating operation on it (e.g. `DELETE /auth/sessions/{id}`'s "my
    /// session, or I am admin" check), rather than authorizing only after
    /// the side effect already happened.
    async fn get(&self, session_id: &SessionId) -> AccountsResult<Session>;
    /// Bind a hex Ed25519 public key to a session for proof-of-possession
    /// auth (114E). Called immediately after `issue` when a login carried a
    /// `session_public_key`; a session with a bound key thereafter
    /// authenticates by request signature (`resolve_signed_session` in
    /// `fabric-hub/src/auth.rs`) rather than by the opaque access secret. A
    /// one-time bind on a fresh, not-yet-used session: guarded to only set a
    /// currently-NULL key on a non-revoked session, so it cannot rebind or
    /// hijack an established session.
    async fn bind_public_key(
        &self,
        session_id: &SessionId,
        public_key_hex: &str,
        now: &str,
    ) -> AccountsResult<()>;
    /// Validates by the hashed lookup key, not by account/session ID --
    /// mirrors the plan's "opaque, server-side sessions" model: presenting
    /// the ID alone must never be sufficient.
    async fn validate_by_access_hash(&self, access_secret_hash: &str) -> AccountsResult<Session>;
    async fn rotate_refresh(
        &self,
        session_id: &SessionId,
        expected_refresh_secret_hash: &str,
        new_refresh_secret_hash: &str,
        now: &str,
    ) -> AccountsResult<Session>;
    async fn revoke(
        &self,
        session_id: &SessionId,
        reason: &str,
        now: &str,
    ) -> AccountsResult<Session>;
    async fn revoke_all_for_account(
        &self,
        account_id: &AccountId,
        reason: &str,
        now: &str,
    ) -> AccountsResult<i64>;
    async fn list_for_account(&self, account_id: &AccountId) -> AccountsResult<Vec<Session>>;
    /// Elevate a live session to `Aal2` and stamp its `step_up_at`, issuing
    /// a fresh access secret in the same write (114C.6). Satisfies the
    /// plan's "regenerate session secrets after... step-up" literally: same
    /// session row, new access secret, not a new session. Single-statement
    /// CAS on `session_id` + `revoked_at IS NULL` -- a revoked session
    /// cannot be stepped up, and there is no read-then-write window. Returns
    /// the new plaintext access secret (the caller hands it to the client;
    /// only its hash is stored), or `SessionRevoked` if the session no
    /// longer exists or is revoked.
    async fn rotate_access_secret_and_elevate(
        &self,
        session_id: &SessionId,
        now: &str,
    ) -> AccountsResult<crate::secret::SecretString>;
}

/// The result of a successful login: the durable session record plus the
/// two secrets the caller must hand to the client's protected storage and
/// never persist itself. `access_secret`/`refresh_secret` exist only in this
/// struct and the caller's immediate stack frame -- they are never written
/// anywhere except through a hash into the `human_sessions` row already
/// created by the time this struct is returned.
pub struct LoginOutcome {
    pub session: Session,
    pub access_secret: SecretString,
    pub refresh_secret: SecretString,
}

/// 114D D.2: the result of a successful genesis seal -- the newly
/// established realm identity, the minted Master account, and its plaintext
/// recovery codes. Recovery codes follow the same "only this call's return
/// value ever sees the plaintext" contract as
/// [`AccountOrchestration::generate_recovery_codes`]: only their hash is
/// persisted, so a caller that discards this value has permanently lost the
/// ability to ever redisplay them.
#[derive(Debug)]
pub struct GenesisOutcome {
    pub realm: RealmIdentity,
    pub account: Account,
    pub recovery_codes: Vec<SecretString>,
}

/// Cross-cutting operations spanning more than one of the four repositories
/// above, or requiring atomicity primitives (a real multi-statement
/// transaction) those traits do not expose generically. A separate trait
/// rather than inherent methods on a concrete backend type: `fabric-hub`'s
/// `HubState.store` is `Arc<dyn FabricStore>`, an abstraction over the
/// backend exactly like every other store operation in this codebase
/// (`create_or_get_pending_approval`, `put_settings_document`, etc. are all
/// trait methods, never inherent-only) -- these operations must be reachable
/// the same way, or route handlers cannot call them at all.
#[async_trait]
pub trait AccountOrchestration: Send + Sync {
    /// `true` if no administrator has completed bootstrap yet.
    async fn bootstrap_status(&self) -> AccountsResult<bool>;

    /// Atomically create the realm's first administrator: account, password
    /// credential, and admin membership, gated so that under concurrent
    /// callers exactly one succeeds and every other caller gets
    /// `BootstrapClosed` with no partial state created.
    async fn bootstrap_first_administrator(
        &self,
        realm_id: &str,
        username: &str,
        display_name: &str,
        password_plaintext: &str,
        now: &str,
    ) -> AccountsResult<Account>;

    /// 114D D.2: atomically establish the realm's founding identity (114D
    /// sec 15.1) AND the Master's account, password credential, admin
    /// membership, and durable (non-expiring) recovery codes -- the genesis
    /// seal, one SQL transaction. Loopback + `bootstrap_open` +
    /// `¬realm_established` gating is the caller's job (`/setup/complete`);
    /// this method's own guard is the CAS: the `realm_identity` singleton
    /// insert and the `human_bootstrap_state` singleton insert are both in
    /// the *same* transaction as the account rows, so a losing concurrent
    /// caller -- either singleton already taken -- gets
    /// [`crate::error::AccountsError::RealmAlreadyEstablished`] or
    /// [`crate::error::AccountsError::BootstrapClosed`] respectively, with
    /// **no** partial state either way: the whole batch commits or none of
    /// it does.
    ///
    /// Genesis recovery codes are durable break-glass material
    /// (`expires_at` NULL, never expires) -- unlike the 72-hour
    /// admin-assisted codes
    /// [`generate_recovery_codes`](AccountOrchestration::generate_recovery_codes)
    /// mints, the Master is not expected to redeem these within days, only
    /// if their credential is ever lost.
    ///
    /// `account_realm_id` is deliberately **not** the same value as the
    /// realm identity's own freshly-generated `realm_id` (which this method
    /// still mints internally for the `realm_identity` row). Every
    /// pre-existing 114C route (`/auth/login`, passkey login/registration,
    /// every admin account route) is hardcoded to `crate::auth`'s
    /// `DEFAULT_REALM_ID` when scoping `human_accounts`/`human_memberships`
    /// -- a fresh per-realm UUID here would mint an account those routes can
    /// never find (a real bug caught live: genesis's own embedded post-seal
    /// session worked, because it used the matching realm_id internally, but
    /// every *subsequent* `/auth/login` failed with `InvalidCredentials`,
    /// indistinguishable from a wrong password, since account lookup is
    /// realm-scoped and non-enumerating). The caller passes
    /// `DEFAULT_REALM_ID` here until a future increment threads a dynamic
    /// realm_id through the rest of 114C's surface -- a materially larger
    /// change than this fix, and out of scope for it.
    #[allow(clippy::too_many_arguments)]
    async fn complete_genesis(
        &self,
        realm_name: &str,
        rp_id: &str,
        origins: &[String],
        key_alg: &str,
        genesis_node: Option<&str>,
        account_realm_id: &str,
        username: &str,
        display_name: &str,
        password_plaintext: &str,
        recovery_code_count: i64,
        now: &str,
    ) -> AccountsResult<GenesisOutcome>;

    /// Verify a username/password and, on success, issue a new session.
    /// `client_fingerprint`, when supplied, throttles independently of the
    /// username dimension (114C.3 negative-auth).
    #[allow(clippy::too_many_arguments)]
    async fn authenticate_and_issue_session(
        &self,
        realm_id: &str,
        username: &str,
        password_plaintext: &str,
        client_kind: ClientKind,
        client_label: Option<&str>,
        client_fingerprint: Option<&str>,
        idle_timeout_minutes: i64,
        absolute_timeout_hours: i64,
        now: &str,
    ) -> AccountsResult<LoginOutcome>;

    /// Complete a WebAuthn authentication ceremony and issue a session
    /// (114C.6). Unlike [`authenticate_and_issue_session`](AccountOrchestration::authenticate_and_issue_session),
    /// this performs no credential verification itself -- the caller (the
    /// hub, which alone depends on the WebAuthn crypto crate; see
    /// `fabric_accounts::webauthn`'s module doc comment on why that
    /// verification cannot live in this crate) has already run
    /// `finish_passkey_authentication` and is handing over its verified
    /// result: which credential answered (`credential_id`) and that
    /// credential's new sign counter (`new_sign_count`) and updated,
    /// re-serialized public-key blob (`updated_public_key_blob`, from
    /// `Passkey::update_credential`).
    ///
    /// Atomically guards against a cloned/replayed authenticator: the sign
    /// counter is only accepted if it strictly advances the credential's
    /// previously stored counter (or that credential has never recorded
    /// one), with a carve-out for `new_sign_count == 0` -- many real
    /// authenticators never implement a counter and legitimately report 0
    /// on every assertion. A rejected counter returns
    /// [`crate::error::AccountsError::CredentialReplaySuspected`] and
    /// issues no session; the credential itself is not modified or revoked
    /// (a policy choice, not an oversight -- see this method's
    /// implementation for why auto-revocation-on-anomaly is left as a
    /// separate, explicitly reviewed toggle rather than a default).
    ///
    /// Apply the sign-count replay guard for a verified WebAuthn assertion:
    /// atomically advance the credential's stored sign counter (and its
    /// re-serialized public-key blob) only if the incoming counter strictly
    /// exceeds the stored one -- with a carve-out for `new_sign_count == 0`
    /// (authenticators that never implement a counter). Returns `Ok(())` on
    /// accept, [`crate::error::AccountsError::CredentialReplaySuspected`] on
    /// a non-advancing counter. Shared by both passkey *login*
    /// ([`authenticate_with_passkey_and_issue_session`](AccountOrchestration::authenticate_with_passkey_and_issue_session))
    /// and passkey *step-up*, so the security-critical CAS has exactly one
    /// implementation.
    #[allow(clippy::too_many_arguments)]
    async fn verify_and_advance_passkey_sign_count(
        &self,
        account_id: &AccountId,
        credential_id: &CredentialId,
        new_sign_count: i64,
        updated_public_key_blob: &str,
        backup_eligible: bool,
        backup_state: bool,
        now: &str,
    ) -> AccountsResult<()>;

    /// A successful WebAuthn assertion is user-verified by definition, so
    /// the issued session starts at `Aal2` with `step_up_at` set to `now`
    /// -- treating it as an implicit step-up avoids forcing the caller
    /// through a redundant step-up round-trip immediately after signing in
    /// with a passkey.
    #[allow(clippy::too_many_arguments)]
    async fn authenticate_with_passkey_and_issue_session(
        &self,
        realm_id: &str,
        account_id: &AccountId,
        credential_id: &CredentialId,
        new_sign_count: i64,
        updated_public_key_blob: &str,
        backup_eligible: bool,
        backup_state: bool,
        client_kind: ClientKind,
        client_label: Option<&str>,
        idle_timeout_minutes: i64,
        absolute_timeout_hours: i64,
        now: &str,
    ) -> AccountsResult<LoginOutcome>;

    /// Disable an account and revoke every session it has, with no
    /// last-administrator protection -- callers that must not accidentally
    /// remove the last admin use
    /// [`disable_account_protecting_last_admin`](AccountOrchestration::disable_account_protecting_last_admin)
    /// instead.
    async fn disable_account_and_revoke_sessions(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
        now: &str,
    ) -> AccountsResult<Account>;

    /// Disable an account, refusing if it is the realm's last enabled admin
    /// (114C.5). Revokes sessions on success.
    async fn disable_account_protecting_last_admin(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
        now: &str,
    ) -> AccountsResult<Account>;

    /// Change a password credential's verifier and revoke every existing
    /// session for the account.
    async fn change_password_and_revoke_sessions(
        &self,
        account_id: &AccountId,
        credential_id: &CredentialId,
        new_password_plaintext: &str,
        has_second_factor: bool,
        now: &str,
    ) -> AccountsResult<Credential>;

    /// Revoke an `admin` membership, refusing if the account is the realm's
    /// last enabled admin (114C.5). Revoking a non-admin membership is never
    /// blocked by this guard.
    async fn revoke_membership_protecting_last_admin(
        &self,
        membership_id: &MembershipId,
        now: &str,
    ) -> AccountsResult<Membership>;

    /// Bound `human_login_attempts`' growth without deleting a durable
    /// security event from the audit chain (this table is not the audit
    /// chain itself).
    async fn prune_login_attempts(&self, older_than: &str) -> AccountsResult<i64>;

    /// Admin-initiated account creation (114C.5's "account create/invite"
    /// deliverable): atomically create an account, a password credential,
    /// and one initial role membership. Unlike
    /// [`bootstrap_first_administrator`](AccountOrchestration::bootstrap_first_administrator),
    /// this is an ordinary, repeatable operation -- no singleton exactly-once
    /// gate -- and requires an already-authenticated administrator as
    /// `granted_by_account_id`. The created account is `Active` immediately
    /// (the admin sets/communicates the initial password out of band);
    /// self-service invite completion via a one-time recovery code is a
    /// distinct, not-yet-built capability (114C.5's separate recovery-codes
    /// deliverable).
    #[allow(clippy::too_many_arguments)]
    async fn create_account_with_password(
        &self,
        realm_id: &str,
        username: &str,
        display_name: &str,
        password_plaintext: &str,
        role: Role,
        granted_by_account_id: &str,
        now: &str,
    ) -> AccountsResult<Account>;

    /// Atomically create an "invited" account plus its initial membership --
    /// the shared primitive behind 114C.5's account-import apply path.
    /// Distinct from [`create_account_with_password`](AccountOrchestration::create_account_with_password):
    /// never creates a credential (nothing is imported by default, per the
    /// plan's ForgeWire-migration rule "password verifier import is disabled
    /// by default"), and starts the account at [`AccountStatus::Invited`]
    /// rather than `Active` (an imported user must enroll a new Fabric
    /// credential through the existing invitation/recovery flow before they
    /// can sign in at all). Rejects `Role::Admin` in addition to the usual
    /// `!role.human_assignable()` (`Runner`) rejection -- import must never
    /// auto-grant `admin`, a binding rule stated explicitly in the plan's
    /// migration section, stricter here than `grant_membership`'s general
    /// human-assignable check.
    #[allow(clippy::too_many_arguments)]
    async fn create_invited_account(
        &self,
        realm_id: &str,
        username: &str,
        display_name: &str,
        email: Option<&str>,
        role: Role,
        granted_by_account_id: &str,
        now: &str,
    ) -> AccountsResult<Account>;

    /// Grant a role to an existing account. Generates the membership ID and
    /// constructs it through [`crate::domain::Membership::for_human`] (which
    /// rejects `Role::Runner`), then delegates to
    /// [`MembershipRepository::grant`] -- the actual "an account may hold at
    /// most one active membership per role" invariant is enforced by a
    /// partial unique index at the store layer, not by a separate read here,
    /// so this method's job is only ID generation and construction, not the
    /// race-proofing itself.
    async fn grant_membership(
        &self,
        account_id: &AccountId,
        realm_id: &RealmId,
        role: Role,
        granted_by_account_id: &str,
        now: &str,
    ) -> AccountsResult<Membership>;

    /// Generate a fresh batch of one-time recovery codes for an account.
    /// Returns the plaintext codes -- this is the *only* place they ever
    /// exist outside this call's return value; only their hash is persisted
    /// (`human_recovery_codes.code_verifier`), so a caller that discards the
    /// return value without displaying it has permanently lost the ability
    /// to ever redisplay these codes, by construction ("never redisplayed").
    /// Generating a new batch does not revoke a prior batch's still-valid
    /// codes.
    async fn generate_recovery_codes(
        &self,
        account_id: &AccountId,
        count: i64,
        now: &str,
    ) -> AccountsResult<Vec<SecretString>>;

    /// Complete operator-assisted recovery: verify a presented one-time
    /// code, and on success atomically consume it, set a new password,
    /// revoke every existing session, and restore the account to `Active`.
    /// Requires the account to currently be `RecoveryRequired` (set by an
    /// admin via the account-status route) -- a valid code alone is not
    /// sufficient if the account was never actually placed into recovery,
    /// so a leaked/guessed code cannot be used against an account that
    /// isn't expecting recovery.
    async fn complete_recovery_with_code(
        &self,
        account_id: &AccountId,
        code_plaintext: &str,
        new_password_plaintext: &str,
        now: &str,
    ) -> AccountsResult<Account>;

    /// Step one of the plan's two-step deletion lifecycle
    /// (`deletion_pending -> deleted_tombstone`): mark an account for
    /// deletion and revoke its sessions, refusing if it is the realm's last
    /// enabled admin (the same last-administrator guard as
    /// [`disable_account_protecting_last_admin`](AccountOrchestration::disable_account_protecting_last_admin),
    /// applied here because deletion is strictly more destructive than
    /// disablement). Refuses if the account is already `deletion_pending`
    /// or `deleted_tombstone`. Known gap, not fixed here: the plan's
    /// "Sensitive-action step-up" list names "deleting an account" as
    /// requiring a recent high-assurance authentication; no step-up
    /// mechanism exists yet (114C.6, not built), so this method enforces
    /// only the role check every other admin route enforces.
    async fn initiate_account_deletion_protecting_last_admin(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
        now: &str,
    ) -> AccountsResult<Account>;

    /// Step two: irreversibly tombstone an account already in
    /// `deletion_pending`. Revokes every session, active credential, and
    /// active membership; scrubs `display_name`/`email_normalized` and
    /// replaces `username_normalized`/`username_display` with an
    /// account-ID-derived placeholder (freeing the original username for
    /// reuse, since the unique index is on `(realm_id,
    /// username_normalized)`). The row itself is never deleted -- "a
    /// tombstone preserves non-secret referential integrity for audit
    /// records": any audit payload that already carries this `account_id`
    /// continues to resolve to a real (if scrubbed) row, never a dangling
    /// reference.
    async fn complete_account_deletion(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
        now: &str,
    ) -> AccountsResult<Account>;

    /// 114C.5's "bounded login/session security history" deliverable: an
    /// account's most recent login attempts (successful and failed, newest
    /// first) and most recent sessions (including revoked ones, newest
    /// first), each capped at `limit` rows. "Bounded" is enforced with a SQL
    /// `LIMIT`, not by fetching everything and truncating in the caller --
    /// `human_login_attempts` and `human_sessions` are both unbounded-growth
    /// tables by design (the former is pruned periodically, not on read;
    /// sessions are never pruned at all), so an unbounded read here would
    /// reintroduce the exact growth problem `prune_login_attempts` exists to
    /// bound on the write side.
    async fn account_security_history(
        &self,
        account_id: &AccountId,
        limit: i64,
    ) -> AccountsResult<(Vec<LoginAttemptDto>, Vec<Session>)>;
}
