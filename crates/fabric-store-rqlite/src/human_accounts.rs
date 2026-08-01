//! Additive rqlite schema and repository implementations for 114C's human
//! account, credential, membership, and session authority.
//!
//! Every table here is new -- `init_human_accounts_schema` touches no
//! existing table, matching 114C.2's acceptance requirement ("no change to
//! existing tables") and its rollback note ("Additive tables may remain
//! inert; destructive down-migrations are not required"). The seven tables
//! and their exact names are locked in `114C-name-lock.md`; the field list
//! per table follows the rqlite data model section of
//! `114C-human-accounts-sessions-operator-identity.md`.
//!
//! This module implements the repository *traits* defined in
//! `fabric-accounts` (the domain crate) -- it is the adapter, not the port,
//! matching the plan's rule: "Store implementations depend on domain
//! contracts; domain policy does not depend on HTTP or a client renderer."

use async_trait::async_trait;
use serde_json::{json, Value};

use fabric_accounts::domain::{
    Account, AccountId, AccountStatus, AssuranceLevel, ClientKind, Credential, CredentialId,
    CredentialKind, Membership, MembershipId, RealmId, RealmIdentity, Role, Session, SessionId,
};
use fabric_accounts::dto::LoginAttemptDto;
use fabric_accounts::error::{AccountsError, AccountsResult};
use fabric_accounts::repository::{
    AccountOrchestration, AccountRepository, CredentialRepository, GenesisOutcome, LoginOutcome,
    MembershipRepository, RealmRepository, SessionRepository,
};
use fabric_accounts::secret::SecretString;
use fabric_accounts::{password, secrets, validation};
use fabric_store::StoreResult;

use crate::{bool_val, generate_id, opt_str, str_val, utc_offset, RqliteError, RqliteStore};

impl RqliteStore {
    /// Create the seven `human_*` tables and their indexes if they do not
    /// already exist. Idempotent: safe to call on every hub startup, the
    /// same way `init_schema` is.
    pub async fn init_human_accounts_schema(&self) -> StoreResult<()> {
        let creates = [
            "CREATE TABLE IF NOT EXISTS human_accounts (account_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, username_normalized TEXT NOT NULL, username_display TEXT NOT NULL, display_name TEXT NOT NULL, email_normalized TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, disabled_at TEXT, deleted_at TEXT, revision INTEGER NOT NULL DEFAULT 0, security_version INTEGER NOT NULL DEFAULT 0)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_human_accounts_realm_username ON human_accounts (realm_id, username_normalized)",
            "CREATE TABLE IF NOT EXISTS human_credentials (credential_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, kind TEXT NOT NULL, secret_verifier TEXT, algorithm TEXT, algorithm_params TEXT, version INTEGER NOT NULL DEFAULT 1, webauthn_public_key TEXT, webauthn_credential_id TEXT, webauthn_transports TEXT, webauthn_sign_count INTEGER, webauthn_backup_eligible INTEGER, webauthn_backup_state INTEGER, label TEXT, created_at TEXT NOT NULL, last_used_at TEXT, compromised_at TEXT, revoked_at TEXT, revision INTEGER NOT NULL DEFAULT 0)",
            "CREATE INDEX IF NOT EXISTS idx_human_credentials_account ON human_credentials (account_id)",
            "CREATE TABLE IF NOT EXISTS human_memberships (membership_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, realm_id TEXT NOT NULL, role TEXT NOT NULL, granted_by_account_id TEXT, granted_at TEXT NOT NULL, revoked_at TEXT, revision INTEGER NOT NULL DEFAULT 0)",
            "CREATE INDEX IF NOT EXISTS idx_human_memberships_account ON human_memberships (account_id)",
            "CREATE INDEX IF NOT EXISTS idx_human_memberships_realm_role ON human_memberships (realm_id, role)",
            // `bound_public_key` (114E Slice 1): the hex Ed25519 public key a
            // proof-of-possession client bound to this session at login. NULL
            // for a bearer-only session (114C) -- both coexist. Included in
            // the fresh-install CREATE TABLE here; the idempotent ALTER TABLE
            // below covers hubs that already ran this statement before the
            // column existed.
            "CREATE TABLE IF NOT EXISTS human_sessions (session_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, realm_id TEXT NOT NULL, access_secret_hash TEXT NOT NULL, refresh_family_id TEXT NOT NULL, refresh_secret_hash TEXT NOT NULL, client_identity_id TEXT, client_kind TEXT NOT NULL, client_label TEXT, assurance_level TEXT NOT NULL, authenticated_at TEXT NOT NULL, step_up_at TEXT, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, idle_expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL, security_version_at_issue INTEGER NOT NULL, revoked_at TEXT, revoke_reason TEXT, revision INTEGER NOT NULL DEFAULT 0, bound_public_key TEXT)",
            // Login/access lookup: the hot path validating every authenticated request.
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_human_sessions_access_hash ON human_sessions (access_secret_hash)",
            // Account session lists (GET /auth/sessions).
            "CREATE INDEX IF NOT EXISTS idx_human_sessions_account ON human_sessions (account_id)",
            // Refresh-family replay detection.
            "CREATE INDEX IF NOT EXISTS idx_human_sessions_refresh_family ON human_sessions (refresh_family_id)",
            // 114E Slice 4: strict single-use nonces for proof-of-possession
            // requests. Lives beside `human_sessions` rather than in the main
            // schema because it is scoped to a human session and is created by
            // the same initializer the session path runs.
            //
            // PRIMARY KEY (session_id, nonce) IS the replay check: a duplicate
            // INSERT fails. That is what makes this strict, unlike the
            // "remember one last_nonce" compare-and-set used for dispatchers
            // and runners, which accepts the sequence A, B, A.
            "CREATE TABLE IF NOT EXISTS session_nonces (session_id TEXT NOT NULL, nonce TEXT NOT NULL, used_at TEXT NOT NULL, PRIMARY KEY (session_id, nonce))",
            // Supports the retention prune (`used_at < cutoff`).
            "CREATE INDEX IF NOT EXISTS idx_session_nonces_used_at ON session_nonces (used_at)",
            "CREATE TABLE IF NOT EXISTS human_refresh_uses (id INTEGER PRIMARY KEY AUTOINCREMENT, refresh_family_id TEXT NOT NULL, token_fingerprint TEXT NOT NULL, issued_at TEXT NOT NULL, used_at TEXT, replaced_at TEXT, result TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_human_refresh_uses_family ON human_refresh_uses (refresh_family_id)",
            "CREATE TABLE IF NOT EXISTS human_recovery_codes (code_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, code_verifier TEXT NOT NULL, batch_id TEXT NOT NULL, created_at TEXT NOT NULL, consumed_at TEXT, revoked_at TEXT, expires_at TEXT)",
            "CREATE INDEX IF NOT EXISTS idx_human_recovery_codes_account ON human_recovery_codes (account_id)",
            // 114C.6 Slice 1: `ceremony_state` holds the serialized
            // `webauthn-rs` ceremony state (PasskeyRegistration/
            // PasskeyAuthentication) between /options and /verify -- opaque
            // to this crate (see `fabric_accounts::webauthn`'s module doc
            // comment). Included in the fresh-install CREATE TABLE here;
            // the idempotent ALTER TABLE below covers hubs that already ran
            // this statement before the column existed.
            "CREATE TABLE IF NOT EXISTS human_auth_challenges (challenge_id TEXT PRIMARY KEY, kind TEXT NOT NULL, account_id TEXT, session_id TEXT, client_identity_id TEXT, challenge_hash TEXT NOT NULL, ceremony_state TEXT, purpose TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT, attempt_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending')",
            // Unexpired-challenge lookup and pruning.
            "CREATE INDEX IF NOT EXISTS idx_human_auth_challenges_expires ON human_auth_challenges (expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_human_auth_challenges_account ON human_auth_challenges (account_id)",
            // Eighth human_* table (114C.3): a singleton exactly-once gate for
            // first-administrator bootstrap, matching the settings_document
            // singleton-row pattern (id INTEGER PRIMARY KEY CHECK (id = 1)).
            // See 114C-name-lock.md's addendum -- HUMAN_TABLES in
            // tests/test_ephemeral_rqlite_harness.py was updated in the same commit.
            "CREATE TABLE IF NOT EXISTS human_bootstrap_state (id INTEGER PRIMARY KEY CHECK (id = 1), account_id TEXT NOT NULL, completed_at TEXT NOT NULL)",
            // Ninth human_* table (114C.3, negative-auth): append-only
            // login-attempt records backing the rolling-window throttle.
            // See 114C-name-lock.md's second addendum -- HUMAN_TABLES in
            // tests/test_ephemeral_rqlite_harness.py was updated in the same commit.
            "CREATE TABLE IF NOT EXISTS human_login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, dimension_kind TEXT NOT NULL, dimension_key TEXT NOT NULL, attempted_at TEXT NOT NULL, successful INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_human_login_attempts_dimension ON human_login_attempts (dimension_kind, dimension_key, attempted_at)",
            // 114C.5: race-proof "an account may hold at most one active
            // membership per role" -- a partial unique index (SQLite
            // supports a WHERE clause on an index) rather than an
            // application-level check-then-insert, matching this session's
            // established compare-and-set discipline. Without this, two
            // concurrent grants of the same role could both succeed,
            // silently double-counting the account in
            // `count_enabled_admins`'s row-count query.
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_human_memberships_active_role ON human_memberships (account_id, role) WHERE revoked_at IS NULL",
            // 114D D.1: the realm's founding cryptographic identity. A
            // singleton (`id INTEGER PRIMARY KEY CHECK (id = 1)`, the same
            // shape as `human_bootstrap_state`) so a second genesis insert
            // hits a PRIMARY KEY conflict and maps to RealmAlreadyEstablished
            // -- the concurrent-genesis compare-and-set guard (114D sec 15.1).
            // `origins` is a JSON array string; `rp_id`+`origins` are what the
            // hub's WebAuthn verifier reads instead of a local hostname,
            // closing the cross-node relying-party trap (114D sec 5). Not a
            // `human_*` table (it is realm-scoped, not account-scoped), but
            // created here so the single `init_human_accounts_schema` startup
            // call establishes the whole identity schema.
            "CREATE TABLE IF NOT EXISTS realm_identity (id INTEGER PRIMARY KEY CHECK (id = 1), realm_id TEXT NOT NULL, name TEXT NOT NULL, rp_id TEXT NOT NULL, origins TEXT NOT NULL, created_at TEXT NOT NULL, genesis_node TEXT, key_alg TEXT NOT NULL)",
        ];
        for stmt in creates {
            self.execute_one(stmt, &[]).await?;
        }

        // Upgrade path for a `human_auth_challenges` table created before
        // 114C.6 Slice 1 added `ceremony_state` to the CREATE TABLE above --
        // mirrors `run_additive_migrations`' "swallow duplicate column"
        // idempotency pattern, kept local to this function (rather than
        // added to that generic list) because it must run after the CREATE
        // TABLE IF NOT EXISTS above, not before it exists on a fresh install.
        match self
            .execute_one(
                "ALTER TABLE human_auth_challenges ADD COLUMN ceremony_state TEXT",
                &[],
            )
            .await
        {
            Ok(_) => {}
            Err(RqliteError::Status { body, .. }) if body.contains("duplicate column") => {}
            Err(e) => return Err(e.into()),
        }
        // Same idempotent upgrade for `human_sessions.bound_public_key` (114E
        // Slice 1) on hubs whose sessions table predates the column.
        match self
            .execute_one(
                "ALTER TABLE human_sessions ADD COLUMN bound_public_key TEXT",
                &[],
            )
            .await
        {
            Ok(_) => {}
            Err(RqliteError::Status { body, .. }) if body.contains("duplicate column") => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
}

/// 114D D.1: the realm's founding-identity authority. `origins` is stored as a
/// JSON array string; every other field maps one-to-one to a column.
#[async_trait]
impl RealmRepository for RqliteStore {
    async fn get_realm_identity(&self) -> AccountsResult<Option<RealmIdentity>> {
        let rows = self
            .query(
                "SELECT realm_id,name,rp_id,origins,created_at,genesis_node,key_alg FROM realm_identity WHERE id=1",
                &[],
            )
            .await
            .map_err(map_backend_error)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        Ok(Some(row_to_realm_identity(row)?))
    }

    async fn establish_realm_identity(
        &self,
        realm: &RealmIdentity,
    ) -> AccountsResult<RealmIdentity> {
        // `origins` persisted verbatim (order preserved) as a JSON array. A
        // serialization failure here is a caller/programming error, not an
        // infra failure, so it maps to a policy violation rather than the
        // fail-closed AuthServiceUnavailable.
        let origins_json = serde_json::to_string(&realm.origins).map_err(|e| {
            AccountsError::AccountPolicyViolation {
                reason: format!("realm_origins_not_serializable: {e}"),
            }
        })?;

        // Compare-and-set singleton: the fixed `id=1` means a second caller's
        // INSERT hits the PRIMARY KEY (CHECK id=1) conflict and is reported by
        // SQLite as a UNIQUE violation -- mapped to RealmAlreadyEstablished so
        // a concurrent-genesis loser (114D sec 15.1/15.2) can convert to join
        // rather than founding a second realm. No partial state on the losing
        // path: the single INSERT either lands whole or not at all.
        self.execute_one(
            "INSERT INTO realm_identity (id,realm_id,name,rp_id,origins,created_at,genesis_node,key_alg) VALUES (1,?,?,?,?,?,?,?)",
            &[
                json!(realm.realm_id),
                json!(realm.name),
                json!(realm.rp_id),
                json!(origins_json),
                json!(realm.created_at),
                json!(realm.genesis_node),
                json!(realm.key_alg),
            ],
        )
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                AccountsError::RealmAlreadyEstablished
            } else {
                map_backend_error(e)
            }
        })?;

        // Read back the stored row so the returned record reflects exactly
        // what was persisted (and normalizes `origins` back through the same
        // JSON round-trip a later `get_realm_identity` would).
        //
        // Unreachable in practice: the INSERT above just succeeded on this
        // node's authoritative write path. If a read immediately after
        // cannot see it, the store is failing -- fail closed.
        RealmRepository::get_realm_identity(self)
            .await?
            .ok_or(AccountsError::AuthServiceUnavailable)
    }
}

fn row_to_realm_identity(row: &Value) -> Result<RealmIdentity, AccountsError> {
    let origins_raw = str_val(row, "origins");
    let origins: Vec<String> = serde_json::from_str(&origins_raw).map_err(|e| {
        // A corrupt/non-array `origins` column is store-state corruption, not
        // a transient outage; surface it as a policy violation naming the
        // field rather than the generic fail-closed code.
        AccountsError::AccountPolicyViolation {
            reason: format!("realm_origins_corrupt: {e}"),
        }
    })?;
    Ok(RealmIdentity {
        realm_id: str_val(row, "realm_id"),
        name: str_val(row, "name"),
        rp_id: str_val(row, "rp_id"),
        origins,
        created_at: str_val(row, "created_at"),
        genesis_node: opt_str(row, "genesis_node"),
        key_alg: str_val(row, "key_alg"),
    })
}

// -- string <-> domain-enum conversions --------------------------------------
// The domain crate only defines the forward direction (`as_str`); parsing a
// persisted string back into the enum is a store-layer concern, since only
// the store reconstructs domain values from rows.

fn parse_status(s: &str) -> Result<AccountStatus, AccountsError> {
    match s {
        "invited" => Ok(AccountStatus::Invited),
        "active" => Ok(AccountStatus::Active),
        "disabled" => Ok(AccountStatus::Disabled),
        "locked" => Ok(AccountStatus::Locked),
        "recovery_required" => Ok(AccountStatus::RecoveryRequired),
        "deletion_pending" => Ok(AccountStatus::DeletionPending),
        "deleted_tombstone" => Ok(AccountStatus::DeletedTombstone),
        other => Err(AccountsError::AccountPolicyViolation {
            reason: format!("unrecognized_account_status:{other}"),
        }),
    }
}

fn parse_role(s: &str) -> Result<Role, AccountsError> {
    match s {
        "observer" => Ok(Role::Observer),
        "dispatcher" => Ok(Role::Dispatcher),
        "approver" => Ok(Role::Approver),
        "reviewer" => Ok(Role::Reviewer),
        "admin" => Ok(Role::Admin),
        "runner" => Ok(Role::Runner),
        other => Err(AccountsError::AccountPolicyViolation {
            reason: format!("unrecognized_role:{other}"),
        }),
    }
}

fn parse_credential_kind(s: &str) -> Result<CredentialKind, AccountsError> {
    match s {
        "password" => Ok(CredentialKind::Password),
        "webauthn" => Ok(CredentialKind::Webauthn),
        other => Err(AccountsError::AccountPolicyViolation {
            reason: format!("unrecognized_credential_kind:{other}"),
        }),
    }
}

fn parse_assurance(s: &str) -> Result<AssuranceLevel, AccountsError> {
    match s {
        "aal1" => Ok(AssuranceLevel::Aal1),
        "aal2" => Ok(AssuranceLevel::Aal2),
        "recovery_limited" => Ok(AssuranceLevel::RecoveryLimited),
        other => Err(AccountsError::AccountPolicyViolation {
            reason: format!("unrecognized_assurance_level:{other}"),
        }),
    }
}

fn parse_client_kind(s: &str) -> ClientKind {
    match s {
        "vsix" => ClientKind::Vsix,
        "desktop" => ClientKind::Desktop,
        "cli" => ClientKind::Cli,
        _ => ClientKind::Other,
    }
}

// Takes ownership rather than `&RqliteError` so every call site can stay
// the ergonomic `.map_err(map_backend_error)` (a `FnOnce(RqliteError) -> _`)
// instead of `.map_err(|e| map_backend_error(&e))` at ~15 call sites.
// `pub(crate)` so `human_webauthn_challenges.rs` (114C.6) reuses the exact
// same infra-failure mapping rather than a near-duplicate copy.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn map_backend_error(e: RqliteError) -> AccountsError {
    // Infra failures (transport, quorum loss, schema) fail closed as
    // AuthServiceUnavailable, matching the plan's "New login, refresh, role
    // change, recovery, and account administration fail closed when
    // authoritative rqlite state cannot be read or written."
    tracing::warn!(error = %e, "human accounts store backend error");
    AccountsError::AuthServiceUnavailable
}

fn is_unique_violation(e: &RqliteError) -> bool {
    matches!(e, RqliteError::Status { body, .. } if body.contains("UNIQUE constraint failed"))
}

/// 114D D.2: `complete_genesis`'s transaction inserts into *two* different
/// singleton tables (`realm_identity` and `human_bootstrap_state`), so a
/// bare [`is_unique_violation`] cannot say which one a losing caller
/// actually lost to -- and the two mean different things to the client
/// (found an existing realm to join, vs. found an existing admin with no
/// realm, a legacy/mixed state). SQLite's own constraint-violation message
/// names the table, so this reads that name out of the same error body
/// `is_unique_violation` already inspects, rather than issuing a second
/// query to disambiguate. `None` for any error that is not a unique
/// violation on either table -- the caller falls back to
/// [`map_backend_error`] in that case.
fn realm_or_bootstrap_conflict(e: &RqliteError) -> Option<AccountsError> {
    let RqliteError::Status { body, .. } = e else {
        return None;
    };
    if !body.contains("UNIQUE constraint failed") {
        return None;
    }
    if body.contains("realm_identity") {
        Some(AccountsError::RealmAlreadyEstablished)
    } else if body.contains("human_bootstrap_state") {
        Some(AccountsError::BootstrapClosed)
    } else {
        None
    }
}

// -- row <-> domain conversions -----------------------------------------------

fn row_to_account(row: &Value) -> Result<Account, AccountsError> {
    Ok(Account {
        account_id: str_val(row, "account_id"),
        realm_id: str_val(row, "realm_id"),
        username_normalized: str_val(row, "username_normalized"),
        username_display: str_val(row, "username_display"),
        display_name: str_val(row, "display_name"),
        email_normalized: opt_str(row, "email_normalized"),
        status: parse_status(&str_val(row, "status"))?,
        created_at: str_val(row, "created_at"),
        updated_at: str_val(row, "updated_at"),
        disabled_at: opt_str(row, "disabled_at"),
        deleted_at: opt_str(row, "deleted_at"),
        revision: row["revision"].as_i64().unwrap_or(0),
        security_version: row["security_version"].as_i64().unwrap_or(0),
    })
}

fn row_to_credential(row: &Value) -> Result<Credential, AccountsError> {
    Ok(Credential {
        credential_id: str_val(row, "credential_id"),
        account_id: str_val(row, "account_id"),
        kind: parse_credential_kind(&str_val(row, "kind"))?,
        secret_verifier: opt_str(row, "secret_verifier").map(SecretString::new),
        algorithm: opt_str(row, "algorithm"),
        algorithm_params: opt_str(row, "algorithm_params")
            .and_then(|s| serde_json::from_str(&s).ok()),
        version: row["version"].as_i64().unwrap_or(1),
        public_key_material: opt_str(row, "webauthn_public_key"),
        label: opt_str(row, "label"),
        created_at: str_val(row, "created_at"),
        last_used_at: opt_str(row, "last_used_at"),
        compromised_at: opt_str(row, "compromised_at"),
        revoked_at: opt_str(row, "revoked_at"),
        revision: row["revision"].as_i64().unwrap_or(0),
        // NULL (never written, e.g. a password credential or a webauthn row
        // predating this column being populated) reads as `false` via
        // `bool_val`'s own `unwrap_or(false)`.
        backup_eligible: bool_val(row, "webauthn_backup_eligible"),
        backup_state: bool_val(row, "webauthn_backup_state"),
    })
}

fn row_to_membership(row: &Value) -> Result<Membership, AccountsError> {
    // `Membership::for_human`/`for_automation_migration` validate at
    // *construction* time; reconstructing a row that already passed that
    // validation when it was written (see `MembershipRepository::grant`,
    // which independently re-checks the human/runner invariant against
    // `human_accounts` regardless of how the value arrived) does not need to
    // re-validate. All fields are `pub`, so this is an ordinary struct
    // literal, not a constructor bypass.
    Ok(Membership {
        membership_id: str_val(row, "membership_id"),
        account_id: str_val(row, "account_id"),
        realm_id: str_val(row, "realm_id"),
        role: parse_role(&str_val(row, "role"))?,
        granted_by_account_id: opt_str(row, "granted_by_account_id"),
        granted_at: str_val(row, "granted_at"),
        revoked_at: opt_str(row, "revoked_at"),
        revision: row["revision"].as_i64().unwrap_or(0),
    })
}

fn row_to_session(row: &Value) -> Result<Session, AccountsError> {
    Ok(Session {
        session_id: str_val(row, "session_id"),
        account_id: str_val(row, "account_id"),
        realm_id: str_val(row, "realm_id"),
        access_secret_hash: str_val(row, "access_secret_hash"),
        refresh_family_id: str_val(row, "refresh_family_id"),
        refresh_secret_hash: str_val(row, "refresh_secret_hash"),
        client_identity_id: opt_str(row, "client_identity_id"),
        client_kind: parse_client_kind(&str_val(row, "client_kind")),
        client_label: opt_str(row, "client_label"),
        assurance_level: parse_assurance(&str_val(row, "assurance_level"))?,
        authenticated_at: str_val(row, "authenticated_at"),
        step_up_at: opt_str(row, "step_up_at"),
        created_at: str_val(row, "created_at"),
        last_seen_at: str_val(row, "last_seen_at"),
        idle_expires_at: str_val(row, "idle_expires_at"),
        absolute_expires_at: str_val(row, "absolute_expires_at"),
        security_version_at_issue: row["security_version_at_issue"].as_i64().unwrap_or(0),
        revoked_at: opt_str(row, "revoked_at"),
        revoke_reason: opt_str(row, "revoke_reason"),
        revision: row["revision"].as_i64().unwrap_or(0),
        bound_public_key: opt_str(row, "bound_public_key"),
    })
}

// -- AccountRepository ---------------------------------------------------------

#[async_trait]
impl AccountRepository for RqliteStore {
    async fn create_account(&self, account: Account) -> AccountsResult<Account> {
        self.execute_one(
            "INSERT INTO human_accounts (account_id,realm_id,username_normalized,username_display,display_name,email_normalized,status,created_at,updated_at,disabled_at,deleted_at,revision,security_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            &[
                json!(account.account_id), json!(account.realm_id), json!(account.username_normalized),
                json!(account.username_display), json!(account.display_name), json!(account.email_normalized),
                json!(account.status.as_str()), json!(account.created_at), json!(account.updated_at),
                json!(account.disabled_at), json!(account.deleted_at), json!(account.revision), json!(account.security_version),
            ],
        )
        .await
        .map_err(|e| if is_unique_violation(&e) { AccountsError::UsernameConflict } else { map_backend_error(e) })?;
        Ok(account)
    }

    async fn get_account(&self, account_id: &AccountId) -> AccountsResult<Account> {
        let rows = self
            .query(
                "SELECT * FROM human_accounts WHERE account_id=?",
                &[json!(account_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "account_not_found".to_owned(),
            })?;
        row_to_account(row)
    }

    async fn find_by_username(
        &self,
        realm_id: &RealmId,
        username_normalized: &str,
    ) -> AccountsResult<Option<Account>> {
        let rows = self
            .query(
                "SELECT * FROM human_accounts WHERE realm_id=? AND username_normalized=?",
                &[json!(realm_id), json!(username_normalized)],
            )
            .await
            .map_err(map_backend_error)?;
        rows.first().map(row_to_account).transpose()
    }

    async fn update_status(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
        new_status: AccountStatus,
    ) -> AccountsResult<Account> {
        let now = crate::utc_now();
        let affected = self
            .execute_one(
                "UPDATE human_accounts SET status=?,updated_at=?,revision=revision+1 WHERE account_id=? AND revision=?",
                &[json!(new_status.as_str()), json!(now), json!(account_id), json!(expected_revision)],
            )
            .await
            .map_err(map_backend_error)?;
        if affected != 1 {
            return Err(AccountsError::AccountPolicyViolation {
                reason: "revision_conflict".to_owned(),
            });
        }
        self.get_account(account_id).await
    }

    async fn list_accounts(
        &self,
        realm_id: &RealmId,
        limit: i64,
        offset: i64,
    ) -> AccountsResult<Vec<Account>> {
        let rows = self
            .query(
                "SELECT * FROM human_accounts WHERE realm_id=? ORDER BY created_at,account_id LIMIT ? OFFSET ?",
                &[json!(realm_id), json!(limit.clamp(1, 500)), json!(offset.max(0))],
            )
            .await
            .map_err(map_backend_error)?;
        rows.iter().map(row_to_account).collect()
    }
}

// -- CredentialRepository -------------------------------------------------------

#[async_trait]
impl CredentialRepository for RqliteStore {
    async fn add_credential(&self, credential: Credential) -> AccountsResult<Credential> {
        let secret = credential
            .secret_verifier
            .as_ref()
            .map(SecretString::expose_secret);
        self.execute_one(
            "INSERT INTO human_credentials (credential_id,account_id,kind,secret_verifier,algorithm,algorithm_params,version,webauthn_public_key,webauthn_backup_eligible,webauthn_backup_state,label,created_at,last_used_at,compromised_at,revoked_at,revision) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            &[
                json!(credential.credential_id), json!(credential.account_id), json!(credential.kind.as_str()),
                json!(secret), json!(credential.algorithm),
                json!(credential.algorithm_params.as_ref().map(|v| v.to_string())),
                json!(credential.version), json!(credential.public_key_material),
                json!(credential.backup_eligible), json!(credential.backup_state), json!(credential.label),
                json!(credential.created_at), json!(credential.last_used_at), json!(credential.compromised_at),
                json!(credential.revoked_at), json!(credential.revision),
            ],
        )
        .await
        .map_err(|e| if is_unique_violation(&e) { AccountsError::CredentialConflict } else { map_backend_error(e) })?;
        Ok(credential)
    }

    async fn get_active_for_account(
        &self,
        account_id: &AccountId,
    ) -> AccountsResult<Vec<Credential>> {
        let rows = self
            .query(
                "SELECT * FROM human_credentials WHERE account_id=? AND revoked_at IS NULL",
                &[json!(account_id)],
            )
            .await
            .map_err(map_backend_error)?;
        rows.iter().map(row_to_credential).collect()
    }

    async fn mark_compromised(
        &self,
        credential_id: &CredentialId,
        now: &str,
    ) -> AccountsResult<Credential> {
        self.execute_one(
            "UPDATE human_credentials SET compromised_at=?,revision=revision+1 WHERE credential_id=? AND compromised_at IS NULL",
            &[json!(now), json!(credential_id)],
        )
        .await
        .map_err(map_backend_error)?;
        let rows = self
            .query(
                "SELECT * FROM human_credentials WHERE credential_id=?",
                &[json!(credential_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "credential_not_found".to_owned(),
            })?;
        row_to_credential(row)
    }

    async fn revoke(&self, credential_id: &CredentialId, now: &str) -> AccountsResult<Credential> {
        self.execute_one(
            "UPDATE human_credentials SET revoked_at=?,revision=revision+1 WHERE credential_id=? AND revoked_at IS NULL",
            &[json!(now), json!(credential_id)],
        )
        .await
        .map_err(map_backend_error)?;
        let rows = self
            .query(
                "SELECT * FROM human_credentials WHERE credential_id=?",
                &[json!(credential_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "credential_not_found".to_owned(),
            })?;
        row_to_credential(row)
    }

    async fn rehash_secret(
        &self,
        credential_id: &CredentialId,
        new_secret_verifier: SecretString,
        new_algorithm: &str,
        new_algorithm_params: Option<Value>,
        new_version: i64,
    ) -> AccountsResult<Credential> {
        self.execute_one(
            "UPDATE human_credentials SET secret_verifier=?,algorithm=?,algorithm_params=?,version=?,revision=revision+1 WHERE credential_id=?",
            &[
                json!(new_secret_verifier.expose_secret()), json!(new_algorithm),
                json!(new_algorithm_params.as_ref().map(|v| v.to_string())), json!(new_version),
                json!(credential_id),
            ],
        )
        .await
        .map_err(map_backend_error)?;
        let rows = self
            .query(
                "SELECT * FROM human_credentials WHERE credential_id=?",
                &[json!(credential_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "credential_not_found".to_owned(),
            })?;
        row_to_credential(row)
    }
}

// -- MembershipRepository --------------------------------------------------------

#[async_trait]
impl MembershipRepository for RqliteStore {
    async fn grant(&self, membership: Membership) -> AccountsResult<Membership> {
        // Store-side re-check, independent of Membership::for_human: a
        // Membership's fields are public, so a caller could in principle
        // construct one without going through the validating constructor.
        // "the store rejects runner membership for a human account"
        // (114C-name-lock.md) is enforced here regardless of how the value
        // arrived.
        if membership.role == Role::Runner {
            let is_human_account = !self
                .query(
                    "SELECT account_id FROM human_accounts WHERE account_id=?",
                    &[json!(membership.account_id)],
                )
                .await
                .map_err(map_backend_error)?
                .is_empty();
            if is_human_account {
                return Err(AccountsError::AccountPolicyViolation {
                    reason: "human_runner_membership_forbidden".to_owned(),
                });
            }
        }
        self.execute_one(
            "INSERT INTO human_memberships (membership_id,account_id,realm_id,role,granted_by_account_id,granted_at,revoked_at,revision) VALUES (?,?,?,?,?,?,?,?)",
            &[
                json!(membership.membership_id), json!(membership.account_id), json!(membership.realm_id),
                json!(membership.role.as_str()), json!(membership.granted_by_account_id), json!(membership.granted_at),
                json!(membership.revoked_at), json!(membership.revision),
            ],
        )
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                AccountsError::AccountPolicyViolation { reason: "role_already_granted".to_owned() }
            } else {
                map_backend_error(e)
            }
        })?;
        Ok(membership)
    }

    async fn revoke(&self, membership_id: &MembershipId, now: &str) -> AccountsResult<Membership> {
        self.execute_one(
            "UPDATE human_memberships SET revoked_at=?,revision=revision+1 WHERE membership_id=? AND revoked_at IS NULL",
            &[json!(now), json!(membership_id)],
        )
        .await
        .map_err(map_backend_error)?;
        let rows = self
            .query(
                "SELECT * FROM human_memberships WHERE membership_id=?",
                &[json!(membership_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "membership_not_found".to_owned(),
            })?;
        row_to_membership(row)
    }

    async fn list_for_account(&self, account_id: &AccountId) -> AccountsResult<Vec<Membership>> {
        let rows = self
            .query(
                "SELECT * FROM human_memberships WHERE account_id=?",
                &[json!(account_id)],
            )
            .await
            .map_err(map_backend_error)?;
        rows.iter().map(row_to_membership).collect()
    }

    async fn count_enabled_admins(&self, realm_id: &RealmId) -> AccountsResult<i64> {
        self.query_scalar::<i64>(
            "SELECT COUNT(*) FROM human_memberships m JOIN human_accounts a ON m.account_id=a.account_id WHERE m.realm_id=? AND m.role='admin' AND m.revoked_at IS NULL AND a.status='active'",
            &[json!(realm_id)],
        )
        .await
        .map_err(map_backend_error)
        .map(|v| v.unwrap_or(0))
    }
}

// -- SessionRepository ------------------------------------------------------------

#[async_trait]
impl SessionRepository for RqliteStore {
    async fn issue(&self, session: Session) -> AccountsResult<Session> {
        self.execute_one(
            "INSERT INTO human_sessions (session_id,account_id,realm_id,access_secret_hash,refresh_family_id,refresh_secret_hash,client_identity_id,client_kind,client_label,assurance_level,authenticated_at,step_up_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at,security_version_at_issue,revoked_at,revoke_reason,revision,bound_public_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            &[
                json!(session.session_id), json!(session.account_id), json!(session.realm_id),
                json!(session.access_secret_hash), json!(session.refresh_family_id), json!(session.refresh_secret_hash),
                json!(session.client_identity_id), json!(session.client_kind.as_str()), json!(session.client_label),
                json!(session.assurance_level.as_str()), json!(session.authenticated_at), json!(session.step_up_at),
                json!(session.created_at), json!(session.last_seen_at), json!(session.idle_expires_at),
                json!(session.absolute_expires_at), json!(session.security_version_at_issue),
                json!(session.revoked_at), json!(session.revoke_reason), json!(session.revision),
                json!(session.bound_public_key),
            ],
        )
        .await
        .map_err(map_backend_error)?;
        Ok(session)
    }

    async fn get(&self, session_id: &SessionId) -> AccountsResult<Session> {
        let rows = self
            .query(
                "SELECT * FROM human_sessions WHERE session_id=?",
                &[json!(session_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "session_not_found".to_owned(),
            })?;
        row_to_session(row)
    }

    async fn bind_public_key(
        &self,
        session_id: &SessionId,
        public_key_hex: &str,
        now: &str,
    ) -> AccountsResult<()> {
        // One-time bind: only sets a currently-NULL key on a live session, so
        // it cannot rebind or hijack an already-established (or already-PoP)
        // session. `affected != 1` means the session is missing, revoked, or
        // already bound -- all a policy violation, not a transport error.
        let affected = self
            .execute_one(
                "UPDATE human_sessions SET bound_public_key=?,last_seen_at=?,revision=revision+1 WHERE session_id=? AND bound_public_key IS NULL AND revoked_at IS NULL",
                &[json!(public_key_hex), json!(now), json!(session_id)],
            )
            .await
            .map_err(map_backend_error)?;
        if affected != 1 {
            return Err(AccountsError::AccountPolicyViolation {
                reason: "session_key_bind_conflict".to_owned(),
            });
        }
        Ok(())
    }

    async fn validate_by_access_hash(&self, access_secret_hash: &str) -> AccountsResult<Session> {
        let rows = self
            .query(
                "SELECT * FROM human_sessions WHERE access_secret_hash=? AND revoked_at IS NULL",
                &[json!(access_secret_hash)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows.first().ok_or(AccountsError::SessionExpired)?;
        row_to_session(row)
    }

    async fn rotate_refresh(
        &self,
        session_id: &SessionId,
        expected_refresh_secret_hash: &str,
        new_refresh_secret_hash: &str,
        now: &str,
    ) -> AccountsResult<Session> {
        let rows = self
            .query(
                "SELECT * FROM human_sessions WHERE session_id=?",
                &[json!(session_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let existing = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "session_not_found".to_owned(),
            })?;
        if opt_str(existing, "revoked_at").is_some() {
            return Err(AccountsError::SessionRevoked);
        }
        if str_val(existing, "refresh_secret_hash") != expected_refresh_secret_hash {
            // Reuse of an already-rotated (or never-valid) refresh secret:
            // revoke the entire family, per the plan's "Detect refresh-token
            // reuse, revoke the entire token family" requirement. Emitting
            // the accompanying security event is a fabric-hub/audit concern
            // (114C.4), not this store method's.
            let family_id = str_val(existing, "refresh_family_id");
            let _ = self
                .execute_one(
                    "UPDATE human_sessions SET revoked_at=?,revoke_reason='refresh_replay_detected',revision=revision+1 WHERE refresh_family_id=? AND revoked_at IS NULL",
                    &[json!(now), json!(family_id)],
                )
                .await;
            return Err(AccountsError::RefreshReplayDetected);
        }
        let affected = self
            .execute_one(
                "UPDATE human_sessions SET refresh_secret_hash=?,last_seen_at=?,revision=revision+1 WHERE session_id=? AND refresh_secret_hash=? AND revoked_at IS NULL",
                &[json!(new_refresh_secret_hash), json!(now), json!(session_id), json!(expected_refresh_secret_hash)],
            )
            .await
            .map_err(map_backend_error)?;
        if affected != 1 {
            // Lost the race between the SELECT above and this UPDATE (a
            // concurrent refresh or revoke won) -- report replay rather than
            // a generic conflict, since from the caller's perspective the
            // secret it presented is no longer the current one either way.
            return Err(AccountsError::RefreshReplayDetected);
        }
        let rows = self
            .query(
                "SELECT * FROM human_sessions WHERE session_id=?",
                &[json!(session_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "session_not_found".to_owned(),
            })?;
        row_to_session(row)
    }

    async fn revoke(
        &self,
        session_id: &SessionId,
        reason: &str,
        now: &str,
    ) -> AccountsResult<Session> {
        self.execute_one(
            "UPDATE human_sessions SET revoked_at=?,revoke_reason=?,revision=revision+1 WHERE session_id=? AND revoked_at IS NULL",
            &[json!(now), json!(reason), json!(session_id)],
        )
        .await
        .map_err(map_backend_error)?;
        let rows = self
            .query(
                "SELECT * FROM human_sessions WHERE session_id=?",
                &[json!(session_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "session_not_found".to_owned(),
            })?;
        row_to_session(row)
    }

    async fn revoke_all_for_account(
        &self,
        account_id: &AccountId,
        reason: &str,
        now: &str,
    ) -> AccountsResult<i64> {
        self.execute_one(
            "UPDATE human_sessions SET revoked_at=?,revoke_reason=?,revision=revision+1 WHERE account_id=? AND revoked_at IS NULL",
            &[json!(now), json!(reason), json!(account_id)],
        )
        .await
        .map_err(map_backend_error)
    }

    async fn list_for_account(&self, account_id: &AccountId) -> AccountsResult<Vec<Session>> {
        let rows = self
            .query(
                "SELECT * FROM human_sessions WHERE account_id=?",
                &[json!(account_id)],
            )
            .await
            .map_err(map_backend_error)?;
        rows.iter().map(row_to_session).collect()
    }

    async fn rotate_access_secret_and_elevate(
        &self,
        session_id: &SessionId,
        now: &str,
    ) -> AccountsResult<SecretString> {
        let access_secret = secrets::generate_opaque_secret();
        let new_hash = secrets::hash_opaque_secret(access_secret.expose_secret());
        // Single-statement CAS: only a live (non-revoked) session is
        // elevated, and the fresh access-secret hash replaces the old one in
        // the same write (the old access secret stops validating instantly).
        let affected = self
            .execute_one(
                "UPDATE human_sessions SET access_secret_hash=?,assurance_level='aal2',step_up_at=?,last_seen_at=?,revision=revision+1 WHERE session_id=? AND revoked_at IS NULL",
                &[json!(new_hash), json!(now), json!(now), json!(session_id)],
            )
            .await
            .map_err(map_backend_error)?;
        if affected != 1 {
            return Err(AccountsError::SessionRevoked);
        }
        Ok(access_secret)
    }
}

// -- Bootstrap and login orchestration ------------------------------------------
//
// These implement `fabric_accounts::repository::AccountOrchestration`
// (114C.5) rather than the four basic repository traits: bootstrap needs
// cross-table atomicity (`execute_tx`, an rqlite-specific primitive not
// exposed generically), and login is a multi-step orchestration (find
// account, check status, verify credential, rehash-on-success, issue
// session) rather than a single CRUD operation. They are a trait impl, not
// inherent methods, specifically so `fabric-hub`'s `Arc<dyn FabricStore>`
// can reach them -- see `AccountOrchestration`'s own doc comment for why an
// inherent-only version of this code would have been unreachable from any
// route handler.

#[async_trait]
impl AccountOrchestration for RqliteStore {
    async fn bootstrap_status(&self) -> AccountsResult<bool> {
        let rows = self
            .query("SELECT id FROM human_bootstrap_state WHERE id=1", &[])
            .await
            .map_err(map_backend_error)?;
        Ok(rows.is_empty())
    }

    /// Atomically create the realm's first administrator: account, password
    /// credential, and admin membership, gated by the `human_bootstrap_state`
    /// singleton row so that under concurrent callers, exactly one succeeds
    /// and every other caller gets `BootstrapClosed` with no partial state
    /// created. "Atomically" here means a single rqlite transaction
    /// (`execute_tx`, `?transaction`) -- either all four inserts commit or
    /// none do; a losing caller's account/credential/membership inserts are
    /// never durably written, because SQLite aborts the whole transaction
    /// the moment the bootstrap-state insert hits its `PRIMARY KEY`
    /// conflict.
    async fn bootstrap_first_administrator(
        &self,
        realm_id: &str,
        username: &str,
        display_name: &str,
        password_plaintext: &str,
        now: &str,
    ) -> AccountsResult<Account> {
        let username_normalized = validation::normalize_username(username)?;
        password::validate_password(password_plaintext, false)?;
        let password_hash = password::hash_password(password_plaintext)?;

        let account_id = generate_id();
        let credential_id = generate_id();
        let membership_id = generate_id();

        let bootstrap_stmt = (
            "INSERT INTO human_bootstrap_state (id,account_id,completed_at) VALUES (1,?,?)",
            vec![json!(account_id), json!(now)],
        );
        let account_stmt = (
            "INSERT INTO human_accounts (account_id,realm_id,username_normalized,username_display,display_name,email_normalized,status,created_at,updated_at,disabled_at,deleted_at,revision,security_version) VALUES (?,?,?,?,?,NULL,?,?,?,NULL,NULL,0,0)",
            vec![
                json!(account_id), json!(realm_id), json!(username_normalized), json!(username),
                json!(display_name), json!(AccountStatus::Active.as_str()), json!(now), json!(now),
            ],
        );
        let credential_stmt = (
            "INSERT INTO human_credentials (credential_id,account_id,kind,secret_verifier,algorithm,algorithm_params,version,created_at,revision) VALUES (?,?,?,?,?,NULL,1,?,0)",
            vec![
                json!(credential_id), json!(account_id), json!(CredentialKind::Password.as_str()),
                json!(password_hash.expose_secret()), json!("argon2id"), json!(now),
            ],
        );
        let membership_stmt = (
            "INSERT INTO human_memberships (membership_id,account_id,realm_id,role,granted_by_account_id,granted_at,revoked_at,revision) VALUES (?,?,?,?,NULL,?,NULL,0)",
            vec![json!(membership_id), json!(account_id), json!(realm_id), json!(Role::Admin.as_str()), json!(now)],
        );

        let statements = [
            bootstrap_stmt,
            account_stmt,
            credential_stmt,
            membership_stmt,
        ];
        let stmt_refs: Vec<(&str, &[Value])> = statements
            .iter()
            .map(|(sql, params)| (*sql, params.as_slice()))
            .collect();

        self.execute_tx(&stmt_refs).await.map_err(|e| {
            if is_unique_violation(&e) {
                AccountsError::BootstrapClosed
            } else {
                map_backend_error(e)
            }
        })?;

        AccountRepository::get_account(self, &account_id).await
    }

    /// 114D D.2 -- see the trait doc comment for the full contract. Mirrors
    /// `bootstrap_first_administrator`'s shape (one `execute_tx` batch, IDs
    /// generated up front, typed conflict on the losing branch) with two
    /// differences: a `realm_identity` insert joins the batch as its first
    /// statement, and the recovery-code inserts (durable, `expires_at`
    /// NULL) join it as its last -- everything the design calls the
    /// "genesis document" lands in the one transaction.
    ///
    /// Two different "realm id" concepts are deliberately kept apart here:
    /// `realm_identity_id` (generated below, written only to the
    /// `realm_identity` row) is D.1's own new, freshly-minted identifier;
    /// `account_realm_id` (the caller-supplied parameter, always
    /// `DEFAULT_REALM_ID` in practice) is the pre-existing 114C
    /// `human_accounts`/`human_memberships` scoping value every other route
    /// already hardcodes. Using the same value for both silently produces an
    /// account that only genesis's own embedded login can ever authenticate
    /// -- caught live once, see the trait doc comment for the full story.
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
    ) -> AccountsResult<GenesisOutcome> {
        let username_normalized = validation::normalize_username(username)?;
        password::validate_password(password_plaintext, false)?;
        let password_hash = password::hash_password(password_plaintext)?;
        let origins_json =
            serde_json::to_string(origins).map_err(|e| AccountsError::AccountPolicyViolation {
                reason: format!("realm_origins_not_serializable: {e}"),
            })?;

        let realm_identity_id = generate_id();
        let account_id = generate_id();
        let credential_id = generate_id();
        let membership_id = generate_id();

        let mut statements: Vec<(&str, Vec<Value>)> = vec![
            (
                "INSERT INTO realm_identity (id,realm_id,name,rp_id,origins,created_at,genesis_node,key_alg) VALUES (1,?,?,?,?,?,?,?)",
                vec![
                    json!(realm_identity_id), json!(realm_name), json!(rp_id), json!(origins_json),
                    json!(now), json!(genesis_node), json!(key_alg),
                ],
            ),
            (
                "INSERT INTO human_bootstrap_state (id,account_id,completed_at) VALUES (1,?,?)",
                vec![json!(account_id), json!(now)],
            ),
            (
                "INSERT INTO human_accounts (account_id,realm_id,username_normalized,username_display,display_name,email_normalized,status,created_at,updated_at,disabled_at,deleted_at,revision,security_version) VALUES (?,?,?,?,?,NULL,?,?,?,NULL,NULL,0,0)",
                vec![
                    json!(account_id), json!(account_realm_id), json!(username_normalized), json!(username),
                    json!(display_name), json!(AccountStatus::Active.as_str()), json!(now), json!(now),
                ],
            ),
            (
                "INSERT INTO human_credentials (credential_id,account_id,kind,secret_verifier,algorithm,algorithm_params,version,created_at,revision) VALUES (?,?,?,?,?,NULL,1,?,0)",
                vec![
                    json!(credential_id), json!(account_id), json!(CredentialKind::Password.as_str()),
                    json!(password_hash.expose_secret()), json!("argon2id"), json!(now),
                ],
            ),
            (
                "INSERT INTO human_memberships (membership_id,account_id,realm_id,role,granted_by_account_id,granted_at,revoked_at,revision) VALUES (?,?,?,?,NULL,?,NULL,0)",
                vec![json!(membership_id), json!(account_id), json!(account_realm_id), json!(Role::Admin.as_str()), json!(now)],
            ),
        ];

        // Durable break-glass recovery codes: expires_at is NULL (never
        // expires), unlike generate_recovery_codes's 72-hour
        // admin-assisted-recovery TTL -- the Master is not expected to
        // redeem these within days, only if their credential is ever lost.
        // Clamped the same way generate_recovery_codes clamps its own
        // count, reusing MAX_RECOVERY_CODES_PER_BATCH so genesis cannot
        // mint an unbounded batch.
        let clamped_count =
            usize::try_from(recovery_code_count.clamp(1, MAX_RECOVERY_CODES_PER_BATCH))
                .unwrap_or(1);
        let recovery_batch_id = generate_id();
        let mut recovery_codes = Vec::with_capacity(clamped_count);
        for _ in 0..clamped_count {
            let code = secrets::generate_opaque_secret();
            let code_id = generate_id();
            statements.push((
                "INSERT INTO human_recovery_codes (code_id,account_id,code_verifier,batch_id,created_at,consumed_at,revoked_at,expires_at) VALUES (?,?,?,?,?,NULL,NULL,NULL)",
                vec![
                    json!(code_id), json!(account_id),
                    json!(secrets::hash_opaque_secret(code.expose_secret())),
                    json!(recovery_batch_id), json!(now),
                ],
            ));
            recovery_codes.push(code);
        }

        let stmt_refs: Vec<(&str, &[Value])> = statements
            .iter()
            .map(|(sql, params)| (*sql, params.as_slice()))
            .collect();

        self.execute_tx(&stmt_refs)
            .await
            .map_err(|e| realm_or_bootstrap_conflict(&e).unwrap_or_else(|| map_backend_error(e)))?;

        let account = AccountRepository::get_account(self, &account_id).await?;
        let realm = RealmRepository::get_realm_identity(self)
            .await?
            .ok_or(AccountsError::AuthServiceUnavailable)?;

        Ok(GenesisOutcome {
            realm,
            account,
            recovery_codes,
        })
    }

    /// Verify a username/password against the realm and, on success, issue
    /// a new session with freshly generated access/refresh secrets. Returns
    /// `AccountsError::InvalidCredentials` uniformly for "no such username",
    /// "no password credential on file", "malformed stored hash", and
    /// "wrong password" -- the plan's "unknown username and known username
    /// return equivalent public errors" requirement, extended to cover every
    /// other reason a login can fail without leaking which one it was.
    /// Distinguishable failures (`AccountDisabled`, `AccountLocked`,
    /// `RecoveryRequired`) are the ones the plan's own typed-error baseline
    /// deliberately makes distinguishable -- they describe account *state*,
    /// which a legitimate client is expected to react to differently, not a
    /// property of the guess itself.
    ///
    /// `client_fingerprint`, when supplied by the caller (a per-request IP
    /// or client-instance identifier -- there is no HTTP layer here to
    /// derive one from yet, that is 114C.4's job), throttles independently
    /// of the username dimension. This is the fix for the ForgeWire
    /// account-behavior inventory's named defect: "Lockout throttles only by
    /// username, never IP/client" -- an attacker spreading guesses across
    /// many usernames from one source was never slowed down at all.
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
    ) -> AccountsResult<LoginOutcome> {
        let username_normalized = validation::normalize_username(username)
            .map_err(|_| AccountsError::InvalidCredentials)?;

        // Throttle keyed by the presented username string, regardless of
        // whether an account with that username exists -- so probing
        // non-existent usernames is throttled identically to a real one,
        // rather than becoming a cheaper oracle than guessing a real
        // account's password. Checked before any account/credential I/O, so
        // a throttled caller also can't use repeated attempts to waste
        // Argon2id CPU time.
        self.enforce_login_throttle("username", &username_normalized)
            .await?;
        if let Some(fingerprint) = client_fingerprint {
            self.enforce_login_throttle("client", fingerprint).await?;
        }

        let result = self
            .try_authenticate(
                realm_id,
                &username_normalized,
                password_plaintext,
                client_kind,
                client_label,
                idle_timeout_minutes,
                absolute_timeout_hours,
                now,
            )
            .await;

        let successful = result.is_ok();
        let _ = self
            .record_login_attempt("username", &username_normalized, successful, now)
            .await;
        if let Some(fingerprint) = client_fingerprint {
            let _ = self
                .record_login_attempt("client", fingerprint, successful, now)
                .await;
        }

        result
    }

    /// See the trait method's own doc comment for the full contract. The
    /// sign-count regression guard is a single-statement CAS, matching this
    /// codebase's established discipline (see the last-administrator
    /// protection and 114C.6 Slice 1's challenge-consumption CAS): the
    /// `UPDATE`'s `WHERE` clause is the entire enforcement, not a
    /// SELECT-then-compare-then-UPDATE that a mutation test would prove
    /// races under concurrent replay attempts.
    ///
    /// The `?=0` clause is the carve-out for authenticators that never
    /// implement a counter (spec-legal, reports 0 on every assertion) --
    /// without it, every subsequent assertion from such an authenticator
    /// would be misclassified as a replay. Binding `new_sign_count` twice
    /// (once for that check, once for the strict-advance comparison) rather
    /// than computing the OR in Rust keeps the whole guard inside the one
    /// atomic statement.
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
    ) -> AccountsResult<()> {
        let affected = self
            .execute_one(
                "UPDATE human_credentials SET webauthn_sign_count=?,webauthn_public_key=?,webauthn_backup_eligible=?,webauthn_backup_state=?,last_used_at=?,revision=revision+1 WHERE credential_id=? AND account_id=? AND kind='webauthn' AND revoked_at IS NULL AND (?=0 OR webauthn_sign_count IS NULL OR webauthn_sign_count<?)",
                &[
                    json!(new_sign_count), json!(updated_public_key_blob),
                    json!(backup_eligible), json!(backup_state), json!(now),
                    json!(credential_id), json!(account_id),
                    json!(new_sign_count), json!(new_sign_count),
                ],
            )
            .await
            .map_err(map_backend_error)?;
        if affected != 1 {
            // On detection: deny this assertion and leave the credential row
            // untouched -- deliberately not auto-revoked. Auto-revoke-on-
            // anomaly would turn one false positive (a legitimate but buggy
            // authenticator, or a lost race against a concurrent genuine
            // login) into a full account lockout; that tradeoff belongs to
            // a separately reviewed policy toggle, not this method's default.
            return Err(AccountsError::CredentialReplaySuspected);
        }
        Ok(())
    }

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
    ) -> AccountsResult<LoginOutcome> {
        let account = AccountRepository::get_account(self, account_id).await?;
        match account.status {
            AccountStatus::Active => {}
            AccountStatus::Disabled => return Err(AccountsError::AccountDisabled),
            AccountStatus::Locked => {
                return Err(AccountsError::AccountLocked {
                    retry_after_seconds: None,
                })
            }
            AccountStatus::RecoveryRequired => return Err(AccountsError::RecoveryRequired),
            AccountStatus::Invited
            | AccountStatus::DeletionPending
            | AccountStatus::DeletedTombstone => {
                return Err(AccountsError::InvalidCredentials);
            }
        }

        self.verify_and_advance_passkey_sign_count(
            account_id,
            credential_id,
            new_sign_count,
            updated_public_key_blob,
            backup_eligible,
            backup_state,
            now,
        )
        .await?;

        let access_secret = secrets::generate_opaque_secret();
        let refresh_secret = secrets::generate_opaque_secret();
        let session = Session {
            session_id: generate_id(),
            account_id: account.account_id.clone(),
            realm_id: realm_id.to_owned(),
            access_secret_hash: secrets::hash_opaque_secret(access_secret.expose_secret()),
            refresh_family_id: generate_id(),
            refresh_secret_hash: secrets::hash_opaque_secret(refresh_secret.expose_secret()),
            client_identity_id: None,
            client_kind,
            client_label: client_label.map(str::to_owned),
            // A successful WebAuthn assertion is user-verified by
            // definition -- treat it as an implicit step-up so the caller
            // is not immediately forced through a second step-up round-trip
            // right after signing in with a passkey.
            assurance_level: AssuranceLevel::Aal2,
            authenticated_at: now.to_owned(),
            step_up_at: Some(now.to_owned()),
            created_at: now.to_owned(),
            last_seen_at: now.to_owned(),
            idle_expires_at: utc_offset(idle_timeout_minutes * 60),
            absolute_expires_at: utc_offset(absolute_timeout_hours * 3600),
            security_version_at_issue: account.security_version,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
            // Sessions issue bearer-only; a PoP client binds its public key
            // immediately after via `SessionRepository::bind_public_key`
            // (114E). Kept out of the issuance signature to avoid threading
            // an optional key through every login path and its many callers.
            bound_public_key: None,
        };
        let issued = SessionRepository::issue(self, session).await?;
        Ok(LoginOutcome {
            session: issued,
            access_secret,
            refresh_secret,
        })
    }

    /// Disable an account and revoke every session it has -- "account
    /// disablement... invalidate[s] required sessions." Two writes, not one
    /// atomic transaction: if the process dies between them, the account is
    /// already disabled (the more conservative failure direction -- a
    /// disabled account with a lingering session is caught by the next
    /// access-hash validation reading `human_accounts.status`... note this
    /// store does not currently re-check account status on every session
    /// validation; that join is a 114C.4 concern when session validation is
    /// wired into the hub's request path).
    async fn disable_account_and_revoke_sessions(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
        now: &str,
    ) -> AccountsResult<Account> {
        let account = AccountRepository::update_status(
            self,
            account_id,
            expected_revision,
            AccountStatus::Disabled,
        )
        .await?;
        SessionRepository::revoke_all_for_account(self, account_id, "account_disabled", now)
            .await?;
        Ok(account)
    }

    /// Change a password credential's verifier and revoke every existing
    /// session for the account -- "password change... invalidate[s]
    /// required sessions." This revokes *all* sessions including the one
    /// that requested the change (the plan's "regenerate session secrets
    /// after... password change" is satisfied by requiring a fresh login,
    /// the simplest safe reading of "regenerate" available without a
    /// separate in-place session-secret-rotation path, which is not yet
    /// built).
    async fn change_password_and_revoke_sessions(
        &self,
        account_id: &AccountId,
        credential_id: &CredentialId,
        new_password_plaintext: &str,
        has_second_factor: bool,
        now: &str,
    ) -> AccountsResult<Credential> {
        password::validate_password(new_password_plaintext, has_second_factor)?;
        let current = CredentialRepository::get_active_for_account(self, account_id)
            .await?
            .into_iter()
            .find(|c| &c.credential_id == credential_id)
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "credential_not_found".to_owned(),
            })?;
        let new_hash = password::hash_password(new_password_plaintext)?;
        let credential = CredentialRepository::rehash_secret(
            self,
            credential_id,
            new_hash,
            "argon2id",
            None,
            current.version + 1,
        )
        .await?;
        SessionRepository::revoke_all_for_account(self, account_id, "password_changed", now)
            .await?;
        Ok(credential)
    }

    /// Bound the table's growth -- "bound or prune high-volume login-attempt
    /// and challenge records without deleting the durable security event
    /// from the audit chain" (this table is not the audit chain itself;
    /// that join is 114C.4's job at the hub layer, so pruning here loses no
    /// durable security record).
    async fn prune_login_attempts(&self, older_than: &str) -> AccountsResult<i64> {
        self.execute_one(
            "DELETE FROM human_login_attempts WHERE attempted_at<?",
            &[json!(older_than)],
        )
        .await
        .map_err(map_backend_error)
    }

    /// Atomically create an account, password credential, and initial
    /// membership -- the ongoing counterpart to `bootstrap_first_administrator`
    /// for every account after the first. No singleton gate: unlike
    /// bootstrap, concurrent callers creating *different* usernames must both
    /// succeed, so the only conflict this guards against is the same
    /// `(realm_id, username_normalized)` pair, which the unique index on
    /// `human_accounts` already enforces and this maps to `UsernameConflict`.
    async fn create_account_with_password(
        &self,
        realm_id: &str,
        username: &str,
        display_name: &str,
        password_plaintext: &str,
        role: Role,
        granted_by_account_id: &str,
        now: &str,
    ) -> AccountsResult<Account> {
        if !role.human_assignable() {
            return Err(AccountsError::AccountPolicyViolation {
                reason: "human_runner_membership_forbidden".to_owned(),
            });
        }
        let username_normalized = validation::normalize_username(username)?;
        password::validate_password(password_plaintext, false)?;
        let password_hash = password::hash_password(password_plaintext)?;

        let account_id = generate_id();
        let credential_id = generate_id();
        let membership_id = generate_id();

        let account_stmt = (
            "INSERT INTO human_accounts (account_id,realm_id,username_normalized,username_display,display_name,email_normalized,status,created_at,updated_at,disabled_at,deleted_at,revision,security_version) VALUES (?,?,?,?,?,NULL,?,?,?,NULL,NULL,0,0)",
            vec![
                json!(account_id), json!(realm_id), json!(username_normalized), json!(username),
                json!(display_name), json!(AccountStatus::Active.as_str()), json!(now), json!(now),
            ],
        );
        let credential_stmt = (
            "INSERT INTO human_credentials (credential_id,account_id,kind,secret_verifier,algorithm,algorithm_params,version,created_at,revision) VALUES (?,?,?,?,?,NULL,1,?,0)",
            vec![
                json!(credential_id), json!(account_id), json!(CredentialKind::Password.as_str()),
                json!(password_hash.expose_secret()), json!("argon2id"), json!(now),
            ],
        );
        let membership_stmt = (
            "INSERT INTO human_memberships (membership_id,account_id,realm_id,role,granted_by_account_id,granted_at,revoked_at,revision) VALUES (?,?,?,?,?,?,NULL,0)",
            vec![
                json!(membership_id), json!(account_id), json!(realm_id), json!(role.as_str()),
                json!(granted_by_account_id), json!(now),
            ],
        );

        let statements = [account_stmt, credential_stmt, membership_stmt];
        let stmt_refs: Vec<(&str, &[Value])> = statements
            .iter()
            .map(|(sql, params)| (*sql, params.as_slice()))
            .collect();

        self.execute_tx(&stmt_refs).await.map_err(|e| {
            if is_unique_violation(&e) {
                AccountsError::UsernameConflict
            } else {
                map_backend_error(e)
            }
        })?;

        AccountRepository::get_account(self, &account_id).await
    }

    async fn create_invited_account(
        &self,
        realm_id: &str,
        username: &str,
        display_name: &str,
        email: Option<&str>,
        role: Role,
        granted_by_account_id: &str,
        now: &str,
    ) -> AccountsResult<Account> {
        if role == Role::Admin || !role.human_assignable() {
            return Err(AccountsError::AccountPolicyViolation {
                reason: "import_may_not_grant_admin_or_runner".to_owned(),
            });
        }
        let username_normalized = validation::normalize_username(username)?;

        let account_id = generate_id();
        let membership_id = generate_id();

        let account_stmt = (
            "INSERT INTO human_accounts (account_id,realm_id,username_normalized,username_display,display_name,email_normalized,status,created_at,updated_at,disabled_at,deleted_at,revision,security_version) VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL,0,0)",
            vec![
                json!(account_id), json!(realm_id), json!(username_normalized), json!(username),
                json!(display_name), json!(email), json!(AccountStatus::Invited.as_str()), json!(now), json!(now),
            ],
        );
        let membership_stmt = (
            "INSERT INTO human_memberships (membership_id,account_id,realm_id,role,granted_by_account_id,granted_at,revoked_at,revision) VALUES (?,?,?,?,?,?,NULL,0)",
            vec![
                json!(membership_id), json!(account_id), json!(realm_id), json!(role.as_str()),
                json!(granted_by_account_id), json!(now),
            ],
        );

        let statements = [account_stmt, membership_stmt];
        let stmt_refs: Vec<(&str, &[Value])> = statements
            .iter()
            .map(|(sql, params)| (*sql, params.as_slice()))
            .collect();

        self.execute_tx(&stmt_refs).await.map_err(|e| {
            if is_unique_violation(&e) {
                AccountsError::UsernameConflict
            } else {
                map_backend_error(e)
            }
        })?;

        AccountRepository::get_account(self, &account_id).await
    }

    // -- Last-administrator invariant (114C.5) -------------------------------
    //
    // "The hub must reject any mutation that would leave the realm with zero
    // enabled, credentialed administrators... This is a compare-and-set
    // invariant, not a UI warning." Both guards below enforce this inside a
    // single UPDATE statement's WHERE clause -- not a separate read-then-
    // write check, which would leave a race window where two concurrent
    // requests each read "at least one other admin exists" against the
    // *same* stale count and both proceed, jointly leaving zero. A
    // correlated subquery counting *other* enabled admins is evaluated by
    // rqlite's single-writer backend as part of the same atomic write.

    /// Disable an account, refusing if it is the realm's last enabled admin.
    /// Revokes sessions on success, matching `disable_account_and_revoke_sessions`.
    async fn disable_account_protecting_last_admin(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
        now: &str,
    ) -> AccountsResult<Account> {
        let affected = self
            .execute_one(
                "UPDATE human_accounts SET status='disabled',updated_at=?,revision=revision+1 \
                 WHERE account_id=? AND revision=? AND ( \
                   NOT EXISTS (SELECT 1 FROM human_memberships m WHERE m.account_id=human_accounts.account_id AND m.role='admin' AND m.revoked_at IS NULL) \
                   OR (SELECT COUNT(*) FROM human_memberships m2 JOIN human_accounts a2 ON m2.account_id=a2.account_id \
                       WHERE m2.realm_id=human_accounts.realm_id AND m2.role='admin' AND m2.revoked_at IS NULL AND a2.status='active' \
                       AND m2.account_id<>human_accounts.account_id) >= 1 \
                 )",
                &[json!(now), json!(account_id), json!(expected_revision)],
            )
            .await
            .map_err(map_backend_error)?;
        if affected != 1 {
            return Err(self
                .diagnose_blocked_write(account_id, expected_revision)
                .await);
        }
        SessionRepository::revoke_all_for_account(self, account_id, "account_disabled", now)
            .await?;
        AccountRepository::get_account(self, account_id).await
    }

    /// Revoke an `admin` membership, refusing if the account is the realm's
    /// last enabled admin. Revoking a non-admin membership never triggers
    /// this guard (see `MembershipRepository::revoke`, which this delegates
    /// to for the non-admin case since no invariant applies there).
    async fn revoke_membership_protecting_last_admin(
        &self,
        membership_id: &MembershipId,
        now: &str,
    ) -> AccountsResult<Membership> {
        let rows = self
            .query(
                "SELECT * FROM human_memberships WHERE membership_id=?",
                &[json!(membership_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let existing = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "membership_not_found".to_owned(),
            })?;
        if str_val(existing, "role") != Role::Admin.as_str() {
            return MembershipRepository::revoke(self, membership_id, now).await;
        }
        let affected = self
            .execute_one(
                "UPDATE human_memberships SET revoked_at=?,revision=revision+1 \
                 WHERE membership_id=? AND revoked_at IS NULL AND ( \
                   SELECT COUNT(*) FROM human_memberships m2 JOIN human_accounts a2 ON m2.account_id=a2.account_id \
                   WHERE m2.realm_id=human_memberships.realm_id AND m2.role='admin' AND m2.revoked_at IS NULL AND a2.status='active' \
                   AND m2.membership_id<>human_memberships.membership_id \
                 ) >= 1",
                &[json!(now), json!(membership_id)],
            )
            .await
            .map_err(map_backend_error)?;
        if affected != 1 {
            // The only two ways this UPDATE can affect 0 rows: the row was
            // already revoked (or vanished) between the SELECT above and
            // here, or the last-admin guard blocked it. Re-read to tell them
            // apart for the caller's error message -- the safety already
            // happened atomically in the UPDATE regardless of which it was.
            let recheck = self
                .query(
                    "SELECT revoked_at FROM human_memberships WHERE membership_id=?",
                    &[json!(membership_id)],
                )
                .await
                .map_err(map_backend_error)?;
            return match recheck.first().and_then(|r| opt_str(r, "revoked_at")) {
                Some(_) => Err(AccountsError::AccountPolicyViolation {
                    reason: "membership_already_revoked".to_owned(),
                }),
                None => Err(AccountsError::LastAdministratorViolation),
            };
        }
        let rows = self
            .query(
                "SELECT * FROM human_memberships WHERE membership_id=?",
                &[json!(membership_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows
            .first()
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "membership_not_found".to_owned(),
            })?;
        row_to_membership(row)
    }

    /// Grant a role to an existing account. ID generation and construction
    /// only -- the actual "at most one active membership per role" race
    /// safety lives in `idx_human_memberships_active_role`, a partial unique
    /// index `MembershipRepository::grant`'s INSERT hits and maps to
    /// `AccountPolicyViolation { reason: "role_already_granted" }` on
    /// conflict.
    async fn grant_membership(
        &self,
        account_id: &AccountId,
        realm_id: &RealmId,
        role: Role,
        granted_by_account_id: &str,
        now: &str,
    ) -> AccountsResult<Membership> {
        let membership_id = generate_id();
        let membership = Membership::for_human(
            membership_id,
            account_id.clone(),
            realm_id.clone(),
            role,
            Some(granted_by_account_id.to_owned()),
            now.to_owned(),
        )?;
        MembershipRepository::grant(self, membership).await
    }

    /// Generate a fresh batch of one-time recovery codes. Each code is a
    /// high-entropy opaque secret (the same primitive sessions use), hashed
    /// with a fast keyed hash before storage -- recovery codes are
    /// system-generated random tokens, not user-chosen passwords, so the
    /// deliberately slow Argon2id path `human_credentials` uses would be the
    /// wrong tool here (nothing to protect against a weak-guess dictionary
    /// attack; the entropy already exceeds what a work factor buys you).
    async fn generate_recovery_codes(
        &self,
        account_id: &AccountId,
        count: i64,
        now: &str,
    ) -> AccountsResult<Vec<SecretString>> {
        let batch_id = generate_id();
        let expires_at = utc_offset(RECOVERY_CODE_TTL_SECS);
        // MAX_RECOVERY_CODES_PER_BATCH is a small positive constant, so this
        // clamp result is always representable as a usize.
        let clamped = usize::try_from(count.clamp(1, MAX_RECOVERY_CODES_PER_BATCH)).unwrap_or(1);
        let mut codes = Vec::with_capacity(clamped);
        for _ in 0..clamped {
            let code = secrets::generate_opaque_secret();
            let code_id = generate_id();
            self.execute_one(
                "INSERT INTO human_recovery_codes (code_id,account_id,code_verifier,batch_id,created_at,consumed_at,revoked_at,expires_at) VALUES (?,?,?,?,?,NULL,NULL,?)",
                &[
                    json!(code_id),
                    json!(account_id),
                    json!(secrets::hash_opaque_secret(code.expose_secret())),
                    json!(batch_id),
                    json!(now),
                    json!(expires_at),
                ],
            )
            .await
            .map_err(map_backend_error)?;
            codes.push(code);
        }
        Ok(codes)
    }

    /// Complete operator-assisted recovery. The code lookup-and-consume is a
    /// single atomic UPDATE keyed by the code's hash (mirrors
    /// `SessionRepository::validate_by_access_hash`'s "opaque, server-side
    /// secret" model) with `consumed_at IS NULL` in the WHERE clause, so two
    /// concurrent attempts to use the same code cannot both succeed -- the
    /// same compare-and-set discipline as this file's other guards, not a
    /// separate read-then-write check.
    async fn complete_recovery_with_code(
        &self,
        account_id: &AccountId,
        code_plaintext: &str,
        new_password_plaintext: &str,
        now: &str,
    ) -> AccountsResult<Account> {
        let account = AccountRepository::get_account(self, account_id).await?;
        if account.status != AccountStatus::RecoveryRequired {
            return Err(AccountsError::AccountPolicyViolation {
                reason: "account_not_in_recovery".to_owned(),
            });
        }

        let code_hash = secrets::hash_opaque_secret(code_plaintext);
        let affected = self
            .execute_one(
                "UPDATE human_recovery_codes SET consumed_at=? \
                 WHERE account_id=? AND code_verifier=? AND consumed_at IS NULL AND revoked_at IS NULL \
                 AND (expires_at IS NULL OR expires_at > ?)",
                &[json!(now), json!(account_id), json!(code_hash), json!(now)],
            )
            .await
            .map_err(map_backend_error)?;
        if affected != 1 {
            return Err(AccountsError::InvalidCredentials);
        }

        password::validate_password(new_password_plaintext, false)?;
        let credentials = CredentialRepository::get_active_for_account(self, account_id).await?;
        let password_credential = credentials
            .iter()
            .find(|c| c.kind == CredentialKind::Password)
            .ok_or_else(|| AccountsError::AccountPolicyViolation {
                reason: "no_password_credential_to_reset".to_owned(),
            })?;
        let new_hash = password::hash_password(new_password_plaintext)?;
        CredentialRepository::rehash_secret(
            self,
            &password_credential.credential_id,
            new_hash,
            "argon2id",
            None,
            password_credential.version + 1,
        )
        .await?;

        SessionRepository::revoke_all_for_account(self, account_id, "recovery_completed", now)
            .await?;
        AccountRepository::update_status(self, account_id, account.revision, AccountStatus::Active)
            .await
    }

    /// Step one of two-step deletion. Same last-administrator CAS discipline
    /// as `disable_account_protecting_last_admin` -- a correlated subquery
    /// inside the UPDATE's WHERE clause, not a separate read-then-write
    /// check -- plus a source-status guard so deletion can only be
    /// initiated once (not re-initiated from an already-`deletion_pending`
    /// or `deleted_tombstone` account).
    async fn initiate_account_deletion_protecting_last_admin(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
        now: &str,
    ) -> AccountsResult<Account> {
        let affected = self
            .execute_one(
                "UPDATE human_accounts SET status='deletion_pending',updated_at=?,revision=revision+1 \
                 WHERE account_id=? AND revision=? \
                 AND status NOT IN ('deletion_pending','deleted_tombstone') \
                 AND ( \
                   NOT EXISTS (SELECT 1 FROM human_memberships m WHERE m.account_id=human_accounts.account_id AND m.role='admin' AND m.revoked_at IS NULL) \
                   OR (SELECT COUNT(*) FROM human_memberships m2 JOIN human_accounts a2 ON m2.account_id=a2.account_id \
                       WHERE m2.realm_id=human_accounts.realm_id AND m2.role='admin' AND m2.revoked_at IS NULL AND a2.status='active' \
                       AND m2.account_id<>human_accounts.account_id) >= 1 \
                 )",
                &[json!(now), json!(account_id), json!(expected_revision)],
            )
            .await
            .map_err(map_backend_error)?;
        if affected != 1 {
            return Err(self
                .diagnose_blocked_deletion(account_id, expected_revision)
                .await);
        }
        SessionRepository::revoke_all_for_account(
            self,
            account_id,
            "account_deletion_initiated",
            now,
        )
        .await?;
        AccountRepository::get_account(self, account_id).await
    }

    /// Step two: irreversible. Requires the account to currently be
    /// `deletion_pending` -- embedded in the UPDATE's WHERE clause, the same
    /// "guard in SQL, not a separate read" discipline as every other CAS
    /// write in this file.
    async fn complete_account_deletion(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
        now: &str,
    ) -> AccountsResult<Account> {
        let tombstone_username = format!("deleted-{account_id}");
        let affected = self
            .execute_one(
                "UPDATE human_accounts SET status='deleted_tombstone',username_normalized=?,username_display=?,display_name='Deleted account',email_normalized=NULL,deleted_at=?,updated_at=?,revision=revision+1 \
                 WHERE account_id=? AND revision=? AND status='deletion_pending'",
                &[
                    json!(tombstone_username),
                    json!(tombstone_username),
                    json!(now),
                    json!(now),
                    json!(account_id),
                    json!(expected_revision),
                ],
            )
            .await
            .map_err(|e| {
                if is_unique_violation(&e) {
                    AccountsError::AccountPolicyViolation { reason: "tombstone_username_conflict".to_owned() }
                } else {
                    map_backend_error(e)
                }
            })?;
        if affected != 1 {
            return Err(self
                .diagnose_blocked_tombstone(account_id, expected_revision)
                .await);
        }

        SessionRepository::revoke_all_for_account(self, account_id, "account_deleted", now).await?;
        for credential in CredentialRepository::get_active_for_account(self, account_id).await? {
            CredentialRepository::revoke(self, &credential.credential_id, now).await?;
        }
        for membership in MembershipRepository::list_for_account(self, account_id).await? {
            if membership.revoked_at.is_none() {
                MembershipRepository::revoke(self, &membership.membership_id, now).await?;
            }
        }
        AccountRepository::get_account(self, account_id).await
    }

    /// Bounded, SQL-`LIMIT`-enforced security history: an account's most
    /// recent login attempts (by username dimension) and most recent
    /// sessions (including revoked ones), each capped at `limit`.
    async fn account_security_history(
        &self,
        account_id: &AccountId,
        limit: i64,
    ) -> AccountsResult<(Vec<LoginAttemptDto>, Vec<Session>)> {
        let account = AccountRepository::get_account(self, account_id).await?;
        let bounded = limit.clamp(1, MAX_SECURITY_HISTORY_ROWS);

        let attempt_rows = self
            .query(
                "SELECT attempted_at, successful FROM human_login_attempts \
                 WHERE dimension_kind='username' AND dimension_key=? \
                 ORDER BY attempted_at DESC, id DESC LIMIT ?",
                &[json!(account.username_normalized), json!(bounded)],
            )
            .await
            .map_err(map_backend_error)?;
        let login_attempts = attempt_rows
            .iter()
            .map(|row| LoginAttemptDto {
                attempted_at: str_val(row, "attempted_at"),
                successful: row["successful"].as_i64().unwrap_or(0) != 0,
            })
            .collect();

        let session_rows = self
            .query(
                "SELECT * FROM human_sessions WHERE account_id=? ORDER BY created_at DESC LIMIT ?",
                &[json!(account_id), json!(bounded)],
            )
            .await
            .map_err(map_backend_error)?;
        let sessions = session_rows
            .iter()
            .map(row_to_session)
            .collect::<Result<Vec<_>, _>>()?;

        Ok((login_attempts, sessions))
    }
}

const RECOVERY_CODE_TTL_SECS: i64 = 72 * 60 * 60;
const MAX_RECOVERY_CODES_PER_BATCH: i64 = 10;
const MAX_SECURITY_HISTORY_ROWS: i64 = 200;

impl RqliteStore {
    #[allow(clippy::too_many_arguments)]
    async fn try_authenticate(
        &self,
        realm_id: &str,
        username_normalized: &str,
        password_plaintext: &str,
        client_kind: ClientKind,
        client_label: Option<&str>,
        idle_timeout_minutes: i64,
        absolute_timeout_hours: i64,
        now: &str,
    ) -> AccountsResult<LoginOutcome> {
        let account =
            AccountRepository::find_by_username(self, &realm_id.to_owned(), username_normalized)
                .await?
                .ok_or(AccountsError::InvalidCredentials)?;

        match account.status {
            AccountStatus::Active => {}
            AccountStatus::Disabled => return Err(AccountsError::AccountDisabled),
            AccountStatus::Locked => {
                return Err(AccountsError::AccountLocked {
                    retry_after_seconds: None,
                })
            }
            AccountStatus::RecoveryRequired => return Err(AccountsError::RecoveryRequired),
            AccountStatus::Invited
            | AccountStatus::DeletionPending
            | AccountStatus::DeletedTombstone => {
                return Err(AccountsError::InvalidCredentials); // non-enumerating: do not distinguish from "wrong password"
            }
        }

        let credentials =
            CredentialRepository::get_active_for_account(self, &account.account_id).await?;
        let password_credential = credentials
            .iter()
            .find(|c| c.kind == CredentialKind::Password)
            .ok_or(AccountsError::InvalidCredentials)?;
        let stored_hash = password_credential
            .secret_verifier
            .as_ref()
            .ok_or(AccountsError::InvalidCredentials)?;

        let verified = password::verify_password(password_plaintext, stored_hash.expose_secret())
            .unwrap_or(false);
        if !verified {
            return Err(AccountsError::InvalidCredentials);
        }

        if password::needs_rehash(stored_hash.expose_secret()) {
            if let Ok(new_hash) = password::hash_password(password_plaintext) {
                // Best-effort: a rehash failure must not fail the login that
                // already succeeded on the old (still-valid) hash.
                let _ = CredentialRepository::rehash_secret(
                    self,
                    &password_credential.credential_id,
                    new_hash,
                    "argon2id",
                    None,
                    password_credential.version + 1,
                )
                .await;
            }
        }

        let access_secret = secrets::generate_opaque_secret();
        let refresh_secret = secrets::generate_opaque_secret();
        let session = Session {
            session_id: generate_id(),
            account_id: account.account_id.clone(),
            realm_id: realm_id.to_owned(),
            access_secret_hash: secrets::hash_opaque_secret(access_secret.expose_secret()),
            refresh_family_id: generate_id(),
            refresh_secret_hash: secrets::hash_opaque_secret(refresh_secret.expose_secret()),
            client_identity_id: None,
            client_kind,
            client_label: client_label.map(str::to_owned),
            assurance_level: AssuranceLevel::Aal1,
            authenticated_at: now.to_owned(),
            step_up_at: None,
            created_at: now.to_owned(),
            last_seen_at: now.to_owned(),
            idle_expires_at: utc_offset(idle_timeout_minutes * 60),
            absolute_expires_at: utc_offset(absolute_timeout_hours * 3600),
            security_version_at_issue: account.security_version,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
            // Sessions issue bearer-only; a PoP client binds its public key
            // immediately after via `SessionRepository::bind_public_key`
            // (114E). Kept out of the issuance signature to avoid threading
            // an optional key through every login path and its many callers.
            bound_public_key: None,
        };
        let issued = SessionRepository::issue(self, session).await?;
        Ok(LoginOutcome {
            session: issued,
            access_secret,
            refresh_secret,
        })
    }
}

impl RqliteStore {
    // -- Login throttling (114C.3, negative-auth) --------------------------
    //
    // A rolling window, not a manual-unlock lockout: a dimension's failure
    // count only ever includes attempts within the last
    // `LOGIN_THROTTLE_WINDOW_SECS`, so access restores itself as old
    // failures age out -- "throttling without permanent lockout" by
    // construction, not by a separate expiry mechanism that could be
    // forgotten. Two independent dimensions (username, client) close the
    // gap named in the 114C.0 ForgeWire account-behavior inventory.

    async fn enforce_login_throttle(
        &self,
        dimension_kind: &str,
        dimension_key: &str,
    ) -> AccountsResult<()> {
        let window_start = utc_offset(-LOGIN_THROTTLE_WINDOW_SECS);
        let failures = self
            .count_recent_failures(dimension_kind, dimension_key, &window_start)
            .await?;
        if failures >= LOGIN_FAILURE_THRESHOLD {
            return Err(AccountsError::AccountLocked {
                retry_after_seconds: Some(LOGIN_THROTTLE_WINDOW_SECS),
            });
        }
        Ok(())
    }

    async fn count_recent_failures(
        &self,
        dimension_kind: &str,
        dimension_key: &str,
        since: &str,
    ) -> AccountsResult<i64> {
        self.query_scalar::<i64>(
            "SELECT COUNT(*) FROM human_login_attempts WHERE dimension_kind=? AND dimension_key=? AND successful=0 AND attempted_at>=?",
            &[json!(dimension_kind), json!(dimension_key), json!(since)],
        )
        .await
        .map_err(map_backend_error)
        .map(|v| v.unwrap_or(0))
    }

    async fn record_login_attempt(
        &self,
        dimension_kind: &str,
        dimension_key: &str,
        successful: bool,
        now: &str,
    ) -> AccountsResult<()> {
        self.execute_one(
            "INSERT INTO human_login_attempts (dimension_kind,dimension_key,attempted_at,successful) VALUES (?,?,?,?)",
            &[json!(dimension_kind), json!(dimension_key), json!(now), json!(i64::from(successful))],
        )
        .await
        .map_err(map_backend_error)?;
        Ok(())
    }
}

impl RqliteStore {
    async fn diagnose_blocked_write(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
    ) -> AccountsError {
        match AccountRepository::get_account(self, account_id).await {
            Ok(current) if current.revision == expected_revision => {
                AccountsError::LastAdministratorViolation
            }
            Ok(_) => AccountsError::AccountPolicyViolation {
                reason: "revision_conflict".to_owned(),
            },
            Err(e) => e,
        }
    }

    /// Distinguishes the three ways `initiate_account_deletion_protecting_last_admin`'s
    /// UPDATE can affect 0 rows: a stale revision, an account already past
    /// the point deletion can be (re-)initiated, or the last-admin guard.
    async fn diagnose_blocked_deletion(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
    ) -> AccountsError {
        match AccountRepository::get_account(self, account_id).await {
            Ok(current) if current.revision != expected_revision => {
                AccountsError::AccountPolicyViolation {
                    reason: "revision_conflict".to_owned(),
                }
            }
            Ok(current)
                if matches!(
                    current.status,
                    AccountStatus::DeletionPending | AccountStatus::DeletedTombstone
                ) =>
            {
                AccountsError::AccountPolicyViolation {
                    reason: "already_pending_or_deleted".to_owned(),
                }
            }
            Ok(_) => AccountsError::LastAdministratorViolation,
            Err(e) => e,
        }
    }

    /// Distinguishes why `complete_account_deletion`'s UPDATE affected 0
    /// rows: a stale revision, or the account was never actually
    /// `deletion_pending` (deletion was never initiated, or this is a
    /// repeat call after it already completed).
    async fn diagnose_blocked_tombstone(
        &self,
        account_id: &AccountId,
        expected_revision: i64,
    ) -> AccountsError {
        match AccountRepository::get_account(self, account_id).await {
            Ok(current) if current.revision != expected_revision => {
                AccountsError::AccountPolicyViolation {
                    reason: "revision_conflict".to_owned(),
                }
            }
            Ok(_) => AccountsError::AccountPolicyViolation {
                reason: "account_not_deletion_pending".to_owned(),
            },
            Err(e) => e,
        }
    }
}

const LOGIN_FAILURE_THRESHOLD: i64 = 5;
const LOGIN_THROTTLE_WINDOW_SECS: i64 = 300;
