//! Domain types for the human-account, credential, membership, and session
//! authority (114C). These are the internal, full-fidelity records -- they
//! deliberately do not derive `Serialize`, so a route handler cannot return
//! one directly across the API boundary even by accident. Only the safe DTOs
//! in `dto.rs`, built by explicit field extraction, are meant to cross it.
//!
//! Field shapes follow the locked rqlite data model in
//! `114C-human-accounts-sessions-operator-identity.md`; exact SQL is a
//! 114C.2 concern, not this crate's.

use crate::secret::SecretString;

pub type AccountId = String;
pub type RealmId = String;
pub type SessionId = String;
pub type CredentialId = String;
pub type MembershipId = String;

/// Account lifecycle states. See the human-accounts plan's "Account
/// lifecycle" section for the transition rules; this crate models the states,
/// the store (114C.2) and services (114C.3+) enforce the transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountStatus {
    Invited,
    Active,
    Disabled,
    Locked,
    RecoveryRequired,
    DeletionPending,
    DeletedTombstone,
}

impl AccountStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Invited => "invited",
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Locked => "locked",
            Self::RecoveryRequired => "recovery_required",
            Self::DeletionPending => "deletion_pending",
            Self::DeletedTombstone => "deleted_tombstone",
        }
    }

    /// `true` for a status that may still authenticate (subject to
    /// credential/membership policy). `locked`/`recovery_required` are
    /// intentionally excluded here -- both permit only narrower, explicitly
    /// scoped operations than "may authenticate normally".
    pub fn may_authenticate_normally(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// The full authorization-role vocabulary, matching
/// `fabric-hub::auth::VALID_ROLES` plus the new `admin` composite role.
/// `Runner` exists in this enum because it is a real role in the system --
/// the point of 114C is that it can never be reached by [`Membership::for_human`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Observer,
    Dispatcher,
    Approver,
    Reviewer,
    Admin,
    Runner,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observer => "observer",
            Self::Dispatcher => "dispatcher",
            Self::Approver => "approver",
            Self::Reviewer => "reviewer",
            Self::Admin => "admin",
            Self::Runner => "runner",
        }
    }

    /// The human-role baseline table in the plan: every role except `runner`
    /// may be held by a human account.
    pub fn human_assignable(&self) -> bool {
        !matches!(self, Self::Runner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    Password,
    Webauthn,
}

impl CredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Webauthn => "webauthn",
        }
    }
}

/// A password or WebAuthn credential bound to an account.
///
/// `secret_verifier` is `None` for a WebAuthn credential (the public key
/// lives in `public_key_material`, which is not secret by definition and may
/// be exposed through safe DTOs if a caller ever needs it -- unlike
/// `secret_verifier`, which never crosses `dto.rs`).
#[derive(Debug)]
pub struct Credential {
    pub credential_id: CredentialId,
    pub account_id: AccountId,
    pub kind: CredentialKind,
    pub secret_verifier: Option<SecretString>,
    pub algorithm: Option<String>,
    pub algorithm_params: Option<serde_json::Value>,
    pub version: i64,
    pub public_key_material: Option<String>,
    pub label: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub compromised_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revision: i64,
    /// WebAuthn "backup eligible" flag (BE bit): the authenticator's private
    /// key is *capable* of being backed up/synced across devices (e.g. a
    /// platform passkey stored in a cloud keychain), as opposed to being
    /// sealed to a single hardware authenticator. Always `false` for
    /// password credentials.
    pub backup_eligible: bool,
    /// WebAuthn "backup state" flag (BS bit): the credential *is currently*
    /// backed up/synced. Can change between logins for the same credential
    /// (e.g. a newly registered synced passkey may not have finished
    /// syncing yet). Always `false` for password credentials.
    pub backup_state: bool,
}

/// The realm's founding cryptographic identity (114D D.1): the single
/// replicated record every principal, credential, policy, and origin attaches
/// to. It is a store-layer *singleton* -- at most one exists per cluster,
/// enforced by a compare-and-set insert (114D sec 15.1) so that two freshly
/// installed nodes racing genesis produce exactly one realm, never two.
///
/// `rp_id` + `origins` are the load-bearing fields: every node's WebAuthn
/// verifier reads them from this replicated record rather than a local
/// hostname, which is what makes "any node verifies any human's passkey" true
/// cluster-wide and closes the per-hostname relying-party trap (114D sec 5).
/// `rp_id` defaults to `localhost` with loopback-origin ceremonies and is the
/// single override point for a realm-bound domain. Like [`Account`]/[`Session`],
/// fields are `pub` -- a store adapter reconstructs an already-validated row
/// with a struct literal; new-write validation lives at the store write path.
#[derive(Debug, Clone)]
pub struct RealmIdentity {
    pub realm_id: RealmId,
    pub name: String,
    pub rp_id: String,
    pub origins: Vec<String>,
    pub created_at: String,
    /// The node that founded the realm (genesis). Informational: the head is
    /// mobile (114D sec 2/3), so this records where genesis *ran*, not a
    /// permanent authority.
    pub genesis_node: Option<String>,
    pub key_alg: String,
}

/// A stable human-principal record. Never itself a credential -- see
/// [`Credential`] for what proves control of it.
#[derive(Debug)]
pub struct Account {
    pub account_id: AccountId,
    pub realm_id: RealmId,
    pub username_normalized: String,
    pub username_display: String,
    pub display_name: String,
    pub email_normalized: Option<String>,
    pub status: AccountStatus,
    pub created_at: String,
    pub updated_at: String,
    pub disabled_at: Option<String>,
    pub deleted_at: Option<String>,
    pub revision: i64,
    pub security_version: i64,
}

/// An account's role assignment. New memberships should be constructed
/// through [`Membership::for_human`] or [`Membership::for_automation_migration`],
/// which validate the human/runner invariant. Fields are `pub` -- like
/// [`Account`] and [`Session`], a store adapter reconstructing an
/// already-validated row from persistence uses a plain struct literal rather
/// than re-running validation meant for new writes. The invariant that
/// matters at persistence time (a human account may never hold `Role::Runner`)
/// is enforced independently at the store layer's write path
/// (`MembershipRepository::grant`), not solely by this constructor.
#[derive(Debug)]
pub struct Membership {
    pub membership_id: MembershipId,
    pub account_id: AccountId,
    pub realm_id: RealmId,
    pub role: Role,
    pub granted_by_account_id: Option<AccountId>,
    pub granted_at: String,
    pub revoked_at: Option<String>,
    pub revision: i64,
}

impl Membership {
    /// Construct a membership for a human account. Rejects `Role::Runner`
    /// outright -- this is the domain-layer half of "human runner membership
    /// is rejected in domain validation" (114C.1 acceptance); the store
    /// (114C.2) enforces the same rule again at the persistence boundary so
    /// neither layer depends solely on the other.
    pub fn for_human(
        membership_id: MembershipId,
        account_id: AccountId,
        realm_id: RealmId,
        role: Role,
        granted_by_account_id: Option<AccountId>,
        granted_at: String,
    ) -> Result<Self, crate::error::AccountsError> {
        if !role.human_assignable() {
            return Err(crate::error::AccountsError::AccountPolicyViolation {
                reason: "human_runner_membership_forbidden".to_owned(),
            });
        }
        Ok(Self {
            membership_id,
            account_id,
            realm_id,
            role,
            granted_by_account_id,
            granted_at,
            revoked_at: None,
            revision: 0,
        })
    }

    /// Construct a membership for the machine-only `runner` purpose during a
    /// bootstrap/system migration path (`granted_by_account_id` is always
    /// `None` here, matching the field's documented bootstrap/system-migration
    /// use). Kept as a distinct, narrowly named constructor so a `Runner`
    /// membership can never be produced by the same code path a human
    /// operator's request flows through.
    pub fn for_automation_migration(
        membership_id: MembershipId,
        account_id: AccountId,
        realm_id: RealmId,
        granted_at: String,
    ) -> Self {
        Self {
            membership_id,
            account_id,
            realm_id,
            role: Role::Runner,
            granted_by_account_id: None,
            granted_at,
            revoked_at: None,
            revision: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssuranceLevel {
    Aal1,
    Aal2,
    RecoveryLimited,
}

impl AssuranceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aal1 => "aal1",
            Self::Aal2 => "aal2",
            Self::RecoveryLimited => "recovery_limited",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKind {
    Vsix,
    Desktop,
    Cli,
    Other,
}

impl ClientKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vsix => "vsix",
            Self::Desktop => "desktop",
            Self::Cli => "cli",
            Self::Other => "other",
        }
    }
}

/// A server-side authenticated continuity record. `access_secret_hash` and
/// `refresh_secret_hash` are keyed-hash lookup keys, not the secrets
/// themselves -- the plan requires "store only keyed hashes/digests", so
/// these fields are plain `String`, not [`SecretString`]: they are not
/// secret material to begin with, they are a hash of it. They are still kept
/// out of the safe DTO in `dto.rs`, because a hash is still not something a
/// renderer needs.
#[derive(Debug)]
pub struct Session {
    pub session_id: SessionId,
    pub account_id: AccountId,
    pub realm_id: RealmId,
    pub access_secret_hash: String,
    pub refresh_family_id: String,
    pub refresh_secret_hash: String,
    pub client_identity_id: Option<String>,
    pub client_kind: ClientKind,
    pub client_label: Option<String>,
    pub assurance_level: AssuranceLevel,
    pub authenticated_at: String,
    pub step_up_at: Option<String>,
    pub created_at: String,
    pub last_seen_at: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    pub security_version_at_issue: i64,
    pub revoked_at: Option<String>,
    pub revoke_reason: Option<String>,
    pub revision: i64,
    /// Hex Ed25519 public key a proof-of-possession client bound to this
    /// session at login (114E). `None` for a bearer-only session (114C).
    /// When set, the session authenticates by request *signature* (the
    /// private key never leaves the client) rather than by presenting the
    /// opaque `access_secret` -- see `resolve_signed_session` in
    /// `fabric-hub/src/auth.rs`. Not a secret (a public key), but kept off
    /// the safe DTO like the hashes above -- a renderer has no need for it.
    pub bound_public_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_assignable_excludes_only_runner() {
        assert!(Role::Observer.human_assignable());
        assert!(Role::Dispatcher.human_assignable());
        assert!(Role::Approver.human_assignable());
        assert!(Role::Reviewer.human_assignable());
        assert!(Role::Admin.human_assignable());
        assert!(!Role::Runner.human_assignable());
    }

    #[test]
    fn for_human_rejects_runner() {
        let result = Membership::for_human(
            "m-1".into(),
            "a-1".into(),
            "r-1".into(),
            Role::Runner,
            Some("admin-1".into()),
            "2026-07-17 00:00:00".into(),
        );
        assert!(matches!(
            result,
            Err(crate::error::AccountsError::AccountPolicyViolation { .. })
        ));
    }

    #[test]
    fn for_human_accepts_every_non_runner_role() {
        for role in [
            Role::Observer,
            Role::Dispatcher,
            Role::Approver,
            Role::Reviewer,
            Role::Admin,
        ] {
            let result = Membership::for_human(
                "m-1".into(),
                "a-1".into(),
                "r-1".into(),
                role,
                Some("admin-1".into()),
                "2026-07-17 00:00:00".into(),
            );
            assert!(result.is_ok(), "role {role:?} should be human-assignable");
        }
    }

    #[test]
    fn for_automation_migration_produces_runner_with_no_grantor() {
        let membership = Membership::for_automation_migration(
            "m-2".into(),
            "runner-acct-1".into(),
            "r-1".into(),
            "2026-07-17 00:00:00".into(),
        );
        assert_eq!(membership.role, Role::Runner);
        assert!(membership.granted_by_account_id.is_none());
    }

    #[test]
    fn account_status_round_trips_through_as_str() {
        let all = [
            AccountStatus::Invited,
            AccountStatus::Active,
            AccountStatus::Disabled,
            AccountStatus::Locked,
            AccountStatus::RecoveryRequired,
            AccountStatus::DeletionPending,
            AccountStatus::DeletedTombstone,
        ];
        let strings: Vec<&str> = all.iter().map(AccountStatus::as_str).collect();
        assert_eq!(
            strings,
            vec![
                "invited",
                "active",
                "disabled",
                "locked",
                "recovery_required",
                "deletion_pending",
                "deleted_tombstone",
            ]
        );
    }

    #[test]
    fn only_active_may_authenticate_normally() {
        assert!(AccountStatus::Active.may_authenticate_normally());
        assert!(!AccountStatus::Invited.may_authenticate_normally());
        assert!(!AccountStatus::Locked.may_authenticate_normally());
        assert!(!AccountStatus::RecoveryRequired.may_authenticate_normally());
        assert!(!AccountStatus::Disabled.may_authenticate_normally());
    }
}
