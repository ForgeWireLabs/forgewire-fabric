//! Safe, serializable DTOs. These are the only account/session types allowed
//! to derive `Serialize` in this crate, and every field on them is drawn from
//! the plan's "Safe shared models" list. Conversions from domain types are
//! explicit field-by-field extraction (`From<&Account>` etc.) rather than
//! `#[serde(flatten)]` or a blanket derive on the domain type itself, so
//! adding a field to [`crate::domain::Account`] never silently widens what a
//! DTO exposes -- a new domain field requires a new line here, on purpose.

use serde::{Deserialize, Serialize};

use crate::domain::{Account, AccountStatus, ClientKind, Credential, Membership, Role, Session};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSummaryDto {
    pub account_id: String,
    pub username: String,
    pub display_name: String,
    pub status: String,
    pub roles: Vec<String>,
    /// The *account's own* `revision` (compare-and-set token for
    /// `PATCH /accounts/{id}`, `/disable`, `/enable`, `/delete`,
    /// `/tombstone` -- every route that takes `expected_revision`). Added in
    /// 114C.7: without it, no client can ever populate `expected_revision`
    /// for those five routes, since this summary is the only place an
    /// account's current state reaches a caller. This is the account's own
    /// `revision` field (see `Account::revision` and the plan's "revision
    /// for compare-and-set changes" under Account fields) -- deliberately
    /// distinct from a *membership's* `revision`, which stays off this DTO
    /// per the "never a membership's ... revision" rule below.
    pub revision: i64,
}

impl AccountSummaryDto {
    /// Build a summary from an account plus its current (non-revoked)
    /// memberships. Only `Role::as_str()` output reaches the DTO -- never a
    /// membership's `granted_by_account_id`, `revision`, or any other
    /// administrative field not on the plan's safe-models list.
    pub fn from_account_and_memberships(account: &Account, memberships: &[Membership]) -> Self {
        let roles = memberships
            .iter()
            .filter(|m| m.revoked_at.is_none() && m.account_id == account.account_id)
            .map(|m| m.role.as_str().to_owned())
            .collect();
        Self {
            account_id: account.account_id.clone(),
            username: account.username_display.clone(),
            display_name: account.display_name.clone(),
            status: account.status.as_str().to_owned(),
            roles,
            revision: account.revision,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummaryDto {
    pub session_id: String,
    pub account_id: String,
    pub client_kind: String,
    pub client_label: Option<String>,
    pub assurance_level: String,
    pub authenticated_at: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    pub current: bool,
}

impl SessionSummaryDto {
    /// `current` is supplied by the caller rather than derived from the
    /// session itself: "is this the session the requester is using right
    /// now" is a property of the request, not of the session row.
    pub fn from_session(session: &Session, current: bool) -> Self {
        Self {
            session_id: session.session_id.clone(),
            account_id: session.account_id.clone(),
            client_kind: session.client_kind.as_str().to_owned(),
            client_label: session.client_label.clone(),
            assurance_level: session.assurance_level.as_str().to_owned(),
            authenticated_at: session.authenticated_at.clone(),
            idle_expires_at: session.idle_expires_at.clone(),
            absolute_expires_at: session.absolute_expires_at.clone(),
            current,
        }
    }
}

/// One row of an account's bounded login-attempt history (114C.5's "bounded
/// login/session security history" deliverable). Deliberately minimal: no
/// `dimension_kind`/`dimension_key` (internal throttle bookkeeping, not a
/// safe shared model), no client IP or fingerprint -- only whether an
/// attempt against this account's username succeeded, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginAttemptDto {
    pub attempted_at: String,
    pub successful: bool,
}

/// A registered WebAuthn credential, safe to return over HTTP (114C.6).
/// Never the raw public key/COSE material -- `Credential::public_key_material`
/// holds the full serialized `webauthn-rs` `Passkey` blob, which is
/// mechanically necessary for running future ceremonies but is not itself
/// on the plan's "Safe shared models" list, so it stops here, matching this
/// file's own "explicit field-by-field extraction" rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeySummaryDto {
    pub credential_id: String,
    pub label: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    /// Whether this credential's private key is capable of being backed
    /// up/synced across devices (WebAuthn BE bit) -- metadata only, not a
    /// trust decision; see `Credential::backup_eligible`'s doc comment.
    pub backup_eligible: bool,
    /// Whether this credential is currently backed up/synced (WebAuthn BS
    /// bit); see `Credential::backup_state`'s doc comment.
    pub backup_state: bool,
}

impl PasskeySummaryDto {
    /// Callers are responsible for filtering to `CredentialKind::Webauthn`,
    /// non-revoked rows before calling this -- it does not filter or
    /// inspect `kind` itself, matching `SessionSummaryDto::from_session`'s
    /// precedent of taking `current` as caller-supplied context rather than
    /// re-deriving it.
    pub fn from_credential(credential: &Credential) -> Self {
        Self {
            credential_id: credential.credential_id.clone(),
            label: credential.label.clone(),
            created_at: credential.created_at.clone(),
            last_used_at: credential.last_used_at.clone(),
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
        }
    }
}

/// A safe, exportable snapshot of one account's profile fields (114C.5
/// account export). Never credentials, sessions, or any secret -- the same
/// "explicit field-by-field extraction" guarantee as every other DTO in
/// this file, structurally incapable of carrying a secret even if a future
/// domain field is added without a matching line here. Includes `email`
/// (which `AccountSummaryDto` deliberately omits) because export's whole
/// purpose is a durable profile backup/migration artifact, not a UI-facing
/// summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountExportDto {
    pub account_id: String,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub status: String,
    pub roles: Vec<String>,
    pub created_at: String,
}

impl AccountExportDto {
    pub fn from_account_and_memberships(account: &Account, memberships: &[Membership]) -> Self {
        let roles = memberships
            .iter()
            .filter(|m| m.revoked_at.is_none() && m.account_id == account.account_id)
            .map(|m| m.role.as_str().to_owned())
            .collect();
        Self {
            account_id: account.account_id.clone(),
            username: account.username_display.clone(),
            display_name: account.display_name.clone(),
            email: account.email_normalized.clone(),
            status: account.status.as_str().to_owned(),
            roles,
            created_at: account.created_at.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedAuthErrorDto {
    pub code: String,
    pub message: String,
}

impl From<&crate::error::AccountsError> for TypedAuthErrorDto {
    fn from(error: &crate::error::AccountsError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
        }
    }
}

fn _assert_role_and_status_produce_stable_strings(
    role: Role,
    status: AccountStatus,
    kind: ClientKind,
) {
    let _ = (role.as_str(), status.as_str(), kind.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AssuranceLevel, Credential, CredentialKind};
    use crate::secret::SecretString;

    fn sample_account() -> Account {
        Account {
            account_id: "acct-1".into(),
            realm_id: "realm-1".into(),
            username_normalized: "operator1".into(),
            username_display: "operator1".into(),
            display_name: "Operator One".into(),
            email_normalized: None,
            status: AccountStatus::Active,
            created_at: "2026-07-17 00:00:00".into(),
            updated_at: "2026-07-17 00:00:00".into(),
            disabled_at: None,
            deleted_at: None,
            revision: 1,
            security_version: 1,
        }
    }

    fn sample_membership(role: Role, revoked: bool) -> Membership {
        Membership::for_human(
            "m-1".into(),
            "acct-1".into(),
            "realm-1".into(),
            role,
            Some("acct-admin".into()),
            "2026-07-17 00:00:00".into(),
        )
        .map(|mut m| {
            if revoked {
                m.revoked_at = Some("2026-07-17 01:00:00".into());
            }
            m
        })
        .expect("role is human-assignable")
    }

    fn sample_session() -> Session {
        Session {
            session_id: "sess-1".into(),
            account_id: "acct-1".into(),
            realm_id: "realm-1".into(),
            access_secret_hash: "hash-of-access-secret".into(),
            refresh_family_id: "family-1".into(),
            refresh_secret_hash: "hash-of-refresh-secret".into(),
            client_identity_id: Some("dispatcher-1".into()),
            client_kind: ClientKind::Vsix,
            client_label: Some("VS Code on desktop-a".into()),
            assurance_level: AssuranceLevel::Aal1,
            authenticated_at: "2026-07-17 00:00:00".into(),
            step_up_at: None,
            created_at: "2026-07-17 00:00:00".into(),
            last_seen_at: "2026-07-17 00:05:00".into(),
            idle_expires_at: "2026-07-17 01:00:00".into(),
            absolute_expires_at: "2026-07-18 00:00:00".into(),
            security_version_at_issue: 1,
            revoked_at: None,
            revoke_reason: None,
            revision: 1,
            bound_public_key: None,
        }
    }

    #[test]
    fn account_summary_includes_only_non_revoked_memberships_for_the_right_account() {
        let account = sample_account();
        let memberships = vec![
            sample_membership(Role::Dispatcher, false),
            sample_membership(Role::Reviewer, true), // revoked -- must not appear
        ];
        let summary = AccountSummaryDto::from_account_and_memberships(&account, &memberships);
        assert_eq!(summary.roles, vec!["dispatcher"]);
        assert_eq!(summary.status, "active");
    }

    #[test]
    fn session_summary_never_carries_the_secret_hashes() {
        let session = sample_session();
        let summary = SessionSummaryDto::from_session(&session, true);
        let json = serde_json::to_string(&summary).expect("serialize");
        assert!(!json.contains("hash-of-access-secret"));
        assert!(!json.contains("hash-of-refresh-secret"));
        assert!(json.contains("sess-1"));
        assert!(json.contains("true"));
    }

    /// The runtime half of "secret fields cannot serialize through safe DTO
    /// types": build a credential holding a real secret, prove the safe DTOs
    /// built alongside it never mention it in their JSON, and prove
    /// `SecretString`'s own `Debug` redacts even if something were to debug-
    /// print the domain struct directly.
    #[test]
    fn a_real_secret_never_reaches_any_safe_dto_json() {
        const SENTINEL: &str = "sekrit-value-should-never-leak-anywhere";
        let credential = Credential {
            credential_id: "cred-1".into(),
            account_id: "acct-1".into(),
            kind: CredentialKind::Password,
            secret_verifier: Some(SecretString::new(SENTINEL)),
            algorithm: Some("argon2id".into()),
            algorithm_params: None,
            version: 1,
            public_key_material: None,
            label: None,
            created_at: "2026-07-17 00:00:00".into(),
            last_used_at: None,
            compromised_at: None,
            revoked_at: None,
            revision: 1,
            backup_eligible: false,
            backup_state: false,
        };

        let account = sample_account();
        let memberships = vec![sample_membership(Role::Admin, false)];
        let session = sample_session();

        let account_json = serde_json::to_string(&AccountSummaryDto::from_account_and_memberships(
            &account,
            &memberships,
        ))
        .expect("serialize account summary");
        let export_json = serde_json::to_string(&AccountExportDto::from_account_and_memberships(
            &account,
            &memberships,
        ))
        .expect("serialize account export");
        assert!(!export_json.contains(SENTINEL));
        let session_json = serde_json::to_string(&SessionSummaryDto::from_session(&session, false))
            .expect("serialize session summary");
        let debug_output = format!("{credential:?}");

        assert!(!account_json.contains(SENTINEL));
        assert!(!session_json.contains(SENTINEL));
        assert!(
            !debug_output.contains(SENTINEL),
            "Credential's Debug output must redact secret_verifier"
        );
        assert!(debug_output.contains("REDACTED"));
    }

    #[test]
    fn passkey_summary_never_carries_the_serialized_public_key_blob() {
        const SENTINEL: &str = "opaque-serialized-passkey-blob-should-never-leak";
        let credential = Credential {
            credential_id: "cred-webauthn-1".into(),
            account_id: "acct-1".into(),
            kind: CredentialKind::Webauthn,
            secret_verifier: None,
            algorithm: None,
            algorithm_params: None,
            version: 1,
            public_key_material: Some(SENTINEL.into()),
            label: Some("YubiKey 5".into()),
            created_at: "2026-07-17 00:00:00".into(),
            last_used_at: Some("2026-07-17 01:00:00".into()),
            compromised_at: None,
            revoked_at: None,
            revision: 1,
            backup_eligible: true,
            backup_state: true,
        };
        let summary = PasskeySummaryDto::from_credential(&credential);
        assert_eq!(summary.credential_id, "cred-webauthn-1");
        assert_eq!(summary.label.as_deref(), Some("YubiKey 5"));
        assert!(summary.backup_eligible);
        assert!(summary.backup_state);
        let json = serde_json::to_string(&summary).expect("serialize");
        assert!(!json.contains(SENTINEL));
    }
}
