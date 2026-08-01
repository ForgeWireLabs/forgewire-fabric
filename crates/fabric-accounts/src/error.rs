//! The typed-error baseline from the human-accounts plan's "API contract"
//! section, "at minimum" list. Every variant is a stable code with only safe
//! fields -- "errors cross the API as stable typed codes without credential
//! enumeration or secret-bearing debug strings" is enforced here by
//! construction: no variant below can hold a [`crate::secret::SecretString`]
//! or anything else that doesn't already implement `Serialize`.
//!
//! [`AccountsError::ALL_CODES`] is the single source of truth the
//! cross-language fixture test checks both this enum and the TypeScript
//! `TYPED_AUTH_ERROR_CODES` array against, so the two cannot drift apart
//! silently the way `ENDPOINT_AUTH_MATRIX.md` did before 114C.0's
//! role-policy-baseline fixture pinned it.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum AccountsError {
    #[error("authentication is required")]
    AuthenticationRequired,

    #[error("the provided credentials are invalid")]
    InvalidCredentials,

    #[error("the session has expired")]
    SessionExpired,

    #[error("the session has been revoked")]
    SessionRevoked,

    #[error("refresh secret reuse detected; the token family has been revoked")]
    RefreshReplayDetected,

    #[error("the account is disabled")]
    AccountDisabled,

    #[error("the account is locked")]
    AccountLocked { retry_after_seconds: Option<i64> },

    #[error("recovery must be completed before this operation")]
    RecoveryRequired,

    #[error("a fresh high-assurance authentication (step-up) is required")]
    StepUpRequired,

    #[error("the current session assurance level is too low for this operation")]
    AssuranceTooLow,

    #[error("the operation violates account policy: {reason}")]
    AccountPolicyViolation { reason: String },

    #[error("this would leave the realm with no enabled administrator")]
    LastAdministratorViolation,

    #[error("the requested username is already in use")]
    UsernameConflict,

    #[error("the credential conflicts with an existing one")]
    CredentialConflict,

    #[error("bootstrap is closed: a realm administrator already exists")]
    BootstrapClosed,

    #[error("bootstrap is only permitted from a local/native administrative channel")]
    BootstrapLocalOnly,

    #[error("the authentication service is temporarily unavailable")]
    AuthServiceUnavailable,

    /// Reused from `fabric-hub::auth`'s existing role-policy-violation code
    /// rather than duplicated, so a caller distinguishing "no role" from "role
    /// denied by human-account policy" sees the same code either way.
    #[error("the role does not authorize this operation")]
    RolePolicyViolation,

    /// A WebAuthn ceremony challenge (registration, authentication, or
    /// step-up) could not be redeemed: it does not exist, has expired, was
    /// already consumed, or exceeded its attempt cap (114C.6). Deliberately
    /// one code for all four cases -- distinguishing them would hand an
    /// attacker a retry oracle for exactly the kind of enumeration the
    /// plan's "non-enumerating errors" principle already rejects for login.
    #[error("the challenge is invalid, expired, or already used")]
    ChallengeInvalid,

    /// A WebAuthn assertion's sign counter did not strictly advance the
    /// credential's previously stored counter (114C.6) -- a signal a
    /// cloned/duplicated authenticator may be in use. Deliberately distinct
    /// from `ChallengeInvalid`: this is raised only after the ceremony's
    /// cryptographic signature itself verified correctly, so it carries a
    /// different, more specific meaning an operator/UI may want to surface
    /// differently (e.g. "this passkey may be compromised") rather than the
    /// generic "try the ceremony again" `ChallengeInvalid` implies.
    #[error("the credential's sign counter did not advance; possible cloned authenticator")]
    CredentialReplaySuspected,

    /// The realm's founding identity already exists (114D D.1): a caller tried
    /// to establish a second realm on a cluster that already has one. Raised by
    /// the `realm_identity` singleton compare-and-set insert. Deliberately
    /// distinct from `BootstrapClosed` (which is about the first *human admin*
    /// existing): genesis (114D D.2) uses this specific code to detect that it
    /// lost a concurrent-genesis race and must convert to joining the existing
    /// realm rather than founding a new one (114D sec 15.1/15.2).
    #[error("the realm identity is already established")]
    RealmAlreadyEstablished,
}

impl AccountsError {
    /// The stable string code sent across the API. Distinct from the
    /// `Display` message, which is safe to log but not guaranteed stable for
    /// client `switch`/`match` dispatch.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "AuthenticationRequired",
            Self::InvalidCredentials => "InvalidCredentials",
            Self::SessionExpired => "SessionExpired",
            Self::SessionRevoked => "SessionRevoked",
            Self::RefreshReplayDetected => "RefreshReplayDetected",
            Self::AccountDisabled => "AccountDisabled",
            Self::AccountLocked { .. } => "AccountLocked",
            Self::RecoveryRequired => "RecoveryRequired",
            Self::StepUpRequired => "StepUpRequired",
            Self::AssuranceTooLow => "AssuranceTooLow",
            Self::AccountPolicyViolation { .. } => "AccountPolicyViolation",
            Self::LastAdministratorViolation => "LastAdministratorViolation",
            Self::UsernameConflict => "UsernameConflict",
            Self::CredentialConflict => "CredentialConflict",
            Self::BootstrapClosed => "BootstrapClosed",
            Self::BootstrapLocalOnly => "BootstrapLocalOnly",
            Self::AuthServiceUnavailable => "AuthServiceUnavailable",
            Self::RolePolicyViolation => "RolePolicyViolation",
            Self::ChallengeInvalid => "ChallengeInvalid",
            Self::CredentialReplaySuspected => "CredentialReplaySuspected",
            Self::RealmAlreadyEstablished => "RealmAlreadyEstablished",
        }
    }

    /// Every stable code this enum can produce, independent of any
    /// particular instance. Used to check the cross-language fixture for
    /// completeness (every code in the fixture must be one of these, and
    /// every one of these must appear in the fixture) rather than just
    /// checking that the fixture parses.
    pub const ALL_CODES: &'static [&'static str] = &[
        "AuthenticationRequired",
        "InvalidCredentials",
        "SessionExpired",
        "SessionRevoked",
        "RefreshReplayDetected",
        "AccountDisabled",
        "AccountLocked",
        "RecoveryRequired",
        "StepUpRequired",
        "AssuranceTooLow",
        "AccountPolicyViolation",
        "LastAdministratorViolation",
        "UsernameConflict",
        "CredentialConflict",
        "BootstrapClosed",
        "BootstrapLocalOnly",
        "AuthServiceUnavailable",
        "RolePolicyViolation",
        "ChallengeInvalid",
        "CredentialReplaySuspected",
        "RealmAlreadyEstablished",
    ];
}

pub type AccountsResult<T> = Result<T, AccountsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_never_embeds_a_secret_or_free_text() {
        // Every variant's code() must be one of the fixed ALL_CODES strings --
        // guards against a future variant returning something derived from
        // instance data (e.g. formatting `reason` into the code itself).
        let instances = [
            AccountsError::AuthenticationRequired,
            AccountsError::InvalidCredentials,
            AccountsError::SessionExpired,
            AccountsError::SessionRevoked,
            AccountsError::RefreshReplayDetected,
            AccountsError::AccountDisabled,
            AccountsError::AccountLocked {
                retry_after_seconds: Some(30),
            },
            AccountsError::RecoveryRequired,
            AccountsError::StepUpRequired,
            AccountsError::AssuranceTooLow,
            AccountsError::AccountPolicyViolation {
                reason: "anything".into(),
            },
            AccountsError::LastAdministratorViolation,
            AccountsError::UsernameConflict,
            AccountsError::CredentialConflict,
            AccountsError::BootstrapClosed,
            AccountsError::BootstrapLocalOnly,
            AccountsError::AuthServiceUnavailable,
            AccountsError::RolePolicyViolation,
            AccountsError::ChallengeInvalid,
            AccountsError::CredentialReplaySuspected,
            AccountsError::RealmAlreadyEstablished,
        ];
        for instance in &instances {
            assert!(
                AccountsError::ALL_CODES.contains(&instance.code()),
                "code {:?} for {:?} is not in ALL_CODES",
                instance.code(),
                instance
            );
        }
        assert_eq!(instances.len(), AccountsError::ALL_CODES.len());
    }

    #[test]
    fn all_codes_has_no_duplicates() {
        let mut sorted = AccountsError::ALL_CODES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), AccountsError::ALL_CODES.len());
    }
}
