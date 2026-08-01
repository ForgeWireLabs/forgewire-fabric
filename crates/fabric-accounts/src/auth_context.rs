//! The additive request-authorization context from the plan's "Request
//! authentication and authorization context" section.
//!
//! This is a new, standalone type -- it does not modify
//! `fabric_hub::auth::AuthContext`, and nothing in `fabric-hub` constructs or
//! consumes it yet. Wiring it into the hub's request pipeline (inserting the
//! human-session-validation step ahead of the existing signature/policy
//! check, per `114C-0-identity-trust-boundaries.md` section 2) is 114C.4's
//! job. Per this milestone's rollback note -- "no database or live mode
//! change... without enabling routes" -- this crate only needs to prove the
//! contract's shape is sound, not thread it through any route.

use serde::{Deserialize, Serialize};

/// Which of the four identity layers authenticated the current request.
/// Exactly one of the corresponding fields on [`AccountAuthContext`] is
/// populated for a given kind -- see the type's own doc comment for the rule
/// this maps to ("no single identifier is allowed to impersonate all four
/// layers").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    HumanSession,
    AutomationToken,
    RunnerIdentity,
    Anonymous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAuthInfo {
    pub session_id: String,
    pub assurance_level: String,
    pub auth_time: String,
    pub step_up_time: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdentityInfo {
    pub identity_id: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomationCredentialInfo {
    /// A safe token fingerprint (e.g. the existing SHA-256 hash prefix used
    /// by `fabric-hub::auth`), never the token value itself.
    pub safe_token_id: String,
    pub granted_roles: Vec<String>,
}

/// The additive authorization context. Every field beyond
/// `authentication_kind` is optional and populated only for the layer(s)
/// actually present on the request -- credential precedence (plan §"Request
/// authentication and authorization context") is enforced by the code that
/// *constructs* this type in 114C.4, not by this type refusing to hold
/// contradictory data. This type is a record, not a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountAuthContext {
    pub authentication_kind: PrincipalKind,
    pub human_principal_account_id: Option<String>,
    pub session: Option<SessionAuthInfo>,
    pub effective_roles: Vec<String>,
    pub client_identity: Option<ClientIdentityInfo>,
    pub automation_credential: Option<AutomationCredentialInfo>,
}

impl AccountAuthContext {
    pub fn anonymous() -> Self {
        Self {
            authentication_kind: PrincipalKind::Anonymous,
            human_principal_account_id: None,
            session: None,
            effective_roles: Vec::new(),
            client_identity: None,
            automation_credential: None,
        }
    }

    /// A human session cannot be represented without a human principal --
    /// this constructor is the one place that invariant is enforced in code
    /// rather than left to caller discipline.
    pub fn human_session(
        account_id: String,
        session: SessionAuthInfo,
        effective_roles: Vec<String>,
        client_identity: Option<ClientIdentityInfo>,
    ) -> Self {
        Self {
            authentication_kind: PrincipalKind::HumanSession,
            human_principal_account_id: Some(account_id),
            session: Some(session),
            effective_roles,
            client_identity,
            automation_credential: None,
        }
    }

    /// Automation is never attributed to a person: this constructor has no
    /// `account_id` parameter, so an automation-authenticated request cannot
    /// even accidentally carry one -- directly serving the plan's
    /// "automation credential use... is never labeled as a person" rule and
    /// this crate's own audit-leakage/dual-attribution boundary.
    pub fn automation(credential: AutomationCredentialInfo, effective_roles: Vec<String>) -> Self {
        Self {
            authentication_kind: PrincipalKind::AutomationToken,
            human_principal_account_id: None,
            session: None,
            effective_roles,
            client_identity: None,
            automation_credential: Some(credential),
        }
    }

    pub fn is_human(&self) -> bool {
        matches!(self.authentication_kind, PrincipalKind::HumanSession)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automation_context_never_carries_a_human_principal() {
        let ctx = AccountAuthContext::automation(
            AutomationCredentialInfo {
                safe_token_id: "sha256:abcd1234".into(),
                granted_roles: vec!["dispatcher".into(), "runner".into()],
            },
            vec!["dispatcher".into(), "runner".into()],
        );
        assert!(ctx.human_principal_account_id.is_none());
        assert!(!ctx.is_human());
        assert_eq!(ctx.authentication_kind, PrincipalKind::AutomationToken);
    }

    #[test]
    fn human_session_context_always_carries_a_principal() {
        let ctx = AccountAuthContext::human_session(
            "acct-1".into(),
            SessionAuthInfo {
                session_id: "sess-1".into(),
                assurance_level: "aal1".into(),
                auth_time: "2026-07-17 00:00:00".into(),
                step_up_time: None,
            },
            vec!["dispatcher".into()],
            None,
        );
        assert_eq!(ctx.human_principal_account_id.as_deref(), Some("acct-1"));
        assert!(ctx.is_human());
    }

    #[test]
    fn anonymous_context_has_no_roles_and_no_identity() {
        let ctx = AccountAuthContext::anonymous();
        assert!(ctx.effective_roles.is_empty());
        assert!(ctx.human_principal_account_id.is_none());
        assert!(ctx.client_identity.is_none());
        assert!(ctx.automation_credential.is_none());
    }
}
