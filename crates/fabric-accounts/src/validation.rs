//! Structural validators. Password/credential policy (length, blocklist,
//! Argon2id parameters) is 114C.3's job -- these are the account/username
//! shape rules the plan states directly in "Account lifecycle": "usernames
//! are normalized and unique within the realm."

use crate::error::AccountsError;

const MIN_USERNAME_LENGTH: usize = 3;
const MAX_USERNAME_LENGTH: usize = 64;

/// Normalize a username for storage/lookup: trim, lowercase. Uniqueness
/// itself is a store-layer (114C.2) invariant on `(realm_id,
/// username_normalized)`; this function only produces the value that
/// invariant is checked against, and rejects shapes that can never be valid
/// regardless of uniqueness.
pub fn normalize_username(raw: &str) -> Result<String, AccountsError> {
    let trimmed = raw.trim();
    if trimmed.len() < MIN_USERNAME_LENGTH || trimmed.chars().count() > MAX_USERNAME_LENGTH {
        return Err(AccountsError::AccountPolicyViolation {
            reason: "username_length_out_of_range".to_owned(),
        });
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(AccountsError::AccountPolicyViolation {
            reason: "username_contains_disallowed_characters".to_owned(),
        });
    }
    if trimmed.starts_with(['_', '.', '-']) || trimmed.ends_with(['_', '.', '-']) {
        return Err(AccountsError::AccountPolicyViolation {
            reason: "username_edge_character_disallowed".to_owned(),
        });
    }
    Ok(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trims_whitespace() {
        assert_eq!(normalize_username("  Operator1  ").unwrap(), "operator1");
    }

    #[test]
    fn rejects_too_short() {
        assert!(normalize_username("ab").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(65);
        assert!(normalize_username(&long).is_err());
    }

    #[test]
    fn rejects_disallowed_characters() {
        assert!(normalize_username("operator one").is_err());
        assert!(normalize_username("operator@example").is_err());
    }

    #[test]
    fn rejects_leading_and_trailing_punctuation() {
        assert!(normalize_username("_operator").is_err());
        assert!(normalize_username("operator_").is_err());
        assert!(normalize_username(".operator").is_err());
    }

    #[test]
    fn accepts_interior_punctuation() {
        assert_eq!(
            normalize_username("operator.one_2").unwrap(),
            "operator.one_2"
        );
    }

    #[test]
    fn error_reason_is_stable_and_does_not_echo_the_raw_input() {
        let err = normalize_username("bad username!").unwrap_err();
        match err {
            AccountsError::AccountPolicyViolation { reason } => {
                assert_eq!(reason, "username_contains_disallowed_characters");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
