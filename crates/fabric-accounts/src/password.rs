//! Password policy and Argon2id hashing -- the binding "Authentication
//! requirements / Password baseline" section of the human-accounts plan,
//! reviewed and approved by Security (`20260717-114c-0-security-approval-and-name-lock`).
//!
//! ## What is and is not calibrated here
//!
//! The plan requires Argon2id parameters "measured on both real machines...
//! may exceed OWASP's published minimum, but may not be lowered below it
//! without a recorded Security decision." [`ARGON2_PARAMS`] below is the
//! OWASP-published minimum itself (m=19MiB, t=2, p=1) -- a documented,
//! defensible floor, not a guess. Measuring whether the real deployment
//! hosts can afford to exceed it is 114C.8's live-two-machine job, not
//! this module's; shipping the OWASP floor now is not the same claim as
//! having measured a higher value, and this module does not claim it.

use argon2::{Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use password_hash::{PasswordHashString, SaltString};
use rand::rngs::OsRng;
use unicode_normalization::UnicodeNormalization;

use crate::error::AccountsError;
use crate::secret::SecretString;

/// At least 15 characters when the account has no second factor.
pub const MIN_LENGTH_SINGLE_FACTOR: usize = 15;
/// At least 8 characters when the account has a required second factor
/// (passkey/WebAuthn as step-up, or MFA in general).
pub const MIN_LENGTH_MFA: usize = 8;
/// The plan requires accepting "at least 64" Unicode characters; this is a
/// generous upper bound chosen to prevent a multi-megabyte input from being
/// hashed (a denial-of-service consideration), not a policy restriction --
/// nothing in the plan asks for a cap this low to matter to a real password.
pub const MAX_LENGTH: usize = 512;

/// OWASP Password Storage Cheat Sheet's published Argon2id minimum as of
/// this review: memory cost 19 MiB, 2 iterations, 1 degree of parallelism,
/// 32-byte output. See this module's top-level doc comment for what "not
/// yet measured on real hardware" means here.
pub fn argon2_params() -> Params {
    Params::new(19 * 1024, 2, 1, Some(32)).expect("static Argon2id parameters are valid")
}

fn hasher() -> Argon2<'static> {
    Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params())
}

/// NFC-normalize, per the plan's "normalize with NFC before hashing" -- so a
/// password typed on a platform/input method that composes Unicode
/// differently (e.g. a precomposed "é" vs. "e" + combining acute accent)
/// still hashes identically. This is the concrete fix for a gap the
/// ForgeWire account-behavior inventory named explicitly: ForgeWire's
/// `password_policy.py` hashes via plain `.encode("utf-8")` with no
/// normalization step at all.
fn nfc_normalize(input: &str) -> String {
    input.nfc().collect()
}

/// A conservative, explicitly local blocklist of extremely common
/// passwords -- the plan requires "a local blocklist-capable verifier," not
/// a specific dataset. This is deliberately small and well-known rather than
/// an attempt at a comprehensive breach-corpus check (the plan treats a
/// remote breach-check service as optional and explicitly not a login
/// dependency). Matching is case-insensitive against the NFC-normalized
/// input.
const BLOCKLIST: &[&str] = &[
    "password",
    "password1",
    "password123",
    "123456",
    "123456789",
    "12345678",
    "12345",
    "1234567890",
    "qwerty",
    "qwerty123",
    "111111",
    "123123",
    "abc123",
    "letmein",
    "welcome",
    "welcome1",
    "monkey",
    "dragon",
    "master",
    "iloveyou",
    "admin",
    "administrator",
    "root",
    "toor",
    "changeme",
    "passw0rd",
    "trustno1",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "superman",
    "starwars",
    "shadow",
    "michael",
    "jennifer",
    "michelle",
    "jordan23",
    "hunter2",
    "letmein123",
    "qwertyuiop",
    "1q2w3e4r",
    "1qaz2wsx",
    "zaq12wsx",
    "asdfghjkl",
    "000000",
    "121212",
    "1111111111",
    "abcdefgh",
    "abcd1234",
    "password!",
    "P@ssw0rd",
    "P@ssword1",
    "Passw0rd!",
    "correcthorsebatterystaple",
];

/// Validate a password against the plan's binding requirements. Does not
/// hash it -- call [`hash_password`] afterward on success.
pub fn validate_password(password: &str, has_second_factor: bool) -> Result<(), AccountsError> {
    let normalized = nfc_normalize(password);
    let min_length = if has_second_factor {
        MIN_LENGTH_MFA
    } else {
        MIN_LENGTH_SINGLE_FACTOR
    };
    let char_count = normalized.chars().count();

    if char_count < min_length {
        return Err(AccountsError::AccountPolicyViolation {
            reason: "password_too_short".to_owned(),
        });
    }
    if char_count > MAX_LENGTH {
        return Err(AccountsError::AccountPolicyViolation {
            reason: "password_too_long".to_owned(),
        });
    }
    let lowered = normalized.to_lowercase();
    if BLOCKLIST
        .iter()
        .any(|blocked| blocked.to_lowercase() == lowered)
    {
        return Err(AccountsError::AccountPolicyViolation {
            reason: "password_is_commonly_known".to_owned(),
        });
    }
    // No composition rules (no required uppercase/digit/symbol), no
    // rotation policy, no truncation -- all deliberate omissions matching
    // the plan and current NIST SP 800-63B guidance, not oversights.
    Ok(())
}

/// Hash an already-validated password. Returns a self-describing PHC string
/// (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`) -- the algorithm and
/// parameters travel with the hash, matching the plan's "record algorithm
/// and parameters per credential" and this crate's own `human_credentials`
/// schema (`algorithm`, `algorithm_params`, `version` columns).
pub fn hash_password(password: &str) -> Result<SecretString, AccountsError> {
    let normalized = nfc_normalize(password);
    let salt = SaltString::generate(&mut OsRng);
    let hash: PasswordHashString = hasher()
        .hash_password(normalized.as_bytes(), &salt)
        .map_err(|_| AccountsError::AccountPolicyViolation {
            reason: "password_hashing_failed".to_owned(),
        })?
        .serialize();
    Ok(SecretString::new(hash.as_str()))
}

/// Verify a presented password against a stored PHC hash string.
/// Constant-time by construction: `argon2::Argon2` (via the `password-hash`
/// crate's `PasswordVerifier`) compares digests without early-exit branching
/// on byte position, the same discipline `fabric-hub::auth::constant_time_eq`
/// applies to bearer tokens.
///
/// Returns `Ok(false)` for "hash doesn't match" and `Err` only for a
/// malformed/unparseable stored hash -- callers must not let the two cases
/// produce visibly different behavior to an external caller (that would be
/// an enumeration/oracle regression); both ultimately resolve to
/// `AccountsError::InvalidCredentials` at the login orchestration layer.
pub fn verify_password(password: &str, phc_hash: &str) -> Result<bool, AccountsError> {
    let normalized = nfc_normalize(password);
    let parsed =
        PasswordHash::new(phc_hash).map_err(|_| AccountsError::AccountPolicyViolation {
            reason: "stored_hash_unparseable".to_owned(),
        })?;
    Ok(hasher()
        .verify_password(normalized.as_bytes(), &parsed)
        .is_ok())
}

/// `true` when a stored hash's parameters are weaker than the current
/// target -- the caller (the login orchestration layer) rehashes and
/// persists the result on the same successful login, per "support
/// rehash-on-success when the configured work factor increases."
pub fn needs_rehash(phc_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc_hash) else {
        return false; // unparseable hashes are a validate_password-time concern, not this one
    };
    let current = argon2_params();
    let Some(m_cost) = parsed.params.get("m").and_then(|v| v.decimal().ok()) else {
        return true; // no recorded cost at all -- treat as outdated
    };
    let Some(t_cost) = parsed.params.get("t").and_then(|v| v.decimal().ok()) else {
        return true;
    };
    m_cost < current.m_cost() || t_cost < current.t_cost()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_single_factor_password() {
        assert!(validate_password("short12345678", false).is_err()); // 13 chars < 15
    }

    #[test]
    fn accepts_minimum_length_single_factor_password() {
        assert!(validate_password("exactly15chars!", false).is_ok()); // 15 chars
    }

    #[test]
    fn accepts_shorter_password_with_second_factor() {
        assert!(validate_password("eight123", true).is_ok()); // 8 chars, MFA
        assert!(validate_password("seven12", true).is_err()); // 7 chars, still too short
    }

    #[test]
    fn rejects_blocklisted_password_case_insensitively() {
        assert!(validate_password("PASSWORD123", false).is_err());
        assert!(validate_password("correcthorsebatterystaple", false).is_err());
    }

    #[test]
    fn accepts_a_long_unicode_password_with_spaces_and_no_composition_rules() {
        // No uppercase/digit/symbol required, spaces permitted, well over 64 chars.
        let password =
            "こんにちは world this is a very long passphrase with spaces and 日本語 characters too";
        assert!(password.chars().count() >= 64);
        assert!(validate_password(password, false).is_ok());
    }

    #[test]
    fn rejects_password_longer_than_the_dos_guard() {
        let too_long = "a".repeat(MAX_LENGTH + 1);
        assert!(validate_password(&too_long, false).is_err());
    }

    #[test]
    fn nfc_normalization_makes_decomposed_and_precomposed_forms_hash_identically() {
        // "é" as a single precomposed codepoint (U+00E9) vs. "e" + combining
        // acute accent (U+0065 U+0301) -- visually identical, byte-different.
        // This is the exact gap the ForgeWire inventory found: hashing raw
        // UTF-8 bytes with no normalization would make these two inputs
        // verify as different passwords.
        let precomposed = "caf\u{00E9} is a long enough passphrase";
        let decomposed = "cafe\u{0301} is a long enough passphrase";
        assert_ne!(
            precomposed, decomposed,
            "the two forms are byte-different, as intended"
        );
        assert_eq!(nfc_normalize(precomposed), nfc_normalize(decomposed));

        let hash = hash_password(precomposed).expect("hash the precomposed form");
        assert!(
            verify_password(decomposed, hash.expose_secret()).expect("verify"),
            "the decomposed form must verify against a hash of the precomposed form"
        );
    }

    #[test]
    fn hash_and_verify_round_trip() {
        let hash = hash_password("a perfectly cromulent passphrase").expect("hash");
        assert!(
            verify_password("a perfectly cromulent passphrase", hash.expose_secret())
                .expect("verify")
        );
        assert!(
            !verify_password("the wrong passphrase entirely", hash.expose_secret())
                .expect("verify")
        );
    }

    #[test]
    fn hash_is_self_describing_argon2id() {
        let hash = hash_password("another perfectly cromulent passphrase").expect("hash");
        assert!(hash.expose_secret().starts_with("$argon2id$"));
    }

    #[test]
    fn two_hashes_of_the_same_password_differ_by_salt() {
        let a = hash_password("identical input password here").expect("hash a");
        let b = hash_password("identical input password here").expect("hash b");
        assert_ne!(a.expose_secret(), b.expose_secret(), "salts must differ");
        assert!(verify_password("identical input password here", a.expose_secret()).unwrap());
        assert!(verify_password("identical input password here", b.expose_secret()).unwrap());
    }

    #[test]
    fn malformed_stored_hash_is_a_typed_error_not_a_panic() {
        let result = verify_password("anything", "not-a-real-phc-hash");
        assert!(matches!(
            result,
            Err(AccountsError::AccountPolicyViolation { .. })
        ));
    }

    #[test]
    fn current_parameters_never_need_rehash() {
        let hash = hash_password("current param passphrase here").expect("hash");
        assert!(!needs_rehash(hash.expose_secret()));
    }

    #[test]
    fn a_weaker_historical_hash_needs_rehash() {
        // Hash with parameters weaker than argon2_params()'s current target.
        let weak_params = Params::new(8 * 1024, 1, 1, Some(32)).unwrap();
        let weak_hasher = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, weak_params);
        let salt = SaltString::generate(&mut OsRng);
        let weak_hash = weak_hasher
            .hash_password(b"weak param passphrase", &salt)
            .unwrap()
            .serialize();
        assert!(needs_rehash(weak_hash.as_str()));
    }
}
