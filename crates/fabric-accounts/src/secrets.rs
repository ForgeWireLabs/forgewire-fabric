//! Opaque secret generation and lookup-hashing for session/refresh/reset
//! secrets -- distinct from [`crate::password`], which is for the much
//! lower-entropy, human-chosen credential.
//!
//! ## Why SHA-256 here and Argon2id there
//!
//! A session or refresh secret is generated with 256 bits of CSPRNG
//! entropy (`generate_opaque_secret`) -- infeasible to brute-force even as a
//! fast, unsalted digest. A password is chosen by a human and typically
//! carries far less real entropy, which is exactly why it needs a slow,
//! memory-hard hash. Storing an opaque secret's hash as a fast digest and
//! using it as an indexed lookup key matches the plan's "store only keyed
//! hashes/digests of access, refresh, reset, enrollment, and recovery
//! secrets" and the precedent already set by `fabric-hub::auth`'s existing
//! bearer-token hash (`hex::encode(Sha256::digest(...))`) -- this module
//! extends that exact convention to human-session secrets rather than
//! inventing a second one.

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::secret::SecretString;

/// Bits of entropy the plan requires as a floor ("at least 128 bits").
/// 256 bits (32 bytes) is used here -- exceeding the floor costs nothing at
/// this size and removes any need to argue the margin is adequate.
const SECRET_BYTES: usize = 32;

/// Generate a new opaque secret from an OS CSPRNG, base64url-encoded
/// (unpadded) so it is safe to place in a header value or URL path segment
/// without further escaping -- session/refresh secrets are transmitted this
/// way, even though the plan forbids putting them in a URL *query string*.
pub fn generate_opaque_secret() -> SecretString {
    let mut bytes = [0u8; SECRET_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    use base64::Engine;
    SecretString::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Hash an opaque secret for storage/lookup. Not for passwords -- see this
/// module's top-level doc comment.
pub fn hash_opaque_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secrets_are_unique() {
        let a = generate_opaque_secret();
        let b = generate_opaque_secret();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn generated_secret_has_at_least_128_bits_of_encoded_entropy() {
        let secret = generate_opaque_secret();
        // base64url encodes 6 bits/char; 32 raw bytes -> 256 bits -> at
        // least 42 chars unpadded, comfortably over the 128-bit/~22-char floor.
        assert!(secret.expose_secret().len() >= 42);
    }

    #[test]
    fn hash_is_deterministic_and_lookup_stable() {
        let secret = "a-fixed-example-secret-value";
        assert_eq!(hash_opaque_secret(secret), hash_opaque_secret(secret));
    }

    #[test]
    fn different_secrets_hash_differently() {
        assert_ne!(
            hash_opaque_secret("secret-a"),
            hash_opaque_secret("secret-b")
        );
    }

    #[test]
    fn hash_never_contains_the_raw_secret_as_a_substring() {
        let secret = "sekrit-value-should-never-leak-anywhere";
        let hash = hash_opaque_secret(secret);
        assert!(!hash.contains(secret));
    }
}
