//! Encrypted-at-rest storage for [`IdentityFile`](crate::IdentityFile).
//!
//! The on-disk format is a magic-prefixed AES-256-GCM blob wrapping the exact
//! same JSON that the legacy plaintext format wrote directly:
//!
//! ```text
//! [ MAGIC: 8 bytes ][ NONCE: 12 bytes ][ CIPHERTEXT + AEAD TAG ]
//! ```
//!
//! The wrapping key is resolved, in order:
//!
//! 1. `FABRIC_IDENTITY_WRAPPING_KEY_FILE` — an operator-supplied path to an
//!    exactly-32-byte key file. This is the explicit headless/server path;
//!    generate one with e.g. `openssl rand -out key.bin 32` and protect it
//!    with the same care as the identities it wraps.
//! 2. The OS keyring (feature `os-keyring`, on by default) — created on first
//!    use, read thereafter.
//!
//! If neither resolves, encryption and decryption both fail closed with
//! [`IdentityError::VaultUnavailable`](crate::IdentityError::VaultUnavailable).
//! There is no plaintext fallback: a wrapping key that cannot be resolved
//! means the identity cannot be persisted, not that it is persisted unsafely.

use std::path::Path;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{IdentityError, IdentityFile};

pub(crate) const VAULT_MAGIC: &[u8; 8] = b"FBRCVLT1";
const NONCE_BYTES: usize = 12;
const WRAPPING_KEY_BYTES: usize = 32;
pub(crate) const WRAPPING_KEY_FILE_ENV: &str = "FABRIC_IDENTITY_WRAPPING_KEY_FILE";

/// True if `data` looks like a vault-format blob. Anything else is assumed to
/// be a legacy plaintext (native or Python-era) file.
pub(crate) fn looks_like_vault(data: &[u8]) -> bool {
    data.len() >= VAULT_MAGIC.len() && &data[..VAULT_MAGIC.len()] == VAULT_MAGIC
}

/// Encrypt `identity` for `path`. Never returns plaintext bytes on failure —
/// an unresolved wrapping key is an error, not a fallback.
pub(crate) fn encrypt_to_bytes(
    path: &Path,
    identity: &IdentityFile,
) -> Result<Vec<u8>, IdentityError> {
    let key = resolve_wrapping_key()?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| IdentityError::VaultUnavailable("invalid wrapping key length".into()))?;
    let mut nonce_bytes = [0_u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    let plaintext = serde_json::to_vec(identity)?;
    let aad = path_aad(path);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| IdentityError::VaultUnavailable("encryption failed".into()))?;

    let mut blob = Vec::with_capacity(VAULT_MAGIC.len() + NONCE_BYTES + ciphertext.len());
    blob.extend_from_slice(VAULT_MAGIC);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt a vault-format blob previously produced by [`encrypt_to_bytes`] for
/// the same `path`. The path is bound in as AEAD associated data, so a blob
/// copied to a different path fails to decrypt there.
pub(crate) fn decrypt_from_bytes(path: &Path, blob: &[u8]) -> Result<IdentityFile, IdentityError> {
    if blob.len() < VAULT_MAGIC.len() + NONCE_BYTES {
        return Err(IdentityError::VaultCorrupted("blob too short".into()));
    }
    let key = resolve_wrapping_key()?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| IdentityError::VaultUnavailable("invalid wrapping key length".into()))?;
    let nonce_start = VAULT_MAGIC.len();
    let ciphertext_start = nonce_start + NONCE_BYTES;
    let nonce = Nonce::from_slice(&blob[nonce_start..ciphertext_start]);
    let aad = path_aad(path);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &blob[ciphertext_start..],
                aad: &aad,
            },
        )
        .map_err(|_| {
            IdentityError::VaultCorrupted(
                "decryption failed (wrong wrapping key, tampered file, or moved path)".into(),
            )
        })?;
    let identity: IdentityFile = serde_json::from_slice(&plaintext)?;
    Ok(identity)
}

fn path_aad(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

fn resolve_wrapping_key() -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    if let Ok(file_path) = std::env::var(WRAPPING_KEY_FILE_ENV) {
        let trimmed = file_path.trim();
        if !trimmed.is_empty() {
            return read_wrapping_key_file(Path::new(trimmed));
        }
    }
    #[cfg(feature = "os-keyring")]
    {
        os_keyring::load_or_create()
    }
    #[cfg(not(feature = "os-keyring"))]
    {
        Err(IdentityError::VaultUnavailable(format!(
            "no wrapping key available: set {WRAPPING_KEY_FILE_ENV} to a 32-byte key file \
             (this build has the os-keyring feature disabled)"
        )))
    }
}

fn read_wrapping_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let bytes = std::fs::read(path).map_err(|e| {
        IdentityError::VaultUnavailable(format!(
            "cannot read {WRAPPING_KEY_FILE_ENV} at {}: {e}",
            path.display()
        ))
    })?;
    if bytes.len() != WRAPPING_KEY_BYTES {
        return Err(IdentityError::VaultUnavailable(format!(
            "{WRAPPING_KEY_FILE_ENV} at {} must contain exactly {WRAPPING_KEY_BYTES} bytes, found {}",
            path.display(),
            bytes.len()
        )));
    }
    Ok(Zeroizing::new(bytes))
}

#[cfg(feature = "os-keyring")]
mod os_keyring {
    use super::{IdentityError, WRAPPING_KEY_BYTES, WRAPPING_KEY_FILE_ENV};
    use rand::{rngs::OsRng, RngCore};
    use zeroize::Zeroizing;

    const KEYRING_SERVICE: &str = "com.forgewirelabs.fabric.identity-vault";
    const KEYRING_ACCOUNT: &str = "fabric-identity-wrapping-key-v1";

    pub(super) fn load_or_create() -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        let entry = keyring::v1::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .map_err(|e| unavailable(&e.to_string()))?;
        match entry.get_secret() {
            Ok(secret) if secret.len() == WRAPPING_KEY_BYTES => Ok(Zeroizing::new(secret)),
            Ok(_) => Err(IdentityError::VaultCorrupted(
                "OS keyring secret has the wrong length".into(),
            )),
            Err(keyring::v1::Error::NoEntry) => {
                let mut secret = Zeroizing::new(vec![0_u8; WRAPPING_KEY_BYTES]);
                OsRng.fill_bytes(secret.as_mut_slice());
                entry
                    .set_secret(secret.as_slice())
                    .map_err(|e| unavailable(&e.to_string()))?;
                Ok(secret)
            }
            Err(e) => Err(unavailable(&e.to_string())),
        }
    }

    fn unavailable(detail: &str) -> IdentityError {
        IdentityError::VaultUnavailable(format!(
            "OS keyring unavailable ({detail}); set {WRAPPING_KEY_FILE_ENV} to a 32-byte key file for headless use"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These test `read_wrapping_key_file` directly with an explicit path,
    // never touching `FABRIC_IDENTITY_WRAPPING_KEY_FILE` -- that env var is
    // process-global and shared with every other test in this crate (see
    // `lib.rs`'s `ensure_test_wrapping_key`); mutating it here would race
    // against them under parallel test execution.

    #[test]
    fn wrapping_key_file_wrong_length_is_rejected() {
        let path = std::env::temp_dir().join(format!(
            "fabric-identity-vault-test-bad-length-{}.bin",
            std::process::id()
        ));
        std::fs::write(&path, [1_u8; 16]).unwrap(); // 16, not 32
        let result = read_wrapping_key_file(&path);
        assert!(matches!(result, Err(IdentityError::VaultUnavailable(_))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrapping_key_file_missing_is_a_clear_diagnostic() {
        let path = std::env::temp_dir().join(format!(
            "fabric-identity-vault-test-missing-{}.bin",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path); // ensure it does not exist
        let result = read_wrapping_key_file(&path);
        assert!(matches!(result, Err(IdentityError::VaultUnavailable(_))));
    }

    #[test]
    fn wrapping_key_file_correct_length_is_accepted() {
        let path = std::env::temp_dir().join(format!(
            "fabric-identity-vault-test-good-length-{}.bin",
            std::process::id()
        ));
        std::fs::write(&path, [9_u8; WRAPPING_KEY_BYTES]).unwrap();
        let result = read_wrapping_key_file(&path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_slice(), [9_u8; WRAPPING_KEY_BYTES]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn looks_like_vault_matches_only_the_magic_prefix() {
        let mut blob = VAULT_MAGIC.to_vec();
        blob.extend_from_slice(b"anything after the magic is fine");
        assert!(looks_like_vault(&blob));
        assert!(!looks_like_vault(b"{\"id\":\"plain-json\"}"));
        assert!(!looks_like_vault(b"short"));
    }
}
