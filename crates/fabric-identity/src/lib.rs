//! Durable ed25519 identity management for ForgeWire Fabric.
//!
//! Each ForgeWire node, dispatcher, runner, or hub has a persistent identity
//! file containing an ed25519 keypair, a human-readable ID, and a key purpose
//! tag. The identity file is the single durable secret on the machine.
//!
//! ## Design rules
//!
//! - **Never silently regenerate.** If the identity file is unreadable,
//!   corrupted, or has wrong permissions, return a diagnostic error. The
//!   operator must explicitly generate a new identity.
//! - **Key purposes are tagged.** A dispatcher key cannot be used as a runner
//!   key without an explicit re-tag. This prevents accidental cross-role
//!   signing.
//! - **File format is JSON.** Human-inspectable, easy to back up, easy to
//!   verify with `jq` — as the *decrypted* payload; see `SECURITY` below for
//!   what actually sits on disk.
//!
//! ## SECURITY: the secret key is encrypted at rest
//!
//! `IdentityFile::secret_key_hex` is never written to disk in the clear.
//! `save()` encrypts the identity (AES-256-GCM) under a wrapping key resolved
//! from `FABRIC_IDENTITY_WRAPPING_KEY_FILE` (an operator-supplied 32-byte key
//! file — the explicit path for headless/server deployments with no OS
//! keyring) or, by default, the OS keyring (feature `os-keyring`, on by
//! default). See [`vault`] for the wire format and resolution order.
//!
//! **This fails closed.** If no wrapping key can be resolved, `save()`
//! returns [`IdentityError::VaultUnavailable`] and writes nothing — there is
//! no plaintext fallback. A file that already exists in the legacy plaintext
//! format (from a build before this change) is transparently decrypted on
//! `load()` for backward compatibility, then **eagerly re-encrypted** before
//! `load()` returns, so the very next successful load of a legacy file closes
//! the gap for it. If re-encryption fails on that pass (e.g. no wrapping key
//! configured yet), the identity is still returned — a load never fails
//! because migration couldn't complete — and the file stays plaintext,
//! restricted to owner-only permissions on Unix, until a load succeeds with a
//! resolvable wrapping key.
//!
//! This closes the gap tracked in
//! `forgewire/work/active/204-shared-node-identity-crate/compatibility-inventory.md`,
//! ported from ForgeLink's linked-node identity vault (a downstream consumer
//! of the same ed25519 stack), which never serialized the secret at all.

#![deny(rust_2018_idioms)]

mod vault;

use std::path::Path;

use ed25519_dalek::SigningKey;
use fabric_types::KeyPurpose;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// On-disk identity file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityFile {
    pub id: String,
    pub purpose: KeyPurpose,
    pub public_key_hex: String,
    pub secret_key_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity file not found: {0}")]
    NotFound(String),

    #[error("identity file is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("identity file I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("identity file corrupted: secret key hex is not 64 characters (got {0})")]
    BadSecretKeyLength(usize),

    #[error("identity file corrupted: public key hex is not 64 characters (got {0})")]
    BadPublicKeyLength(usize),

    #[error("identity file corrupted: secret key hex is not valid hex: {0}")]
    BadSecretKeyHex(String),

    #[error("identity file corrupted: public/secret key mismatch — the public key in the file does not match the secret key")]
    KeyMismatch,

    #[error("key purpose mismatch: expected {expected}, found {found}")]
    PurposeMismatch {
        expected: KeyPurpose,
        found: KeyPurpose,
    },

    #[error("{0}")]
    VaultUnavailable(String),

    #[error("{0}")]
    VaultCorrupted(String),
}

/// Generate a fresh ed25519 identity.
pub fn generate(id: &str, purpose: KeyPurpose) -> IdentityFile {
    let signing = SigningKey::generate(&mut OsRng);
    let public = signing.verifying_key();
    IdentityFile {
        id: id.to_owned(),
        purpose,
        public_key_hex: hex::encode(public.to_bytes()),
        secret_key_hex: hex::encode(signing.to_bytes()),
        hostname: hostname(),
        created_at: Some(utc_now_iso()),
    }
}

/// Load and validate an identity file from disk.
///
/// Reads the encrypted vault format written by `save()` (see the crate-level
/// `SECURITY` note) if present. Otherwise falls back, for backward
/// compatibility, to the legacy plaintext native Rust format (`id`,
/// `public_key_hex`, `secret_key_hex`) or the Python/legacy format
/// (`runner_id` or `dispatcher_id`, `public_key`, `private_key`) — and, on a
/// successful legacy load, **eagerly re-encrypts the file** before returning
/// so the gap closes the moment it is next read. Re-encryption failure (e.g.
/// no wrapping key configured yet) does not fail the load; the identity is
/// still returned, and the file is migrated on a later successful load.
///
/// Returns a diagnostic error if the file is missing, corrupted, undecryptable
/// with the resolved wrapping key, or the public key doesn't match the secret
/// key. Never silently regenerates.
pub fn load(path: &Path) -> Result<IdentityFile, IdentityError> {
    if !path.exists() {
        return Err(IdentityError::NotFound(path.display().to_string()));
    }
    let data = std::fs::read(path)?;
    if vault::looks_like_vault(&data) {
        let identity = vault::decrypt_from_bytes(path, &data)?;
        validate(&identity)?;
        return Ok(identity);
    }
    let identity = parse_legacy(&data)?;
    validate(&identity)?;
    // Best-effort transparent migration. The identity was already validly
    // loaded from the legacy format; a failed re-encryption attempt must not
    // turn a successful load into an error.
    let _ = save(path, &identity);
    Ok(identity)
}

/// Parse the legacy plaintext native-Rust or Python-era identity JSON.
fn parse_legacy(data: &[u8]) -> Result<IdentityFile, IdentityError> {
    if let Ok(identity) = serde_json::from_slice::<IdentityFile>(data) {
        return Ok(identity);
    }
    let raw: serde_json::Value = serde_json::from_slice(data)?;
    let id = raw
        .get("runner_id")
        .or_else(|| raw.get("dispatcher_id"))
        .or_else(|| raw.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| serde_json::from_str::<IdentityFile>("").unwrap_err())?
        .to_owned();
    let public_key_hex = raw
        .get("public_key")
        .or_else(|| raw.get("public_key_hex"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| serde_json::from_str::<IdentityFile>("").unwrap_err())?
        .to_owned();
    let secret_key_hex = raw
        .get("private_key")
        .or_else(|| raw.get("secret_key_hex").or_else(|| raw.get("secret_key")))
        .and_then(|v| v.as_str())
        .ok_or_else(|| serde_json::from_str::<IdentityFile>("").unwrap_err())?
        .to_owned();
    Ok(IdentityFile {
        id,
        purpose: KeyPurpose::Runner, // Python format doesn't carry purpose; default Runner
        public_key_hex,
        secret_key_hex,
        hostname: raw
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned()),
        created_at: raw
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned()),
    })
}

/// Load and validate, also checking that the key purpose matches.
pub fn load_with_purpose(path: &Path, expected: KeyPurpose) -> Result<IdentityFile, IdentityError> {
    let identity = load(path)?;
    if identity.purpose != expected {
        return Err(IdentityError::PurposeMismatch {
            expected,
            found: identity.purpose,
        });
    }
    Ok(identity)
}

/// Validate an identity's internal consistency.
pub fn validate(identity: &IdentityFile) -> Result<(), IdentityError> {
    if identity.secret_key_hex.len() != 64 {
        return Err(IdentityError::BadSecretKeyLength(
            identity.secret_key_hex.len(),
        ));
    }
    if identity.public_key_hex.len() != 64 {
        return Err(IdentityError::BadPublicKeyLength(
            identity.public_key_hex.len(),
        ));
    }
    let sk_bytes = hex::decode(&identity.secret_key_hex)
        .map_err(|e| IdentityError::BadSecretKeyHex(e.to_string()))?;
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let signing = SigningKey::from_bytes(&sk_arr);
    let derived_pk = hex::encode(signing.verifying_key().to_bytes());
    if derived_pk != identity.public_key_hex {
        return Err(IdentityError::KeyMismatch);
    }
    Ok(())
}

/// Save an identity file to disk, encrypted (see the crate-level `SECURITY`
/// note).
///
/// Fails closed: if no wrapping key can be resolved
/// ([`IdentityError::VaultUnavailable`]), nothing is written — there is no
/// plaintext fallback. On success, the file is additionally restricted to
/// owner read/write on Unix (best-effort defense in depth on top of
/// encryption; no effect on Windows, which needs an ACL-based equivalent not
/// implemented here).
pub fn save(path: &Path, identity: &IdentityFile) -> Result<(), IdentityError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let blob = vault::encrypt_to_bytes(path, identity)?;
    std::fs::write(path, blob)?;
    restrict_permissions(path)?;
    Ok(())
}

/// Restrict the identity file to owner read/write only. No-op on platforms
/// without POSIX permission bits (see `SECURITY` note: Windows needs an
/// ACL-based equivalent, not implemented here).
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

/// Sign arbitrary bytes using the identity's secret key.
pub fn sign(identity: &IdentityFile, payload: &[u8]) -> Result<String, IdentityError> {
    fabric_protocol::sign_payload_hex(&identity.secret_key_hex, payload)
        .map_err(|e| IdentityError::BadSecretKeyHex(e.to_string()))
}

/// Verify a signature using the identity's public key.
pub fn verify(
    identity: &IdentityFile,
    payload: &[u8],
    signature_hex: &str,
) -> Result<bool, IdentityError> {
    fabric_protocol::verify_signature_hex(&identity.public_key_hex, payload, signature_hex)
        .map_err(|e| IdentityError::BadPublicKeyLength(e.to_string().len()))
}

fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        })
        .ok()
}

fn utc_now_iso() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    // Simple UTC ISO format without pulling in chrono
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test in this module that touches `save`/`load` must call this
    /// first. It points `FABRIC_IDENTITY_WRAPPING_KEY_FILE` at a fixed,
    /// process-local key file so tests are deterministic and never depend on
    /// a real OS keyring/secret service being present in the test
    /// environment. Uses `Once` so the one-time env var write happens before
    /// any test reads it, safely under parallel test execution.
    fn ensure_test_wrapping_key() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let path = std::env::temp_dir().join(format!(
                "fabric-identity-test-wrapping-key-{}.bin",
                std::process::id()
            ));
            std::fs::write(&path, [7_u8; 32]).expect("write test wrapping key");
            std::env::set_var(
                vault::WRAPPING_KEY_FILE_ENV,
                path.to_string_lossy().to_string(),
            );
        });
    }

    #[test]
    fn generate_and_validate() {
        let id = generate("test-node", KeyPurpose::Runner);
        assert_eq!(id.purpose, KeyPurpose::Runner);
        assert_eq!(id.public_key_hex.len(), 64);
        assert_eq!(id.secret_key_hex.len(), 64);
        assert!(validate(&id).is_ok());
    }

    #[test]
    fn detect_key_mismatch() {
        let mut id = generate("test-node", KeyPurpose::Dispatcher);
        id.public_key_hex = "0".repeat(64);
        assert!(matches!(validate(&id), Err(IdentityError::KeyMismatch)));
    }

    #[test]
    fn detect_bad_hex() {
        let mut id = generate("test-node", KeyPurpose::Hub);
        id.secret_key_hex = "zz".repeat(32);
        assert!(matches!(
            validate(&id),
            Err(IdentityError::BadSecretKeyHex(_))
        ));
    }

    #[test]
    fn detect_wrong_purpose() {
        ensure_test_wrapping_key();
        let id = generate("test-node", KeyPurpose::Runner);
        let path = std::env::temp_dir().join("test_identity_purpose.json");
        save(&path, &id).unwrap();
        let result = load_with_purpose(&path, KeyPurpose::Dispatcher);
        assert!(matches!(result, Err(IdentityError::PurposeMismatch { .. })));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_load_roundtrip() {
        ensure_test_wrapping_key();
        let id = generate("roundtrip-test", KeyPurpose::Node);
        let path = std::env::temp_dir().join("test_identity_roundtrip.json");
        save(&path, &id).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.id, id.id);
        assert_eq!(loaded.public_key_hex, id.public_key_hex);
        assert_eq!(loaded.secret_key_hex, id.secret_key_hex);
        assert_eq!(loaded.purpose, id.purpose);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn save_restricts_permissions_to_owner_only() {
        ensure_test_wrapping_key();
        use std::os::unix::fs::PermissionsExt;
        let id = generate("perm-test", KeyPurpose::Node);
        let path = std::env::temp_dir().join("test_identity_permissions.json");
        save(&path, &id).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn save_retightens_permissions_on_an_already_loose_file() {
        ensure_test_wrapping_key();
        use std::os::unix::fs::PermissionsExt;
        let id = generate("perm-retighten-test", KeyPurpose::Node);
        let path = std::env::temp_dir().join("test_identity_permissions_retighten.json");
        // Simulate a file written before this hardening existed.
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save(&path, &id).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(not(unix))]
    #[test]
    fn save_succeeds_without_posix_permission_bits() {
        ensure_test_wrapping_key();
        let id = generate("perm-noop-test", KeyPurpose::Node);
        let path = std::env::temp_dir().join("test_identity_permissions_noop.json");
        save(&path, &id).unwrap();
        assert!(path.exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sign_and_verify() {
        let id = generate("signer", KeyPurpose::Dispatcher);
        let payload = b"test payload";
        let sig = sign(&id, payload).unwrap();
        assert!(verify(&id, payload, &sig).unwrap());
        assert!(!verify(&id, b"tampered", &sig).unwrap());
    }

    #[test]
    fn not_found_is_diagnostic() {
        let result = load(Path::new("/nonexistent/identity.json"));
        assert!(matches!(result, Err(IdentityError::NotFound(_))));
    }

    #[test]
    fn saved_bytes_never_contain_the_plaintext_secret() {
        ensure_test_wrapping_key();
        let id = generate("no-plaintext-test", KeyPurpose::Hub);
        let path = std::env::temp_dir().join("test_identity_no_plaintext.json");
        save(&path, &id).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(vault::looks_like_vault(&raw));
        // Neither the secret hex string nor its raw bytes anywhere in the file.
        assert!(!raw
            .windows(id.secret_key_hex.len())
            .any(|w| w == id.secret_key_hex.as_bytes()));
        let secret_bytes = hex::decode(&id.secret_key_hex).unwrap();
        assert!(!raw.windows(secret_bytes.len()).any(|w| w == secret_bytes));

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.secret_key_hex, id.secret_key_hex);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn detects_tampered_vault_ciphertext() {
        ensure_test_wrapping_key();
        let id = generate("tamper-test", KeyPurpose::Node);
        let path = std::env::temp_dir().join("test_identity_tamper.json");
        save(&path, &id).unwrap();

        let mut blob = std::fs::read(&path).unwrap();
        let last = blob.last_mut().unwrap();
        *last ^= 0x01;
        std::fs::write(&path, &blob).unwrap();

        let result = load(&path);
        assert!(matches!(result, Err(IdentityError::VaultCorrupted(_))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn migrates_legacy_plaintext_identity_on_load() {
        ensure_test_wrapping_key();
        let id = generate("migrate-test", KeyPurpose::Dispatcher);
        let path = std::env::temp_dir().join("test_identity_migrate.json");
        // Write in the pre-vault plaintext format directly, bypassing save().
        std::fs::write(&path, serde_json::to_string_pretty(&id).unwrap()).unwrap();
        let raw_before = std::fs::read(&path).unwrap();
        assert!(!vault::looks_like_vault(&raw_before));

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.id, id.id);
        assert_eq!(loaded.secret_key_hex, id.secret_key_hex);

        let raw_after = std::fs::read(&path).unwrap();
        assert!(
            vault::looks_like_vault(&raw_after),
            "legacy file should be re-encrypted after a successful load"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_of_legacy_file_still_succeeds_when_migration_cannot_write() {
        ensure_test_wrapping_key();
        let id = generate("migrate-readonly-test", KeyPurpose::Node);
        let dir =
            std::env::temp_dir().join(format!("fabric-identity-readonly-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.json");
        std::fs::write(&path, serde_json::to_string_pretty(&id).unwrap()).unwrap();

        // Point the wrapping-key env var at a nonexistent file for this call
        // only is not possible without races against other tests sharing the
        // process; instead simulate migration failure by making the target
        // file read-only so the re-encrypting write fails, while the read
        // that already succeeded must still return Ok.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o400);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        #[cfg(windows)]
        {
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(&path, perms).unwrap();
        }

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.id, id.id);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        #[cfg(windows)]
        {
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            // Windows readonly is a single attribute bit, not Unix mode bits;
            // clearing it does not make the file world-writable the way
            // clippy's lint warns about on Unix.
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
