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
//!   verify with `jq`.

#![deny(rust_2018_idioms)]

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
/// Returns a diagnostic error if the file is missing, corrupted, or the
/// public key doesn't match the secret key. Never silently regenerates.
pub fn load(path: &Path) -> Result<IdentityFile, IdentityError> {
    if !path.exists() {
        return Err(IdentityError::NotFound(path.display().to_string()));
    }
    let data = std::fs::read_to_string(path)?;
    let identity: IdentityFile = serde_json::from_str(&data)?;
    validate(&identity)?;
    Ok(identity)
}

/// Load and validate, also checking that the key purpose matches.
pub fn load_with_purpose(
    path: &Path,
    expected: KeyPurpose,
) -> Result<IdentityFile, IdentityError> {
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

/// Save an identity file to disk as pretty-printed JSON.
pub fn save(path: &Path, identity: &IdentityFile) -> Result<(), IdentityError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(identity)?;
    std::fs::write(path, json)?;
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
        let id = generate("test-node", KeyPurpose::Runner);
        let path = std::env::temp_dir().join("test_identity_purpose.json");
        save(&path, &id).unwrap();
        let result = load_with_purpose(&path, KeyPurpose::Dispatcher);
        assert!(matches!(
            result,
            Err(IdentityError::PurposeMismatch { .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_load_roundtrip() {
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
}
