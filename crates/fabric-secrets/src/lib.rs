//! AES-256-GCM secret envelopes and master-key providers.
//!
//! Storage receives only versioned ciphertext envelopes. Plaintext exists only
//! while a route is sealing, redacting, or dispatching a claimed task.

#![deny(rust_2018_idioms)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const PREFIX: &str = "fwsecret:v1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Platform-appropriate default state directory: `%PROGRAMDATA%\forgewire`
/// on Windows, `~/Library/Application Support/forgewire` on macOS,
/// `/var/lib/forgewire` on Linux (the FHS convention for a system-service
/// daemon -- not a bug to fix here, unlike Windows/macOS). Only consulted
/// as a fallback; every shipped installer sets an explicit override, so
/// this default never relocates an already-configured installation.
fn default_state_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\forgewire")
    } else if cfg!(target_os = "macos") {
        std::env::var("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support/forgewire"))
            .unwrap_or_else(|_| PathBuf::from("/var/lib/forgewire"))
    } else {
        PathBuf::from("/var/lib/forgewire")
    }
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("master key unavailable: {0}")]
    KeyUnavailable(String),
    #[error("master key is invalid: {0}")]
    InvalidKey(String),
    #[error("secret '{name}' contains a legacy unsealed value; rotate or delete it before use")]
    LegacyUnsealed { name: String },
    #[error("secret '{name}' has an invalid encrypted envelope: {detail}")]
    InvalidEnvelope { name: String, detail: String },
    #[error("secret '{0}' is missing; create or rotate it before claiming this task")]
    MissingSecret(String),
    #[error("secret provider I/O failed: {0}")]
    ProviderIo(String),
}

impl SecretError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::KeyUnavailable(_) => "secret_key_unavailable",
            Self::InvalidKey(_) => "secret_key_invalid",
            Self::LegacyUnsealed { .. } => "legacy_secret_requires_rotation",
            Self::InvalidEnvelope { .. } => "secret_envelope_invalid",
            Self::MissingSecret(_) => "secret_missing",
            Self::ProviderIo(_) => "secret_provider_io",
        }
    }

    pub fn remediation(&self) -> &'static str {
        match self {
            Self::LegacyUnsealed { .. } => "rotate or delete the named legacy secret",
            Self::MissingSecret(_) => "create the named secret or remove it from secrets_needed",
            Self::KeyUnavailable(_) | Self::InvalidKey(_) | Self::ProviderIo(_) => {
                "provision a valid 32-byte master key provider and retry"
            }
            Self::InvalidEnvelope { .. } => "rotate or delete the named corrupt secret",
        }
    }
}

/// A provider returns exactly 32 key bytes. The returned buffer zeroizes on drop.
pub trait MasterKeyProvider: Send + Sync {
    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, SecretError>;
    fn name(&self) -> &'static str;
}

/// Highest-precedence provider: `FORGEWIRE_SECRETS_KEY_HEX`.
pub struct EnvKeyProvider;

impl MasterKeyProvider for EnvKeyProvider {
    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        let mut encoded = std::env::var("FORGEWIRE_SECRETS_KEY_HEX").map_err(|_| {
            SecretError::KeyUnavailable("FORGEWIRE_SECRETS_KEY_HEX is not set".into())
        })?;
        let decoded = hex_decode(&encoded);
        encoded.zeroize();
        let bytes = decoded?;
        validate_key(bytes)
    }

    fn name(&self) -> &'static str {
        "environment"
    }
}

pub struct UnavailableKeyProvider {
    reason: String,
}

impl UnavailableKeyProvider {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl MasterKeyProvider for UnavailableKeyProvider {
    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        Err(SecretError::KeyUnavailable(self.reason.clone()))
    }

    fn name(&self) -> &'static str {
        "unavailable"
    }
}

/// ACL-restricted file provider. Missing files are initialized atomically with
/// a random key; existing missing/invalid/unreadable files fail closed.
pub struct FileKeyProvider {
    path: PathBuf,
}

impl FileKeyProvider {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn default_path() -> PathBuf {
        default_state_dir().join("secrets.key")
    }

    fn initialize(&self) -> Result<(), SecretError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(io_error)?;
        }
        let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
        rand::rngs::OsRng.fill_bytes(&mut key);
        write_private_file(&self.path, &key)
    }
}

impl MasterKeyProvider for FileKeyProvider {
    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        if !self.path.exists() {
            self.initialize()?;
        }
        let bytes = Zeroizing::new(std::fs::read(&self.path).map_err(io_error)?);
        validate_key(bytes)
    }

    fn name(&self) -> &'static str {
        "acl-file"
    }
}

/// OS-protected provider. Windows uses DPAPI machine protection; Linux uses
/// libsecret's `secret-tool`; macOS uses the login/system Keychain `security`
/// CLI. It is selected explicitly with `FORGEWIRE_SECRETS_KEY_PROVIDER=os`.
#[cfg_attr(windows, allow(dead_code))]
pub struct OsKeychainProvider {
    service: String,
    account: String,
    protected_file: PathBuf,
}

impl OsKeychainProvider {
    pub fn new(
        service: impl Into<String>,
        account: impl Into<String>,
        protected_file: impl Into<PathBuf>,
    ) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
            protected_file: protected_file.into(),
        }
    }

    pub fn for_fabric() -> Self {
        let path = if cfg!(windows) {
            default_state_dir().join("secrets.key.dpapi")
        } else {
            default_state_dir().join("secrets.key.os")
        };
        Self::new("forgewire-fabric", "hub-master-key", path)
    }
}

impl MasterKeyProvider for OsKeychainProvider {
    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        os_keychain_load(self)
    }

    fn name(&self) -> &'static str {
        "os-keychain"
    }
}

/// Real broker used by the hub. Tests inject an in-memory provider through the
/// same provider boundary rather than bypassing encryption.
#[derive(Clone)]
pub struct SecretBroker {
    provider: Arc<dyn MasterKeyProvider>,
}

impl SecretBroker {
    pub fn new(provider: Arc<dyn MasterKeyProvider>) -> Self {
        Self { provider }
    }

    pub fn from_env() -> Result<Self, SecretError> {
        if std::env::var_os("FORGEWIRE_SECRETS_KEY_HEX").is_some() {
            return Ok(Self::new(Arc::new(EnvKeyProvider)));
        }
        let selected = std::env::var("FORGEWIRE_SECRETS_KEY_PROVIDER")
            .unwrap_or_else(|_| "file".into())
            .to_ascii_lowercase();
        match selected.as_str() {
            "file" => {
                let path = std::env::var_os("FORGEWIRE_SECRETS_KEY_FILE")
                    .map(PathBuf::from)
                    .unwrap_or_else(FileKeyProvider::default_path);
                Ok(Self::new(Arc::new(FileKeyProvider::new(path))))
            }
            "os" | "keychain" | "dpapi" | "libsecret" => {
                Ok(Self::new(Arc::new(OsKeychainProvider::for_fabric())))
            }
            other => Err(SecretError::KeyUnavailable(format!(
                "unknown FORGEWIRE_SECRETS_KEY_PROVIDER '{other}'"
            ))),
        }
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    pub fn check_key(&self) -> Result<(), SecretError> {
        self.provider.load_key().map(|_| ())
    }

    pub fn seal(&self, name: &str, plaintext: &str) -> Result<String, SecretError> {
        let key = self.provider.load_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| SecretError::InvalidKey("AES-256 requires 32 bytes".into()))?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| SecretError::InvalidEnvelope {
                name: name.into(),
                detail: "encryption failed".into(),
            })?;
        Ok(format!(
            "{PREFIX}:{}:{}",
            B64.encode(nonce),
            B64.encode(ciphertext)
        ))
    }

    pub fn open(&self, name: &str, envelope: &str) -> Result<Zeroizing<String>, SecretError> {
        let mut parts = envelope.split(':');
        let valid_prefix = parts.next() == Some("fwsecret") && parts.next() == Some("v1");
        if !valid_prefix {
            return Err(SecretError::LegacyUnsealed { name: name.into() });
        }
        let nonce_text = parts
            .next()
            .ok_or_else(|| invalid_envelope(name, "nonce missing"))?;
        let cipher_text = parts
            .next()
            .ok_or_else(|| invalid_envelope(name, "ciphertext missing"))?;
        if parts.next().is_some() {
            return Err(invalid_envelope(name, "unexpected envelope fields"));
        }
        let nonce = B64
            .decode(nonce_text)
            .map_err(|_| invalid_envelope(name, "nonce is not base64"))?;
        if nonce.len() != NONCE_LEN {
            return Err(invalid_envelope(name, "nonce must be 12 bytes"));
        }
        let ciphertext = B64
            .decode(cipher_text)
            .map_err(|_| invalid_envelope(name, "ciphertext is not base64"))?;
        let key = self.provider.load_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| SecretError::InvalidKey("AES-256 requires 32 bytes".into()))?;
        let mut plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: name.as_bytes(),
                    },
                )
                .map_err(|_| invalid_envelope(name, "authentication failed"))?,
        );
        let decoded = String::from_utf8(std::mem::take(&mut *plaintext))
            .map_err(|_| invalid_envelope(name, "plaintext is not UTF-8"))?;
        Ok(Zeroizing::new(decoded))
    }

    pub fn redact_text<'a, I>(&self, text: &str, envelopes: I) -> Result<String, SecretError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut values: Vec<(String, Zeroizing<String>)> = envelopes
            .into_iter()
            .map(|(name, envelope)| {
                self.open(name, envelope)
                    .map(|value| (name.to_owned(), value))
            })
            .collect::<Result<_, _>>()?;
        values.sort_by_key(|(_, value)| std::cmp::Reverse(value.len()));
        let mut redacted = text.to_owned();
        for (name, value) in &values {
            if !value.is_empty() {
                redacted = redacted.replace(value.as_str(), &format!("[REDACTED:secret:{name}]"));
            }
        }
        Ok(redacted)
    }

    /// Redact JSON string values before serialization so secrets containing
    /// quotes, backslashes, or newlines cannot bypass matching via escaping.
    pub fn redact_value<'a, I>(
        &self,
        value: &serde_json::Value,
        envelopes: I,
    ) -> Result<serde_json::Value, SecretError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut values: Vec<(String, Zeroizing<String>)> = envelopes
            .into_iter()
            .map(|(name, envelope)| {
                self.open(name, envelope)
                    .map(|value| (name.to_owned(), value))
            })
            .collect::<Result<_, _>>()?;
        values.sort_by_key(|(_, value)| std::cmp::Reverse(value.len()));

        fn visit(
            value: &serde_json::Value,
            secrets: &[(String, Zeroizing<String>)],
        ) -> serde_json::Value {
            match value {
                serde_json::Value::String(text) => {
                    let mut redacted = text.clone();
                    for (name, secret) in secrets {
                        if !secret.is_empty() {
                            redacted = redacted
                                .replace(secret.as_str(), &format!("[REDACTED:secret:{name}]"));
                        }
                    }
                    serde_json::Value::String(redacted)
                }
                serde_json::Value::Array(items) => serde_json::Value::Array(
                    items.iter().map(|item| visit(item, secrets)).collect(),
                ),
                serde_json::Value::Object(entries) => serde_json::Value::Object(
                    entries
                        .iter()
                        .map(|(key, item)| (key.clone(), visit(item, secrets)))
                        .collect(),
                ),
                scalar => scalar.clone(),
            }
        }

        Ok(visit(value, &values))
    }
}

fn validate_key(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    if bytes.len() != KEY_LEN {
        return Err(SecretError::InvalidKey(format!(
            "expected 32 bytes, received {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn hex_decode(encoded: &str) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    if encoded.len() != KEY_LEN * 2 {
        return Err(SecretError::InvalidKey(
            "hex key must contain exactly 64 characters".into(),
        ));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(KEY_LEN));
    for pair in encoded.as_bytes().chunks_exact(2) {
        let s = std::str::from_utf8(pair)
            .map_err(|_| SecretError::InvalidKey("hex key is not UTF-8".into()))?;
        out.push(
            u8::from_str_radix(s, 16).map_err(|_| {
                SecretError::InvalidKey("hex key contains non-hex characters".into())
            })?,
        );
    }
    Ok(out)
}

fn invalid_envelope(name: &str, detail: &str) -> SecretError {
    SecretError::InvalidEnvelope {
        name: name.into(),
        detail: detail.into(),
    }
}

// Takes ownership (not `&io::Error`) so every call site can stay the
// ergonomic `.map_err(io_error)` (a `FnOnce(io::Error) -> _`) instead of
// `.map_err(|e| io_error(&e))` at each of its six call sites.
#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> SecretError {
    SecretError::ProviderIo(error.to_string())
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SecretError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

#[cfg(windows)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SecretError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    let status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", "SYSTEM:F", "Administrators:F"])
        .status()
        .map_err(io_error)?;
    if !status.success() {
        let _ = std::fs::remove_file(path);
        return Err(SecretError::ProviderIo(
            "icacls failed to restrict the master-key file".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn os_keychain_load(provider: &OsKeychainProvider) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };

    if !provider.protected_file.exists() {
        let mut raw = Zeroizing::new(vec![0u8; KEY_LEN]);
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let raw_len = u32::try_from(raw.len()).map_err(|_| {
            SecretError::KeyUnavailable("master key material is implausibly large".into())
        })?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: raw_len,
            pbData: raw.as_mut_ptr(),
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(SecretError::KeyUnavailable(
                "DPAPI CryptProtectData failed".into(),
            ));
        }
        let protected =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
        let write = write_private_file(&provider.protected_file, protected);
        unsafe { LocalFree(output.pbData.cast()) };
        write?;
    }

    let mut protected = Zeroizing::new(std::fs::read(&provider.protected_file).map_err(io_error)?);
    let protected_len = u32::try_from(protected.len()).map_err(|_| {
        SecretError::KeyUnavailable("protected key file is implausibly large".into())
    })?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: protected_len,
        pbData: protected.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(SecretError::KeyUnavailable(
            "DPAPI CryptUnprotectData failed".into(),
        ));
    }
    let result = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec(),
    );
    unsafe { LocalFree(output.pbData.cast()) };
    validate_key(result)
}

#[cfg(target_os = "linux")]
fn os_keychain_load(provider: &OsKeychainProvider) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let output = std::process::Command::new("secret-tool")
        .args([
            "lookup",
            "service",
            &provider.service,
            "account",
            &provider.account,
        ])
        .output()
        .map_err(|e| {
            SecretError::KeyUnavailable(format!("libsecret secret-tool unavailable: {e}"))
        })?;
    if !output.status.success() {
        return Err(SecretError::KeyUnavailable(
            "libsecret entry is missing; provision it with secret-tool store".into(),
        ));
    }
    validate_key(Zeroizing::new(
        B64.decode(String::from_utf8_lossy(&output.stdout).trim())
            .map_err(|_| SecretError::InvalidKey("libsecret value is not base64".into()))?,
    ))
}

#[cfg(target_os = "macos")]
fn os_keychain_load(provider: &OsKeychainProvider) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let output = std::process::Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            &provider.service,
            "-a",
            &provider.account,
            "-w",
        ])
        .output()
        .map_err(|e| {
            SecretError::KeyUnavailable(format!("Keychain security tool unavailable: {e}"))
        })?;
    if !output.status.success() {
        return Err(SecretError::KeyUnavailable(
            "Keychain master-key entry is missing".into(),
        ));
    }
    validate_key(Zeroizing::new(
        B64.decode(String::from_utf8_lossy(&output.stdout).trim())
            .map_err(|_| SecretError::InvalidKey("Keychain value is not base64".into()))?,
    ))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn os_keychain_load(_provider: &OsKeychainProvider) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    Err(SecretError::KeyUnavailable(
        "no OS keychain backend exists for this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryProvider(Vec<u8>);
    impl MasterKeyProvider for MemoryProvider {
        fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
            validate_key(Zeroizing::new(self.0.clone()))
        }
        fn name(&self) -> &'static str {
            "test-memory"
        }
    }

    fn broker(byte: u8) -> SecretBroker {
        // OS keychains are genuinely unavailable/non-deterministic in unit CI;
        // this in-memory provider exercises the real broker and cipher path.
        SecretBroker::new(Arc::new(MemoryProvider(vec![byte; KEY_LEN])))
    }

    #[test]
    fn seal_round_trip_uses_random_nonce_and_name_aad() {
        let b = broker(7);
        let one = b.seal("TOKEN", "swordfish").unwrap();
        let two = b.seal("TOKEN", "swordfish").unwrap();
        assert_ne!(one, two);
        assert!(one.starts_with("fwsecret:v1:"));
        assert_eq!(b.open("TOKEN", &one).unwrap().as_str(), "swordfish");
        assert!(matches!(
            b.open("OTHER", &one),
            Err(SecretError::InvalidEnvelope { .. })
        ));
    }

    #[test]
    fn legacy_and_wrong_keys_fail_closed_without_returning_plaintext() {
        assert!(matches!(
            broker(1).open("TOKEN", "plaintext"),
            Err(SecretError::LegacyUnsealed { .. })
        ));
        let envelope = broker(1).seal("TOKEN", "plaintext").unwrap();
        let err = broker(2).open("TOKEN", &envelope).unwrap_err().to_string();
        assert!(!err.contains("plaintext"));
    }

    #[test]
    fn redaction_uses_name_only_markers_and_overlapping_values() {
        let b = broker(3);
        let a = b.seal("SHORT", "abc").unwrap();
        let z = b.seal("LONG", "abcdef").unwrap();
        let out = b
            .redact_text(
                "x=abcdef y=abc",
                [("SHORT", a.as_str()), ("LONG", z.as_str())],
            )
            .unwrap();
        assert_eq!(out, "x=[REDACTED:secret:LONG] y=[REDACTED:secret:SHORT]");
        assert!(!out.contains("abcdef"));
    }

    #[test]
    fn json_redaction_happens_before_serialization_escaping() {
        let b = broker(4);
        let secret = "line one\n\"quoted\"\\tail";
        let envelope = b.seal("COMPLEX", secret).unwrap();
        let redacted = b
            .redact_value(
                &serde_json::json!({"nested": [secret], "unchanged": 7}),
                [("COMPLEX", envelope.as_str())],
            )
            .unwrap();
        let encoded = serde_json::to_string(&redacted).unwrap();
        assert_eq!(redacted["nested"][0], "[REDACTED:secret:COMPLEX]");
        assert!(!encoded.contains("line one"));
        assert_eq!(redacted["unchanged"], 7);
    }

    #[test]
    fn invalid_key_length_fails_before_crypto() {
        let b = SecretBroker::new(Arc::new(MemoryProvider(vec![1; 31])));
        assert!(matches!(
            b.seal("TOKEN", "value"),
            Err(SecretError::InvalidKey(_))
        ));
    }
}
