//! A string wrapper that deliberately does not implement `Serialize`.
//!
//! This is the compile-time half of "secret fields cannot serialize through
//! safe DTO types" (114C.1 acceptance). Any domain field holding credential
//! material, a session secret, a refresh secret, a reset/recovery token, or
//! challenge material is typed as [`SecretString`]. A struct that derives
//! `Serialize` and contains a `SecretString` field simply does not compile --
//! there is no runtime check to forget, and no code-review discipline to
//! erode. Safe DTOs (see `dto.rs`) are built by explicit field-by-field
//! extraction, never by deriving `Serialize` on a domain type directly.
//!
//! `Debug` is implemented, but redacts: it exists so a `SecretString` can sit
//! inside a struct that derives `Debug` for diagnostics, without a debug print
//! ever discharging the secret into a log.

use zeroize::Zeroize;

pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The only way to read the wrapped value. Callers that reach for this
    /// are declaring "I am about to do something that requires the actual
    /// secret" (hash comparison, signing, handing to a protected-storage
    /// adapter) -- it is not meant to be a convenience accessor.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(REDACTED)")
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl PartialEq for SecretString {
    /// Deliberately not constant-time: this compares two in-memory secrets
    /// for test/debug convenience, not a credential against an untrusted
    /// presented value. Verification paths (114C.3) use their own
    /// constant-time comparison, mirroring `fabric-hub::auth::constant_time_eq`.
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts() {
        let secret = SecretString::new("do-not-leak-this");
        let formatted = format!("{secret:?}");
        assert!(!formatted.contains("do-not-leak-this"));
        assert_eq!(formatted, "SecretString(REDACTED)");
    }

    #[test]
    fn expose_secret_returns_the_wrapped_value() {
        let secret = SecretString::new("value");
        assert_eq!(secret.expose_secret(), "value");
    }
}
