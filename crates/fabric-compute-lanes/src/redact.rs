//! Redaction for capability advertisement.
//!
//! Device descriptions come from hardware probes, driver strings, and vendor
//! SDKs. Those are not trusted to be free of host-identifying detail, and
//! whatever survives here gets advertised to the hub and stored in evidence.
//! The 114F design doc requires capability advertisement to exclude usernames,
//! tokens, arbitrary paths, serial numbers, and sensitive driver output.
//!
//! The rules below are deliberately conservative in one specific direction:
//! they must not mangle ordinary device names. `"NVIDIA GeForce RTX 4090"`,
//! `"Intel(R) Core(TM) i9-14900K"`, and `"AMD Radeon RX 7900 XTX"` have to pass
//! through untouched, because a redactor that corrupts normal hardware names
//! makes capability data useless and will simply be turned off.
//!
//! Every redaction returns a reason so the caller can surface it as a
//! projection warning — silent alteration of advertised capability would be
//! worse than either extreme.

/// Maximum length for an advertised free-form field. Real device names are far
/// under this; anything longer is dumped driver output, not a name.
const MAX_FIELD_LEN: usize = 128;

/// Minimum run length before an unbroken alphanumeric string is treated as a
/// possible token or serial rather than a model number. Set above the longest
/// realistic model identifier (`GeForce RTX 4090`-style tokens are short; the
/// longest plausible unbroken run in a real device name is well under 24).
const TOKEN_RUN_LEN: usize = 24;

/// Result of redacting one field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionOutcome {
    /// Field was safe as-is.
    Clean(String),
    /// Field was altered. `reason` is suitable for a projection warning.
    Redacted { value: String, reason: String },
}

impl RedactionOutcome {
    /// The resulting value either way.
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            RedactionOutcome::Clean(v) => v,
            RedactionOutcome::Redacted { value, .. } => value,
        }
    }

    #[must_use]
    pub fn was_redacted(&self) -> bool {
        matches!(self, RedactionOutcome::Redacted { .. })
    }
}

/// Redact a single free-form capability field.
///
/// Applied in order; the first rule that fires wins, so the reason reported is
/// the most specific one rather than a pile-up.
#[must_use]
pub fn redact_field(value: &str) -> RedactionOutcome {
    // Control characters and newlines: multi-line driver dumps have no place in
    // an advertised name, and embedded control bytes corrupt downstream logs.
    if value.chars().any(|c| c.is_control()) {
        let cleaned: String = value
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        return RedactionOutcome::Redacted {
            value: truncate(cleaned.trim()),
            reason: "contained control characters".into(),
        };
    }

    if let Some(reason) = looks_like_path(value) {
        return RedactionOutcome::Redacted {
            value: "[redacted-path]".into(),
            reason,
        };
    }

    if contains_current_username(value) {
        return RedactionOutcome::Redacted {
            value: "[redacted-user]".into(),
            reason: "contained the current username".into(),
        };
    }

    if let Some(run) = long_opaque_run(value) {
        return RedactionOutcome::Redacted {
            value: "[redacted-token]".into(),
            reason: format!("contained a {run}-character opaque run (possible token or serial)"),
        };
    }

    if value.len() > MAX_FIELD_LEN {
        return RedactionOutcome::Redacted {
            value: truncate(value),
            reason: format!("exceeded {MAX_FIELD_LEN} characters"),
        };
    }

    RedactionOutcome::Clean(value.to_owned())
}

fn truncate(value: &str) -> String {
    if value.len() <= MAX_FIELD_LEN {
        return value.to_owned();
    }
    // Respect char boundaries — device strings can carry non-ASCII.
    let mut end = MAX_FIELD_LEN;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

/// Detect filesystem paths and UNC shares.
fn looks_like_path(value: &str) -> Option<String> {
    // UNC share: \\server\share
    if value.starts_with("\\\\") {
        return Some("contained a UNC path".into());
    }
    // Windows drive path: C:\ or C:/
    let bytes = value.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i].is_ascii_alphabetic()
            && bytes[i + 1] == b':'
            && (bytes[i + 2] == b'\\' || bytes[i + 2] == b'/')
        {
            return Some("contained a Windows filesystem path".into());
        }
    }
    // Unix absolute path: a leading slash with at least one more component.
    // Requires a second slash so "N/A" and "Ada/Lovelace"-style names survive.
    if value.starts_with('/') && value[1..].contains('/') {
        return Some("contained a Unix filesystem path".into());
    }
    // Common home-directory markers anywhere in the string.
    for marker in ["/home/", "/Users/", "\\Users\\", "%USERPROFILE%", "~/"] {
        if value.contains(marker) {
            return Some(format!("contained a home-directory path marker ({marker})"));
        }
    }
    None
}

/// Whether the string contains the current OS username.
///
/// Short usernames are ignored: a two-character username would match inside
/// ordinary device names constantly, and the false-positive cost (destroying
/// every device name on that host) far exceeds the benefit.
fn contains_current_username(value: &str) -> bool {
    const MIN_USERNAME_LEN: usize = 4;

    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();

    if user.len() < MIN_USERNAME_LEN {
        return false;
    }
    value
        .to_ascii_lowercase()
        .contains(&user.to_ascii_lowercase())
}

/// Find an unbroken run of token-ish characters long enough to be a secret or
/// a serial number rather than a model identifier.
///
/// Runs are broken by spaces and common punctuation found in device names
/// (`-`, `(`, `)`, `.`, `,`, `/`), so `"Intel(R) Core(TM) i9-14900K"` never
/// forms a long run, while a 32-character hex blob does.
fn long_opaque_run(value: &str) -> Option<usize> {
    let mut current = 0usize;
    let mut longest = 0usize;
    let mut has_digit = false;
    let mut has_alpha = false;
    let mut run_had_both = false;

    for c in value.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '+' || c == '=' {
            current += 1;
            if c.is_ascii_digit() {
                has_digit = true;
            } else if c.is_ascii_alphabetic() {
                has_alpha = true;
            }
            if current > longest && has_digit && has_alpha {
                longest = current;
                run_had_both = true;
            }
        } else {
            current = 0;
            has_digit = false;
            has_alpha = false;
        }
    }

    if run_had_both && longest >= TOKEN_RUN_LEN {
        Some(longest)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_device_names_pass_through_untouched() {
        // The single most important property: a redactor that corrupts real
        // hardware names is worse than no redactor, because it will be
        // disabled and then nothing is redacted.
        for name in [
            "NVIDIA GeForce RTX 4090",
            "Intel(R) Core(TM) i9-14900K",
            "AMD Radeon RX 7900 XTX",
            "NVIDIA Quadro M1200",
            "Intel(R) UHD Graphics 630",
            "Apple M2 Max",
            "NVIDIA",
            "Intel",
            "AMD",
            "",
        ] {
            assert_eq!(
                redact_field(name),
                RedactionOutcome::Clean(name.to_owned()),
                "device name was wrongly redacted: {name:?}"
            );
        }
    }

    #[test]
    fn windows_paths_are_redacted() {
        let out = redact_field(r"C:\Users\jerem\driver.dll");
        assert!(out.was_redacted());
        assert_eq!(out.value(), "[redacted-path]");
    }

    #[test]
    fn unc_paths_are_redacted() {
        assert!(redact_field(r"\\fileserver\gpu\driver").was_redacted());
    }

    #[test]
    fn unix_paths_are_redacted() {
        assert!(redact_field("/opt/rocm/lib/libhsa.so").was_redacted());
        assert!(redact_field("/home/someone/models").was_redacted());
    }

    #[test]
    fn slash_containing_names_are_not_treated_as_paths() {
        // "N/A" and similar must survive — a single slash is not a path.
        assert_eq!(
            redact_field("N/A"),
            RedactionOutcome::Clean("N/A".to_owned())
        );
    }

    #[test]
    fn long_opaque_runs_are_redacted() {
        // 32-char mixed hex blob — a plausible serial or token.
        let out = redact_field("GPU a1b2c3d4e5f60718293a4b5c6d7e8f90");
        assert!(out.was_redacted(), "expected token-like run to be redacted");
        assert_eq!(out.value(), "[redacted-token]");
    }

    #[test]
    fn pure_digit_runs_are_not_treated_as_tokens() {
        // A long number is not a secret; requiring both letters and digits
        // keeps model numbers and capacities safe.
        let value = "Device 12345678901234567890123456";
        assert_eq!(
            redact_field(value),
            RedactionOutcome::Clean(value.to_owned())
        );
    }

    #[test]
    fn control_characters_are_stripped() {
        let out = redact_field("NVIDIA\nDriver\tdump");
        assert!(out.was_redacted());
        assert!(!out.value().contains('\n'));
        assert!(!out.value().contains('\t'));
    }

    #[test]
    fn overlong_fields_are_truncated() {
        let long = "A".repeat(MAX_FIELD_LEN + 50);
        let out = redact_field(&long);
        assert!(out.was_redacted());
        assert!(out.value().chars().count() <= MAX_FIELD_LEN + 1);
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        // Multi-byte characters must not be split mid-codepoint.
        let long = "é".repeat(MAX_FIELD_LEN);
        let out = redact_field(&long);
        assert!(out.was_redacted());
        // The value is valid UTF-8 by construction if this does not panic.
        assert!(!out.value().is_empty());
    }

    #[test]
    fn current_username_is_redacted() {
        // Build a value containing whatever this host's username actually is.
        let user = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_default();
        if user.len() < 4 {
            // Host has no usable username to test against; the rule is
            // deliberately inert in that case.
            return;
        }
        let out = redact_field(&format!("GPU owned by {user}"));
        assert!(out.was_redacted());
        assert_eq!(out.value(), "[redacted-user]");
    }
}
