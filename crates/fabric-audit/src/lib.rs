//! Hash-chained audit log for ForgeWire Fabric.
//!
//! Reproduces the exact byte formula from the Python oracle at
//! `oracle/v2.7.0-baseline`. The literal `b"|"` separator bytes between
//! `prev_hash`, `kind`, and `payload` are part of the compatibility
//! contract.
//!
//! ## Audit hash formula (byte-exact)
//!
//! ```text
//! event_id_hash = sha256(
//!     ascii(prev_event_id_hash)   // hex string as ASCII bytes
//!     || b"|"                     // LITERAL separator
//!     || utf8(kind)               // event kind string
//!     || b"|"                     // LITERAL separator
//!     || audit_canonical_json(payload)
//! )
//!
//! audit_canonical_json(payload) =
//!     json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
//!         .encode("utf-8")
//! ```
//!
//! ## Genesis hash
//!
//! The chain's "previous hash" before any event is recorded.
//! 64 ASCII zero characters.

#![deny(rust_2018_idioms)]

use sha2::{Digest, Sha256};
use serde_json::Value;
use thiserror::Error;

/// The chain's genesis hash — 64 ASCII zeros.
pub const AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// The literal separator byte used between fields in the audit hash.
pub const SEPARATOR: u8 = b'|';

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("chain break at event {index}: prev_hash {found} != expected {expected}")]
    ChainBreak {
        index: usize,
        expected: String,
        found: String,
    },

    #[error("hash mismatch at event {index}: stored {stored} != recomputed {recomputed}")]
    HashMismatch {
        index: usize,
        stored: String,
        recomputed: String,
    },

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Canonical JSON for audit payloads.
///
/// Matches Python's `json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)`
/// for the subset of types that appear in audit payloads (strings, ints, lists,
/// dicts, nulls, booleans). The `default=str` fallback is not needed here
/// because Rust types are already concrete — there are no datetime objects
/// that need string coercion.
pub fn audit_canonical_json(payload: &Value) -> Vec<u8> {
    // serde_json's to_string with sorted keys isn't available out of the
    // box, but the audit payloads are always objects with string/int/list
    // values. We use the same recursive sorted-key approach as
    // fabric-protocol's canonicalize, but with serde_json's default
    // number formatting (which matches Python's json.dumps for ints).
    let mut out = Vec::with_capacity(256);
    write_canonical(payload, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            out.push(b'{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                // Keys are quoted strings — use serde_json for correct escaping
                let key_json = serde_json::to_string(k).unwrap_or_default();
                out.extend_from_slice(key_json.as_bytes());
                out.push(b':');
                write_canonical(v, out);
            }
            out.push(b'}');
        }
        Value::Array(arr) => {
            out.push(b'[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(v, out);
            }
            out.push(b']');
        }
        // Scalars: serde_json's compact representation matches Python's
        // json.dumps for strings, numbers, booleans, and null.
        other => {
            let s = serde_json::to_string(other).unwrap_or_default();
            out.extend_from_slice(s.as_bytes());
        }
    }
}

/// Compute the audit event hash from the previous hash, event kind, and payload.
///
/// This is the core byte-exact formula. The literal `b"|"` separator bytes
/// are part of the compatibility contract.
pub fn audit_event_hash(prev_hash: &str, kind: &str, payload: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes()); // ascii(prev_hash)
    hasher.update([SEPARATOR]);          // b"|"
    hasher.update(kind.as_bytes());      // utf8(kind)
    hasher.update([SEPARATOR]);          // b"|"
    hasher.update(audit_canonical_json(payload)); // audit_canonical_json(payload)
    hex::encode(hasher.finalize())
}

/// An audit event for chain verification.
pub struct AuditEvent<'a> {
    pub event_id_hash: &'a str,
    pub prev_event_id_hash: &'a str,
    pub kind: &'a str,
    pub payload: &'a Value,
}

/// Verify a sequence of audit events forms a valid hash chain.
///
/// Mirrors `Blackboard.verify_audit_chain` from the Python oracle.
/// For partial slices (e.g. one day's export), the first event's
/// `prev_event_id_hash` is trusted as the starting point.
pub fn verify_chain(events: &[AuditEvent<'_>]) -> Result<(), AuditError> {
    let mut prev: Option<&str> = None;
    for (i, event) in events.iter().enumerate() {
        if let Some(expected_prev) = prev {
            if event.prev_event_id_hash != expected_prev {
                return Err(AuditError::ChainBreak {
                    index: i,
                    expected: expected_prev.to_owned(),
                    found: event.prev_event_id_hash.to_owned(),
                });
            }
        }
        let recomputed =
            audit_event_hash(event.prev_event_id_hash, event.kind, event.payload);
        if recomputed != event.event_id_hash {
            return Err(AuditError::HashMismatch {
                index: i,
                stored: event.event_id_hash.to_owned(),
                recomputed,
            });
        }
        prev = Some(event.event_id_hash);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn genesis_hash_is_64_zeros() {
        assert_eq!(AUDIT_GENESIS_HASH.len(), 64);
        assert!(AUDIT_GENESIS_HASH.chars().all(|c| c == '0'));
    }

    #[test]
    fn separator_is_pipe() {
        assert_eq!(SEPARATOR, b'|');
    }

    #[test]
    fn separator_prevents_field_collisions() {
        // Without separators, different inputs could collide.
        // prev="A", kind="B", payload={} should differ from
        // a hypothetical no-separator hash of "A" + "B" + "{}"
        use sha2::Digest;
        let no_sep = {
            let mut h = Sha256::new();
            h.update(b"A");
            h.update(b"B");
            h.update(b"{}");
            hex::encode(h.finalize())
        };
        let with_sep = audit_event_hash("A", "B", &json!({}));
        assert_ne!(no_sep, with_sep);
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let payload = json!({"z": 1, "a": 2, "m": 3});
        let canonical = audit_canonical_json(&payload);
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            r#"{"a":2,"m":3,"z":1}"#
        );
    }

    #[test]
    fn canonical_json_compact_separators() {
        let payload = json!({"key": "value", "list": [1, 2, 3]});
        let canonical = std::str::from_utf8(&audit_canonical_json(&payload))
            .unwrap()
            .to_owned();
        assert!(!canonical.contains(' '));
        assert!(canonical.contains(","));
        assert!(canonical.contains(":"));
    }

    #[test]
    fn canonical_json_null_handling() {
        let payload = json!({"a": null, "b": 1});
        let canonical = std::str::from_utf8(&audit_canonical_json(&payload))
            .unwrap()
            .to_owned();
        assert_eq!(canonical, r#"{"a":null,"b":1}"#);
    }

    #[test]
    fn verify_valid_chain() {
        let genesis = AUDIT_GENESIS_HASH;
        let p1 = json!({"task_id": 1, "title": "Test"});
        let h1 = audit_event_hash(genesis, "dispatch", &p1);

        let p2 = json!({"task_id": 1, "worker_id": "runner-1"});
        let h2 = audit_event_hash(&h1, "claim", &p2);

        let events = [
            AuditEvent {
                event_id_hash: &h1,
                prev_event_id_hash: genesis,
                kind: "dispatch",
                payload: &p1,
            },
            AuditEvent {
                event_id_hash: &h2,
                prev_event_id_hash: &h1,
                kind: "claim",
                payload: &p2,
            },
        ];
        assert!(verify_chain(&events).is_ok());
    }

    #[test]
    fn detect_tampered_payload() {
        let genesis = AUDIT_GENESIS_HASH;
        let p1 = json!({"task_id": 1, "title": "Test"});
        let h1 = audit_event_hash(genesis, "dispatch", &p1);

        let tampered = json!({"task_id": 1, "title": "Tampered"});
        let events = [AuditEvent {
            event_id_hash: &h1,
            prev_event_id_hash: genesis,
            kind: "dispatch",
            payload: &tampered,
        }];
        assert!(matches!(
            verify_chain(&events),
            Err(AuditError::HashMismatch { .. })
        ));
    }

    #[test]
    fn detect_chain_break() {
        let genesis = AUDIT_GENESIS_HASH;
        let p1 = json!({"task_id": 1});
        let h1 = audit_event_hash(genesis, "dispatch", &p1);

        let p2 = json!({"task_id": 1, "worker_id": "r"});
        let h2 = audit_event_hash(&h1, "claim", &p2);

        // Event 2 claims its prev is genesis (skipping event 1)
        let events = [
            AuditEvent {
                event_id_hash: &h1,
                prev_event_id_hash: genesis,
                kind: "dispatch",
                payload: &p1,
            },
            AuditEvent {
                event_id_hash: &h2,
                prev_event_id_hash: genesis, // wrong — should be h1
                kind: "claim",
                payload: &p2,
            },
        ];
        assert!(matches!(
            verify_chain(&events),
            Err(AuditError::ChainBreak { .. })
        ));
    }
}
