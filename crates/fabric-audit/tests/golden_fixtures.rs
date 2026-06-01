//! Golden fixture tests — loads tests/fixtures/audit/chain.json and validates
//! every hash against the Rust implementation. If both this and the Python
//! test_fixtures.py pass, byte-level cross-language parity is proven.

use fabric_audit::{audit_canonical_json, audit_event_hash, verify_chain, AuditEvent, AUDIT_GENESIS_HASH};
use serde_json::Value;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    // crates/fabric-audit/tests/ -> crates/fabric-audit -> crates -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
}

fn load_audit_fixtures() -> Value {
    let path = fixtures_dir().join("audit").join("chain.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("invalid JSON in chain.json")
}

fn load_protocol_fixtures() -> Value {
    let path = fixtures_dir().join("protocol").join("envelope_v2.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("invalid JSON in envelope_v2.json")
}

#[test]
fn genesis_hash_matches_fixture() {
    let fixtures = load_audit_fixtures();
    let expected = fixtures["formula"]["genesis_hash"].as_str().unwrap();
    assert_eq!(AUDIT_GENESIS_HASH, expected);
}

#[test]
fn separator_byte_matches_fixture() {
    let fixtures = load_audit_fixtures();
    let expected_hex = fixtures["formula"]["separator_byte_hex"].as_str().unwrap();
    let expected_byte = u8::from_str_radix(expected_hex, 16).unwrap();
    assert_eq!(fabric_audit::SEPARATOR, expected_byte);
}

#[test]
fn separator_isolation_proof() {
    let fixtures = load_audit_fixtures();
    let proof = &fixtures["separator_isolation_proof"];
    let without = proof["attempt_without_separators_hex"].as_str().unwrap();
    let with = proof["result_with_separators_hex"].as_str().unwrap();

    // Reproduce: sha256("A" + "B" + "{}") without separators
    use sha2::{Digest, Sha256};
    let no_sep = {
        let mut h = Sha256::new();
        h.update(b"A");
        h.update(b"B");
        h.update(b"{}");
        hex::encode(h.finalize())
    };
    assert_eq!(no_sep, without);

    let with_sep = audit_event_hash("A", "B", &serde_json::json!({}));
    assert_eq!(with_sep, with);
    assert_ne!(no_sep, with_sep);
}

#[test]
fn valid_chain_event_hashes_match_fixture() {
    let fixtures = load_audit_fixtures();
    let events = fixtures["valid_chain"]["events"].as_array().unwrap();

    for event in events {
        let prev = event["prev_hash"].as_str().unwrap();
        let kind = event["kind"].as_str().unwrap();
        let payload = &event["payload"];
        let expected_hash = event["event_id_hash"].as_str().unwrap();

        let computed = audit_event_hash(prev, kind, payload);
        assert_eq!(
            computed, expected_hash,
            "hash mismatch for event seq={}",
            event["seq"]
        );
    }
}

#[test]
fn valid_chain_canonical_payload_hex_matches() {
    let fixtures = load_audit_fixtures();
    let events = fixtures["valid_chain"]["events"].as_array().unwrap();

    for event in events {
        let payload = &event["payload"];
        let expected_hex = event["canonical_payload_hex"].as_str().unwrap();

        let computed = audit_canonical_json(payload);
        assert_eq!(
            hex::encode(&computed),
            expected_hex,
            "canonical payload mismatch for event seq={}",
            event["seq"]
        );
    }
}

#[test]
fn chain_continuity_matches_fixture() {
    let fixtures = load_audit_fixtures();
    let events_json = fixtures["valid_chain"]["events"].as_array().unwrap();
    let expected_tail = fixtures["valid_chain"]["chain_tail"].as_str().unwrap();

    let events: Vec<AuditEvent<'_>> = events_json
        .iter()
        .map(|e| AuditEvent {
            event_id_hash: e["event_id_hash"].as_str().unwrap(),
            prev_event_id_hash: e["prev_hash"].as_str().unwrap(),
            kind: e["kind"].as_str().unwrap(),
            payload: &e["payload"],
        })
        .collect();

    assert!(verify_chain(&events).is_ok());

    let actual_tail = events.last().unwrap().event_id_hash;
    assert_eq!(actual_tail, expected_tail);
}

#[test]
fn tamper_rejection_matches_fixture() {
    let fixtures = load_audit_fixtures();
    let tamper = &fixtures["tamper_rejection"];
    let original_hash = tamper["original_event_id_hash"].as_str().unwrap();
    let tampered_hash = tamper["tampered_event_id_hash"].as_str().unwrap();

    let genesis = AUDIT_GENESIS_HASH;
    let first_event = &fixtures["valid_chain"]["events"][0];
    let kind = first_event["kind"].as_str().unwrap();

    let recomputed = audit_event_hash(genesis, kind, &tamper["tampered_payload"]);
    assert_eq!(recomputed, tampered_hash);
    assert_ne!(recomputed, original_hash);
}

#[test]
fn missing_event_breaks_chain() {
    let fixtures = load_audit_fixtures();
    let me = &fixtures["missing_event"];
    let valid_h3 = me["valid_hash_3"].as_str().unwrap();
    let gap_h3 = me["gap_hash_3"].as_str().unwrap();

    let events = fixtures["valid_chain"]["events"].as_array().unwrap();
    let e1_hash = events[0]["event_id_hash"].as_str().unwrap();
    let e3_kind = events[2]["kind"].as_str().unwrap();
    let e3_payload = &events[2]["payload"];

    let recomputed = audit_event_hash(e1_hash, e3_kind, e3_payload);
    assert_eq!(recomputed, gap_h3);
    assert_ne!(recomputed, valid_h3);
}

#[test]
fn expected_tail_conflict_matches_fixture() {
    let fixtures = load_audit_fixtures();
    let etc = &fixtures["expected_tail_conflict"];
    let prev = etc["prev_hash"].as_str().unwrap();

    let ha = audit_event_hash(
        prev,
        etc["writer_a"]["kind"].as_str().unwrap(),
        &etc["writer_a"]["payload"],
    );
    let hb = audit_event_hash(
        prev,
        etc["writer_b"]["kind"].as_str().unwrap(),
        &etc["writer_b"]["payload"],
    );

    assert_eq!(ha, etc["writer_a"]["event_id_hash"].as_str().unwrap());
    assert_eq!(hb, etc["writer_b"]["event_id_hash"].as_str().unwrap());
    assert_ne!(ha, hb);
}

#[test]
fn secret_name_only_in_payload() {
    let fixtures = load_audit_fixtures();
    let sn = &fixtures["secret_name_only_logging"];
    let kind = sn["kind"].as_str().unwrap();
    let payload = &sn["payload"];
    let expected_hash = sn["event_id_hash"].as_str().unwrap();

    let computed = audit_event_hash(AUDIT_GENESIS_HASH, kind, payload);
    assert_eq!(computed, expected_hash);

    // Verify secrets_dispatched contains names, not values
    let secrets = payload["secrets_dispatched"].as_array().unwrap();
    assert!(secrets.iter().all(|s| s.is_string()));
    assert!(payload.get("value").is_none());
    assert!(payload.get("secret_value").is_none());
    assert!(payload.get("plaintext").is_none());
}

// -- Protocol fixture tests (canonicalization + signing) ----------------------

#[test]
fn protocol_canonical_matches_fixture() {
    let fixtures = load_protocol_fixtures();
    let cases = fixtures["cases"].as_array().unwrap();

    for case in cases {
        if let (Some(envelope), Some(expected_hex)) = (
            case.get("envelope"),
            case.get("canonical_hex").and_then(|v| v.as_str()),
        ) {
            let computed = fabric_protocol::canonicalize(envelope).unwrap();
            assert_eq!(
                hex::encode(&computed),
                expected_hex,
                "canonical mismatch for case {}",
                case["id"].as_str().unwrap_or("?")
            );
        }
    }
}

#[test]
fn protocol_signatures_match_fixture() {
    let fixtures = load_protocol_fixtures();
    let kp = &fixtures["test_keypair"];
    let pk = kp["public_key_hex"].as_str().unwrap();
    let sk = kp["secret_key_hex"].as_str().unwrap();

    for case in fixtures["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap_or("?");

        // Verify correct-key cases
        if case.get("verify_with_correct_key") == Some(&Value::Bool(true)) {
            let canonical_hex = case["canonical_hex"].as_str().unwrap();
            let sig_hex = case["signature_hex"].as_str().unwrap();
            let canonical = hex::decode(canonical_hex).unwrap();
            let ok = fabric_protocol::verify_signature_hex(pk, &canonical, sig_hex).unwrap();
            assert!(ok, "case {id}: expected signature to verify");
        }

        // Verify tamper rejection
        if case.get("tampered_verifies") == Some(&Value::Bool(false)) {
            let tampered_hex = case["tampered_canonical_hex"].as_str().unwrap();
            let sig_hex = case["signature_hex"].as_str().unwrap();
            let tampered = hex::decode(tampered_hex).unwrap();
            let ok = fabric_protocol::verify_signature_hex(pk, &tampered, sig_hex).unwrap();
            assert!(!ok, "case {id}: tampered payload should not verify");
        }

        // Verify wrong-key rejection
        if case.get("verifies_with_test_key") == Some(&Value::Bool(false)) {
            let canonical_hex = case["canonical_hex"].as_str().unwrap();
            let wrong_sig = case["wrong_signature_hex"].as_str().unwrap();
            let canonical = hex::decode(canonical_hex).unwrap();
            let ok = fabric_protocol::verify_signature_hex(pk, &canonical, wrong_sig).unwrap();
            assert!(!ok, "case {id}: wrong-key sig should not verify");
        }
    }

    // Round-trip: sign with test key, verify
    let minimal = &fixtures["cases"][0];
    let canonical = hex::decode(minimal["canonical_hex"].as_str().unwrap()).unwrap();
    let sig = fabric_protocol::sign_payload_hex(sk, &canonical).unwrap();
    assert!(fabric_protocol::verify_signature_hex(pk, &canonical, &sig).unwrap());
}
