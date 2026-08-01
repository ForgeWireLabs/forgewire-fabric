//! Golden baseline for the machine authorization surface (114C.0).
//!
//! 114C adds human principals and sessions above the existing role tokens and
//! Ed25519 identities. Its binding architecture requires signed interactive
//! mutations to gain human authorization "without weakening existing
//! signature/policy/approval gates", and forbids ever giving a human the
//! machine-only `runner` role.
//!
//! Nothing pinned those gates. `VALID_ROLES` appeared only in `auth.rs`, and
//! `ENDPOINT_AUTH_MATRIX.md` is cited from `//!` doc comments asserting routes
//! "map 1:1" to it while no test reads the file. An assertion in a comment is
//! not a test, which is how the 114B audit found four criteria satisfied on
//! prose.
//!
//! These tests load `tests/fixtures/authz/role_policy_baseline.json` and fail
//! if the policy drifts. A change here is a change to who may do what on the
//! cluster: update the fixture deliberately, in the same commit, or don't make
//! the change.

use fabric_hub::auth::{required_roles, LEGACY_COMPAT_ROLES, VALID_ROLES};
use serde_json::Value;
use std::path::PathBuf;

fn load_baseline() -> Value {
    // crates/fabric-hub/tests/ -> crates/fabric-hub -> crates -> repo root
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("authz")
        .join("role_policy_baseline.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("invalid JSON in role_policy_baseline.json")
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("expected a JSON array")
        .iter()
        .map(|v| v.as_str().expect("expected a string").to_string())
        .collect()
}

#[test]
fn valid_roles_match_the_baseline() {
    let baseline = load_baseline();
    let expected = string_list(&baseline["valid_roles"]);
    let actual: Vec<String> = VALID_ROLES.iter().map(|r| r.to_string()).collect();
    assert_eq!(
        actual, expected,
        "the role vocabulary changed. 114C must not alter machine roles; if this \
         is deliberate, update tests/fixtures/authz/role_policy_baseline.json in \
         the same commit."
    );
}

#[test]
fn legacy_compat_roles_match_the_baseline() {
    let baseline = load_baseline();
    let expected = string_list(&baseline["legacy_compat_roles"]);
    let actual: Vec<String> = LEGACY_COMPAT_ROLES.iter().map(|r| r.to_string()).collect();
    assert_eq!(
        actual, expected,
        "the legacy compatibility roles changed. The 114C plan keeps legacy role \
         tokens as an explicit parity/recovery path until a separately approved \
         retirement plan."
    );
}

#[test]
fn runner_is_machine_only_and_still_exists() {
    // 114C: "A human account must never be assigned the machine-only `runner`
    // role." That invariant is only meaningful while the role exists and is
    // spelled this way.
    assert!(
        VALID_ROLES.contains(&"runner"),
        "the machine-only `runner` role vanished; 114C's human/machine \
         separation invariant is written against it"
    );
}

#[test]
fn route_policy_matches_the_baseline() {
    let baseline = load_baseline();
    let routes = baseline["route_policy"]
        .as_array()
        .expect("route_policy must be an array");

    let mut drift: Vec<String> = Vec::new();
    for entry in routes {
        let method = entry["method"].as_str().expect("method");
        let path = entry["path"].as_str().expect("path");
        let expected = string_list(&entry["roles"]);
        let actual: Vec<String> = required_roles(method, path)
            .iter()
            .map(|r| r.to_string())
            .collect();
        if actual != expected {
            drift.push(format!(
                "  {method} {path}\n    baseline: {expected:?}\n    actual:   {actual:?}"
            ));
        }
    }

    assert!(
        drift.is_empty(),
        "the route authorization policy drifted from the 114C.0 baseline:\n{}\n\n\
         This is a change to who may do what on the cluster. If deliberate, update \
         tests/fixtures/authz/role_policy_baseline.json in the same commit and say \
         why in the message.",
        drift.join("\n")
    );
}

#[test]
fn unmapped_routes_fail_closed_to_reviewer() {
    // The fallthrough must stay closed. A refactor that makes unknown paths
    // permissive would not be caught by any route-specific test.
    assert_eq!(required_roles("GET", "/no/such/route"), &["reviewer"]);
    assert_eq!(required_roles("POST", "/no/such/route"), &["reviewer"]);
    assert_eq!(required_roles("DELETE", "/totally/unknown"), &["reviewer"]);
}

#[test]
fn every_baseline_role_is_a_valid_role() {
    // Guards the fixture against itself: a typo here would silently weaken a
    // route rather than fail.
    let baseline = load_baseline();
    for entry in baseline["route_policy"].as_array().expect("route_policy") {
        let path = entry["path"].as_str().expect("path");
        for role in string_list(&entry["roles"]) {
            assert!(
                VALID_ROLES.contains(&role.as_str()),
                "baseline names role {role:?} for {path}, which is not in VALID_ROLES"
            );
        }
    }
}
