//! Golden baseline for the 114C.5 human-account route policy -- the
//! counterpart to `role_policy_baseline.rs` for routes gated on `admin`, a
//! role that deliberately does not exist in that file's `VALID_ROLES`
//! machine vocabulary (see the fixture's own header comment for why this is
//! a separate file rather than an addition to that one).

use fabric_hub::auth::required_roles;
use serde_json::Value;
use std::path::PathBuf;

fn load_baseline() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("authz")
        .join("human_account_route_policy_baseline.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("invalid JSON in human_account_route_policy_baseline.json")
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
fn account_route_policy_matches_the_baseline() {
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
        "the account route authorization policy drifted from the 114C.5 baseline:\n{}\n\n\
         Update tests/fixtures/authz/human_account_route_policy_baseline.json in the same commit and say why.",
        drift.join("\n")
    );
}

#[test]
fn admin_only_routes_reject_every_machine_role() {
    // The invariant this whole split exists to protect: no route requiring
    // only "admin" can ever be satisfied by a role token or the legacy
    // bearer, because "admin" is not in VALID_ROLES and no role-token
    // vocabulary check ever adds it. This test asserts the *shape* of the
    // policy (admin-only routes contain no VALID_ROLES member), which is
    // what makes that true regardless of how a caller authenticated.
    use fabric_hub::auth::VALID_ROLES;
    let admin_only_routes = [
        ("POST", "/accounts"),
        ("PATCH", "/accounts/acct-1"),
        ("POST", "/accounts/acct-1/membership"),
        ("DELETE", "/accounts/acct-1/membership/admin"),
        ("POST", "/accounts/acct-1/disable"),
        ("POST", "/accounts/acct-1/enable"),
        ("POST", "/accounts/acct-1/recovery-codes"),
        ("POST", "/accounts/acct-1/recovery/complete"),
        ("POST", "/accounts/acct-1/delete"),
        ("POST", "/accounts/acct-1/tombstone"),
        ("POST", "/accounts/import"),
    ];
    for (method, path) in admin_only_routes {
        let roles = required_roles(method, path);
        assert_eq!(roles, &["admin"], "{method} {path} must be admin-only");
        for machine_role in VALID_ROLES {
            assert!(
                !roles.contains(machine_role),
                "{method} {path} must not be reachable by machine role {machine_role:?}"
            );
        }
    }
}

#[test]
fn every_human_only_role_can_reach_its_own_self_service_routes() {
    // Regression for the first-admin deadlock's self-service facet: a human who
    // holds ONLY `admin` (every bootstrap first administrator), or only
    // `approver`/`dispatcher`, must still reach their own identity/session/
    // credential routes -- most importantly passkey registration. The prior
    // `OBSERVE = [observer, reviewer]` gate 403'd a fresh admin out of setting
    // up a passkey, listing/revoking their sessions, logging out, or even
    // `/auth/me`.
    use fabric_hub::auth::{is_authorized, AuthContext};
    let self_service = [
        ("GET", "/auth/me"),
        ("GET", "/auth/sessions"),
        ("DELETE", "/auth/sessions/sess-1"),
        ("POST", "/auth/logout"),
        ("POST", "/auth/logout-all"),
        ("POST", "/auth/passkeys/register/options"),
        ("POST", "/auth/passkeys/register/verify"),
        ("POST", "/auth/step-up/options"),
        ("POST", "/auth/step-up/verify"),
        ("GET", "/auth-policy"),
    ];
    for role in ["admin", "approver", "dispatcher", "observer", "reviewer"] {
        let ctx = AuthContext::for_test("acct-x", &[role], Some("acct-x"));
        for (method, path) in self_service {
            assert!(
                is_authorized(&ctx, method, path),
                "a human holding only {role:?} must reach {method} {path}"
            );
        }
    }
}

#[test]
fn unmapped_account_style_paths_still_fail_closed_to_reviewer() {
    assert_eq!(
        required_roles("GET", "/accounts-not-a-real-prefix"),
        &["reviewer"]
    );
}

fn load_step_up_baseline() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("authz")
        .join("human_account_step_up_baseline.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("invalid JSON in human_account_step_up_baseline.json")
}

#[test]
fn step_up_policy_matches_the_baseline() {
    use fabric_hub::auth::requires_step_up;
    let baseline = load_step_up_baseline();

    let mut drift: Vec<String> = Vec::new();
    for (key, expected) in [("step_up_required", true), ("step_up_not_required", false)] {
        for entry in baseline[key].as_array().expect("array") {
            let method = entry["method"].as_str().expect("method");
            let path = entry["path"].as_str().expect("path");
            let actual = requires_step_up(method, path);
            if actual != expected {
                drift.push(format!(
                    "  {method} {path}\n    baseline: {expected}\n    actual:   {actual}"
                ));
            }
        }
    }

    assert!(
        drift.is_empty(),
        "the step-up policy drifted from the 114C.6 baseline:\n{}\n\n\
         Update tests/fixtures/authz/human_account_step_up_baseline.json in the same commit and say why.",
        drift.join("\n")
    );
}
