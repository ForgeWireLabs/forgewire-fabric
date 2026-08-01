//! Cross-language fixture parity (114C.1 acceptance: "Rust and TypeScript
//! parse the same fixtures").
//!
//! `tests/fixtures/accounts/account_session_summary.json` is parsed here and
//! by `packages/fabric-client-core/src/authContracts.test.ts`. Two things are
//! checked, not one: that the fixture deserializes into the safe DTOs at all,
//! and that the fixture's `typed_error_codes` list is exactly
//! `AccountsError::ALL_CODES` -- same length, same members, same order. A
//! fixture that merely parses but silently drops or reorders codes would
//! pass a weaker test and still let Rust and TypeScript's error vocabularies
//! drift apart the way `ENDPOINT_AUTH_MATRIX.md` drifted from `auth.rs`
//! before 114C.0 pinned it.

use std::path::PathBuf;

use fabric_accounts::error::AccountsError;
use fabric_accounts::{AccountSummaryDto, SessionSummaryDto};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    account_summary: AccountSummaryDto,
    session_summary: SessionSummaryDto,
    typed_error_codes: Vec<String>,
}

fn load_fixture() -> Fixture {
    // crates/fabric-accounts/tests/ -> crates/fabric-accounts -> crates -> repo root
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("accounts")
        .join("account_session_summary.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("invalid JSON in account_session_summary.json: {e}"))
}

#[test]
fn account_summary_fixture_parses_with_expected_fields() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.account_summary.account_id,
        "acct-01hxfixture0000000000000"
    );
    assert_eq!(fixture.account_summary.username, "operator1");
    assert_eq!(fixture.account_summary.display_name, "Operator One");
    assert_eq!(fixture.account_summary.status, "active");
    assert_eq!(
        fixture.account_summary.roles,
        vec!["dispatcher", "reviewer"]
    );
    assert_eq!(fixture.account_summary.revision, 3);
}

#[test]
fn session_summary_fixture_parses_with_expected_fields() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.session_summary.session_id,
        "sess-01hxfixture0000000000000"
    );
    assert_eq!(
        fixture.session_summary.account_id,
        "acct-01hxfixture0000000000000"
    );
    assert_eq!(fixture.session_summary.client_kind, "vsix");
    assert_eq!(fixture.session_summary.assurance_level, "aal1");
    assert!(fixture.session_summary.current);
}

#[test]
fn typed_error_codes_in_the_fixture_exactly_match_accounts_error_all_codes() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.typed_error_codes,
        AccountsError::ALL_CODES,
        "the fixture's typed_error_codes must match AccountsError::ALL_CODES exactly \
         (same members, same order) -- this is also what \
         packages/fabric-client-core's TYPED_AUTH_ERROR_CODES is checked against, \
         so all three must agree"
    );
}

#[test]
fn every_all_codes_entry_is_unique_and_present_in_the_fixture() {
    let fixture = load_fixture();
    let mut sorted_fixture = fixture.typed_error_codes.clone();
    sorted_fixture.sort_unstable();
    sorted_fixture.dedup();
    assert_eq!(
        sorted_fixture.len(),
        fixture.typed_error_codes.len(),
        "fixture typed_error_codes contains a duplicate"
    );
    for code in AccountsError::ALL_CODES {
        assert!(
            fixture.typed_error_codes.iter().any(|c| c == code),
            "AccountsError code {code:?} is missing from the fixture"
        );
    }
}
