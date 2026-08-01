//! `authenticate_with_passkey_and_issue_session` + the sign-count
//! replay-defense CAS (114C.6 Slice 3). Every test runs against an ephemeral
//! node (114C evidence plan, Rule 2).
//!
//! These tests exercise the store method directly with a pre-seeded webauthn
//! credential row -- they do NOT run a real WebAuthn ceremony (that's the
//! hub-layer route's job, and a real signature requires hardware/a browser;
//! see `crates/fabric-hub/tests/human_passkey_registration.rs`'s header for
//! why the ceremony-success path is manual). What they DO cover is the part
//! this method actually owns: the sign-count regression guard, the AAL2/
//! step_up_at session issuance, and account-status gating.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::domain::{AssuranceLevel, ClientKind};
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{AccountOrchestration, SessionRepository};
use fabric_store_rqlite::RqliteStore;
use support::provision_or_skip;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_id(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{nanos}-{n}")
}

const NOW: &str = "2026-07-17 12:00:00";
const REALM: &str = "realm-test";
const STRONG_PASSWORD: &str = "a genuinely strong passkey-login test passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_passkey_login test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

/// Bootstrap an account, then seed a webauthn credential row for it directly
/// (bypassing the full ceremony this test does not exercise), with an
/// initial stored sign count. Returns `(account_id, credential_id)`.
async fn seed_account_with_passkey(
    node: &support::EphemeralRqlite,
    store: &RqliteStore,
    initial_sign_count: Option<i64>,
) -> (String, String) {
    let username = unique_id("passkey-login");
    let account = store
        .bootstrap_first_administrator(REALM, &username, "Passkey Login User", STRONG_PASSWORD, NOW)
        .await
        .expect("bootstrap");
    let credential_id = unique_id("cred-webauthn");
    let count_sql = match initial_sign_count {
        Some(c) => c.to_string(),
        None => "NULL".to_owned(),
    };
    node.raw_execute(&format!(
        "INSERT INTO human_credentials (credential_id,account_id,kind,version,webauthn_public_key,webauthn_sign_count,created_at,revision) VALUES ('{}','{}','webauthn',1,'{{}}',{},'{}',0)",
        credential_id, account.account_id, count_sql, NOW
    ))
    .await
    .expect("seed webauthn credential");
    (account.account_id, credential_id)
}

#[allow(clippy::too_many_arguments)]
async fn login(
    store: &RqliteStore,
    account_id: &str,
    credential_id: &str,
    new_sign_count: i64,
) -> Result<fabric_accounts::repository::LoginOutcome, AccountsError> {
    login_with_backup_flags(
        store,
        account_id,
        credential_id,
        new_sign_count,
        false,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn login_with_backup_flags(
    store: &RqliteStore,
    account_id: &str,
    credential_id: &str,
    new_sign_count: i64,
    backup_eligible: bool,
    backup_state: bool,
) -> Result<fabric_accounts::repository::LoginOutcome, AccountsError> {
    store
        .authenticate_with_passkey_and_issue_session(
            REALM,
            &account_id.to_owned(),
            &credential_id.to_owned(),
            new_sign_count,
            "{}",
            backup_eligible,
            backup_state,
            ClientKind::Desktop,
            Some("test client"),
            60,
            24,
            NOW,
        )
        .await
}

#[tokio::test]
async fn a_passkey_login_issues_an_aal2_session_with_step_up_set() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_id, credential_id) = seed_account_with_passkey(&node, &store, Some(5)).await;

    let outcome = login(&store, &account_id, &credential_id, 6)
        .await
        .expect("passkey login succeeds when the counter advances");
    assert_eq!(outcome.session.assurance_level, AssuranceLevel::Aal2);
    assert_eq!(outcome.session.step_up_at.as_deref(), Some(NOW));
    assert!(!outcome.access_secret.expose_secret().is_empty());
    assert!(!outcome.refresh_secret.expose_secret().is_empty());
}

#[tokio::test]
async fn a_login_persists_the_backup_eligible_and_backup_state_flags() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_id, credential_id) = seed_account_with_passkey(&node, &store, Some(5)).await;

    login_with_backup_flags(&store, &account_id, &credential_id, 6, true, true)
        .await
        .expect("passkey login succeeds when the counter advances");

    let dump = node
        .raw_query(&format!(
            "SELECT webauthn_backup_eligible, webauthn_backup_state FROM human_credentials WHERE credential_id='{credential_id}'"
        ))
        .await
        .expect("raw dump");
    let values = dump["results"][0]["values"][0]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        values[0].as_i64(),
        Some(1),
        "backup_eligible must be persisted as 1"
    );
    assert_eq!(
        values[1].as_i64(),
        Some(1),
        "backup_state must be persisted as 1"
    );
}

#[tokio::test]
async fn a_strictly_advancing_counter_is_accepted() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_id, credential_id) = seed_account_with_passkey(&node, &store, Some(10)).await;
    login(&store, &account_id, &credential_id, 11)
        .await
        .expect("11 > 10 must be accepted");
}

/// `LoginOutcome` deliberately has no `Debug` impl (it holds
/// `SecretString`s), so `.expect_err()` cannot be used on these results --
/// assert the error variant directly instead.
fn assert_replay(result: Result<fabric_accounts::repository::LoginOutcome, AccountsError>) {
    match result {
        Ok(_) => panic!("expected CredentialReplaySuspected, got a successful login"),
        Err(error) => assert_eq!(error, AccountsError::CredentialReplaySuspected),
    }
}

#[tokio::test]
async fn an_equal_counter_is_rejected_as_replay() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_id, credential_id) = seed_account_with_passkey(&node, &store, Some(10)).await;
    assert_replay(login(&store, &account_id, &credential_id, 10).await);
}

#[tokio::test]
async fn a_regressing_counter_is_rejected_as_replay() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_id, credential_id) = seed_account_with_passkey(&node, &store, Some(10)).await;
    assert_replay(login(&store, &account_id, &credential_id, 9).await);
}

#[tokio::test]
async fn a_zero_counter_authenticator_is_never_flagged_as_replay() {
    let Some((node, store)) = setup().await else {
        return;
    };
    // Authenticator that never implements a counter: stored count starts at
    // 0, every assertion also reports 0. Without the `?=0` carve-out this
    // would be misclassified as a replay on every login after the first.
    let (account_id, credential_id) = seed_account_with_passkey(&node, &store, Some(0)).await;
    login(&store, &account_id, &credential_id, 0)
        .await
        .expect("first zero-counter login");
    login(&store, &account_id, &credential_id, 0)
        .await
        .expect("second zero-counter login must also succeed, not be flagged as replay");
    login(&store, &account_id, &credential_id, 0)
        .await
        .expect("third zero-counter login must also succeed");
}

#[tokio::test]
async fn a_never_recorded_counter_accepts_the_first_assertion() {
    let Some((node, store)) = setup().await else {
        return;
    };
    // webauthn_sign_count IS NULL (never recorded) -- the first real
    // assertion's counter must be accepted and stored.
    let (account_id, credential_id) = seed_account_with_passkey(&node, &store, None).await;
    login(&store, &account_id, &credential_id, 1)
        .await
        .expect("first assertion against a never-counted credential is accepted");
    // And now that 1 is stored, a replay at 1 is rejected.
    assert_replay(login(&store, &account_id, &credential_id, 1).await);
}

#[tokio::test]
async fn a_rejected_replay_does_not_advance_the_stored_counter_or_issue_a_session() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_id, credential_id) = seed_account_with_passkey(&node, &store, Some(10)).await;

    assert_replay(login(&store, &account_id, &credential_id, 10).await);
    // No session issued.
    let sessions = SessionRepository::list_for_account(&store, &account_id.to_owned())
        .await
        .expect("list sessions");
    assert!(
        sessions.is_empty(),
        "a rejected replay must not issue a session"
    );
    // And a subsequent legitimate advance to 11 still works -- the rejected
    // attempt left the stored counter at 10, it did not corrupt it.
    login(&store, &account_id, &credential_id, 11)
        .await
        .expect("a legitimate later advance still works after a rejected replay");
}

#[tokio::test]
async fn concurrent_logins_at_the_same_counter_let_at_most_one_win() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_id, credential_id) = seed_account_with_passkey(&node, &store, Some(10)).await;

    // Two assertions both claiming counter 11 arrive together (a cloned
    // authenticator, or a replayed capture). At most one may succeed.
    let (a, b) = tokio::join!(
        login(&store, &account_id, &credential_id, 11),
        login(&store, &account_id, &credential_id, 11),
    );
    let successes = [&a, &b].iter().filter(|r| r.is_ok()).count();
    assert!(
        successes <= 1,
        "at most one of two concurrent same-counter logins may succeed, got {successes}"
    );
}
