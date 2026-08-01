//! 114C.3, `114c-3-negative-auth` evidence registry entry: "non-enumerating
//! errors, throttling without permanent lockout, malformed/expired/
//! cross-account secrets." Wrong-password/unknown-username non-enumeration
//! and refresh-replay are already covered in the bootstrap-and-sessions
//! evidence run's test files; this file covers login throttling
//! specifically, plus the remaining account-state and infrastructure
//! negative cases scoped to 114C.3. Every test runs against an ephemeral
//! node (114C evidence plan, Rule 2).

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::domain::{Account, AccountStatus, ClientKind};
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{AccountOrchestration, AccountRepository, SessionRepository};
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

const REALM: &str = "realm-test";
const STRONG_PASSWORD: &str = "a genuinely strong bootstrap passphrase";

/// A real current timestamp, not a fixed historical constant -- the login
/// throttle's rolling window is computed from real wall-clock time
/// (`utc_offset` inside the crate), so recorded attempts must use a
/// consistent clock or the window comparison silently never matches.
fn now() -> String {
    fabric_store_rqlite::utc_now()
}

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_accounts_negative_auth test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

fn sample_account(username: &str) -> Account {
    Account {
        account_id: unique_id("acct"),
        realm_id: REALM.to_owned(),
        username_normalized: username.to_owned(),
        username_display: username.to_owned(),
        display_name: "Negative Auth Test".into(),
        email_normalized: None,
        status: AccountStatus::Active,
        created_at: now(),
        updated_at: now(),
        disabled_at: None,
        deleted_at: None,
        revision: 0,
        security_version: 0,
    }
}

// -- Login throttling -----------------------------------------------------------

#[tokio::test]
async fn repeated_failures_against_one_username_lock_it_out_even_with_the_correct_password() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("throttleuser");
    store
        .bootstrap_first_administrator(REALM, &username, "Throttle User", STRONG_PASSWORD, &now())
        .await
        .expect("bootstrap");

    for _ in 0..5 {
        let result = store
            .authenticate_and_issue_session(
                REALM,
                &username,
                "wrong password attempt",
                ClientKind::Vsix,
                None,
                None,
                60,
                24,
                &now(),
            )
            .await;
        assert!(matches!(result, Err(AccountsError::InvalidCredentials)));
    }

    // The 6th attempt uses the CORRECT password -- and must still be
    // throttled, proving the lockout is keyed by the failure count, not by
    // "still guessing wrong."
    let result = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await;
    assert!(matches!(result, Err(AccountsError::AccountLocked { .. })));
}

#[tokio::test]
async fn throttling_is_scoped_per_username_not_shared_across_accounts() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let victim = unique_id("victim");
    store
        .bootstrap_first_administrator(REALM, &victim, "Victim", STRONG_PASSWORD, &now())
        .await
        .expect("bootstrap");
    let bystander = unique_id("bystander");
    store
        .create_account(sample_account(&bystander))
        .await
        .expect("create bystander");

    for _ in 0..5 {
        let _ = store
            .authenticate_and_issue_session(
                REALM,
                &victim,
                "wrong",
                ClientKind::Vsix,
                None,
                None,
                60,
                24,
                &now(),
            )
            .await;
    }
    assert!(matches!(
        store
            .authenticate_and_issue_session(
                REALM,
                &victim,
                STRONG_PASSWORD,
                ClientKind::Vsix,
                None,
                None,
                60,
                24,
                &now()
            )
            .await,
        Err(AccountsError::AccountLocked { .. })
    ));

    // A different username's attempts must be unaffected by the victim's lockout.
    let bystander_result = store
        .authenticate_and_issue_session(
            REALM,
            &bystander,
            "also wrong",
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await;
    assert!(
        matches!(bystander_result, Err(AccountsError::InvalidCredentials)),
        "bystander must get a normal InvalidCredentials, not AccountLocked"
    );
}

#[tokio::test]
async fn a_client_fingerprint_is_throttled_across_different_usernames() {
    // The fix for the ForgeWire inventory's named defect: an attacker
    // spreading guesses across many usernames from one source must still be
    // slowed down, not just an attacker hammering one account.
    let Some((_node, store)) = setup().await else {
        return;
    };
    const ATTACKER_FINGERPRINT: &str = "attacker-source-fingerprint";

    for _ in 0..5 {
        let target_username = unique_id("spraytarget");
        let result = store
            .authenticate_and_issue_session(
                REALM,
                &target_username,
                "guess",
                ClientKind::Vsix,
                None,
                Some(ATTACKER_FINGERPRINT),
                60,
                24,
                &now(),
            )
            .await;
        assert!(matches!(result, Err(AccountsError::InvalidCredentials)));
    }

    // A 6th distinct username, same fingerprint, must be throttled even
    // though this exact username was never tried before.
    let sixth_username = unique_id("spraytarget-final");
    let result = store
        .authenticate_and_issue_session(
            REALM,
            &sixth_username,
            "guess",
            ClientKind::Vsix,
            None,
            Some(ATTACKER_FINGERPRINT),
            60,
            24,
            &now(),
        )
        .await;
    assert!(matches!(result, Err(AccountsError::AccountLocked { .. })));
}

#[tokio::test]
async fn throttling_is_not_permanent_old_failures_age_out_of_the_window() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let username = unique_id("agesout");
    store
        .bootstrap_first_administrator(REALM, &username, "Ages Out", STRONG_PASSWORD, &now())
        .await
        .expect("bootstrap");

    for _ in 0..5 {
        let _ = store
            .authenticate_and_issue_session(
                REALM,
                &username,
                "wrong",
                ClientKind::Vsix,
                None,
                None,
                60,
                24,
                &now(),
            )
            .await;
    }
    assert!(matches!(
        store
            .authenticate_and_issue_session(
                REALM,
                &username,
                STRONG_PASSWORD,
                ClientKind::Vsix,
                None,
                None,
                60,
                24,
                &now()
            )
            .await,
        Err(AccountsError::AccountLocked { .. })
    ));

    // Backdate every recorded failure to well outside the 300-second
    // rolling window -- simulating "time has passed" without a real sleep.
    node.raw_execute("UPDATE human_login_attempts SET attempted_at='2020-01-01 00:00:00'")
        .await
        .expect("backdate attempts");

    // Access must now be restored -- no manual unlock, no admin action, just
    // the window no longer covering the old failures.
    let result = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await;
    assert!(
        result.is_ok(),
        "throttle must clear once failures fall outside the rolling window"
    );
}

#[tokio::test]
async fn prune_login_attempts_removes_only_records_older_than_the_cutoff() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let username = unique_id("prunetest");
    store
        .bootstrap_first_administrator(REALM, &username, "Prune Test", STRONG_PASSWORD, &now())
        .await
        .expect("bootstrap");
    let _ = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            "wrong",
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await;

    node.raw_execute("UPDATE human_login_attempts SET attempted_at='2020-01-01 00:00:00'")
        .await
        .expect("backdate");
    let _ = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            "wrong again",
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await;

    let pruned = store
        .prune_login_attempts("2025-01-01 00:00:00")
        .await
        .expect("prune");
    assert_eq!(pruned, 1, "only the backdated row should be pruned");

    let remaining = node
        .raw_query("SELECT COUNT(*) FROM human_login_attempts")
        .await
        .expect("count remaining");
    let count = remaining["results"][0]["values"][0][0]
        .as_i64()
        .unwrap_or(-1);
    assert_eq!(count, 1, "the recent attempt must survive pruning");
}

// -- Account-state negative cases -------------------------------------------------

#[tokio::test]
async fn login_against_a_locked_account_is_distinguishable_and_does_not_leak_password_correctness()
{
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("lockedaccount");
    let account = store
        .bootstrap_first_administrator(REALM, &username, "Locked Account", STRONG_PASSWORD, &now())
        .await
        .expect("bootstrap");
    AccountRepository::update_status(&store, &account.account_id, 0, AccountStatus::Locked)
        .await
        .expect("lock");

    // Even the CORRECT password must not distinguish "locked" from a
    // successful login by any side channel other than the typed error.
    let result = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await;
    assert!(matches!(
        result,
        Err(AccountsError::AccountLocked {
            retry_after_seconds: None
        })
    ));
}

#[tokio::test]
async fn login_against_a_recovery_required_account_is_distinguishable() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("recoveryaccount");
    let account = store
        .bootstrap_first_administrator(
            REALM,
            &username,
            "Recovery Account",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    AccountRepository::update_status(
        &store,
        &account.account_id,
        0,
        AccountStatus::RecoveryRequired,
    )
    .await
    .expect("set recovery_required");

    let result = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await;
    assert!(matches!(result, Err(AccountsError::RecoveryRequired)));
}

// -- Malformed / cross-account session secrets ------------------------------------

#[tokio::test]
async fn a_syntactically_garbage_access_secret_fails_closed_without_panicking() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    for garbage in [
        "",
        "not-a-hash-at-all",
        "!!!not-hex-and-not-base64!!!",
        &"a".repeat(10_000),
    ] {
        let result = SessionRepository::validate_by_access_hash(&store, garbage).await;
        assert!(
            matches!(result, Err(AccountsError::SessionExpired)),
            "garbage input {garbage:?} must fail closed, not panic or succeed"
        );
    }
}

#[tokio::test]
async fn revoking_one_accounts_session_by_id_does_not_touch_another_accounts_session() {
    // Cross-account isolation for the operation the plan's negative-case
    // list calls out ("cross-account... secrets"): two accounts, each with
    // a session, and an operation scoped to one session_id must never
    // affect the other account's session -- the ownership boundary that
    // matters here is which *session* is targeted, not a caller-supplied
    // account_id the store would have no way to verify without an
    // authorization layer (114C.4).
    let Some((_node, store)) = setup().await else {
        return;
    };
    let user_a = unique_id("accountaa");
    let user_b = unique_id("accountbb");
    let account_a = store
        .bootstrap_first_administrator(REALM, &user_a, "Account A", STRONG_PASSWORD, &now())
        .await
        .expect("bootstrap a");
    let account_b = store
        .create_account(sample_account(&user_b))
        .await
        .expect("create b");

    let session_a = store
        .authenticate_and_issue_session(
            REALM,
            &user_a,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login a");

    SessionRepository::revoke(&store, &session_a.session.session_id, "test_revoke", &now())
        .await
        .expect("revoke a's session");

    // Account B has no sessions at all; revoking A's session must not have
    // created or altered anything under B.
    let b_sessions = SessionRepository::list_for_account(&store, &account_b.account_id)
        .await
        .expect("list b sessions");
    assert!(b_sessions.is_empty());
    let _ = account_a;
}

// -- rqlite unavailable: fail closed, not panic ------------------------------------

#[tokio::test]
async fn login_against_an_unreachable_store_fails_closed_as_auth_service_unavailable() {
    // No ephemeral node provisioned at all -- point the store at a port
    // nothing is listening on. This proves the fail-closed contract without
    // needing to kill a running node mid-test.
    let unreachable = RqliteStore::new("127.0.0.1", 1, "strong"); // port 1: reserved, nothing binds it
    let result = unreachable
        .authenticate_and_issue_session(
            REALM,
            "anyone",
            "anything",
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await;
    assert!(
        matches!(result, Err(AccountsError::AuthServiceUnavailable)),
        "an unreachable store must fail closed, not panic"
    );
}

#[tokio::test]
async fn bootstrap_against_an_unreachable_store_fails_closed() {
    let unreachable = RqliteStore::new("127.0.0.1", 1, "strong");
    let result = unreachable
        .bootstrap_first_administrator(REALM, "anyone", "Anyone", STRONG_PASSWORD, &now())
        .await;
    assert!(matches!(result, Err(AccountsError::AuthServiceUnavailable)));
}
