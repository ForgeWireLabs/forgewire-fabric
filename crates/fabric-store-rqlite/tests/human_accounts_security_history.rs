//! 114C.5 acceptance: "Add bounded login/session security history." Every
//! test runs against an ephemeral node (114C evidence plan, Rule 2).

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::domain::ClientKind;
use fabric_accounts::repository::AccountOrchestration;
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

fn now() -> String {
    fabric_store_rqlite::utc_now()
}

const REALM: &str = "realm-test";
const STRONG_PASSWORD: &str = "a genuinely strong security-history test passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_accounts_security_history test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

async fn seed_account(store: &RqliteStore) -> (String, String) {
    let username = unique_id("history-target");
    let account = store
        .bootstrap_first_administrator(REALM, &username, "History Target", STRONG_PASSWORD, &now())
        .await
        .expect("seed account");
    (account.account_id, username)
}

/// Insert a login-attempt row directly, bypassing the real throttle-guarded
/// login path: real logins stop recording attempts once throttled (5
/// failures locks the account), which would make it fragile to build a
/// specific, larger attempt history through the live path. This exercises
/// `account_security_history`'s real query against real rows either way.
async fn seed_login_attempt(
    node: &support::EphemeralRqlite,
    username_normalized: &str,
    successful: bool,
    attempted_at: &str,
) {
    node.raw_execute(&format!(
        "INSERT INTO human_login_attempts (dimension_kind,dimension_key,attempted_at,successful) VALUES ('username','{username_normalized}','{attempted_at}',{})",
        i64::from(successful)
    ))
    .await
    .expect("seed login attempt");
}

#[tokio::test]
async fn security_history_returns_recent_login_attempts_and_a_live_session() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_id, username) = seed_account(&store).await;

    seed_login_attempt(&node, &username, false, "2026-01-01 00:00:00").await;
    seed_login_attempt(&node, &username, true, "2026-01-01 00:01:00").await;

    let login = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Cli,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");

    let (attempts, sessions) = store
        .account_security_history(&account_id, 50)
        .await
        .expect("security history");
    assert_eq!(
        attempts.len(),
        3,
        "the two seeded attempts plus the real login above"
    );
    assert!(attempts.iter().any(|a| !a.successful));
    assert!(attempts.iter().any(|a| a.successful));
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, login.session.session_id);
}

#[tokio::test]
async fn security_history_login_attempts_are_bounded_by_limit_newest_first() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_id, username) = seed_account(&store).await;

    for i in 0..5 {
        seed_login_attempt(
            &node,
            &username,
            i % 2 == 0,
            &format!("2026-01-01 00:0{i}:00"),
        )
        .await;
    }

    let (attempts, _sessions) = store
        .account_security_history(&account_id, 2)
        .await
        .expect("security history");
    assert_eq!(
        attempts.len(),
        2,
        "must be bounded to the requested limit, not all 5 rows"
    );
    assert_eq!(
        attempts[0].attempted_at, "2026-01-01 00:04:00",
        "newest attempt first"
    );
    assert_eq!(attempts[1].attempted_at, "2026-01-01 00:03:00");
}

#[tokio::test]
async fn security_history_never_leaks_another_accounts_login_attempts() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_a, username_a) = seed_account(&store).await;
    let username_b = unique_id("history-target-b");
    store
        .create_account_with_password(
            REALM,
            &username_b,
            "History Target B",
            STRONG_PASSWORD,
            fabric_accounts::domain::Role::Observer,
            &account_a,
            &now(),
        )
        .await
        .expect("seed second account");

    seed_login_attempt(&node, &username_a, false, "2026-01-01 00:00:00").await;
    seed_login_attempt(&node, &username_b, false, "2026-01-01 00:01:00").await;
    seed_login_attempt(&node, &username_b, false, "2026-01-01 00:02:00").await;

    let (attempts_a, _) = store
        .account_security_history(&account_a, 50)
        .await
        .expect("security history for a");
    assert_eq!(
        attempts_a.len(),
        1,
        "account A must only see its own login attempts, never account B's"
    );
}

#[tokio::test]
async fn security_history_limit_is_clamped_to_at_least_one() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let (account_id, username) = seed_account(&store).await;
    seed_login_attempt(&node, &username, true, "2026-01-01 00:00:00").await;

    let (attempts, _) = store
        .account_security_history(&account_id, 0)
        .await
        .expect("security history with limit=0");
    assert_eq!(
        attempts.len(),
        1,
        "a non-positive limit must clamp to at least 1, not return zero rows or error"
    );
}

#[tokio::test]
async fn security_history_includes_revoked_sessions_not_only_live_ones() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let (account_id, username) = seed_account(&store).await;

    let login = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Cli,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");
    use fabric_accounts::repository::SessionRepository;
    SessionRepository::revoke(&store, &login.session.session_id, "test_revoke", &now())
        .await
        .expect("revoke");

    let (_attempts, sessions) = store
        .account_security_history(&account_id, 50)
        .await
        .expect("security history");
    assert_eq!(
        sessions.len(),
        1,
        "a revoked session must still appear in history, not disappear"
    );
    assert!(sessions[0].revoked_at.is_some());
}
