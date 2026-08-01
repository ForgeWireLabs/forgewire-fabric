//! 114D D.2 acceptance: `complete_genesis` atomically establishes the realm's
//! founding identity AND mints the Master account/credential/membership/
//! recovery material in one transaction -- the genesis seal. Every test here
//! runs against an ephemeral node (114C evidence plan, Rule 2), matching
//! Rule 6's requirement (114D evidence plan) that genesis tests provision a
//! fresh `bootstrap_open ∧ ¬realm_established` instance rather than reuse one.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::domain::AccountStatus;
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{
    AccountOrchestration, AccountRepository, MembershipRepository, RealmRepository,
};
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

const NOW: &str = "2026-07-27 12:00:00";
const STRONG_PASSWORD: &str = "a genuinely strong genesis passphrase";
// Matches `fabric_hub::auth::DEFAULT_REALM_ID` -- duplicated as a literal
// here rather than imported, since fabric-store-rqlite must not depend on
// fabric-hub (wrong direction: hub depends on store, not vice versa). This
// is the value every pre-existing 114C route hardcodes for account-scoping;
// see `complete_genesis`'s own trait doc comment for why it must NOT be the
// same value as the realm identity's own freshly-generated id.
const ACCOUNT_REALM_ID: &str = "default";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("genesis test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

async fn seal(store: &RqliteStore, username: &str) -> fabric_accounts::repository::GenesisOutcome {
    store
        .complete_genesis(
            "Test Realm",
            "localhost",
            &["http://localhost:8765/".to_string()],
            "ed25519",
            Some("DESKTOP-228U8GL"),
            ACCOUNT_REALM_ID,
            username,
            "Master Operator",
            STRONG_PASSWORD,
            5,
            NOW,
        )
        .await
        .expect("complete_genesis")
}

#[tokio::test]
async fn genesis_establishes_the_realm_and_an_active_admin_master_with_recovery_codes() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("master");
    let outcome = seal(&store, &username).await;

    assert_eq!(outcome.realm.name, "Test Realm");
    assert_eq!(outcome.realm.rp_id, "localhost");
    assert_eq!(outcome.realm.origins, vec!["http://localhost:8765/"]);
    assert_eq!(outcome.account.status, AccountStatus::Active);
    assert_eq!(outcome.account.username_normalized, username.to_lowercase());
    assert_eq!(outcome.recovery_codes.len(), 5);
    // Recovery codes are distinct plaintext secrets, not five copies of one.
    let unique_plaintexts: std::collections::HashSet<_> = outcome
        .recovery_codes
        .iter()
        .map(fabric_accounts::secret::SecretString::expose_secret)
        .collect();
    assert_eq!(unique_plaintexts.len(), 5);

    let memberships = MembershipRepository::list_for_account(&store, &outcome.account.account_id)
        .await
        .expect("memberships");
    assert!(
        memberships
            .iter()
            .any(|m| m.role == fabric_accounts::domain::Role::Admin && m.revoked_at.is_none()),
        "the minted Master must hold an active admin membership"
    );

    // Independent reads agree with what establish returned.
    let realm = RealmRepository::get_realm_identity(&store)
        .await
        .expect("get_realm_identity")
        .expect("realm should exist");
    assert_eq!(realm.realm_id, outcome.realm.realm_id);
    assert!(!AccountOrchestration::bootstrap_status(&store)
        .await
        .expect("bootstrap_status"));
}

#[tokio::test]
async fn the_minted_master_can_log_in_with_the_password_immediately() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("master");
    let outcome = seal(&store, &username).await;

    // Deliberately ACCOUNT_REALM_ID here, not outcome.realm.realm_id: this is
    // the realm every pre-existing 114C route (including the real
    // /auth/login this method backs) actually looks under. Asserting against
    // the realm_identity's own id instead would pass even if the two
    // concepts were wrongly conflated again -- exactly the live bug this
    // test now guards against.
    assert_eq!(outcome.account.realm_id, ACCOUNT_REALM_ID);
    let login = AccountOrchestration::authenticate_and_issue_session(
        &store,
        ACCOUNT_REALM_ID,
        &username,
        STRONG_PASSWORD,
        fabric_accounts::domain::ClientKind::Cli,
        None,
        None,
        60,
        24,
        NOW,
    )
    .await
    .expect("login should succeed with the password just set at genesis");
    assert_eq!(login.session.account_id, outcome.account.account_id);
}

#[tokio::test]
async fn genesis_recovery_codes_are_durable_and_redeemable_via_the_existing_recovery_flow() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("master");
    let outcome = seal(&store, &username).await;
    let code = outcome.recovery_codes[0].expose_secret();

    // Place the account into recovery (the existing admin-route precondition
    // for redeeming a code) -- revision 0, since genesis mints a fresh
    // account.
    AccountRepository::update_status(
        &store,
        &outcome.account.account_id,
        0,
        AccountStatus::RecoveryRequired,
    )
    .await
    .expect("update_status to recovery_required");

    let recovered = AccountOrchestration::complete_recovery_with_code(
        &store,
        &outcome.account.account_id,
        code,
        "a brand new post-recovery passphrase",
        NOW,
    )
    .await
    .expect("a genesis recovery code (NULL expires_at) must redeem successfully");
    assert_eq!(recovered.status, AccountStatus::Active);
}

#[tokio::test]
async fn genesis_rejects_a_weak_password_before_writing_anything() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let result = store
        .complete_genesis(
            "Test Realm",
            "localhost",
            &["http://localhost:8765/".to_string()],
            "ed25519",
            None,
            ACCOUNT_REALM_ID,
            &unique_id("master"),
            "Master Operator",
            "short",
            5,
            NOW,
        )
        .await;
    assert!(matches!(
        result,
        Err(AccountsError::AccountPolicyViolation { .. })
    ));
    assert!(
        RealmRepository::get_realm_identity(&store)
            .await
            .expect("get_realm_identity")
            .is_none(),
        "a rejected genesis attempt must not establish a realm"
    );
    assert!(
        AccountOrchestration::bootstrap_status(&store)
            .await
            .expect("bootstrap_status"),
        "a rejected genesis attempt must not consume the bootstrap gate"
    );
}

#[tokio::test]
async fn a_second_genesis_attempt_is_rejected_and_leaves_the_first_untouched() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let first_username = unique_id("master");
    let first = seal(&store, &first_username).await;

    let second = store
        .complete_genesis(
            "A Different Realm",
            "localhost",
            &["http://localhost:9999/".to_string()],
            "ed25519",
            None,
            ACCOUNT_REALM_ID,
            &unique_id("intruder"),
            "Intruder",
            STRONG_PASSWORD,
            5,
            NOW,
        )
        .await;
    assert_eq!(second.unwrap_err(), AccountsError::RealmAlreadyEstablished);

    let realm = RealmRepository::get_realm_identity(&store)
        .await
        .expect("get_realm_identity")
        .expect("realm should still exist");
    assert_eq!(realm.realm_id, first.realm.realm_id);
    assert_eq!(realm.name, "Test Realm");

    // ACCOUNT_REALM_ID, not first.realm.realm_id -- accounts are scoped by
    // the account-realm value complete_genesis was called with, a distinct
    // concept from the realm_identity row's own id (see complete_genesis's
    // trait doc comment).
    let accounts = AccountRepository::list_accounts(&store, &ACCOUNT_REALM_ID.to_string(), 100, 0)
        .await
        .expect("list_accounts");
    assert_eq!(
        accounts.len(),
        1,
        "the losing genesis transaction must not have created a second account"
    );
}

#[tokio::test]
async fn concurrent_genesis_lets_exactly_one_caller_win_and_leaves_no_partial_state() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let store = std::sync::Arc::new(store);

    let mut handles = Vec::new();
    for i in 0..8 {
        let store = store.clone();
        let username = unique_id(&format!("racer{i}"));
        handles.push(tokio::spawn(async move {
            store
                .complete_genesis(
                    "Racer Realm",
                    "localhost",
                    &["http://localhost:8765/".to_string()],
                    "ed25519",
                    None,
                    ACCOUNT_REALM_ID,
                    &username,
                    "Racer",
                    STRONG_PASSWORD,
                    5,
                    NOW,
                )
                .await
        }));
    }
    let mut successes = 0;
    let mut realm_conflicts = 0;
    for handle in handles {
        match handle.await.expect("join") {
            Ok(_) => successes += 1,
            Err(AccountsError::RealmAlreadyEstablished) => realm_conflicts += 1,
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
    assert_eq!(successes, 1, "exactly one concurrent genesis should win");
    assert_eq!(realm_conflicts, 7);

    let _realm = RealmRepository::get_realm_identity(&*store)
        .await
        .expect("get_realm_identity")
        .expect("realm should exist");
    let accounts = AccountRepository::list_accounts(&*store, &ACCOUNT_REALM_ID.to_string(), 100, 0)
        .await
        .expect("list_accounts");
    assert_eq!(accounts.len(), 1, "no partial state from a losing racer");
}
