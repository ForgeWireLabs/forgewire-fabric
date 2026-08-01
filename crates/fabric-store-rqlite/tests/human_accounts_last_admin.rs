//! 114C.5 acceptance: "Last enabled administrator cannot be removed
//! accidentally." Every test runs against an ephemeral node (114C evidence
//! plan, Rule 2).

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::domain::{Account, AccountStatus, Role};
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{AccountOrchestration, AccountRepository, MembershipRepository};
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

const STRONG_PASSWORD: &str = "a genuinely strong last-admin test passphrase";
const REALM: &str = "realm-test";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_accounts_last_admin test").await?;
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
        display_name: "Last Admin Test".into(),
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

#[tokio::test]
async fn disabling_the_sole_admin_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .bootstrap_first_administrator(
            REALM,
            &unique_id("sole"),
            "Sole Admin",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    assert_eq!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("count"),
        1
    );

    let result = store
        .disable_account_protecting_last_admin(&account.account_id, 0, &now())
        .await;
    assert!(matches!(
        result,
        Err(AccountsError::LastAdministratorViolation)
    ));
    assert_eq!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("count after"),
        1,
        "the account must remain enabled"
    );
}

#[tokio::test]
async fn disabling_an_admin_when_another_admin_exists_succeeds() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let first = store
        .bootstrap_first_administrator(
            REALM,
            &unique_id("first"),
            "First Admin",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    let second_account = store
        .create_account(sample_account(&unique_id("second")))
        .await
        .expect("create second account");
    let second_membership = fabric_accounts::domain::Membership::for_human(
        unique_id("mem"),
        second_account.account_id.clone(),
        REALM.to_owned(),
        Role::Admin,
        Some(first.account_id.clone()),
        now(),
    )
    .expect("admin is human-assignable");
    store
        .grant(second_membership)
        .await
        .expect("grant second admin");
    assert_eq!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("count"),
        2
    );

    let result = store
        .disable_account_protecting_last_admin(&first.account_id, 0, &now())
        .await;
    assert!(result.is_ok());
    assert_eq!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("count after"),
        1
    );
}

#[tokio::test]
async fn disabling_a_non_admin_account_is_never_blocked_by_the_guard() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    store
        .bootstrap_first_administrator(REALM, &unique_id("admin"), "Admin", STRONG_PASSWORD, &now())
        .await
        .expect("bootstrap");
    let observer_account = store
        .create_account(sample_account(&unique_id("observer")))
        .await
        .expect("create observer account");

    let result = store
        .disable_account_protecting_last_admin(&observer_account.account_id, 0, &now())
        .await;
    assert!(result.is_ok(), "disabling an account with no admin membership must never be blocked by the last-admin guard");
}

#[tokio::test]
async fn demoting_the_sole_admins_membership_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .bootstrap_first_administrator(
            REALM,
            &unique_id("solemember"),
            "Sole Admin Membership",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    let memberships = MembershipRepository::list_for_account(&store, &account.account_id)
        .await
        .expect("memberships");
    let admin_membership_id = memberships
        .iter()
        .find(|m| m.role == Role::Admin)
        .unwrap()
        .membership_id
        .clone();

    let result = store
        .revoke_membership_protecting_last_admin(&admin_membership_id, &now())
        .await;
    assert!(matches!(
        result,
        Err(AccountsError::LastAdministratorViolation)
    ));
    assert_eq!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("count"),
        1,
        "the membership must remain active"
    );
}

#[tokio::test]
async fn demoting_an_admin_when_another_admin_exists_succeeds() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let first = store
        .bootstrap_first_administrator(
            REALM,
            &unique_id("firstdemote"),
            "First Admin",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    let second_account = store
        .create_account(sample_account(&unique_id("seconddemote")))
        .await
        .expect("create second account");
    let second_membership = fabric_accounts::domain::Membership::for_human(
        unique_id("mem"),
        second_account.account_id.clone(),
        REALM.to_owned(),
        Role::Admin,
        Some(first.account_id.clone()),
        now(),
    )
    .expect("admin is human-assignable");
    store
        .grant(second_membership)
        .await
        .expect("grant second admin");

    let memberships = MembershipRepository::list_for_account(&store, &first.account_id)
        .await
        .expect("memberships");
    let first_admin_membership_id = memberships
        .iter()
        .find(|m| m.role == Role::Admin)
        .unwrap()
        .membership_id
        .clone();

    let result = store
        .revoke_membership_protecting_last_admin(&first_admin_membership_id, &now())
        .await;
    assert!(result.is_ok());
    assert_eq!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("count after"),
        1
    );
}

#[tokio::test]
async fn revoking_a_non_admin_membership_is_never_blocked_by_the_guard() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    store
        .bootstrap_first_administrator(
            REALM,
            &unique_id("adminx"),
            "Admin X",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    let account = store
        .create_account(sample_account(&unique_id("dispatcheronly")))
        .await
        .expect("create account");
    let membership = fabric_accounts::domain::Membership::for_human(
        unique_id("mem"),
        account.account_id.clone(),
        REALM.to_owned(),
        Role::Dispatcher,
        None,
        now(),
    )
    .expect("dispatcher is human-assignable");
    let membership_id = membership.membership_id.clone();
    store.grant(membership).await.expect("grant dispatcher");

    let result = store
        .revoke_membership_protecting_last_admin(&membership_id, &now())
        .await;
    assert!(
        result.is_ok(),
        "revoking a non-admin membership must never be blocked by the last-admin guard"
    );
}

#[tokio::test]
async fn concurrent_attempts_to_disable_two_of_two_admins_leave_at_least_one_enabled() {
    // The property this guard exists for: two concurrent requests, each
    // independently believing "at least one other admin exists" against a
    // stale read, must not both succeed and jointly leave zero. With
    // exactly two admins and both racing to disable each other, at most one
    // may win.
    let Some((_node, store)) = setup().await else {
        return;
    };
    let first = store
        .bootstrap_first_administrator(
            REALM,
            &unique_id("race1"),
            "Racer One",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    let second_account = store
        .create_account(sample_account(&unique_id("race2")))
        .await
        .expect("create second account");
    let second_membership = fabric_accounts::domain::Membership::for_human(
        unique_id("mem"),
        second_account.account_id.clone(),
        REALM.to_owned(),
        Role::Admin,
        Some(first.account_id.clone()),
        now(),
    )
    .expect("admin is human-assignable");
    store
        .grant(second_membership)
        .await
        .expect("grant second admin");
    assert_eq!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("count"),
        2
    );

    let store = std::sync::Arc::new(store);
    let first_id = first.account_id.clone();
    let second_id = second_account.account_id.clone();
    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        async move {
            store_a
                .disable_account_protecting_last_admin(
                    &first_id,
                    0,
                    &fabric_store_rqlite::utc_now(),
                )
                .await
        },
        async move {
            store_b
                .disable_account_protecting_last_admin(
                    &second_id,
                    0,
                    &fabric_store_rqlite::utc_now(),
                )
                .await
        },
    );

    let successes = [&result_a, &result_b].iter().filter(|r| r.is_ok()).count();
    assert!(
        successes <= 1,
        "at most one of two concurrent last-admin-adjacent disables may succeed"
    );
    assert!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("final count")
            >= 1,
        "the realm must never end up with zero enabled admins, regardless of which request won"
    );
}
