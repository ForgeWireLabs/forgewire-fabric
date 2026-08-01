//! 114C.5 acceptance: "Account deletion preserves audit referential
//! integrity." Two-step lifecycle (`deletion_pending -> deleted_tombstone`)
//! per the plan's "Account lifecycle" section. Every test runs against an
//! ephemeral node (114C evidence plan, Rule 2).

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::domain::{AccountStatus, Role};
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{
    AccountOrchestration, AccountRepository, CredentialRepository, MembershipRepository,
    SessionRepository,
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

fn now() -> String {
    fabric_store_rqlite::utc_now()
}

const REALM: &str = "realm-test";
const STRONG_PASSWORD: &str = "a genuinely strong deletion test passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_accounts_deletion test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

async fn seed_sole_admin(store: &RqliteStore) -> String {
    let username = unique_id("sole-admin");
    let account = store
        .bootstrap_first_administrator(REALM, &username, "Sole Admin", STRONG_PASSWORD, &now())
        .await
        .expect("seed sole admin");
    account.account_id
}

async fn seed_non_admin(store: &RqliteStore, grantor: &str) -> String {
    let username = unique_id("plain-account");
    let account = store
        .create_account_with_password(
            REALM,
            &username,
            "Plain Account",
            STRONG_PASSWORD,
            Role::Observer,
            grantor,
            &now(),
        )
        .await
        .expect("seed non-admin account");
    account.account_id
}

#[tokio::test]
async fn deleting_the_sole_admin_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let admin_id = seed_sole_admin(&store).await;

    let result = store
        .initiate_account_deletion_protecting_last_admin(&admin_id, 0, &now())
        .await;
    assert!(matches!(
        result,
        Err(AccountsError::LastAdministratorViolation)
    ));

    let account = AccountRepository::get_account(&store, &admin_id)
        .await
        .expect("get account");
    assert_eq!(
        account.status,
        AccountStatus::Active,
        "the sole admin must remain active"
    );
}

#[tokio::test]
async fn deleting_an_admin_when_another_admin_exists_succeeds() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let admin_id = seed_sole_admin(&store).await;
    let second_admin_id = seed_non_admin(&store, &admin_id).await;
    store
        .grant_membership(
            &second_admin_id,
            &REALM.to_owned(),
            Role::Admin,
            &admin_id,
            &now(),
        )
        .await
        .expect("grant admin");

    let updated = store
        .initiate_account_deletion_protecting_last_admin(&admin_id, 0, &now())
        .await
        .expect("delete succeeds");
    assert_eq!(updated.status, AccountStatus::DeletionPending);
}

#[tokio::test]
async fn initiating_deletion_revokes_every_session() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let admin_id = seed_sole_admin(&store).await;
    let second_admin_id = seed_non_admin(&store, &admin_id).await;
    store
        .grant_membership(
            &second_admin_id,
            &REALM.to_owned(),
            Role::Admin,
            &admin_id,
            &now(),
        )
        .await
        .expect("grant admin");

    let account = AccountRepository::get_account(&store, &admin_id)
        .await
        .expect("get account");
    let username = account.username_normalized.clone();
    let login = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            fabric_accounts::domain::ClientKind::Cli,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");

    store
        .initiate_account_deletion_protecting_last_admin(&admin_id, account.revision, &now())
        .await
        .expect("delete");

    let access_hash =
        fabric_accounts::secrets::hash_opaque_secret(login.access_secret.expose_secret());
    assert!(
        SessionRepository::validate_by_access_hash(&store, &access_hash)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn deletion_cannot_be_reinitiated_once_pending() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let admin_id = seed_sole_admin(&store).await;
    let second_admin_id = seed_non_admin(&store, &admin_id).await;
    store
        .grant_membership(
            &second_admin_id,
            &REALM.to_owned(),
            Role::Admin,
            &admin_id,
            &now(),
        )
        .await
        .expect("grant admin");

    store
        .initiate_account_deletion_protecting_last_admin(&admin_id, 0, &now())
        .await
        .expect("first initiate");
    let second_attempt = store
        .initiate_account_deletion_protecting_last_admin(&admin_id, 1, &now())
        .await;
    assert!(matches!(
        second_attempt,
        Err(AccountsError::AccountPolicyViolation { reason }) if reason == "already_pending_or_deleted"
    ));
}

#[tokio::test]
async fn completing_deletion_tombstones_the_account_and_frees_the_username() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let admin_id = seed_sole_admin(&store).await;
    let target_id = seed_non_admin(&store, &admin_id).await;
    let target_before = AccountRepository::get_account(&store, &target_id)
        .await
        .expect("get account");
    let original_username = target_before.username_normalized.clone();

    let pending = store
        .initiate_account_deletion_protecting_last_admin(&target_id, target_before.revision, &now())
        .await
        .expect("initiate");
    let tombstoned = store
        .complete_account_deletion(&target_id, pending.revision, &now())
        .await
        .expect("complete");

    assert_eq!(tombstoned.status, AccountStatus::DeletedTombstone);
    assert_ne!(
        tombstoned.username_normalized, original_username,
        "the tombstone must not keep the original username"
    );
    assert!(tombstoned.email_normalized.is_none());
    assert!(tombstoned.deleted_at.is_some());

    // The original username is free for reuse.
    let reused = store
        .create_account_with_password(
            REALM,
            &original_username,
            "Reused Username",
            STRONG_PASSWORD,
            Role::Observer,
            &admin_id,
            &now(),
        )
        .await;
    assert!(
        reused.is_ok(),
        "a tombstoned account's original username must be reusable"
    );
}

#[tokio::test]
async fn completing_deletion_revokes_active_credentials_and_memberships() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let admin_id = seed_sole_admin(&store).await;
    let target_id = seed_non_admin(&store, &admin_id).await;
    let target = AccountRepository::get_account(&store, &target_id)
        .await
        .expect("get account");

    let pending = store
        .initiate_account_deletion_protecting_last_admin(&target_id, target.revision, &now())
        .await
        .expect("initiate");
    store
        .complete_account_deletion(&target_id, pending.revision, &now())
        .await
        .expect("complete");

    let credentials = CredentialRepository::get_active_for_account(&store, &target_id)
        .await
        .expect("get credentials");
    assert!(
        credentials.is_empty(),
        "every credential must be revoked on tombstone"
    );
    let memberships = MembershipRepository::list_for_account(&store, &target_id)
        .await
        .expect("get memberships");
    assert!(
        memberships.iter().all(|m| m.revoked_at.is_some()),
        "every membership must be revoked on tombstone"
    );
}

#[tokio::test]
async fn tombstoning_an_account_that_was_never_marked_pending_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let admin_id = seed_sole_admin(&store).await;
    let target_id = seed_non_admin(&store, &admin_id).await;

    let result = store.complete_account_deletion(&target_id, 0, &now()).await;
    assert!(matches!(
        result,
        Err(AccountsError::AccountPolicyViolation { reason }) if reason == "account_not_deletion_pending"
    ));
}

#[tokio::test]
async fn tombstoning_twice_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let admin_id = seed_sole_admin(&store).await;
    let target_id = seed_non_admin(&store, &admin_id).await;
    let target = AccountRepository::get_account(&store, &target_id)
        .await
        .expect("get account");
    let pending = store
        .initiate_account_deletion_protecting_last_admin(&target_id, target.revision, &now())
        .await
        .expect("initiate");
    let tombstoned = store
        .complete_account_deletion(&target_id, pending.revision, &now())
        .await
        .expect("first tombstone");

    let second_attempt = store
        .complete_account_deletion(&target_id, tombstoned.revision, &now())
        .await;
    assert!(matches!(
        second_attempt,
        Err(AccountsError::AccountPolicyViolation { reason }) if reason == "account_not_deletion_pending"
    ));
}

#[tokio::test]
async fn concurrent_deletion_attempts_against_two_of_two_admins_leave_at_least_one_enabled() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let admin_a = seed_sole_admin(&store).await;
    let admin_b = seed_non_admin(&store, &admin_a).await;
    store
        .grant_membership(&admin_b, &REALM.to_owned(), Role::Admin, &admin_a, &now())
        .await
        .expect("grant admin");

    let store = std::sync::Arc::new(store);
    let a = store.clone();
    let b = store.clone();
    let admin_a_clone = admin_a.clone();
    let admin_b_clone = admin_b.clone();
    let (result_a, result_b) = tokio::join!(
        async move {
            a.initiate_account_deletion_protecting_last_admin(&admin_a_clone, 0, &now())
                .await
        },
        async move {
            b.initiate_account_deletion_protecting_last_admin(&admin_b_clone, 0, &now())
                .await
        },
    );

    let successes = [&result_a, &result_b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes, 1,
        "exactly one of two concurrent deletions of the last two admins must win"
    );

    let remaining_admins = store
        .count_enabled_admins(&REALM.to_owned())
        .await
        .expect("count");
    assert!(
        remaining_admins >= 1,
        "at least one admin must survive the race"
    );
}
