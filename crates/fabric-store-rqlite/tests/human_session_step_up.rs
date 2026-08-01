//! `SessionRepository::rotate_access_secret_and_elevate` (114C.6 Slice 4).
//! Every test runs against an ephemeral node (114C evidence plan, Rule 2).

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

const REALM: &str = "realm-test";
const NOW: &str = "2026-07-17 12:00:00";
const LATER: &str = "2026-07-17 12:05:00";
const STRONG_PASSWORD: &str = "a genuinely strong step-up test passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_session_step_up test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

/// Bootstrap an account and issue a password (Aal1) session for it.
async fn seed_aal1_session(store: &RqliteStore) -> (String, String, String) {
    let username = unique_id("step-up-user");
    store
        .bootstrap_first_administrator(REALM, &username, "Step-Up User", STRONG_PASSWORD, NOW)
        .await
        .expect("bootstrap");
    let outcome = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Cli,
            None,
            None,
            60,
            24,
            NOW,
        )
        .await
        .expect("password login");
    (
        outcome.session.account_id,
        outcome.session.session_id,
        outcome.access_secret.expose_secret().to_owned(),
    )
}

#[tokio::test]
async fn elevating_a_session_sets_aal2_and_step_up_at_and_rotates_the_access_secret() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let (_account_id, session_id, old_access_secret) = seed_aal1_session(&store).await;

    // Before: the session is Aal1 and the old access secret validates.
    let before = SessionRepository::get(&store, &session_id.clone())
        .await
        .expect("get session");
    assert_eq!(before.assurance_level, AssuranceLevel::Aal1);
    assert_eq!(before.step_up_at, None);
    let old_hash = fabric_accounts::secrets::hash_opaque_secret(&old_access_secret);
    SessionRepository::validate_by_access_hash(&store, &old_hash)
        .await
        .expect("old access secret validates before step-up");

    let new_access_secret =
        SessionRepository::rotate_access_secret_and_elevate(&store, &session_id.clone(), LATER)
            .await
            .expect("elevate");
    assert_ne!(new_access_secret.expose_secret(), old_access_secret);

    // After: Aal2, step_up_at stamped, new secret validates, old one does not.
    let after = SessionRepository::get(&store, &session_id.clone())
        .await
        .expect("get session");
    assert_eq!(after.assurance_level, AssuranceLevel::Aal2);
    assert_eq!(after.step_up_at.as_deref(), Some(LATER));

    let new_hash = fabric_accounts::secrets::hash_opaque_secret(new_access_secret.expose_secret());
    let validated = SessionRepository::validate_by_access_hash(&store, &new_hash)
        .await
        .expect("new access secret validates after step-up");
    assert_eq!(validated.assurance_level, AssuranceLevel::Aal2);

    // The old access secret no longer resolves to any session.
    let old_result = SessionRepository::validate_by_access_hash(&store, &old_hash).await;
    assert!(
        old_result.is_err(),
        "the pre-step-up access secret must stop validating once rotated"
    );
}

#[tokio::test]
async fn elevating_a_revoked_session_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let (_account_id, session_id, _secret) = seed_aal1_session(&store).await;
    SessionRepository::revoke(&store, &session_id.clone(), "test_revoke", NOW)
        .await
        .expect("revoke");

    let error = SessionRepository::rotate_access_secret_and_elevate(&store, &session_id, LATER)
        .await
        .expect_err("a revoked session cannot be stepped up");
    assert_eq!(error, AccountsError::SessionRevoked);
}

#[tokio::test]
async fn elevating_a_nonexistent_session_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let error = SessionRepository::rotate_access_secret_and_elevate(
        &store,
        &"no-such-session".to_owned(),
        NOW,
    )
    .await
    .expect_err("a nonexistent session cannot be stepped up");
    assert_eq!(error, AccountsError::SessionRevoked);
}
