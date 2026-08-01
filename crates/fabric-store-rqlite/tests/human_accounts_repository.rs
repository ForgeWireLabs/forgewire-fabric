//! Repository CRUD, CAS, and invariant tests for 114C.2. Every test runs
//! against an ephemeral node -- never the live cluster (114C evidence plan,
//! Rule 2) -- since these tests create `human_*` rows.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::domain::{
    Account, AccountStatus, AssuranceLevel, ClientKind, Credential, CredentialKind, Membership,
    RealmId, Role, Session,
};
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{
    AccountRepository, CredentialRepository, MembershipRepository, SessionRepository,
};
use fabric_accounts::secret::SecretString;
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

fn sample_account(username: &str) -> Account {
    Account {
        account_id: unique_id("acct"),
        realm_id: REALM.to_owned(),
        username_normalized: username.to_owned(),
        username_display: username.to_owned(),
        display_name: "Test Operator".into(),
        email_normalized: None,
        status: AccountStatus::Active,
        created_at: NOW.into(),
        updated_at: NOW.into(),
        disabled_at: None,
        deleted_at: None,
        revision: 0,
        security_version: 0,
    }
}

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_accounts_repository test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

// -- AccountRepository ---------------------------------------------------------

#[tokio::test]
async fn create_and_get_account_round_trip() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = sample_account(&unique_id("operator"));
    let created = store.create_account(account).await.expect("create_account");
    let fetched = store
        .get_account(&created.account_id)
        .await
        .expect("get_account");
    assert_eq!(fetched.account_id, created.account_id);
    assert_eq!(fetched.username_normalized, created.username_normalized);
    assert_eq!(fetched.status, AccountStatus::Active);
    assert_eq!(fetched.revision, 0);
}

#[tokio::test]
async fn get_account_not_found_is_a_typed_error() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let result = store.get_account(&"does-not-exist".to_owned()).await;
    assert!(matches!(
        result,
        Err(AccountsError::AccountPolicyViolation { .. })
    ));
}

#[tokio::test]
async fn find_by_username_distinguishes_present_from_absent() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("findme");
    let account = sample_account(&username);
    store.create_account(account).await.expect("create_account");

    let found = store
        .find_by_username(&REALM.to_owned(), &username)
        .await
        .expect("find_by_username");
    assert!(found.is_some());

    let missing = store
        .find_by_username(&REALM.to_owned(), &unique_id("never-created"))
        .await
        .expect("find_by_username");
    assert!(missing.is_none());
}

#[tokio::test]
async fn duplicate_username_in_the_same_realm_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("dupe");
    store
        .create_account(sample_account(&username))
        .await
        .expect("first create");

    let result = store.create_account(sample_account(&username)).await;
    assert!(matches!(result, Err(AccountsError::UsernameConflict)));
}

#[tokio::test]
async fn concurrent_creation_of_the_same_username_lets_exactly_one_win() {
    // The uniqueness invariant must hold under real concurrency against the
    // database, not just an app-level pre-check (which would itself race).
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("race");
    let store = std::sync::Arc::new(store);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let username = username.clone();
        handles.push(tokio::spawn(async move {
            store.create_account(sample_account(&username)).await
        }));
    }
    let mut successes = 0;
    let mut conflicts = 0;
    for handle in handles {
        match handle.await.expect("join") {
            Ok(_) => successes += 1,
            Err(AccountsError::UsernameConflict) => conflicts += 1,
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
    assert_eq!(successes, 1, "exactly one concurrent create should win");
    assert_eq!(conflicts, 7);
}

#[tokio::test]
async fn update_status_cas_succeeds_with_correct_revision_and_rejects_stale() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let created = store
        .create_account(sample_account(&unique_id("statustest")))
        .await
        .expect("create");
    assert_eq!(created.revision, 0);

    let updated = store
        .update_status(&created.account_id, 0, AccountStatus::Disabled)
        .await
        .expect("update_status with correct revision");
    assert_eq!(updated.status, AccountStatus::Disabled);
    assert_eq!(updated.revision, 1);

    // Stale revision (0 again) must now be rejected -- the row is at revision 1.
    let stale = store
        .update_status(&created.account_id, 0, AccountStatus::Active)
        .await;
    assert!(matches!(
        stale,
        Err(AccountsError::AccountPolicyViolation { .. })
    ));
}

// -- CredentialRepository -------------------------------------------------------

#[tokio::test]
async fn credential_round_trips_and_does_not_cross_columns() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let account = store
        .create_account(sample_account(&unique_id("credowner")))
        .await
        .expect("create account");

    const SECRET_SENTINEL: &str = "argon2id$v=19$m=19456,t=2,p=1$fake-hash-value-for-test";
    const LABEL_SENTINEL: &str = "My primary password";

    let credential = Credential {
        credential_id: unique_id("cred"),
        account_id: account.account_id.clone(),
        kind: CredentialKind::Password,
        secret_verifier: Some(SecretString::new(SECRET_SENTINEL)),
        algorithm: Some("argon2id".into()),
        algorithm_params: None,
        version: 1,
        public_key_material: None,
        label: Some(LABEL_SENTINEL.into()),
        created_at: NOW.into(),
        last_used_at: None,
        compromised_at: None,
        revoked_at: None,
        revision: 0,
        backup_eligible: false,
        backup_state: false,
    };
    store
        .add_credential(credential)
        .await
        .expect("add_credential");

    let active = store
        .get_active_for_account(&account.account_id)
        .await
        .expect("get_active_for_account");
    assert_eq!(active.len(), 1);
    assert_eq!(
        active[0].secret_verifier.as_ref().unwrap().expose_secret(),
        SECRET_SENTINEL
    );
    assert_eq!(active[0].label.as_deref(), Some(LABEL_SENTINEL));

    // Raw dump: the secret column holds exactly the secret, the label column
    // exactly the label -- neither leaked into the other. A parameter-order
    // bug in the INSERT statement is exactly what this catches.
    let dump = node
        .raw_query(&format!(
            "SELECT secret_verifier, label FROM human_credentials WHERE account_id='{}'",
            account.account_id
        ))
        .await
        .expect("raw dump");
    let values = dump["results"][0]["values"][0]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(values[0].as_str(), Some(SECRET_SENTINEL));
    assert_eq!(values[1].as_str(), Some(LABEL_SENTINEL));
}

#[tokio::test]
async fn revoked_credential_is_excluded_from_active_list() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .create_account(sample_account(&unique_id("revokeowner")))
        .await
        .expect("create account");
    let credential_id = unique_id("cred");
    let credential = Credential {
        credential_id: credential_id.clone(),
        account_id: account.account_id.clone(),
        kind: CredentialKind::Password,
        secret_verifier: Some(SecretString::new("hash")),
        algorithm: Some("argon2id".into()),
        algorithm_params: None,
        version: 1,
        public_key_material: None,
        label: None,
        created_at: NOW.into(),
        last_used_at: None,
        compromised_at: None,
        revoked_at: None,
        revision: 0,
        backup_eligible: false,
        backup_state: false,
    };
    store
        .add_credential(credential)
        .await
        .expect("add_credential");

    CredentialRepository::revoke(&store, &credential_id, NOW)
        .await
        .expect("revoke");
    let active = store
        .get_active_for_account(&account.account_id)
        .await
        .expect("get_active_for_account");
    assert!(active.is_empty());
}

#[tokio::test]
async fn webauthn_backup_flags_round_trip_through_create_and_read() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .create_account(sample_account(&unique_id("backupflagowner")))
        .await
        .expect("create account");
    let credential = Credential {
        credential_id: unique_id("cred"),
        account_id: account.account_id.clone(),
        kind: CredentialKind::Webauthn,
        secret_verifier: None,
        algorithm: None,
        algorithm_params: None,
        version: 1,
        public_key_material: Some("{}".into()),
        label: None,
        created_at: NOW.into(),
        last_used_at: None,
        compromised_at: None,
        revoked_at: None,
        revision: 0,
        backup_eligible: true,
        backup_state: false,
    };
    store
        .add_credential(credential)
        .await
        .expect("add_credential");

    let active = store
        .get_active_for_account(&account.account_id)
        .await
        .expect("get_active_for_account");
    assert_eq!(active.len(), 1);
    assert!(
        active[0].backup_eligible,
        "backup_eligible must round-trip as true"
    );
    assert!(
        !active[0].backup_state,
        "backup_state must round-trip as false"
    );
}

#[tokio::test]
async fn a_credential_created_without_backup_flags_reads_back_as_false() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .create_account(sample_account(&unique_id("nobackupflagowner")))
        .await
        .expect("create account");
    let credential = Credential {
        credential_id: unique_id("cred"),
        account_id: account.account_id.clone(),
        kind: CredentialKind::Password,
        secret_verifier: Some(SecretString::new("hash")),
        algorithm: Some("argon2id".into()),
        algorithm_params: None,
        version: 1,
        public_key_material: None,
        label: None,
        created_at: NOW.into(),
        last_used_at: None,
        compromised_at: None,
        revoked_at: None,
        revision: 0,
        backup_eligible: false,
        backup_state: false,
    };
    store
        .add_credential(credential)
        .await
        .expect("add_credential");

    let active = store
        .get_active_for_account(&account.account_id)
        .await
        .expect("get_active_for_account");
    assert_eq!(active.len(), 1);
    assert!(!active[0].backup_eligible);
    assert!(!active[0].backup_state);
}

// -- MembershipRepository (the store-level human/runner guard) ------------------

#[tokio::test]
async fn granting_runner_to_a_human_account_is_rejected_at_the_store_layer() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .create_account(sample_account(&unique_id("humanrunner")))
        .await
        .expect("create account");

    // Constructed as a raw struct literal -- deliberately bypassing
    // `Membership::for_human`'s domain-layer check, to prove the store does
    // not rely solely on the caller having used that constructor.
    let bypassing_membership = Membership {
        membership_id: unique_id("mem"),
        account_id: account.account_id.clone(),
        realm_id: REALM.to_owned(),
        role: Role::Runner,
        granted_by_account_id: None,
        granted_at: NOW.into(),
        revoked_at: None,
        revision: 0,
    };
    let result = store.grant(bypassing_membership).await;
    assert!(matches!(
        result,
        Err(AccountsError::AccountPolicyViolation { .. })
    ));
}

#[tokio::test]
async fn granting_runner_to_a_non_human_account_id_is_allowed() {
    // The automation-migration path: an account_id that is not in
    // human_accounts at all (a machine identity being given a Runner
    // membership record) must still be representable.
    let Some((_node, store)) = setup().await else {
        return;
    };
    let machine_membership = Membership {
        membership_id: unique_id("mem"),
        account_id: "runner-machine-not-a-human-account".into(),
        realm_id: REALM.to_owned(),
        role: Role::Runner,
        granted_by_account_id: None,
        granted_at: NOW.into(),
        revoked_at: None,
        revision: 0,
    };
    let result = store.grant(machine_membership).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn granting_a_non_runner_role_to_a_human_account_succeeds() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .create_account(sample_account(&unique_id("dispatcher")))
        .await
        .expect("create account");
    let membership = Membership::for_human(
        unique_id("mem"),
        account.account_id.clone(),
        REALM.to_owned(),
        Role::Dispatcher,
        None,
        NOW.into(),
    )
    .expect("dispatcher is human-assignable");
    let result = store.grant(membership).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn count_enabled_admins_reflects_grant_revoke_and_account_status() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let realm: RealmId = unique_id("realm"); // isolate this test's count from others in the same node
    let account = {
        let mut a = sample_account(&unique_id("admincount"));
        a.realm_id = realm.clone();
        a
    };
    let account = store.create_account(account).await.expect("create account");

    assert_eq!(
        store.count_enabled_admins(&realm).await.expect("count 0"),
        0
    );

    let membership = Membership::for_human(
        unique_id("mem"),
        account.account_id.clone(),
        realm.clone(),
        Role::Admin,
        None,
        NOW.into(),
    )
    .expect("admin is human-assignable");
    let membership_id = membership.membership_id.clone();
    store.grant(membership).await.expect("grant admin");
    assert_eq!(
        store.count_enabled_admins(&realm).await.expect("count 1"),
        1
    );

    // Disabling the account must remove it from the count even though the
    // membership itself is still active.
    store
        .update_status(&account.account_id, 0, AccountStatus::Disabled)
        .await
        .expect("disable");
    assert_eq!(
        store
            .count_enabled_admins(&realm)
            .await
            .expect("count after disable"),
        0
    );
    store
        .update_status(&account.account_id, 1, AccountStatus::Active)
        .await
        .expect("re-enable");
    assert_eq!(
        store
            .count_enabled_admins(&realm)
            .await
            .expect("count after re-enable"),
        1
    );

    MembershipRepository::revoke(&store, &membership_id, NOW)
        .await
        .expect("revoke admin");
    assert_eq!(
        store
            .count_enabled_admins(&realm)
            .await
            .expect("count after revoke"),
        0
    );
}

// -- SessionRepository -----------------------------------------------------------

fn sample_session(
    account_id: &str,
    access_hash: &str,
    refresh_hash: &str,
    family: &str,
) -> Session {
    Session {
        session_id: unique_id("sess"),
        account_id: account_id.to_owned(),
        realm_id: REALM.to_owned(),
        access_secret_hash: access_hash.to_owned(),
        refresh_family_id: family.to_owned(),
        refresh_secret_hash: refresh_hash.to_owned(),
        client_identity_id: None,
        client_kind: ClientKind::Vsix,
        client_label: Some("VS Code on test-host".into()),
        assurance_level: AssuranceLevel::Aal1,
        authenticated_at: NOW.into(),
        step_up_at: None,
        created_at: NOW.into(),
        last_seen_at: NOW.into(),
        idle_expires_at: "2026-07-17 13:00:00".into(),
        absolute_expires_at: "2026-07-18 12:00:00".into(),
        security_version_at_issue: 0,
        revoked_at: None,
        revoke_reason: None,
        revision: 0,
        bound_public_key: None,
    }
}

#[tokio::test]
async fn session_issue_and_validate_by_access_hash_round_trip() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .create_account(sample_account(&unique_id("sessowner")))
        .await
        .expect("create account");
    let access_hash = unique_id("access-hash");
    let session = sample_session(
        &account.account_id,
        &access_hash,
        &unique_id("refresh-hash"),
        &unique_id("family"),
    );
    store.issue(session).await.expect("issue");

    let validated = store
        .validate_by_access_hash(&access_hash)
        .await
        .expect("validate_by_access_hash");
    assert_eq!(validated.account_id, account.account_id);

    let missing = store.validate_by_access_hash("no-such-hash").await;
    assert!(matches!(missing, Err(AccountsError::SessionExpired)));
}

#[tokio::test]
async fn revoked_session_no_longer_validates() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .create_account(sample_account(&unique_id("revokesess")))
        .await
        .expect("create account");
    let access_hash = unique_id("access-hash");
    let session = sample_session(
        &account.account_id,
        &access_hash,
        &unique_id("refresh-hash"),
        &unique_id("family"),
    );
    let session_id = session.session_id.clone();
    store.issue(session).await.expect("issue");

    SessionRepository::revoke(&store, &session_id, "operator_requested", NOW)
        .await
        .expect("revoke");
    let result = store.validate_by_access_hash(&access_hash).await;
    assert!(matches!(result, Err(AccountsError::SessionExpired)));
}

#[tokio::test]
async fn refresh_rotation_succeeds_once_and_replay_revokes_the_whole_family() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .create_account(sample_account(&unique_id("refreshowner")))
        .await
        .expect("create account");
    let access_hash = unique_id("access-hash");
    let original_refresh = unique_id("refresh-v1");
    let family = unique_id("family");
    let session = sample_session(
        &account.account_id,
        &access_hash,
        &original_refresh,
        &family,
    );
    let session_id = session.session_id.clone();
    store.issue(session).await.expect("issue");

    let rotated_refresh = unique_id("refresh-v2");
    let rotated = store
        .rotate_refresh(&session_id, &original_refresh, &rotated_refresh, NOW)
        .await
        .expect("first rotation succeeds");
    assert_eq!(rotated.revision, 1);

    // Replay: presenting the *original* (already-rotated-away) refresh
    // secret again must be detected, not silently accepted.
    let replay = store
        .rotate_refresh(
            &session_id,
            &original_refresh,
            &unique_id("refresh-v3"),
            NOW,
        )
        .await;
    assert!(matches!(replay, Err(AccountsError::RefreshReplayDetected)));

    // The whole family -- and therefore this session's access secret too --
    // must now be revoked, per the plan's "revoke the entire token family."
    let access_after_replay = store.validate_by_access_hash(&access_hash).await;
    assert!(
        matches!(access_after_replay, Err(AccountsError::SessionExpired)),
        "session must be revoked (and so fail access validation) after a detected refresh replay"
    );
}

#[tokio::test]
async fn revoke_all_for_account_revokes_every_session_and_none_of_another_accounts() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account_a = store
        .create_account(sample_account(&unique_id("multisess")))
        .await
        .expect("create a");
    let account_b = store
        .create_account(sample_account(&unique_id("othersess")))
        .await
        .expect("create b");

    let hash_a1 = unique_id("access-a1");
    let hash_a2 = unique_id("access-a2");
    let hash_b1 = unique_id("access-b1");
    store
        .issue(sample_session(
            &account_a.account_id,
            &hash_a1,
            &unique_id("f"),
            &unique_id("fam"),
        ))
        .await
        .expect("issue a1");
    store
        .issue(sample_session(
            &account_a.account_id,
            &hash_a2,
            &unique_id("f"),
            &unique_id("fam"),
        ))
        .await
        .expect("issue a2");
    store
        .issue(sample_session(
            &account_b.account_id,
            &hash_b1,
            &unique_id("f"),
            &unique_id("fam"),
        ))
        .await
        .expect("issue b1");

    let revoked_count = store
        .revoke_all_for_account(&account_a.account_id, "admin_action", NOW)
        .await
        .expect("revoke_all_for_account");
    assert_eq!(revoked_count, 2);

    assert!(store.validate_by_access_hash(&hash_a1).await.is_err());
    assert!(store.validate_by_access_hash(&hash_a2).await.is_err());
    assert!(
        store.validate_by_access_hash(&hash_b1).await.is_ok(),
        "account b's session must be untouched"
    );
}
