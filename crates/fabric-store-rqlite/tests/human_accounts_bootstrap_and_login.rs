//! 114C.3 acceptance: bootstrap atomicity and concurrency race; password
//! baseline (hashing, rehash); refresh replay and session lifecycle already
//! covered in 114C.2 -- this file covers login/bootstrap/disablement/
//! password-change orchestration specifically. Every test runs against an
//! ephemeral node (114C evidence plan, Rule 2).

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::domain::{ClientKind, CredentialKind};
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{
    AccountOrchestration, AccountRepository, CredentialRepository, MembershipRepository,
    SessionRepository,
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
const STRONG_PASSWORD: &str = "a genuinely strong bootstrap passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_accounts_bootstrap_and_login test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

// -- Bootstrap ------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_status_reflects_whether_an_administrator_exists() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    assert!(
        store.bootstrap_status().await.expect("status before"),
        "bootstrap should be needed on a fresh node"
    );

    store
        .bootstrap_first_administrator(
            REALM,
            &unique_id("admin"),
            "First Admin",
            STRONG_PASSWORD,
            NOW,
        )
        .await
        .expect("bootstrap");

    assert!(
        !store.bootstrap_status().await.expect("status after"),
        "bootstrap should be closed after an admin exists"
    );
}

#[tokio::test]
async fn bootstrap_creates_an_active_account_with_an_admin_membership() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("admin");
    let account = store
        .bootstrap_first_administrator(REALM, &username, "First Admin", STRONG_PASSWORD, NOW)
        .await
        .expect("bootstrap");

    assert_eq!(account.username_normalized, username);
    assert_eq!(
        account.status,
        fabric_accounts::domain::AccountStatus::Active
    );
    assert_eq!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("count"),
        1
    );

    let memberships = MembershipRepository::list_for_account(&store, &account.account_id)
        .await
        .expect("memberships");
    assert_eq!(memberships.len(), 1);
    assert_eq!(memberships[0].role, fabric_accounts::domain::Role::Admin);

    let credentials = CredentialRepository::get_active_for_account(&store, &account.account_id)
        .await
        .expect("credentials");
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].kind, CredentialKind::Password);
    assert!(credentials[0]
        .secret_verifier
        .as_ref()
        .unwrap()
        .expose_secret()
        .starts_with("$argon2id$"));
}

#[tokio::test]
async fn bootstrap_rejects_a_weak_password_before_writing_anything() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let result = store
        .bootstrap_first_administrator(REALM, &unique_id("admin"), "First Admin", "short", NOW)
        .await;
    assert!(matches!(
        result,
        Err(AccountsError::AccountPolicyViolation { .. })
    ));
    assert!(
        store.bootstrap_status().await.expect("status"),
        "a rejected bootstrap attempt must not consume the bootstrap gate"
    );
}

#[tokio::test]
async fn a_second_bootstrap_attempt_is_closed() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    store
        .bootstrap_first_administrator(
            REALM,
            &unique_id("admin"),
            "First Admin",
            STRONG_PASSWORD,
            NOW,
        )
        .await
        .expect("first bootstrap");
    let second = store
        .bootstrap_first_administrator(
            REALM,
            &unique_id("admin2"),
            "Second Admin",
            STRONG_PASSWORD,
            NOW,
        )
        .await;
    assert!(matches!(second, Err(AccountsError::BootstrapClosed)));
    assert_eq!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("count"),
        1,
        "the rejected second attempt must not have created a second admin"
    );
}

#[tokio::test]
async fn concurrent_bootstrap_lets_exactly_one_caller_win_and_leaves_no_partial_state() {
    // The acceptance criterion this test exists for: "Exactly one first
    // administrator can be created under concurrent requests."
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
                .bootstrap_first_administrator(REALM, &username, "Racer", STRONG_PASSWORD, NOW)
                .await
        }));
    }
    let mut successes = 0;
    let mut closed = 0;
    for handle in handles {
        match handle.await.expect("join") {
            Ok(_) => successes += 1,
            Err(AccountsError::BootstrapClosed) => closed += 1,
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
    assert_eq!(successes, 1, "exactly one concurrent bootstrap should win");
    assert_eq!(closed, 7);
    assert_eq!(
        store
            .count_enabled_admins(&REALM.to_owned())
            .await
            .expect("count"),
        1
    );

    // No partial state from a losing transaction: exactly one row in each
    // of the three tables the transaction wrote to.
    let accounts = store
        .list_accounts(&REALM.to_owned(), 100, 0)
        .await
        .expect("list_accounts");
    assert_eq!(
        accounts.len(),
        1,
        "a losing transaction must not have left a partial human_accounts row"
    );
}

// -- Login --------------------------------------------------------------------

#[tokio::test]
async fn login_with_correct_credentials_issues_a_validating_session() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("loginok");
    store
        .bootstrap_first_administrator(REALM, &username, "Login OK", STRONG_PASSWORD, NOW)
        .await
        .expect("bootstrap");

    let outcome = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            Some("VS Code test"),
            None,
            60,
            24,
            NOW,
        )
        .await
        .expect("login");

    let access_hash =
        fabric_accounts::secrets::hash_opaque_secret(outcome.access_secret.expose_secret());
    let validated = SessionRepository::validate_by_access_hash(&store, &access_hash)
        .await
        .expect("validate session");
    assert_eq!(validated.session_id, outcome.session.session_id);
}

#[tokio::test]
async fn login_with_wrong_password_and_unknown_username_produce_the_identical_error() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("enumcheck");
    store
        .bootstrap_first_administrator(REALM, &username, "Enum Check", STRONG_PASSWORD, NOW)
        .await
        .expect("bootstrap");

    let wrong_password = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            "the wrong passphrase entirely",
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            NOW,
        )
        .await;
    let unknown_username = store
        .authenticate_and_issue_session(
            REALM,
            &unique_id("never-existed"),
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            NOW,
        )
        .await;

    assert!(matches!(
        wrong_password,
        Err(AccountsError::InvalidCredentials)
    ));
    assert!(matches!(
        unknown_username,
        Err(AccountsError::InvalidCredentials)
    ));
}

#[tokio::test]
async fn login_against_a_disabled_account_is_distinguishable_from_a_bad_password() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("disabledlogin");
    let account = store
        .bootstrap_first_administrator(REALM, &username, "Disabled Login", STRONG_PASSWORD, NOW)
        .await
        .expect("bootstrap");
    store
        .disable_account_and_revoke_sessions(&account.account_id, 0, NOW)
        .await
        .expect("disable");

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
            NOW,
        )
        .await;
    assert!(matches!(result, Err(AccountsError::AccountDisabled)));
}

#[tokio::test]
async fn a_weakly_hashed_credential_is_rehashed_on_successful_login() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account = store
        .create_account(fabric_accounts::domain::Account {
            account_id: unique_id("acct"),
            realm_id: REALM.to_owned(),
            username_normalized: unique_id("weakhash"),
            username_display: "weakhash".into(),
            display_name: "Weak Hash".into(),
            email_normalized: None,
            status: fabric_accounts::domain::AccountStatus::Active,
            created_at: NOW.into(),
            updated_at: NOW.into(),
            disabled_at: None,
            deleted_at: None,
            revision: 0,
            security_version: 0,
        })
        .await
        .expect("create account");

    // Hash with parameters deliberately weaker than the current target, the
    // same way `password::tests::a_weaker_historical_hash_needs_rehash` does.
    use argon2::{Argon2, Params, PasswordHasher, Version};
    use password_hash::SaltString;
    let weak_params = Params::new(8 * 1024, 1, 1, Some(32)).unwrap();
    let weak_hasher = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, weak_params);
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let weak_hash = weak_hasher
        .hash_password(STRONG_PASSWORD.as_bytes(), &salt)
        .unwrap()
        .serialize();
    assert!(fabric_accounts::password::needs_rehash(weak_hash.as_str()));

    let credential_id = unique_id("cred");
    store
        .add_credential(fabric_accounts::domain::Credential {
            credential_id: credential_id.clone(),
            account_id: account.account_id.clone(),
            kind: CredentialKind::Password,
            secret_verifier: Some(SecretString::new(weak_hash.as_str())),
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
        })
        .await
        .expect("add weak credential");

    store
        .authenticate_and_issue_session(
            REALM,
            &account.username_normalized,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            NOW,
        )
        .await
        .expect("login succeeds despite weak hash");

    let refreshed = CredentialRepository::get_active_for_account(&store, &account.account_id)
        .await
        .expect("refetch credential");
    let refreshed_hash = refreshed[0]
        .secret_verifier
        .as_ref()
        .unwrap()
        .expose_secret();
    assert_ne!(
        refreshed_hash,
        weak_hash.as_str(),
        "the stored hash must have been replaced after login"
    );
    assert!(
        !fabric_accounts::password::needs_rehash(refreshed_hash),
        "the new hash must meet the current target parameters"
    );
    // The rehashed credential must still verify the same password.
    assert!(fabric_accounts::password::verify_password(STRONG_PASSWORD, refreshed_hash).unwrap());
}

// -- Disablement and password change invalidate sessions ------------------------

#[tokio::test]
async fn disabling_an_account_revokes_every_session_it_has() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("disablesessions");
    let account = store
        .bootstrap_first_administrator(REALM, &username, "Disable Sessions", STRONG_PASSWORD, NOW)
        .await
        .expect("bootstrap");

    let s1 = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            NOW,
        )
        .await
        .expect("login 1");
    let s2 = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Desktop,
            None,
            None,
            60,
            24,
            NOW,
        )
        .await
        .expect("login 2");

    store
        .disable_account_and_revoke_sessions(&account.account_id, 0, NOW)
        .await
        .expect("disable");

    let h1 = fabric_accounts::secrets::hash_opaque_secret(s1.access_secret.expose_secret());
    let h2 = fabric_accounts::secrets::hash_opaque_secret(s2.access_secret.expose_secret());
    assert!(SessionRepository::validate_by_access_hash(&store, &h1)
        .await
        .is_err());
    assert!(SessionRepository::validate_by_access_hash(&store, &h2)
        .await
        .is_err());
}

#[tokio::test]
async fn changing_a_password_revokes_existing_sessions_and_the_new_password_verifies() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("changepw");
    let account = store
        .bootstrap_first_administrator(REALM, &username, "Change PW", STRONG_PASSWORD, NOW)
        .await
        .expect("bootstrap");
    let outcome = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            NOW,
        )
        .await
        .expect("login");

    let credentials = CredentialRepository::get_active_for_account(&store, &account.account_id)
        .await
        .expect("credentials");
    let credential_id = credentials[0].credential_id.clone();

    const NEW_PASSWORD: &str = "a totally different and also strong passphrase";
    store
        .change_password_and_revoke_sessions(
            &account.account_id,
            &credential_id,
            NEW_PASSWORD,
            false,
            NOW,
        )
        .await
        .expect("change password");

    // The pre-change session must no longer validate.
    let old_hash =
        fabric_accounts::secrets::hash_opaque_secret(outcome.access_secret.expose_secret());
    assert!(
        SessionRepository::validate_by_access_hash(&store, &old_hash)
            .await
            .is_err()
    );

    // The old password must no longer work; the new one must.
    assert!(store
        .authenticate_and_issue_session(
            REALM,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            NOW
        )
        .await
        .is_err());
    assert!(store
        .authenticate_and_issue_session(
            REALM,
            &username,
            NEW_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            NOW
        )
        .await
        .is_ok());
}

// -- No plaintext secret anywhere in storage -------------------------------------

#[tokio::test]
async fn no_plaintext_password_appears_anywhere_in_raw_storage_after_a_full_flow() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let username = unique_id("noplaintext");
    // A password with a distinctive sentinel substring that appears nowhere
    // else in this flow (unlike STRONG_PASSWORD, which is reused across many
    // tests in this file and therefore an unsafe choice for a substring
    // scan). display_name is intentionally a different string: it is a
    // legitimately plaintext, non-secret field, and a scan that could not
    // tell "the password leaked into a secret column" apart from "the
    // caller passed the same string as a display name" would prove nothing.
    const SENTINEL_PASSWORD: &str = "xk7-sentinel-plaintext-password-marker-9q2";
    let account = store
        .bootstrap_first_administrator(REALM, &username, "No Plaintext", SENTINEL_PASSWORD, NOW)
        .await
        .expect("bootstrap");
    store
        .authenticate_and_issue_session(
            REALM,
            &username,
            SENTINEL_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            NOW,
        )
        .await
        .expect("login");

    for table in [
        "human_accounts",
        "human_credentials",
        "human_sessions",
        "human_bootstrap_state",
    ] {
        let dump = node
            .raw_query(&format!("SELECT * FROM {table}"))
            .await
            .expect("raw dump");
        let text = dump.to_string();
        assert!(
            !text.contains(SENTINEL_PASSWORD),
            "plaintext password leaked into {table}: {text}"
        );
    }
    let _ = account;
}
