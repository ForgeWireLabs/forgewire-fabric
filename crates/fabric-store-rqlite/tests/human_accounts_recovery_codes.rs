//! 114C.5 acceptance: "Recovery codes are one-time, individually verifiable,
//! and never redisplayed." Every test runs against an ephemeral node (114C
//! evidence plan, Rule 2).

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::domain::AccountStatus;
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

fn now() -> String {
    fabric_store_rqlite::utc_now()
}

const REALM: &str = "realm-test";
const STRONG_PASSWORD: &str = "a genuinely strong recovery-code test passphrase";
const NEW_PASSWORD: &str = "a completely different post-recovery passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_accounts_recovery_codes test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

/// Seed an active account with a password credential, ready to be put into
/// recovery. Reuses `bootstrap_first_administrator` purely as a convenient
/// account+credential seeding path -- the resulting admin membership is
/// irrelevant to these tests.
async fn seed_account(store: &RqliteStore) -> String {
    let username = unique_id("recover-me");
    let account = store
        .bootstrap_first_administrator(REALM, &username, "Recovery Target", STRONG_PASSWORD, &now())
        .await
        .expect("seed account");
    account.account_id
}

async fn force_recovery_required(store: &RqliteStore, account_id: &str) {
    let account = AccountRepository::get_account(store, &account_id.to_owned())
        .await
        .expect("get account");
    AccountRepository::update_status(
        store,
        &account_id.to_owned(),
        account.revision,
        AccountStatus::RecoveryRequired,
    )
    .await
    .expect("force recovery_required");
}

#[tokio::test]
async fn generating_codes_returns_the_requested_count_of_distinct_plaintext_codes() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account_id = seed_account(&store).await;

    let codes = store
        .generate_recovery_codes(&account_id, 5, &now())
        .await
        .expect("generate");
    assert_eq!(codes.len(), 5);
    let mut plaintexts: Vec<&str> = codes.iter().map(|c| c.expose_secret()).collect();
    plaintexts.sort_unstable();
    plaintexts.dedup();
    assert_eq!(plaintexts.len(), 5, "codes must be distinct");
}

#[tokio::test]
async fn requested_count_is_clamped_to_the_maximum_batch_size() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account_id = seed_account(&store).await;

    let codes = store
        .generate_recovery_codes(&account_id, 999, &now())
        .await
        .expect("generate");
    assert!(
        codes.len() <= 10,
        "batch size must be clamped, got {}",
        codes.len()
    );
}

#[tokio::test]
async fn no_plaintext_recovery_code_appears_anywhere_in_raw_storage() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let account_id = seed_account(&store).await;

    let codes = store
        .generate_recovery_codes(&account_id, 3, &now())
        .await
        .expect("generate");
    let rows = node
        .raw_query("SELECT code_verifier FROM human_recovery_codes")
        .await
        .expect("raw query");
    let dump = rows.to_string();
    for code in &codes {
        assert!(
            !dump.contains(code.expose_secret()),
            "a plaintext recovery code leaked into raw storage"
        );
    }
}

#[tokio::test]
async fn completing_recovery_with_a_valid_code_activates_the_account_resets_the_password_and_revokes_sessions(
) {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account_id = seed_account(&store).await;

    let login = store
        .authenticate_and_issue_session(
            REALM,
            &account_id_to_username(&store, &account_id).await,
            STRONG_PASSWORD,
            fabric_accounts::domain::ClientKind::Cli,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login before recovery");
    force_recovery_required(&store, &account_id).await;

    let codes = store
        .generate_recovery_codes(&account_id, 1, &now())
        .await
        .expect("generate");
    let code = codes[0].expose_secret();

    let updated = store
        .complete_recovery_with_code(&account_id, code, NEW_PASSWORD, &now())
        .await
        .expect("complete recovery");
    assert_eq!(updated.status, AccountStatus::Active);

    // The pre-recovery session must no longer validate.
    let access_hash =
        fabric_accounts::secrets::hash_opaque_secret(login.access_secret.expose_secret());
    assert!(
        SessionRepository::validate_by_access_hash(&store, &access_hash)
            .await
            .is_err()
    );

    // The old password no longer authenticates; the new one does.
    let username = account_id_to_username(&store, &account_id).await;
    let old_login = store
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
        .await;
    assert!(matches!(old_login, Err(AccountsError::InvalidCredentials)));
    let new_login = store
        .authenticate_and_issue_session(
            REALM,
            &username,
            NEW_PASSWORD,
            fabric_accounts::domain::ClientKind::Cli,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await;
    assert!(
        new_login.is_ok(),
        "the new password set by recovery must authenticate"
    );
}

#[tokio::test]
async fn a_code_can_only_be_used_once() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account_id = seed_account(&store).await;
    force_recovery_required(&store, &account_id).await;
    let codes = store
        .generate_recovery_codes(&account_id, 1, &now())
        .await
        .expect("generate");
    let code = codes[0].expose_secret();

    store
        .complete_recovery_with_code(&account_id, code, NEW_PASSWORD, &now())
        .await
        .expect("first use succeeds");

    // Re-arm recovery_required so a status mismatch isn't what blocks the
    // second attempt -- the *code* itself must be the thing that fails.
    force_recovery_required(&store, &account_id).await;
    let second_attempt = store
        .complete_recovery_with_code(&account_id, code, "yet another password entirely", &now())
        .await;
    assert!(
        matches!(second_attempt, Err(AccountsError::InvalidCredentials)),
        "a consumed code must not be reusable"
    );
}

#[tokio::test]
async fn an_unrecognized_code_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account_id = seed_account(&store).await;
    force_recovery_required(&store, &account_id).await;

    let result = store
        .complete_recovery_with_code(&account_id, "not-a-real-code-at-all", NEW_PASSWORD, &now())
        .await;
    assert!(matches!(result, Err(AccountsError::InvalidCredentials)));
}

#[tokio::test]
async fn recovery_is_refused_when_the_account_is_not_in_recovery_required() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let account_id = seed_account(&store).await;
    // Deliberately do NOT call force_recovery_required -- the account is
    // still Active.
    let codes = store
        .generate_recovery_codes(&account_id, 1, &now())
        .await
        .expect("generate");
    let code = codes[0].expose_secret();

    let result = store
        .complete_recovery_with_code(&account_id, code, NEW_PASSWORD, &now())
        .await;
    assert!(matches!(
        result,
        Err(AccountsError::AccountPolicyViolation { reason }) if reason == "account_not_in_recovery"
    ));
}

#[tokio::test]
async fn an_expired_code_is_rejected() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let account_id = seed_account(&store).await;
    force_recovery_required(&store, &account_id).await;
    let codes = store
        .generate_recovery_codes(&account_id, 1, &now())
        .await
        .expect("generate");
    let code = codes[0].expose_secret();

    node.raw_execute("UPDATE human_recovery_codes SET expires_at='2020-01-01 00:00:00'")
        .await
        .expect("backdate expiry");

    let result = store
        .complete_recovery_with_code(&account_id, code, NEW_PASSWORD, &now())
        .await;
    assert!(
        matches!(result, Err(AccountsError::InvalidCredentials)),
        "an expired code must be rejected"
    );
}

async fn account_id_to_username(store: &RqliteStore, account_id: &str) -> String {
    AccountRepository::get_account(store, &account_id.to_owned())
        .await
        .expect("get account")
        .username_normalized
}
