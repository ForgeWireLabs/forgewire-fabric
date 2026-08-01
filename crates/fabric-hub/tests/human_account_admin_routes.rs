//! 114C.5 acceptance: admin HTTP routes for account create/invite,
//! enable/disable, unlock, role management, session revocation, and
//! auth-policy. Calls the route handler functions directly (constructing
//! `State`/`Extension`/`Json` extractors by hand) rather than driving a live
//! HTTP request through axum -- the handlers are the unit under test, and
//! axum's own routing/extraction machinery is exercised separately by
//! `routes::tests::authenticated_route_manifest_matches_pre_split_table`
//! and the `human_account_route_policy_baseline` fixture test. Every test
//! runs against an ephemeral node (114C evidence plan, Rule 2).

mod support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Extension, Path, Query, State};
use axum::Json;
use tokio::sync::Mutex;

use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{AccountOrchestration, AccountRepository, SessionRepository};
use fabric_hub::auth::{AuthContext, DEFAULT_REALM_ID};
use fabric_hub::routes::accounts::{
    self, CompleteRecoveryRequest, CreateAccountRequest, GenerateRecoveryCodesRequest,
    GrantMembershipRequest, ListAccountsQuery, ListSessionsQuery, RevisionGuardedRequest,
    UpdateAccountStatusRequest,
};
use fabric_hub::state::HubState;
use fabric_policy::{BudgetPolicy, DispatchGate, FabricPolicy};
use fabric_secrets::{SecretBroker, UnavailableKeyProvider};
use fabric_store::FabricStore;
use fabric_store_rqlite::RqliteStore;
use fabric_streams::{DurabilityProfile, StreamBuffer};
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

const STRONG_PASSWORD: &str = "a genuinely strong admin-route test passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, Arc<HubState>)> {
    let node = provision_or_skip("human_account_admin_routes test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    let state = test_state(store);
    Some((node, state))
}

/// Build a real `HubState` for direct handler calls. Unrelated fields
/// (`DispatchGate`, `SecretBroker`, `StreamBuffer`, ...) use the same
/// no-op/default constructors `main.rs` falls back to when the corresponding
/// feature is unconfigured -- none of them participate in the account-route
/// logic under test.
fn test_state(store: RqliteStore) -> Arc<HubState> {
    Arc::new(HubState {
        store: Arc::new(store) as Arc<dyn FabricStore>,
        secrets: SecretBroker::new(Arc::new(UnavailableKeyProvider::new(
            "test: no secrets configured",
        ))),
        token: "test-legacy-bearer".into(),
        bootstrap_secret: None,
        webauthn: None,
        step_up_freshness_minutes: 10,
        started_at: Instant::now(),
        started_at_unix: 0.0,
        gate: DispatchGate::new(FabricPolicy::default()),
        effective_policy: serde_json::json!({}),
        budget_caps: BudgetPolicy::default(),
        host: "127.0.0.1".into(),
        port: 0,
        protocol_version: 4,
        package_version: "test".into(),
        sidecar_integrity: "test".into(),
        backend: "rqlite:test".into(),
        stream_buffer: Arc::new(StreamBuffer::new(DurabilityProfile::Strict)),
        input_queues: Arc::new(Mutex::new(HashMap::new())),
        forgelink: fabric_hub::forgelink::ForgeLinkConfig::default(),
        history_status: Arc::new(Mutex::new(serde_json::json!({}))),
    })
}

fn admin_actor(account_id: &str) -> AuthContext {
    AuthContext::for_test(account_id, &["admin"], Some(account_id))
}

fn actor_with_roles(account_id: &str, roles: &[&str]) -> AuthContext {
    AuthContext::for_test(account_id, roles, Some(account_id))
}

/// Bootstrap-equivalent for these tests: create the realm's first admin
/// directly through the orchestration trait (not through the HTTP route,
/// which requires an already-authenticated admin -- an unavoidable
/// chicken-and-egg only bootstrap itself resolves), then act as that admin
/// for every subsequent handler call.
async fn seed_admin(state: &Arc<HubState>) -> (String, AuthContext) {
    let username = unique_id("seed-admin");
    let account = AccountOrchestration::bootstrap_first_administrator(
        &*state.store,
        DEFAULT_REALM_ID,
        &username,
        "Seed Admin",
        STRONG_PASSWORD,
        &fabric_store_rqlite::utc_now(),
    )
    .await
    .expect("seed admin bootstrap");
    let actor = admin_actor(&account.account_id);
    (account.account_id, actor)
}

// ---- POST /accounts -----------------------------------------------------------

#[tokio::test]
async fn creating_an_account_makes_it_immediately_active_with_its_requested_role() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let username = unique_id("new-operator");

    let response = accounts::create_account(
        State(state.clone()),
        Extension(actor),
        Json(CreateAccountRequest {
            username: username.clone(),
            display_name: "New Operator".into(),
            password: STRONG_PASSWORD.into(),
            role: "dispatcher".into(),
        }),
    )
    .await
    .expect("create account");

    let body = response.0;
    assert_eq!(body["status"], "active");
    assert_eq!(body["username"], username);
    assert_eq!(body["roles"], serde_json::json!(["dispatcher"]));
}

#[tokio::test]
async fn creating_an_account_with_a_taken_username_is_rejected() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let username = unique_id("dup-operator");

    let _ = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: username.clone(),
            display_name: "First".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("first create succeeds");

    let result = accounts::create_account(
        State(state.clone()),
        Extension(actor),
        Json(CreateAccountRequest {
            username,
            display_name: "Second".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await;
    assert!(result.is_err(), "duplicate username must be rejected");
}

#[tokio::test]
async fn creating_an_account_with_the_runner_role_is_rejected() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;

    let result = accounts::create_account(
        State(state.clone()),
        Extension(actor),
        Json(CreateAccountRequest {
            username: unique_id("wanna-be-runner"),
            display_name: "Nope".into(),
            password: STRONG_PASSWORD.into(),
            role: "runner".into(),
        }),
    )
    .await;
    assert!(
        result.is_err(),
        "a human account must never be granted the runner role via this route"
    );
}

// ---- GET /accounts, GET /accounts/{id} -----------------------------------------

#[tokio::test]
async fn listing_accounts_includes_a_newly_created_one() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (admin_id, actor) = seed_admin(&state).await;

    let response = accounts::list_accounts(
        State(state.clone()),
        Query(ListAccountsQuery {
            limit: 500,
            offset: 0,
        }),
    )
    .await
    .expect("list");
    let accounts_arr = response.0["accounts"].as_array().expect("array");
    assert!(accounts_arr.iter().any(|a| a["account_id"] == admin_id));
    let _ = actor;
}

#[tokio::test]
async fn getting_an_unknown_account_id_is_a_404() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let result = accounts::get_account(State(state.clone()), Path("does-not-exist".into())).await;
    let err = result.expect_err("must be an error");
    assert_eq!(err.status_code(), axum::http::StatusCode::NOT_FOUND);
}

// ---- POST/DELETE /accounts/{id}/membership --------------------------------------

#[tokio::test]
async fn granting_a_new_role_adds_it_to_the_accounts_summary() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("multi-role"),
            display_name: "Multi Role".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let response = accounts::grant_membership(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(GrantMembershipRequest {
            role: "reviewer".into(),
        }),
    )
    .await
    .expect("grant");
    let mut roles: Vec<String> = response.0["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    roles.sort();
    assert_eq!(roles, vec!["observer".to_owned(), "reviewer".to_owned()]);
}

#[tokio::test]
async fn granting_a_role_the_account_already_holds_is_rejected_not_duplicated() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("re-grant"),
            display_name: "Re Grant".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let result = accounts::grant_membership(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(GrantMembershipRequest {
            role: "observer".into(),
        }),
    )
    .await;
    assert!(
        result.is_err(),
        "re-granting an already-held role must be rejected, not create a second active row"
    );
}

#[tokio::test]
async fn revoking_the_sole_admins_admin_membership_through_the_route_is_rejected() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (admin_id, actor) = seed_admin(&state).await;

    let result = accounts::revoke_membership(
        State(state.clone()),
        Extension(actor),
        Path((admin_id, "admin".into())),
    )
    .await;
    let err = result.expect_err("must be blocked");
    assert_eq!(err.status_code(), axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn revoking_a_non_admin_role_succeeds() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("revoke-me"),
            display_name: "Revoke Me".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let response = accounts::revoke_membership(
        State(state.clone()),
        Extension(actor),
        Path((account_id, "observer".into())),
    )
    .await
    .expect("revoke");
    assert_eq!(response.0["roles"], serde_json::json!([]));
}

// ---- POST /accounts/{id}/disable, /enable --------------------------------------

#[tokio::test]
async fn disabling_the_sole_admin_through_the_route_is_rejected() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (admin_id, actor) = seed_admin(&state).await;

    let result = accounts::disable_account(
        State(state.clone()),
        Extension(actor),
        Path(admin_id),
        Json(RevisionGuardedRequest {
            expected_revision: 0,
        }),
    )
    .await;
    let err = result.expect_err("must be blocked");
    assert_eq!(err.status_code(), axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn disabling_then_enabling_a_non_admin_account_round_trips() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("round-trip"),
            display_name: "Round Trip".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let disabled = accounts::disable_account(
        State(state.clone()),
        Extension(actor.clone()),
        Path(account_id.clone()),
        Json(RevisionGuardedRequest {
            expected_revision: 0,
        }),
    )
    .await
    .expect("disable");
    assert_eq!(disabled.0["status"], "disabled");

    let enabled = accounts::enable_account(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(RevisionGuardedRequest {
            expected_revision: 1,
        }),
    )
    .await
    .expect("enable");
    assert_eq!(enabled.0["status"], "active");
}

#[tokio::test]
async fn enabling_an_already_active_account_is_rejected_not_a_silent_no_op() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (admin_id, actor) = seed_admin(&state).await;

    let result = accounts::enable_account(
        State(state.clone()),
        Extension(actor),
        Path(admin_id),
        Json(RevisionGuardedRequest {
            expected_revision: 0,
        }),
    )
    .await;
    assert!(
        result.is_err(),
        "enable must require the account to currently be disabled"
    );
}

// ---- PATCH /accounts/{id} (unlock / recovery) ------------------------------------

#[tokio::test]
async fn patch_unlocks_a_locked_account() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("locked-out"),
            display_name: "Locked Out".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();
    AccountRepository::update_status(
        &*state.store,
        &account_id,
        0,
        fabric_accounts::domain::AccountStatus::Locked,
    )
    .await
    .expect("force-lock for the test");

    let response = accounts::update_account_status(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(UpdateAccountStatusRequest {
            status: "active".into(),
            expected_revision: 1,
        }),
    )
    .await
    .expect("unlock");
    assert_eq!(response.0["status"], "active");
}

#[tokio::test]
async fn patch_rejects_a_status_string_the_parser_does_not_recognize_as_a_legal_patch_target() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("no-patch-disable"),
            display_name: "No Patch Disable".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let result = accounts::update_account_status(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(UpdateAccountStatusRequest {
            status: "disabled".into(),
            expected_revision: 0,
        }),
    )
    .await;
    assert!(
        result.is_err(),
        "PATCH must not accept 'disabled' as a target status"
    );
}

/// Distinct from the parser-rejection test above: "locked" *does* parse as a
/// legal `AccountStatus`, so this specifically exercises `transition_allowed`
/// -- no pair in its allow-list has `locked` as a *target* (it is only ever
/// a legal *source*, for the unlock transition), so this must be rejected
/// regardless of the account's current status.
#[tokio::test]
async fn patch_cannot_transition_an_active_account_to_locked() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("no-patch-to-locked"),
            display_name: "No Patch To Locked".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let result = accounts::update_account_status(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(UpdateAccountStatusRequest {
            status: "locked".into(),
            expected_revision: 0,
        }),
    )
    .await;
    assert!(
        result.is_err(),
        "PATCH must never be able to move an account into 'locked' -- only throttling does that"
    );
}

// ---- GET /auth-policy -------------------------------------------------------------

#[tokio::test]
async fn auth_policy_reports_the_admin_role_and_the_realm() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let response = accounts::auth_policy(State(state.clone()))
        .await
        .expect("auth-policy");
    assert_eq!(response.0["realm_id"], DEFAULT_REALM_ID);
    let roles: Vec<String> = response.0["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert!(roles.contains(&"admin".to_owned()));
}

// ---- GET /auth/sessions, DELETE /auth/sessions/{id} ------------------------------

async fn login(state: &Arc<HubState>, username: &str) -> fabric_accounts::repository::LoginOutcome {
    AccountOrchestration::authenticate_and_issue_session(
        &*state.store,
        DEFAULT_REALM_ID,
        username,
        STRONG_PASSWORD,
        fabric_accounts::domain::ClientKind::Cli,
        None,
        None,
        60,
        24,
        &fabric_store_rqlite::utc_now(),
    )
    .await
    .expect("login")
}

#[tokio::test]
async fn a_caller_can_list_their_own_sessions_but_not_someone_elses() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (admin_id, admin_actor_ctx) = seed_admin(&state).await;
    let username = unique_id("session-owner");
    let _ = accounts::create_account(
        State(state.clone()),
        Extension(admin_actor_ctx.clone()),
        Json(CreateAccountRequest {
            username: username.clone(),
            display_name: "Session Owner".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let outcome = login(&state, &username).await;
    let owner_actor = actor_with_roles(&outcome.session.account_id, &["observer"]);

    // Owner listing their own sessions (no account_id query) succeeds.
    let own = accounts::list_sessions(
        State(state.clone()),
        Extension(owner_actor.clone()),
        Query(ListSessionsQuery { account_id: None }),
    )
    .await
    .expect("list own");
    assert_eq!(own.0["sessions"].as_array().unwrap().len(), 1);

    // Non-admin owner requesting the admin's sessions is denied.
    let denied = accounts::list_sessions(
        State(state.clone()),
        Extension(owner_actor),
        Query(ListSessionsQuery {
            account_id: Some(admin_id.clone()),
        }),
    )
    .await;
    assert!(
        denied.is_err(),
        "a non-admin must not be able to list another account's sessions"
    );

    // Admin requesting the same account's sessions is allowed.
    let admin_view = accounts::list_sessions(
        State(state.clone()),
        Extension(admin_actor_ctx),
        Query(ListSessionsQuery {
            account_id: Some(outcome.session.account_id.clone()),
        }),
    )
    .await
    .expect("admin can view");
    assert_eq!(admin_view.0["sessions"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn revoking_a_session_you_do_not_own_and_are_not_admin_for_is_denied() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, admin_actor_ctx) = seed_admin(&state).await;
    let username = unique_id("session-target");
    let _ = accounts::create_account(
        State(state.clone()),
        Extension(admin_actor_ctx.clone()),
        Json(CreateAccountRequest {
            username: username.clone(),
            display_name: "Session Target".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let outcome = login(&state, &username).await;

    let bystander = actor_with_roles("some-other-account", &["observer"]);
    let result = accounts::revoke_session(
        State(state.clone()),
        Extension(bystander),
        Path(outcome.session.session_id.clone()),
    )
    .await;
    assert!(
        result.is_err(),
        "a bystander with no ownership and no admin role must be denied"
    );

    // The owner themself can revoke it.
    let owner_actor = actor_with_roles(&outcome.session.account_id, &["observer"]);
    let _ = accounts::revoke_session(
        State(state.clone()),
        Extension(owner_actor),
        Path(outcome.session.session_id.clone()),
    )
    .await
    .expect("owner can revoke their own session");

    let revoked = SessionRepository::get(&*state.store, &outcome.session.session_id)
        .await
        .expect("session still exists");
    assert!(revoked.revoked_at.is_some());
}

#[tokio::test]
async fn an_admin_can_revoke_someone_elses_session() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, admin_actor_ctx) = seed_admin(&state).await;
    let username = unique_id("session-admin-revoked");
    let _ = accounts::create_account(
        State(state.clone()),
        Extension(admin_actor_ctx.clone()),
        Json(CreateAccountRequest {
            username: username.clone(),
            display_name: "Admin Revoked".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let outcome = login(&state, &username).await;

    let _ = accounts::revoke_session(
        State(state.clone()),
        Extension(admin_actor_ctx),
        Path(outcome.session.session_id.clone()),
    )
    .await
    .expect("admin can revoke another account's session");
    let revoked = SessionRepository::get(&*state.store, &outcome.session.session_id)
        .await
        .expect("session still exists");
    assert!(revoked.revoked_at.is_some());
}

// ---- POST /accounts/{id}/recovery-codes, /recovery/complete --------------------

async fn force_recovery_required(state: &Arc<HubState>, account_id: &str) {
    let account = AccountRepository::get_account(&*state.store, &account_id.to_owned())
        .await
        .expect("get account");
    AccountRepository::update_status(
        &*state.store,
        &account_id.to_owned(),
        account.revision,
        fabric_accounts::domain::AccountStatus::RecoveryRequired,
    )
    .await
    .expect("force recovery_required");
}

#[tokio::test]
async fn admin_generates_recovery_codes_and_gets_the_plaintext_back() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("recovery-target"),
            display_name: "Recovery Target".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let response = accounts::generate_recovery_codes(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(GenerateRecoveryCodesRequest { count: 3 }),
    )
    .await
    .expect("generate");
    let codes = response.0["codes"].as_array().expect("codes array");
    assert_eq!(codes.len(), 3);
    for code in codes {
        assert!(!code.as_str().unwrap().is_empty());
    }
}

#[tokio::test]
async fn admin_completes_recovery_and_the_account_becomes_active_again() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("recovery-complete"),
            display_name: "Recovery Complete".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let codes = accounts::generate_recovery_codes(
        State(state.clone()),
        Extension(actor.clone()),
        Path(account_id.clone()),
        Json(GenerateRecoveryCodesRequest { count: 1 }),
    )
    .await
    .expect("generate");
    let code = codes.0["codes"][0].as_str().unwrap().to_owned();

    force_recovery_required(&state, &account_id).await;

    let response = accounts::complete_recovery(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(CompleteRecoveryRequest {
            code,
            new_password: "a totally different recovered passphrase".into(),
        }),
    )
    .await
    .expect("complete recovery");
    assert_eq!(response.0["status"], "active");
}

#[tokio::test]
async fn completing_recovery_for_an_account_not_in_recovery_is_rejected() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("not-in-recovery"),
            display_name: "Not In Recovery".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let codes = accounts::generate_recovery_codes(
        State(state.clone()),
        Extension(actor.clone()),
        Path(account_id.clone()),
        Json(GenerateRecoveryCodesRequest { count: 1 }),
    )
    .await
    .expect("generate");
    let code = codes.0["codes"][0].as_str().unwrap().to_owned();

    // Deliberately skip force_recovery_required -- the account is still active.
    let result = accounts::complete_recovery(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(CompleteRecoveryRequest {
            code,
            new_password: "irrelevant passphrase here".into(),
        }),
    )
    .await;
    assert!(
        result.is_err(),
        "recovery must be refused when the account isn't in recovery_required"
    );
}

#[test]
fn complete_recovery_request_debug_output_never_contains_the_code_or_password() {
    let request = CompleteRecoveryRequest {
        code: "sekrit-recovery-code-value".into(),
        new_password: "sekrit-new-password-value".into(),
    };
    let debug_output = format!("{request:?}");
    assert!(!debug_output.contains("sekrit-recovery-code-value"));
    assert!(!debug_output.contains("sekrit-new-password-value"));
    assert!(debug_output.contains("REDACTED"));
}

// ---- POST /accounts/{id}/delete, /accounts/{id}/tombstone -----------------------

#[tokio::test]
async fn deleting_the_sole_admin_through_the_route_is_rejected() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (admin_id, actor) = seed_admin(&state).await;

    let result = accounts::initiate_deletion(
        State(state.clone()),
        Extension(actor),
        Path(admin_id),
        Json(RevisionGuardedRequest {
            expected_revision: 0,
        }),
    )
    .await;
    let err = result.expect_err("must be blocked");
    assert_eq!(err.status_code(), axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn admin_deletes_then_tombstones_a_non_admin_account_end_to_end() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("delete-me"),
            display_name: "Delete Me".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let pending = accounts::initiate_deletion(
        State(state.clone()),
        Extension(actor.clone()),
        Path(account_id.clone()),
        Json(RevisionGuardedRequest {
            expected_revision: 0,
        }),
    )
    .await
    .expect("initiate deletion");
    assert_eq!(pending.0["status"], "deletion_pending");

    let tombstoned = accounts::complete_deletion(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(RevisionGuardedRequest {
            expected_revision: 1,
        }),
    )
    .await
    .expect("complete deletion");
    assert_eq!(tombstoned.0["status"], "deleted_tombstone");
}

#[tokio::test]
async fn tombstoning_before_initiating_deletion_is_rejected() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: unique_id("premature-tombstone"),
            display_name: "Premature Tombstone".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let result = accounts::complete_deletion(
        State(state.clone()),
        Extension(actor),
        Path(account_id),
        Json(RevisionGuardedRequest {
            expected_revision: 0,
        }),
    )
    .await;
    assert!(
        result.is_err(),
        "tombstone must require the account to already be deletion_pending"
    );
}

// ---- GET /accounts/{id}/security-history -----------------------------------------

#[tokio::test]
async fn security_history_route_returns_bounded_login_attempts_and_sessions() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let username = unique_id("history-route-target");
    let account = accounts::create_account(
        State(state.clone()),
        Extension(actor.clone()),
        Json(CreateAccountRequest {
            username: username.clone(),
            display_name: "History Route Target".into(),
            password: STRONG_PASSWORD.into(),
            role: "observer".into(),
        }),
    )
    .await
    .expect("create");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    // Deliberately fail once and succeed once so both branches appear.
    let _ = AccountOrchestration::authenticate_and_issue_session(
        &*state.store,
        DEFAULT_REALM_ID,
        &username,
        "the wrong passphrase entirely",
        fabric_accounts::domain::ClientKind::Cli,
        None,
        None,
        60,
        24,
        &fabric_store_rqlite::utc_now(),
    )
    .await;
    let _ = AccountOrchestration::authenticate_and_issue_session(
        &*state.store,
        DEFAULT_REALM_ID,
        &username,
        STRONG_PASSWORD,
        fabric_accounts::domain::ClientKind::Cli,
        None,
        None,
        60,
        24,
        &fabric_store_rqlite::utc_now(),
    )
    .await
    .expect("login");

    let response = accounts::security_history(
        State(state.clone()),
        Path(account_id),
        Query(accounts::SecurityHistoryQuery { limit: 10 }),
    )
    .await
    .expect("security history");
    let attempts = response.0["login_attempts"]
        .as_array()
        .expect("login_attempts array");
    assert_eq!(attempts.len(), 2, "one failed and one successful attempt");
    let sessions = response.0["sessions"].as_array().expect("sessions array");
    assert_eq!(sessions.len(), 1, "the one successful login's session");
}

#[allow(dead_code)]
fn ensure_accounts_error_variant_still_compiles(_e: AccountsError) {}
