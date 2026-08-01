//! Closes the 114C.3 debt this session's exploration found: bootstrap,
//! login, refresh, logout, logout-all, and me were fully implemented at the
//! `AccountOrchestration`/`SessionRepository` trait level but never reachable
//! over HTTP. Calls the route handler functions directly (constructing
//! `State`/`Extension`/`ConnectInfo`/`HeaderMap`/`Json` extractors by hand),
//! matching `human_account_admin_routes.rs`'s established pattern -- axum's
//! own routing/extraction machinery is exercised separately by
//! `routes::tests::public_route_manifest_covers_health_and_self_service_auth_only`
//! and `routes::tests::authenticated_route_manifest_matches_pre_split_table`.
//! Every test runs against an ephemeral node (114C evidence plan, Rule 2).

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, Extension, State};
use axum::http::HeaderMap;
use axum::Json;
use tokio::sync::Mutex;

use fabric_accounts::repository::SessionRepository;
use fabric_hub::auth::AuthContext;
use fabric_hub::routes::authn::{
    self, BootstrapRequest, LoginRequest, LogoutRequest, RefreshRequest,
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

const STRONG_PASSWORD: &str = "a genuinely strong self-service auth test passphrase";
const LOOPBACK: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 12345);
const NON_LOOPBACK: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5)),
    12345,
);

async fn setup() -> Option<(support::EphemeralRqlite, Arc<HubState>)> {
    let node = provision_or_skip("human_authn_routes test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    let state = test_state(store, None);
    Some((node, state))
}

fn test_state(store: RqliteStore, bootstrap_secret: Option<String>) -> Arc<HubState> {
    Arc::new(HubState {
        store: Arc::new(store) as Arc<dyn FabricStore>,
        secrets: SecretBroker::new(Arc::new(UnavailableKeyProvider::new(
            "test: no secrets configured",
        ))),
        token: "test-legacy-bearer".into(),
        bootstrap_secret,
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

fn bootstrap_request(username: &str) -> BootstrapRequest {
    BootstrapRequest {
        username: username.to_owned(),
        display_name: "First Admin".to_owned(),
        password: STRONG_PASSWORD.to_owned(),
    }
}

// ---- GET /auth/bootstrap/status --------------------------------------------------

#[tokio::test]
async fn bootstrap_status_flips_false_once_the_first_administrator_exists() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let before = authn::bootstrap_status(State(state.clone()))
        .await
        .expect("bootstrap status");
    assert_eq!(before.0["bootstrap_open"], serde_json::json!(true));

    let username = unique_id("bootstrap-admin");
    let _ = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&username)),
    )
    .await
    .expect("bootstrap succeeds from loopback");

    let after = authn::bootstrap_status(State(state))
        .await
        .expect("bootstrap status");
    assert_eq!(after.0["bootstrap_open"], serde_json::json!(false));
}

// ---- POST /auth/bootstrap ---------------------------------------------------------

#[tokio::test]
async fn bootstrap_succeeds_from_loopback_with_no_secret_configured() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let username = unique_id("loopback-admin");
    let response = authn::bootstrap(
        State(state),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&username)),
    )
    .await
    .expect("bootstrap succeeds");
    assert_eq!(response.0["username"], serde_json::json!(username));
    assert_eq!(response.0["roles"], serde_json::json!(["admin"]));
}

#[tokio::test]
async fn bootstrap_from_a_non_loopback_source_is_rejected() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let username = unique_id("remote-admin");
    let error = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(NON_LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&username)),
    )
    .await
    .expect_err("non-loopback bootstrap must be rejected");
    assert_eq!(error.code(), "BootstrapLocalOnly");

    // And no account was actually created -- bootstrap must still be open.
    let status = authn::bootstrap_status(State(state))
        .await
        .expect("bootstrap status");
    assert_eq!(status.0["bootstrap_open"], serde_json::json!(true));
}

#[tokio::test]
async fn a_configured_bootstrap_secret_must_be_presented_correctly() {
    let Some((node, _unused)) = setup().await else {
        return;
    };
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    let state = test_state(store, Some("correct-horse-battery-staple".to_owned()));

    // No header at all: rejected.
    let username = unique_id("secret-admin");
    let error = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&username)),
    )
    .await
    .expect_err("missing secret must be rejected");
    assert_eq!(error.code(), "BootstrapLocalOnly");

    // Wrong header value: rejected.
    let mut wrong_headers = HeaderMap::new();
    wrong_headers.insert(
        "x-forgewire-bootstrap-secret",
        "wrong-secret".parse().unwrap(),
    );
    let error = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        wrong_headers,
        Json(bootstrap_request(&username)),
    )
    .await
    .expect_err("wrong secret must be rejected");
    assert_eq!(error.code(), "BootstrapLocalOnly");

    // Correct header value: accepted.
    let mut right_headers = HeaderMap::new();
    right_headers.insert(
        "x-forgewire-bootstrap-secret",
        "correct-horse-battery-staple".parse().unwrap(),
    );
    let _ = authn::bootstrap(
        State(state),
        ConnectInfo(LOOPBACK),
        right_headers,
        Json(bootstrap_request(&username)),
    )
    .await
    .expect("correct secret succeeds");
}

// ---- POST /auth/login --------------------------------------------------------------

#[tokio::test]
async fn login_with_correct_credentials_issues_an_aal1_session_with_both_secrets() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let username = unique_id("login-user");
    let _ = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&username)),
    )
    .await
    .expect("bootstrap");

    let response = authn::login(
        State(state),
        Json(LoginRequest {
            username: username.clone(),
            password: STRONG_PASSWORD.to_owned(),
            client_kind: Some("cli".to_owned()),
            client_label: None,
            session_public_key: None,
        }),
    )
    .await
    .expect("login succeeds");
    assert_eq!(response.0["assurance_level"], serde_json::json!("aal1"));
    assert!(response.0["access_secret"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert!(response.0["refresh_secret"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

#[tokio::test]
async fn login_with_the_wrong_password_is_denied_without_revealing_which_field_was_wrong() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let username = unique_id("login-baduser");
    let _ = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&username)),
    )
    .await
    .expect("bootstrap");

    let error = authn::login(
        State(state),
        Json(LoginRequest {
            username,
            password: "definitely the wrong password".to_owned(),
            client_kind: None,
            client_label: None,
            session_public_key: None,
        }),
    )
    .await
    .expect_err("wrong password must be denied");
    assert_eq!(error.code(), "InvalidCredentials");
}

// ---- POST /auth/refresh ------------------------------------------------------------

#[tokio::test]
async fn refresh_rotates_the_refresh_secret_and_a_reused_prior_secret_is_replay_detected() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let username = unique_id("refresh-user");
    let _ = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&username)),
    )
    .await
    .expect("bootstrap");
    let login = authn::login(
        State(state.clone()),
        Json(LoginRequest {
            username,
            password: STRONG_PASSWORD.to_owned(),
            client_kind: None,
            client_label: None,
            session_public_key: None,
        }),
    )
    .await
    .expect("login");
    let session_id = login.0["session_id"].as_str().unwrap().to_owned();
    let original_refresh = login.0["refresh_secret"].as_str().unwrap().to_owned();

    let rotated = authn::refresh(
        State(state.clone()),
        Json(RefreshRequest {
            session_id: session_id.clone(),
            refresh_secret: original_refresh.clone(),
        }),
    )
    .await
    .expect("first refresh succeeds");
    let rotated_secret = rotated.0["refresh_secret"].as_str().unwrap().to_owned();
    assert_ne!(rotated_secret, original_refresh);

    // Reusing the now-superseded original refresh secret is replay: the
    // whole family (including the just-rotated secret) is revoked.
    let error = authn::refresh(
        State(state.clone()),
        Json(RefreshRequest {
            session_id: session_id.clone(),
            refresh_secret: original_refresh,
        }),
    )
    .await
    .expect_err("reused refresh secret must be replay-detected");
    assert_eq!(error.code(), "RefreshReplayDetected");

    // And the family revocation means even the secret from the successful
    // rotation above no longer works -- the session row itself is now
    // revoked, so this later call is rejected by that earlier, more
    // specific check (`SessionRevoked`) rather than re-deriving
    // `RefreshReplayDetected` a second time.
    let error = authn::refresh(
        State(state),
        Json(RefreshRequest {
            session_id,
            refresh_secret: rotated_secret,
        }),
    )
    .await
    .expect_err("the whole family must be revoked, including the newest secret");
    assert_eq!(error.code(), "SessionRevoked");
}

// ---- POST /auth/logout, /auth/logout-all -------------------------------------------

fn human_actor(account_id: &str, roles: &[&str]) -> AuthContext {
    AuthContext::for_test(account_id, roles, Some(account_id))
}

#[tokio::test]
async fn logout_revokes_the_named_session_when_the_caller_owns_it() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let username = unique_id("logout-user");
    let account = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&username)),
    )
    .await
    .expect("bootstrap");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();
    let login = authn::login(
        State(state.clone()),
        Json(LoginRequest {
            username,
            password: STRONG_PASSWORD.to_owned(),
            client_kind: None,
            client_label: None,
            session_public_key: None,
        }),
    )
    .await
    .expect("login");
    let session_id = login.0["session_id"].as_str().unwrap().to_owned();

    let actor = human_actor(&account_id, &["admin"]);
    let response = authn::logout(
        State(state.clone()),
        Extension(actor),
        Json(LogoutRequest {
            session_id: session_id.clone(),
        }),
    )
    .await
    .expect("owner can log themself out");
    assert_eq!(response.0["revoked"], serde_json::json!(true));

    let session = SessionRepository::get(&*state.store, &session_id)
        .await
        .expect("session still exists as a scrubbed row");
    assert!(session.revoked_at.is_some());
}

#[tokio::test]
async fn logout_is_denied_for_a_session_the_caller_does_not_own_and_is_not_admin() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let owner_username = unique_id("logout-owner");
    let _ = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&owner_username)),
    )
    .await
    .expect("bootstrap");
    let owner_login = authn::login(
        State(state.clone()),
        Json(LoginRequest {
            username: owner_username,
            password: STRONG_PASSWORD.to_owned(),
            client_kind: None,
            client_label: None,
            session_public_key: None,
        }),
    )
    .await
    .expect("owner login");
    let session_id = owner_login.0["session_id"].as_str().unwrap().to_owned();

    let intruder = human_actor("some-other-account-id", &["observer"]);
    let error = authn::logout(
        State(state),
        Extension(intruder),
        Json(LogoutRequest { session_id }),
    )
    .await
    .expect_err("a non-owner, non-admin caller must be denied");
    assert_eq!(error.code(), "RolePolicyViolation");
}

#[tokio::test]
async fn logout_all_revokes_every_session_for_the_caller_and_reports_the_count() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let username = unique_id("logout-all-user");
    let account = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&username)),
    )
    .await
    .expect("bootstrap");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    for _ in 0..3 {
        let _ = authn::login(
            State(state.clone()),
            Json(LoginRequest {
                username: username.clone(),
                password: STRONG_PASSWORD.to_owned(),
                client_kind: Some("cli".to_owned()),
                client_label: None,
                session_public_key: None,
            }),
        )
        .await
        .expect("login");
    }

    let actor = human_actor(&account_id, &["admin"]);
    let response = authn::logout_all(State(state.clone()), Extension(actor))
        .await
        .expect("logout-all succeeds");
    assert_eq!(response.0["revoked_count"], serde_json::json!(3));

    let sessions = SessionRepository::list_for_account(&*state.store, &account_id)
        .await
        .expect("list sessions");
    assert!(sessions.iter().all(|s| s.revoked_at.is_some()));
}

// ---- GET /auth/me -------------------------------------------------------------------

#[tokio::test]
async fn me_returns_the_callers_own_account_summary() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let username = unique_id("me-user");
    let account = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(bootstrap_request(&username)),
    )
    .await
    .expect("bootstrap");
    let account_id = account.0["account_id"].as_str().unwrap().to_owned();

    let actor = human_actor(&account_id, &["admin"]);
    let response = authn::me(State(state), Extension(actor))
        .await
        .expect("me succeeds");
    assert_eq!(response.0["account_id"], serde_json::json!(account_id));
    assert_eq!(response.0["username"], serde_json::json!(username));
}

#[tokio::test]
async fn me_is_denied_for_a_non_human_caller() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let non_human = AuthContext::for_test("role-token-xyz", &["dispatcher"], None);
    let error = authn::me(State(state), Extension(non_human))
        .await
        .expect_err("a role-token/legacy caller owns no human account");
    assert_eq!(error.code(), "RolePolicyViolation");
}
