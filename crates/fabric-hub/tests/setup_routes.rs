//! 114D D.2 acceptance: `GET /setup/status` + `POST /setup/complete` over
//! HTTP. Calls the route handler functions directly (constructing
//! `State`/`ConnectInfo`/`HeaderMap`/`Json` extractors by hand), matching
//! `human_authn_routes.rs`'s established pattern -- axum's own routing is
//! exercised separately by
//! `routes::tests::public_route_manifest_covers_health_and_self_service_auth_only`.
//! Every test runs against an ephemeral node (114C evidence plan, Rule 2;
//! 114D evidence plan Rule 6: a fresh `bootstrap_open ∧ ¬realm_established`
//! instance per test, never a shared/reused one).

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use tokio::sync::Mutex;

use fabric_hub::routes::authn;
use fabric_hub::routes::setup::{self, SetupCompleteRequest};
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

const STRONG_PASSWORD: &str = "a genuinely strong genesis setup test passphrase";
const LOOPBACK: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 12345);
const NON_LOOPBACK: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5)),
    12345,
);

async fn setup_state() -> Option<(support::EphemeralRqlite, Arc<HubState>)> {
    let node = provision_or_skip("setup_routes test").await?;
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

fn complete_request(username: &str) -> SetupCompleteRequest {
    SetupCompleteRequest {
        realm_name: "Test Realm".to_owned(),
        rp_id: None,
        origins: vec!["http://localhost:8765/".to_owned()],
        username: username.to_owned(),
        display_name: "Master Operator".to_owned(),
        password: STRONG_PASSWORD.to_owned(),
        client_kind: Some("cli".to_owned()),
        client_label: None,
        session_public_key: None,
    }
}

// ---- GET /setup/status ------------------------------------------------------

#[tokio::test]
async fn status_reports_the_pre_genesis_window_on_a_fresh_cluster() {
    let Some((_node, state)) = setup_state().await else {
        return;
    };
    let status = setup::setup_status(State(state))
        .await
        .expect("setup_status");
    assert_eq!(status.0["bootstrap_open"], serde_json::json!(true));
    assert_eq!(status.0["realm_established"], serde_json::json!(false));
    assert_eq!(status.0["sealing"], serde_json::json!(false));
}

#[tokio::test]
async fn status_flips_both_flags_once_genesis_completes() {
    let Some((_node, state)) = setup_state().await else {
        return;
    };
    let _ = setup::setup_complete(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(complete_request(&unique_id("master"))),
    )
    .await
    .expect("setup_complete succeeds from loopback");

    let status = setup::setup_status(State(state))
        .await
        .expect("setup_status");
    assert_eq!(status.0["bootstrap_open"], serde_json::json!(false));
    assert_eq!(status.0["realm_established"], serde_json::json!(true));
}

// ---- POST /setup/complete ---------------------------------------------------

#[tokio::test]
async fn complete_from_a_non_loopback_source_is_rejected() {
    let Some((_node, state)) = setup_state().await else {
        return;
    };
    let result = setup::setup_complete(
        State(state),
        ConnectInfo(NON_LOOPBACK),
        HeaderMap::new(),
        Json(complete_request(&unique_id("master"))),
    )
    .await;
    assert!(result.is_err(), "a non-loopback caller must be rejected");
}

#[tokio::test]
async fn complete_with_empty_origins_is_rejected_before_any_write() {
    let Some((_node, state)) = setup_state().await else {
        return;
    };
    let mut request = complete_request(&unique_id("master"));
    request.origins = vec![];
    let result = setup::setup_complete(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(request),
    )
    .await;
    assert!(result.is_err(), "empty origins must be rejected");

    let status = setup::setup_status(State(state))
        .await
        .expect("setup_status");
    assert_eq!(
        status.0["realm_established"],
        serde_json::json!(false),
        "a rejected setup_complete must not establish a realm"
    );
}

#[tokio::test]
async fn complete_succeeds_and_lands_the_operator_signed_in_with_recovery_codes() {
    let Some((_node, state)) = setup_state().await else {
        return;
    };
    let username = unique_id("master");
    let response = setup::setup_complete(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(complete_request(&username)),
    )
    .await
    .expect("setup_complete succeeds from loopback")
    .0;

    assert_eq!(response["realm"]["name"], serde_json::json!("Test Realm"));
    assert_eq!(response["realm"]["rp_id"], serde_json::json!("localhost"));
    assert_eq!(response["account"]["status"], serde_json::json!("active"));
    assert!(
        response["account"]["roles"]
            .as_array()
            .expect("roles array")
            .contains(&serde_json::json!("admin")),
        "the minted Master's account summary must show the admin role"
    );
    let codes = response["recovery_codes"]
        .as_array()
        .expect("recovery_codes array");
    assert_eq!(codes.len(), 10, "the route's default genesis batch size");
    // Every returned session field is present and usable-looking (non-empty).
    assert!(!response["session_id"].as_str().unwrap_or("").is_empty());
    assert!(!response["access_secret"].as_str().unwrap_or("").is_empty());
    assert!(!response["refresh_secret"].as_str().unwrap_or("").is_empty());
    assert_eq!(response["assurance_level"], serde_json::json!("aal1"));
}

#[tokio::test]
async fn the_session_setup_complete_returns_authenticates_a_real_request() {
    let Some((_node, state)) = setup_state().await else {
        return;
    };
    let username = unique_id("master");
    let response = setup::setup_complete(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(complete_request(&username)),
    )
    .await
    .expect("setup_complete")
    .0;
    let access_secret = response["access_secret"].as_str().expect("access_secret");

    // Regression guard for a real live bug: the realm_identity row's own id
    // (D.1 sec 15.1, a freshly-minted UUID) must NOT be the same value used
    // to scope the account -- every pre-existing 114C route (including the
    // real require_bearer middleware this test's own resolve_human_session
    // call mirrors) resolves human sessions against
    // `fabric_hub::auth::DEFAULT_REALM_ID` unconditionally, never a
    // per-realm id read from a response body.
    let realm_identity_id = response["realm"]["realm_id"]
        .as_str()
        .expect("realm_id")
        .to_owned();
    assert_ne!(
        realm_identity_id,
        fabric_hub::auth::DEFAULT_REALM_ID,
        "the realm identity's own id must be distinct from the account-scoping realm"
    );
    let outcome = fabric_hub::auth::resolve_human_session(
        &*state.store,
        access_secret,
        fabric_hub::auth::DEFAULT_REALM_ID,
    )
    .await;
    let fabric_hub::auth::HumanSessionOutcome::Authenticated(context) = outcome else {
        panic!("expected an authenticated human session from the genesis-issued access secret");
    };
    assert!(
        context.roles.contains(&"admin".to_string()),
        "the genesis session must authenticate with the admin role"
    );
}

#[tokio::test]
async fn a_second_complete_after_genesis_is_rejected_as_realm_already_established() {
    let Some((_node, state)) = setup_state().await else {
        return;
    };
    let _ = setup::setup_complete(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(complete_request(&unique_id("master"))),
    )
    .await
    .expect("first setup_complete succeeds");

    let second = setup::setup_complete(
        State(state),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(complete_request(&unique_id("intruder"))),
    )
    .await;
    assert!(
        second.is_err(),
        "a second genesis attempt after realm establishment must be rejected"
    );
}

#[tokio::test]
async fn complete_is_rejected_when_a_legacy_admin_already_exists_with_no_realm() {
    // The mixed/legacy scenario 114D sec 14.1 names explicitly: bootstrap_open
    // is false (an admin exists, via the OLD /auth/bootstrap route) but no
    // realm was ever established. Genesis setup must not apply here -- the
    // route-level precondition should reject before even touching
    // complete_genesis's own CAS.
    let Some((_node, state)) = setup_state().await else {
        return;
    };
    let _ = authn::bootstrap(
        State(state.clone()),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(authn::BootstrapRequest {
            username: unique_id("legacy-admin"),
            display_name: "Legacy Admin".to_owned(),
            password: STRONG_PASSWORD.to_owned(),
        }),
    )
    .await
    .expect("legacy bootstrap succeeds");

    let result = setup::setup_complete(
        State(state),
        ConnectInfo(LOOPBACK),
        HeaderMap::new(),
        Json(complete_request(&unique_id("master"))),
    )
    .await;
    assert!(
        result.is_err(),
        "setup_complete must reject when bootstrap_open is already closed"
    );
}
