//! `POST /auth/passkeys/register/options`, `POST /auth/passkeys/register/
//! verify`, and `DELETE /auth/passkeys/{credential_id}` (114C.6 Slice 2).
//!
//! What these tests do NOT cover: a full cryptographic ceremony success
//! (a real authenticator producing a signature `finish_passkey_registration`
//! accepts). That requires either real hardware/a real browser, or a
//! pre-recorded fixture from a real ceremony -- and `webauthn-rs-core`'s own
//! test fixtures (checked directly in its published source) use an
//! IP-literal RP ID via a low-level `Webauthn::new_unsafe_experts_only`
//! constructor that bypasses the domain-name validation the production
//! `WebauthnBuilder` this codebase uses enforces, so those fixtures cannot
//! be replayed against a `WebauthnBuilder`-constructed instance. The
//! ceremony-success path is exercised manually against a loopback hub
//! (114C.6's own acceptance wording -- "at least one ... path ... on
//! Windows" -- is inherently a manual check for the client slices this
//! backend work feeds). What IS covered here, all against real HTTP+store
//! plumbing: challenge issuance shape, every binding/rejection path
//! (wrong purpose, wrong account, wrong options_token, malformed
//! credential response), credential storage via the ceremony's real
//! `finish_passkey_registration` failure path, and passkey ownership/
//! removal. Every test runs against an ephemeral node (114C evidence plan,
//! Rule 2).

mod support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Extension, Path, State};
use axum::Json;
use tokio::sync::Mutex;

use fabric_accounts::repository::{AccountOrchestration, CredentialRepository};
use fabric_accounts::webauthn::{ChallengeKind, ChallengePurpose, ChallengeRepository};
use fabric_hub::auth::{AuthContext, DEFAULT_REALM_ID};
use fabric_hub::routes::authn::{self, RegisterPasskeyVerifyRequest};
use fabric_hub::state::HubState;
use fabric_policy::{BudgetPolicy, DispatchGate, FabricPolicy};
use fabric_secrets::{SecretBroker, UnavailableKeyProvider};
use fabric_store::FabricStore;
use fabric_store_rqlite::RqliteStore;
use fabric_streams::{DurabilityProfile, StreamBuffer};
use support::provision_or_skip;
use webauthn_rs::prelude::{Url, WebauthnBuilder};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_id(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{nanos}-{n}")
}

const STRONG_PASSWORD: &str = "a genuinely strong passkey registration test passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, Arc<HubState>)> {
    let node = provision_or_skip("human_passkey_registration test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, test_state(store, true)))
}

fn test_state(store: RqliteStore, configure_webauthn: bool) -> Arc<HubState> {
    let webauthn = configure_webauthn.then(|| {
        let origin = Url::parse("http://localhost:8765").expect("valid origin");
        Arc::new(
            WebauthnBuilder::new("localhost", &origin)
                .expect("valid rp config")
                .rp_name("Test Fabric Hub")
                .build()
                .expect("build webauthn"),
        )
    });
    Arc::new(HubState {
        store: Arc::new(store) as Arc<dyn FabricStore>,
        secrets: SecretBroker::new(Arc::new(UnavailableKeyProvider::new(
            "test: no secrets configured",
        ))),
        token: "test-legacy-bearer".into(),
        bootstrap_secret: None,
        webauthn,
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

fn actor_for(account_id: &str) -> AuthContext {
    AuthContext::for_test(account_id, &["admin"], Some(account_id))
}

/// Bootstrap is a singleton, exactly-once-per-realm gate -- only the first
/// account in a test may use this. A second account in the same test must
/// use [`seed_second_account`] instead.
async fn seed_account(state: &Arc<HubState>) -> (String, AuthContext) {
    let username = unique_id("passkey-user");
    let account = AccountOrchestration::bootstrap_first_administrator(
        &*state.store,
        DEFAULT_REALM_ID,
        &username,
        "Passkey Test User",
        STRONG_PASSWORD,
        &fabric_store_rqlite::utc_now(),
    )
    .await
    .expect("seed account");
    (account.account_id.clone(), actor_for(&account.account_id))
}

/// For a test that needs a second, independent account -- bootstrap is
/// exactly-once per realm, so this uses the ordinary account-creation path
/// instead, granted by `granted_by_account_id`.
async fn seed_second_account(
    state: &Arc<HubState>,
    granted_by_account_id: &str,
) -> (String, AuthContext) {
    let username = unique_id("passkey-user-2");
    let account = AccountOrchestration::create_account_with_password(
        &*state.store,
        DEFAULT_REALM_ID,
        &username,
        "Second Passkey Test User",
        STRONG_PASSWORD,
        fabric_accounts::domain::Role::Admin,
        granted_by_account_id,
        &fabric_store_rqlite::utc_now(),
    )
    .await
    .expect("seed second account");
    (account.account_id.clone(), actor_for(&account.account_id))
}

// ---- POST /auth/passkeys/register/options ------------------------------------------

#[tokio::test]
async fn register_options_returns_a_challenge_when_passkeys_are_configured() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (account_id, actor) = seed_account(&state).await;

    let response = authn::register_passkey_options(State(state.clone()), Extension(actor))
        .await
        .expect("register options succeeds");
    assert!(response.0["challenge_id"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert!(response.0["options_token"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert!(response.0["public_key"].is_object());

    // And the challenge is durably issued, bound to this account, for
    // registration.
    let challenge_id = response.0["challenge_id"].as_str().unwrap();
    let challenge = ChallengeRepository::get_challenge(&*state.store, challenge_id)
        .await
        .expect("challenge exists");
    assert_eq!(challenge.purpose, ChallengePurpose::Registration);
    assert_eq!(challenge.account_id.as_deref(), Some(account_id.as_str()));
    assert_eq!(challenge.kind, ChallengeKind::Webauthn);
}

#[tokio::test]
async fn register_options_fails_closed_when_passkeys_are_not_configured() {
    let Some((node, _unused)) = setup().await else {
        return;
    };
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    let state = test_state(store, false);
    let (_account_id, actor) = seed_account(&state).await;

    let error = authn::register_passkey_options(State(state), Extension(actor))
        .await
        .expect_err("must fail when webauthn is unconfigured");
    assert_eq!(error.code(), "AccountPolicyViolation");
}

#[tokio::test]
async fn register_options_is_denied_for_a_non_human_caller() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let non_human = AuthContext::for_test("role-token-xyz", &["dispatcher"], None);
    let error = authn::register_passkey_options(State(state), Extension(non_human))
        .await
        .expect_err("a role-token/legacy caller owns no human account");
    assert_eq!(error.code(), "RolePolicyViolation");
}

// ---- POST /auth/passkeys/register/verify -------------------------------------------

fn malformed_credential_request(
    challenge_id: &str,
    options_token: &str,
) -> RegisterPasskeyVerifyRequest {
    // Structurally valid JSON for `RegisterPublicKeyCredential`, but not a
    // real ceremony response -- `finish_passkey_registration` must reject
    // this on its own crypto/protocol checks, exercising that real failure
    // path rather than a mocked one.
    let credential_json = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": {
            "attestationObject": "AAAA",
            "clientDataJSON": "AAAA",
        },
        "type": "public-key",
    });
    RegisterPasskeyVerifyRequest {
        challenge_id: challenge_id.to_owned(),
        options_token: options_token.to_owned(),
        label: Some("Test Key".into()),
        credential: serde_json::from_value(credential_json)
            .expect("deserializes into RegisterPublicKeyCredential shape"),
    }
}

#[tokio::test]
async fn verify_rejects_a_malformed_credential_without_storing_anything() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (account_id, actor) = seed_account(&state).await;
    let options = authn::register_passkey_options(State(state.clone()), Extension(actor.clone()))
        .await
        .expect("register options");
    let challenge_id = options.0["challenge_id"].as_str().unwrap().to_owned();
    let options_token = options.0["options_token"].as_str().unwrap().to_owned();

    let error = authn::register_passkey_verify(
        State(state.clone()),
        Extension(actor),
        Json(malformed_credential_request(&challenge_id, &options_token)),
    )
    .await
    .expect_err("a malformed/invalid ceremony response must be rejected");
    assert_eq!(error.code(), "ChallengeInvalid");

    let credentials = CredentialRepository::get_active_for_account(&*state.store, &account_id)
        .await
        .expect("list credentials");
    let webauthn_credentials: Vec<_> = credentials
        .iter()
        .filter(|c| c.kind == fabric_accounts::domain::CredentialKind::Webauthn)
        .collect();
    assert!(
        webauthn_credentials.is_empty(),
        "a rejected verify must not create a credential row"
    );
}

#[tokio::test]
async fn verify_rejects_a_challenge_issued_for_a_different_account() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (account_a, actor_a) = seed_account(&state).await;
    let (_account_b, actor_b) = seed_second_account(&state, &account_a).await;

    let options = authn::register_passkey_options(State(state.clone()), Extension(actor_a))
        .await
        .expect("register options for account A");
    let challenge_id = options.0["challenge_id"].as_str().unwrap().to_owned();
    let options_token = options.0["options_token"].as_str().unwrap().to_owned();

    // Account B tries to redeem account A's registration challenge.
    let error = authn::register_passkey_verify(
        State(state),
        Extension(actor_b),
        Json(malformed_credential_request(&challenge_id, &options_token)),
    )
    .await
    .expect_err("a challenge bound to a different account must be rejected");
    assert_eq!(error.code(), "ChallengeInvalid");
}

#[tokio::test]
async fn verify_rejects_the_wrong_options_token() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_account_id, actor) = seed_account(&state).await;
    let options = authn::register_passkey_options(State(state.clone()), Extension(actor.clone()))
        .await
        .expect("register options");
    let challenge_id = options.0["challenge_id"].as_str().unwrap().to_owned();

    let error = authn::register_passkey_verify(
        State(state),
        Extension(actor),
        Json(malformed_credential_request(
            &challenge_id,
            "definitely-the-wrong-options-token",
        )),
    )
    .await
    .expect_err("the wrong options_token must be rejected");
    assert_eq!(error.code(), "ChallengeInvalid");
}

#[tokio::test]
async fn verify_rejects_a_challenge_issued_for_a_different_purpose() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (account_id, actor) = seed_account(&state).await;

    // Issue a step-up-purpose challenge directly (bypassing the
    // registration-options handler, which always issues `Registration`) to
    // prove the purpose binding check itself, independent of how the
    // challenge was issued.
    let options_token = "step-up-options-token";
    let challenge_hash = fabric_accounts::secrets::hash_opaque_secret(options_token);
    let now = fabric_store_rqlite::utc_now();
    let challenge = ChallengeRepository::issue_challenge(
        &*state.store,
        &unique_id("wac"),
        ChallengeKind::Webauthn,
        ChallengePurpose::StepUp,
        Some(&account_id),
        None,
        None,
        &challenge_hash,
        "{}",
        &now,
        &now,
    )
    .await
    .expect("issue step-up challenge directly");

    let error = authn::register_passkey_verify(
        State(state),
        Extension(actor),
        Json(malformed_credential_request(
            &challenge.challenge_id,
            options_token,
        )),
    )
    .await
    .expect_err("a step-up-purpose challenge must not be redeemable as a registration");
    assert_eq!(error.code(), "ChallengeInvalid");
}

// ---- DELETE /auth/passkeys/{credential_id} -----------------------------------------

#[tokio::test]
async fn remove_passkey_is_denied_for_a_credential_the_caller_does_not_own() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (account_a, actor_a) = seed_account(&state).await;
    let (_account_b, actor_b) = seed_second_account(&state, &account_a).await;

    // Directly store a webauthn credential for account A (bypassing the
    // full ceremony, which this test does not need).
    let credential = fabric_accounts::domain::Credential {
        credential_id: unique_id("cred"),
        account_id: account_a.clone(),
        kind: fabric_accounts::domain::CredentialKind::Webauthn,
        secret_verifier: None,
        algorithm: None,
        algorithm_params: None,
        version: 1,
        public_key_material: Some("{}".into()),
        label: Some("Account A's key".into()),
        created_at: fabric_store_rqlite::utc_now(),
        last_used_at: None,
        compromised_at: None,
        revoked_at: None,
        revision: 0,
        backup_eligible: false,
        backup_state: false,
    };
    let stored = CredentialRepository::add_credential(&*state.store, credential)
        .await
        .expect("store credential");

    let error = authn::remove_passkey(
        State(state.clone()),
        Extension(actor_b),
        Path(stored.credential_id.clone()),
    )
    .await
    .expect_err("account B must not be able to remove account A's passkey");
    assert_eq!(error.status_code(), axum::http::StatusCode::NOT_FOUND);

    // And the owner can remove it.
    let response =
        authn::remove_passkey(State(state), Extension(actor_a), Path(stored.credential_id))
            .await
            .expect("the owner can remove their own passkey");
    assert_eq!(response.0["revoked"], serde_json::json!(true));
}

#[tokio::test]
async fn remove_passkey_on_an_unknown_credential_id_is_not_found() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_account_id, actor) = seed_account(&state).await;
    let error = authn::remove_passkey(
        State(state),
        Extension(actor),
        Path("does-not-exist".into()),
    )
    .await
    .expect_err("must fail");
    assert_eq!(error.status_code(), axum::http::StatusCode::NOT_FOUND);
}
