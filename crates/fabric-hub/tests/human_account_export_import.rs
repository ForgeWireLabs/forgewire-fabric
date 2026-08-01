//! 114C.5 acceptance: account export and profile-only ForgeWire import
//! preview. Calls the route handler functions directly, same pattern as
//! `human_account_admin_routes.rs` (see its header for why). Step-up
//! enforcement on both routes is pinned separately by
//! `human_account_route_policy_baseline.rs`'s `step_up_policy_matches_the_baseline`
//! (the middleware gate, not something a handler-level test can exercise).
//! Every test runs against an ephemeral node (114C evidence plan, Rule 2).

mod support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Extension, State};
use axum::Json;
use tokio::sync::Mutex;

use fabric_accounts::domain::AccountStatus;
use fabric_accounts::repository::{AccountOrchestration, AccountRepository};
use fabric_hub::auth::{AuthContext, DEFAULT_REALM_ID};
use fabric_hub::routes::accounts::{
    self, AccountImportDocument, ForgeWireAccountRecord, ImportAccountsRequest,
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

const STRONG_PASSWORD: &str = "a genuinely strong export-import test passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, Arc<HubState>)> {
    let node = provision_or_skip("human_account_export_import test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    let state = test_state(store);
    Some((node, state))
}

/// Same no-op/default construction as `human_account_admin_routes.rs`'s
/// `test_state` -- see that file's doc comment for why the unrelated fields
/// are safe to stub here.
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

fn document(records: Vec<ForgeWireAccountRecord>) -> AccountImportDocument {
    AccountImportDocument {
        schema_version: 1,
        source: "test-forgewire-export".into(),
        accounts: records,
    }
}

fn record(username: &str, roles: Vec<&str>) -> ForgeWireAccountRecord {
    ForgeWireAccountRecord {
        username: username.to_owned(),
        display_name: format!("Imported {username}"),
        email: Some(format!("{username}@example.test")),
        roles: roles.into_iter().map(str::to_owned).collect(),
    }
}

// ---- GET /accounts/export ---------------------------------------------------------

#[tokio::test]
async fn export_never_includes_a_credential_or_session_field() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (admin_id, actor) = seed_admin(&state).await;

    let response = accounts::export_accounts(State(state.clone()), Extension(actor))
        .await
        .expect("export");
    let body = response.0;
    let accounts_json = serde_json::to_string(&body["accounts"]).expect("serialize");

    assert!(body["accounts"].as_array().is_some());
    let found = body["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["account_id"] == admin_id);
    assert!(found, "seeded admin must appear in the export");
    // No secret-shaped field name ever appears in the export payload.
    for forbidden in [
        "secret_verifier",
        "access_secret",
        "refresh_secret",
        "password",
    ] {
        assert!(
            !accounts_json.contains(forbidden),
            "export must never contain a {forbidden} field"
        );
    }
}

// ---- POST /accounts/import ---------------------------------------------------------

#[tokio::test]
async fn preview_never_writes_anything() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let username = unique_id("preview-only");

    let response = accounts::import_accounts(
        State(state.clone()),
        Extension(actor),
        Json(ImportAccountsRequest {
            document: document(vec![record(&username, vec!["reviewer"])]),
            dry_run: true,
        }),
    )
    .await
    .expect("preview");
    let body = response.0;

    assert_eq!(body["dry_run"], true);
    assert_eq!(body["summary"]["would_create"], 1);
    assert_eq!(body["created"].as_array().unwrap().len(), 0);

    let username_normalized =
        fabric_accounts::validation::normalize_username(&username).expect("normalize");
    let found = AccountRepository::find_by_username(
        &*state.store,
        &DEFAULT_REALM_ID.to_owned(),
        &username_normalized,
    )
    .await
    .expect("find_by_username");
    assert!(found.is_none(), "preview must never create an account");
}

#[tokio::test]
async fn dry_run_defaults_to_true_when_omitted_from_the_request_json() {
    // The wire-level guarantee that a bare POST body without an explicit
    // "dry_run" key can never write -- exercised via serde directly, since
    // ImportAccountsRequest's #[serde(default = "default_dry_run_true")]
    // is what enforces this, not anything in the handler body.
    let parsed: ImportAccountsRequest =
        serde_json::from_str(r#"{"document":{"schema_version":1,"source":"x","accounts":[]}}"#)
            .expect("parse without dry_run");
    assert!(parsed.dry_run);
}

#[tokio::test]
async fn apply_creates_an_invited_account_with_recovery_codes_and_the_mapped_role() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let username = unique_id("apply-create");

    let response = accounts::import_accounts(
        State(state.clone()),
        Extension(actor),
        Json(ImportAccountsRequest {
            document: document(vec![record(&username, vec!["dispatcher"])]),
            dry_run: false,
        }),
    )
    .await
    .expect("apply");
    let body = response.0;

    assert_eq!(body["summary"]["would_create"], 1);
    let created = body["created"].as_array().expect("created array");
    assert_eq!(created.len(), 1);
    assert!(!created[0]["codes"].as_array().unwrap().is_empty());
    let account_id = created[0]["account_id"]
        .as_str()
        .expect("account_id")
        .to_owned();

    let account = AccountRepository::get_account(&*state.store, &account_id)
        .await
        .expect("get_account");
    assert_eq!(account.status, AccountStatus::Invited);

    let memberships = fabric_accounts::repository::MembershipRepository::list_for_account(
        &*state.store,
        &account_id,
    )
    .await
    .expect("list_for_account");
    assert_eq!(memberships.len(), 1);
    assert_eq!(
        memberships[0].role,
        fabric_accounts::domain::Role::Dispatcher
    );
}

#[tokio::test]
async fn re_applying_the_same_document_is_idempotent() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let username = unique_id("apply-twice");
    let doc = document(vec![record(&username, vec!["observer"])]);

    let first = accounts::import_accounts(
        State(state.clone()),
        Extension(actor.clone()),
        Json(ImportAccountsRequest {
            document: doc.clone(),
            dry_run: false,
        }),
    )
    .await
    .expect("first apply");
    assert_eq!(first.0["summary"]["would_create"], 1);

    let second = accounts::import_accounts(
        State(state.clone()),
        Extension(actor),
        Json(ImportAccountsRequest {
            document: doc,
            dry_run: false,
        }),
    )
    .await
    .expect("second apply");
    assert_eq!(
        second.0["summary"]["skip_existing_username"], 1,
        "re-applying the same document must skip, not duplicate"
    );
    assert_eq!(second.0["created"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn import_never_grants_admin_even_when_the_document_requests_it() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let username = unique_id("wanna-be-admin");

    let response = accounts::import_accounts(
        State(state.clone()),
        Extension(actor),
        Json(ImportAccountsRequest {
            document: document(vec![record(&username, vec!["admin"])]),
            dry_run: false,
        }),
    )
    .await
    .expect("apply");
    let body = response.0;

    assert_eq!(body["summary"]["would_create"], 0);
    assert_eq!(body["summary"]["reject_invalid_record"], 1);
    assert_eq!(body["created"].as_array().unwrap().len(), 0);

    let username_normalized =
        fabric_accounts::validation::normalize_username(&username).expect("normalize");
    let found = AccountRepository::find_by_username(
        &*state.store,
        &DEFAULT_REALM_ID.to_owned(),
        &username_normalized,
    )
    .await
    .expect("find_by_username");
    assert!(found.is_none(), "admin must never be grantable via import");
}

#[tokio::test]
async fn import_rejects_the_runner_role() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let username = unique_id("wanna-be-runner");

    let response = accounts::import_accounts(
        State(state.clone()),
        Extension(actor),
        Json(ImportAccountsRequest {
            document: document(vec![record(&username, vec!["runner"])]),
            dry_run: false,
        }),
    )
    .await
    .expect("apply");
    let body = response.0;
    assert_eq!(body["summary"]["reject_invalid_record"], 1);
    assert_eq!(body["created"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn a_record_with_no_roles_at_all_is_rejected() {
    let Some((_node, state)) = setup().await else {
        return;
    };
    let (_admin_id, actor) = seed_admin(&state).await;
    let username = unique_id("no-roles");

    let response = accounts::import_accounts(
        State(state.clone()),
        Extension(actor),
        Json(ImportAccountsRequest {
            document: document(vec![record(&username, vec![])]),
            dry_run: true,
        }),
    )
    .await
    .expect("preview");
    assert_eq!(response.0["summary"]["reject_invalid_record"], 1);
}

/// The type-level enforcement of "excludes secrets by default": a document
/// carrying an unexpected field (e.g. a legacy password hash) is rejected
/// at parse time, never silently ignored.
#[test]
fn a_document_with_an_unexpected_field_is_rejected_at_parse_time() {
    let raw = r#"{
        "schema_version": 1,
        "source": "test",
        "accounts": [
            { "username": "a", "display_name": "A", "roles": ["reviewer"], "password_hash": "sneaky" }
        ]
    }"#;
    let parsed: Result<AccountImportDocument, _> = serde_json::from_str(raw);
    assert!(
        parsed.is_err(),
        "an unexpected field on an account record must be rejected, not silently dropped"
    );
}

#[test]
fn a_document_with_an_unexpected_top_level_field_is_rejected_at_parse_time() {
    let raw = r#"{
        "schema_version": 1,
        "source": "test",
        "accounts": [],
        "credentials": []
    }"#;
    let parsed: Result<AccountImportDocument, _> = serde_json::from_str(raw);
    assert!(parsed.is_err());
}
