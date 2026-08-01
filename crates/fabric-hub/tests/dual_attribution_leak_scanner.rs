//! Leak-scanner pass for the 114C.4 dual-attribution surface (AC-114C-2).
//!
//! `crate::utils::attribution()` is already proven, at the unit level (see
//! `utils.rs`'s own `attribution_tests` module), to expose exactly three
//! safe fields and to never carry a raw secret -- `AuthContext.subject` is
//! always constructed from a `token_id`, an `account_id`, or the literal
//! `"legacy-cluster-bearer"` (see every `subject:` assignment in `auth.rs`),
//! never from a secret value.
//!
//! What was never proven end to end (per the 2026-07-18
//! `20260718-114c-4-dual-attribution-audit` evidence run's own recorded
//! gap: "no test in this workspace inspects a persisted/emitted audit event
//! JSON and asserts a secret's absence from it") is that `audit_append`'s
//! `redact_value` pass actually reaches into a real persisted event whose
//! payload nests an `attribution()`-shaped actor object alongside other,
//! unrelated fields that might carry a secret's plaintext. This test closes
//! that gap directly: it seals a real secret through a real `SecretBroker`,
//! builds a payload shaped like the ones every now-wired route handler
//! emits (a mix of ordinary fields and a nested `attribution`/`actor`
//! object), appends it through the real `audit_append`, then reads the
//! persisted row back and asserts the plaintext is gone and the redaction
//! marker is present -- proving redaction is not merely applied to
//! top-level fields but to the whole payload tree, dual-attribution
//! sub-object included.
//!
//! Runs against an ephemeral node (114C evidence plan, Rule 2). Uses a
//! fixed in-test `MasterKeyProvider` rather than `FORGEWIRE_SECRETS_KEY_HEX`
//! specifically to avoid mutating process-global environment state that a
//! concurrently-running test in the same binary could race on.

mod support;

use std::sync::Arc;
use std::time::Instant;

use fabric_hub::auth::AuthContext;
use fabric_hub::state::HubState;
use fabric_hub::utils::{attribution, audit_append};
use fabric_policy::{BudgetPolicy, DispatchGate, FabricPolicy};
use fabric_secrets::{MasterKeyProvider, SecretBroker, SecretError};
use fabric_store::{FabricStore, SchemaStore};
use fabric_store_rqlite::RqliteStore;
use fabric_streams::{DurabilityProfile, StreamBuffer};
use serde_json::json;
use support::provision_or_skip;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

/// A deterministic 32-byte key for this test only -- never derived from or
/// written to any shared/env state, so this test is safe to run alongside
/// any other test in this workspace without key collision or cross-test
/// interference.
struct FixedTestKeyProvider;

impl MasterKeyProvider for FixedTestKeyProvider {
    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        Ok(Zeroizing::new(vec![0x42u8; 32]))
    }

    fn name(&self) -> &'static str {
        "fixed-test-key"
    }
}

async fn setup() -> Option<(support::EphemeralRqlite, Arc<HubState>, SecretBroker)> {
    let node = provision_or_skip("dual_attribution_leak_scanner test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store.init_schema().await.expect("init_schema");
    store
        .run_additive_migrations()
        .await
        .expect("run_additive_migrations");
    let secrets = SecretBroker::new(Arc::new(FixedTestKeyProvider));
    let state = test_state(store, secrets.clone());
    Some((node, state, secrets))
}

fn test_state(store: RqliteStore, secrets: SecretBroker) -> Arc<HubState> {
    Arc::new(HubState {
        store: Arc::new(store) as Arc<dyn FabricStore>,
        secrets,
        token: "test-legacy-bearer".into(),
        bootstrap_secret: None,
        webauthn: None,
        step_up_freshness_minutes: 10,
        started_at: Instant::now(),
        started_at_unix: 0.0,
        gate: DispatchGate::new(FabricPolicy::default()),
        effective_policy: json!({}),
        budget_caps: BudgetPolicy::default(),
        host: "127.0.0.1".into(),
        port: 0,
        protocol_version: 4,
        package_version: "test".into(),
        sidecar_integrity: "test".into(),
        backend: "rqlite:test".into(),
        stream_buffer: Arc::new(StreamBuffer::new(DurabilityProfile::Strict)),
        input_queues: Arc::new(Mutex::new(std::collections::HashMap::new())),
        forgelink: fabric_hub::forgelink::ForgeLinkConfig::default(),
        history_status: Arc::new(Mutex::new(json!({}))),
    })
}

#[tokio::test]
async fn a_secret_nested_beside_a_dual_attribution_actor_is_redacted_end_to_end() {
    let Some((_node, state, secrets)) = setup().await else {
        return;
    };
    let now = fabric_store_rqlite::utc_now();

    const SECRET_PLAINTEXT: &str = "s3cr3t-leak-probe-value-do-not-persist";
    let envelope = secrets
        .seal("leak-probe-secret", SECRET_PLAINTEXT)
        .expect("seal secret");
    state
        .store
        .put_secret("leak-probe-secret", &envelope, &now)
        .await
        .expect("put secret");

    // A payload shaped like the ones the now-wired route handlers build:
    // ordinary fields, plus a nested dual-attribution actor object, plus --
    // deliberately, to prove the redaction pass is not scoped to only the
    // top level -- a field that happens to carry the secret's plaintext
    // nested two levels deep, right beside the attribution object.
    let actor = AuthContext::for_test("token-leak-probe", &["dispatcher"], None);
    let payload = json!({
        "task_id": 1,
        "detail": {
            "note": format!("connecting with credential {SECRET_PLAINTEXT}"),
            "actor": attribution(&actor),
        },
    });

    audit_append(
        &*state.store,
        &state.secrets,
        "leak_scanner_probe",
        None,
        &payload,
    )
    .await
    .expect("audit_append succeeds");

    let day = &now[..10];
    let events = state
        .store
        .audit_events_for_day(day)
        .await
        .expect("audit_events_for_day");
    let probe = events
        .iter()
        .find(|e| e.kind == "leak_scanner_probe")
        .expect("the probe event was persisted");

    assert!(
        !probe.payload_json.contains(SECRET_PLAINTEXT),
        "the persisted audit payload must never contain the secret's plaintext, even nested \
         beside an unrelated attribution object: {}",
        probe.payload_json
    );
    assert!(
        probe
            .payload_json
            .contains("[REDACTED:secret:leak-probe-secret]"),
        "the redaction marker must be present in place of the plaintext: {}",
        probe.payload_json
    );

    // The attribution object itself must survive the redaction pass intact
    // -- redaction must not corrupt or strip fields it has no reason to
    // touch, only replace the actual secret substring.
    let persisted: serde_json::Value =
        serde_json::from_str(&probe.payload_json).expect("valid JSON payload");
    assert_eq!(
        persisted["detail"]["actor"]["authenticated_subject"],
        json!("token-leak-probe")
    );
    assert_eq!(
        persisted["detail"]["actor"]["human_account_id"],
        serde_json::Value::Null
    );
}
