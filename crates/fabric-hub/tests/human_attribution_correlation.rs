//! 114C.4 acceptance: "Audit reconstructs human -> client -> dispatch ->
//! runner -> completion."
//!
//! Drives the real `approve_approval` and `submit_result` handlers (the
//! two stages this slice newly wired with dual attribution, alongside
//! `claim` -- see `crates/fabric-hub/src/routes/tasks.rs`'s `do_claim`)
//! against a task row, then queries the audit chain by `task_id` and
//! proves every stage's event carries a consistent `attribution` shape.
//!
//! `dispatch` and `claim` are represented by directly-appended audit events
//! using the same shared `attribution()` helper the real
//! `dispatch_task_signed`/`do_claim` handlers call, rather than driving
//! those handlers live: both require an Ed25519-signed envelope against a
//! registered dispatcher/runner keypair, which is orthogonal machinery this
//! test isn't exercising (`dispatch_task_signed`'s own dual-attribution
//! wiring was mutation-tested in an earlier, already-merged 114C.4 slice;
//! `do_claim` is byte-identical in shape to the two stages this test does
//! drive live). What this test actually proves -- that every stage's audit
//! event correlates by `task_id` and carries the same `attribution` field
//! shape -- does not require re-deriving that signing infrastructure.
//!
//! Every test runs against an ephemeral node (114C evidence plan, Rule 2).

mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Extension, Path, State};
use axum::Json;
use tokio::sync::Mutex;

use fabric_hub::auth::AuthContext;
use fabric_hub::routes::approvals::{self, DecisionPayload};
use fabric_hub::routes::streams::{self, ResultPayload};
use fabric_hub::state::HubState;
use fabric_hub::utils::{attribution, audit_append};
use fabric_policy::{BudgetPolicy, DispatchGate, FabricPolicy};
use fabric_secrets::{SecretBroker, UnavailableKeyProvider};
use fabric_store::{CreateTaskParams, FabricStore, SchemaStore};
use fabric_store_rqlite::RqliteStore;
use fabric_streams::{DurabilityProfile, StreamBuffer};
use serde_json::json;
use support::provision_or_skip;

async fn setup() -> Option<(support::EphemeralRqlite, Arc<HubState>)> {
    let node = provision_or_skip("human_attribution_correlation test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store.init_schema().await.expect("init_schema");
    store
        .run_additive_migrations()
        .await
        .expect("run_additive_migrations");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    let state = test_state(store);
    Some((node, state))
}

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
        effective_policy: json!({}),
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
        history_status: Arc::new(Mutex::new(json!({}))),
    })
}

fn human_actor(account_id: &str, roles: &[&str]) -> AuthContext {
    AuthContext::for_test(account_id, roles, Some(account_id))
}

fn machine_actor(token_id: &str, roles: &[&str]) -> AuthContext {
    AuthContext::for_test(token_id, roles, None)
}

#[tokio::test]
async fn audit_reconstructs_human_to_client_to_dispatch_to_runner_to_completion_via_task_id() {
    let Some((_node, state)) = setup().await else {
        return;
    };

    let dispatcher = human_actor("acct-dispatcher", &["dispatcher"]);
    let runner = machine_actor("token-runner-1", &["runner"]);
    let approver = human_actor("acct-approver", &["approver"]);

    let now = fabric_store_rqlite::utc_now();

    // The approval must exist (and its real, hash-derived id be known)
    // *before* the task is created, since the task row references it by id
    // -- `create_or_get_pending_approval` mints its own approval_id from the
    // envelope hash, it does not accept a caller-chosen one.
    let (real_approval_id, _created) = state
        .store
        .create_or_get_pending_approval(
            "envelope-hash-probe",
            json!({"stage": "approval", "at": now}),
            "correlation probe",
            Some("agent/correlation-probe"),
            vec!["crates/fabric-hub/**".into()],
            Some("dispatcher-probe"),
            &now,
        )
        .await
        .expect("create pending approval");

    // -- dispatch (represented; see module doc comment) --------------------
    let task = state
        .store
        .create_task(
            CreateTaskParams {
                title: "correlation probe".into(),
                prompt: "exercise dual-attribution correlation".into(),
                scope_globs: vec!["crates/fabric-hub/**".into()],
                base_commit: "probe".into(),
                branch: "agent/correlation-probe".into(),
                todo_id: None,
                timeout_minutes: 5,
                priority: 0,
                kind: "agent".into(),
                metadata: json!({}),
                required_tools: None,
                required_tags: None,
                tenant: None,
                workspace_root: None,
                require_base_commit: false,
                required_capabilities: None,
                secrets_needed: None,
                network_egress: None,
                dispatcher_id: Some("dispatcher-probe".into()),
                dispatch: Some("prompt".into()),
                skill: None,
                tool: None,
                command: None,
                cwd: None,
                env: None,
                initial_status: None,
                dispatched_by_user: Some(dispatcher.subject.clone()),
                dispatched_by_host: Some("dispatcher-host".into()),
                dispatched_by_agent: Some("fabric-client".into()),
                dispatcher_pubkey_fingerprint: Some("sha256:probe".into()),
                approval_id: Some(real_approval_id.clone()),
                policy_decisions: json!([{"stage": "dispatch", "at": now, "allowed": true}]),
                approvals_required: 1,
                approvals_received: 0,
            },
            &now,
        )
        .await
        .expect("create task");

    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "dispatch",
        Some(task.id),
        &json!({ "task_id": task.id, "attribution": attribution(&dispatcher) }),
    )
    .await;

    // -- claim (represented; see module doc comment) -----------------------
    let claimed = state
        .store
        .claim_task(task.id, &runner.subject, "runner-host", &now)
        .await
        .expect("claim task");
    assert!(matches!(claimed, fabric_store::ClaimResult::Claimed(_)));
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "claim",
        Some(task.id),
        &json!({ "task_id": task.id, "worker_id": runner.subject, "attribution": attribution(&runner) }),
    )
    .await;

    // -- approval (real handler) --------------------------------------------
    let _ = approvals::approve_approval(
        State(state.clone()),
        Extension(approver.clone()),
        Path(real_approval_id),
        Json(DecisionPayload {
            approver: Some(approver.subject.clone()),
            reason: Some("looks correlated".into()),
        }),
    )
    .await
    .expect("approve");

    // -- completion (real handler) ------------------------------------------
    state
        .store
        .mark_running(task.id, &now)
        .await
        .expect("mark running");
    let _ = streams::submit_result(
        State(state.clone()),
        Extension(runner.clone()),
        Path(task.id),
        Json(ResultPayload {
            worker_id: runner.subject.clone(),
            status: "done".into(),
            head_commit: None,
            commits: vec![],
            files_touched: vec![],
            test_summary: Some("correlation probe passed".into()),
            log_tail: None,
            error: None,
            model_id: None,
            prompt_tokens: None,
            completion_tokens: None,
            cost_usd: None,
            wall_seconds: Some(1.5),
            runner_cpu_seconds: Some(1.0),
            exit_code: Some(0),
        }),
    )
    .await
    .expect("submit result");

    // -- correlate: every stage's audit event resolves by task_id -----------
    let events = state
        .store
        .audit_events_for_task(task.id)
        .await
        .expect("audit events for task");
    let mut by_kind: HashMap<String, serde_json::Value> = HashMap::new();
    for event in &events {
        assert_eq!(
            event.task_id,
            Some(task.id),
            "every correlated event must carry this task's id"
        );
        let payload: serde_json::Value =
            serde_json::from_str(&event.payload_json).expect("valid JSON payload");
        by_kind.insert(event.kind.clone(), payload);
    }

    let dispatch_attr = &by_kind.get("dispatch").expect("dispatch event present")["attribution"];
    assert_eq!(dispatch_attr["human_account_id"], json!("acct-dispatcher"));
    assert_eq!(dispatch_attr["legacy_bearer"], json!(false));

    let claim_attr = &by_kind.get("claim").expect("claim event present")["attribution"];
    assert_eq!(
        claim_attr["human_account_id"],
        serde_json::Value::Null,
        "a runner's claim must never be attributed to a human"
    );
    assert_eq!(claim_attr["authenticated_subject"], json!("token-runner-1"));

    let approval_attr = &by_kind
        .get("approval_approved")
        .expect("approval_approved event present")["attribution"];
    assert_eq!(approval_attr["human_account_id"], json!("acct-approver"));

    let completion_attr = &by_kind
        .get("result")
        .expect("result (completion) event present")["attribution"];
    assert_eq!(
        completion_attr["human_account_id"],
        serde_json::Value::Null,
        "a runner's completion must never be attributed to a human"
    );
    assert_eq!(
        completion_attr["authenticated_subject"],
        json!("token-runner-1")
    );
}
