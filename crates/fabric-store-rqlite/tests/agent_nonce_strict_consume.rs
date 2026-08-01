//! WI-131: strict single-use nonce consume for the dispatcher and runner
//! paths.
//!
//! Before this slice, all three agent paths enforced replay with
//! `WHERE ... AND (last_nonce IS NULL OR last_nonce != ?)`. That remembers
//! exactly one value, so an attacker could replay a captured signed request
//! as long as any other request landed in between: the sequence `A, B, A`
//! passed. The `dispatcher_nonces` / `runner_nonces` tables had existed with
//! the correct `PRIMARY KEY (id, nonce)` shape since the schema was written,
//! but nothing ever inserted into them.
//!
//! The interleaved `A, B, A` case is the whole point of these tests -- an
//! immediate `A, A` repeat was already rejected by the old model, so a test
//! that only covered that would have passed before the fix too.
//!
//! Every test runs against an ephemeral node (114C evidence plan, Rule 2).

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_store::{NonceStore, RunnerStore, SchemaStore, StoreError};
use fabric_store_rqlite::RqliteStore;
use serde_json::json;
use support::provision_or_skip;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique(prefix: &str) -> String {
    format!(
        "{prefix}-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn now() -> String {
    fabric_store_rqlite::utc_now()
}

async fn setup(name: &str) -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip(name).await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store.init_schema().await.expect("init_schema");
    // `init_schema` creates the base tables; the additive migrations add
    // later columns (`runners.kinds` among them) that `upsert_runner` writes.
    // A fresh node needs both.
    store
        .run_additive_migrations()
        .await
        .expect("run_additive_migrations");
    Some((node, store))
}

async fn seed_runner(store: &RqliteStore, runner_id: &str) {
    store
        .upsert_runner(json!({
            "runner_id": runner_id,
            "public_key": "0".repeat(64),
            "hostname": "nonce-test-host",
            "os": "windows",
            "arch": "x86_64",
            "runner_version": "0.0.0-test",
            "protocol_version": 4,
            "max_concurrent": 1,
        }))
        .await
        .expect("upsert runner");
}

#[tokio::test]
async fn a_runner_nonce_cannot_be_reused_after_an_intervening_nonce() {
    let Some((_node, store)) =
        setup("a_runner_nonce_cannot_be_reused_after_an_intervening_nonce").await
    else {
        return;
    };
    let runner_id = unique("runner");
    seed_runner(&store, &runner_id).await;

    let (a, b) = (unique("nonce-a"), unique("nonce-b"));

    store
        .consume_runner_nonce(&runner_id, &a, &now())
        .await
        .expect("first use of A must succeed");
    store
        .consume_runner_nonce(&runner_id, &b, &now())
        .await
        .expect("first use of B must succeed");

    // The case the old `last_nonce` model let through.
    let replay = store.consume_runner_nonce(&runner_id, &a, &now()).await;
    assert!(
        matches!(replay, Err(StoreError::PermissionDenied(_))),
        "replaying nonce A after B must be rejected; got {replay:?}"
    );
}

#[tokio::test]
async fn an_immediately_repeated_runner_nonce_is_still_rejected() {
    // Regression guard: the old model already caught this, and the new one
    // must not lose it while gaining the interleaved case.
    let Some((_node, store)) =
        setup("an_immediately_repeated_runner_nonce_is_still_rejected").await
    else {
        return;
    };
    let runner_id = unique("runner");
    seed_runner(&store, &runner_id).await;
    let nonce = unique("nonce");

    store
        .consume_runner_nonce(&runner_id, &nonce, &now())
        .await
        .expect("first use must succeed");
    let replay = store.consume_runner_nonce(&runner_id, &nonce, &now()).await;
    assert!(
        matches!(replay, Err(StoreError::PermissionDenied(_))),
        "an immediate repeat must be rejected; got {replay:?}"
    );
}

#[tokio::test]
async fn nonces_are_scoped_per_runner() {
    // Two runners independently choosing the same random value must not
    // collide, or one runner could deny service to another.
    let Some((_node, store)) = setup("nonces_are_scoped_per_runner").await else {
        return;
    };
    let one = unique("runner");
    let two = unique("runner");
    seed_runner(&store, &one).await;
    seed_runner(&store, &two).await;
    let shared = unique("shared-nonce");

    store
        .consume_runner_nonce(&one, &shared, &now())
        .await
        .expect("runner one");
    store
        .consume_runner_nonce(&two, &shared, &now())
        .await
        .expect("the same nonce for a different runner must not be a replay");
}

#[tokio::test]
async fn an_unknown_runner_is_not_found_rather_than_a_replay() {
    // The NotFound-vs-replay distinction callers rely on must survive the
    // reordering (existence check now runs before the consume).
    let Some((_node, store)) = setup("an_unknown_runner_is_not_found_rather_than_a_replay").await
    else {
        return;
    };
    let outcome = store
        .consume_runner_nonce("runner-that-does-not-exist", "some-nonce", &now())
        .await;
    assert!(
        matches!(outcome, Err(StoreError::NotFound(_))),
        "an unknown runner must be NotFound, not PermissionDenied; got {outcome:?}"
    );
}

#[tokio::test]
async fn heartbeat_rejects_an_interleaved_nonce_replay_and_still_updates_state() {
    // The heartbeat previously fused the nonce check into the state UPDATE's
    // WHERE clause. Unfusing it must keep BOTH properties: replay rejected,
    // and a legitimate heartbeat still writes its telemetry.
    let Some((_node, store)) =
        setup("heartbeat_rejects_an_interleaved_nonce_replay_and_still_updates_state").await
    else {
        return;
    };
    let runner_id = unique("runner");
    seed_runner(&store, &runner_id).await;
    let (a, b) = (unique("hb-a"), unique("hb-b"));

    let row = store
        .heartbeat_runner(&runner_id, json!({"nonce": a, "on_battery": false, "cpu_load_pct": 11.0}), &now())
        .await
        .expect("first heartbeat");
    assert_eq!(
        row.last_nonce.as_deref(),
        Some(a.as_str()),
        "the heartbeat must still write its state after unfusing the nonce check"
    );

    let row = store
        .heartbeat_runner(&runner_id, json!({"nonce": b, "on_battery": false, "cpu_load_pct": 22.0}), &now())
        .await
        .expect("second heartbeat");
    assert_eq!(row.last_nonce.as_deref(), Some(b.as_str()));

    let replay = store
        .heartbeat_runner(&runner_id, json!({"nonce": a, "on_battery": false, "cpu_load_pct": 99.0}), &now())
        .await;
    assert!(
        matches!(replay, Err(StoreError::PermissionDenied(_))),
        "a heartbeat replaying nonce A after B must be rejected; got {replay:?}"
    );

    // And the rejected replay must not have written any state.
    let current = store.get_runner(&runner_id).await.expect("get_runner");
    assert_eq!(
        current.last_nonce.as_deref(),
        Some(b.as_str()),
        "a rejected replay must leave runner state at the last accepted heartbeat"
    );
}
