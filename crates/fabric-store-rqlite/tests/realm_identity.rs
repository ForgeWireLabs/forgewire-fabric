//! 114D D.1 acceptance: the realm's founding-identity singleton is a
//! compare-and-set guard -- exactly one genesis wins, and `rp_id`/`origins`
//! survive the JSON round-trip so the WebAuthn verifier reads them back
//! faithfully cluster-wide (114D sec 15.1).
//!
//! Every test here runs against an ephemeral node -- never the live cluster
//! (114C evidence plan, Rule 2).

mod support;

use fabric_accounts::domain::RealmIdentity;
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::RealmRepository;
use fabric_store_rqlite::RqliteStore;
use support::provision_or_skip;

fn sample_realm(realm_id: &str) -> RealmIdentity {
    RealmIdentity {
        realm_id: realm_id.to_owned(),
        name: "Test Realm".to_owned(),
        rp_id: "localhost".to_owned(),
        // Order matters and must be preserved through persistence -- the
        // WebAuthn builder splits first/rest, so a reordered read would change
        // which origin becomes the primary.
        origins: vec![
            "http://localhost:8765/".to_owned(),
            "http://tauri.localhost/".to_owned(),
        ],
        created_at: "2026-07-24T12:00:00Z".to_owned(),
        genesis_node: Some("DESKTOP-228U8GL".to_owned()),
        key_alg: "ed25519".to_owned(),
    }
}

async fn store_with_schema(node: &support::EphemeralRqlite) -> RqliteStore {
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    store
}

#[tokio::test]
async fn a_fresh_cluster_has_no_realm_identity() {
    let Some(node) = provision_or_skip("a_fresh_cluster_has_no_realm_identity").await else {
        return;
    };
    let store = store_with_schema(&node).await;
    let got = store
        .get_realm_identity()
        .await
        .expect("get_realm_identity");
    assert!(
        got.is_none(),
        "a pre-genesis cluster must report no realm identity, got {got:?}"
    );
}

#[tokio::test]
async fn establish_then_read_back_preserves_every_field_and_origin_order() {
    let Some(node) =
        provision_or_skip("establish_then_read_back_preserves_every_field_and_origin_order").await
    else {
        return;
    };
    let store = store_with_schema(&node).await;
    let realm = sample_realm("realm-abc123");

    let returned = store
        .establish_realm_identity(&realm)
        .await
        .expect("establish_realm_identity");
    // The returned record is read back from the row, so it must match what we
    // asked to store -- including origin order.
    assert_eq!(returned.realm_id, realm.realm_id);
    assert_eq!(returned.name, realm.name);
    assert_eq!(returned.rp_id, realm.rp_id);
    assert_eq!(returned.origins, realm.origins);
    assert_eq!(returned.created_at, realm.created_at);
    assert_eq!(returned.genesis_node, realm.genesis_node);
    assert_eq!(returned.key_alg, realm.key_alg);

    // A subsequent independent read agrees (the JSON round-trip is stable).
    let fetched = store
        .get_realm_identity()
        .await
        .expect("get_realm_identity")
        .expect("realm identity should exist after establish");
    assert_eq!(fetched.origins, realm.origins);
    assert_eq!(fetched.rp_id, "localhost");
    assert_eq!(fetched.realm_id, "realm-abc123");
}

#[tokio::test]
async fn a_second_genesis_loses_the_cas_race_with_realm_already_established() {
    let Some(node) =
        provision_or_skip("a_second_genesis_loses_the_cas_race_with_realm_already_established")
            .await
    else {
        return;
    };
    let store = store_with_schema(&node).await;

    store
        .establish_realm_identity(&sample_realm("realm-winner"))
        .await
        .expect("first genesis should win");

    // A second attempt -- even with a different realm_id, as two independently
    // provisioned nodes would each generate -- must be rejected by the id=1
    // singleton CAS, not create a second realm.
    let second = store
        .establish_realm_identity(&sample_realm("realm-loser"))
        .await;
    assert_eq!(
        second.unwrap_err(),
        AccountsError::RealmAlreadyEstablished,
        "a second genesis must lose the compare-and-set race"
    );

    // The winner is untouched: still exactly the first realm, no overwrite.
    let fetched = store
        .get_realm_identity()
        .await
        .expect("get_realm_identity")
        .expect("realm identity should still exist");
    assert_eq!(
        fetched.realm_id, "realm-winner",
        "the losing genesis must not have overwritten the established realm"
    );
}
