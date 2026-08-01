//! Proves the Rust ephemeral-rqlite harness holds the guarantees the 114C
//! evidence plan's Rule 2 requires, before anything is built on top of it.
//! Mirrors what `tests/test_ephemeral_rqlite_harness.py` proves on the
//! Python side.

mod support;

use support::{provision_or_skip, LIVE_HTTP_PORT, LIVE_RAFT_PORT};

#[tokio::test]
async fn ephemeral_node_elects_a_leader_and_is_reachable() {
    let Some(node) = provision_or_skip("ephemeral_node_elects_a_leader_and_is_reachable").await
    else {
        return;
    };
    // await_leader() already succeeded inside provision(); confirm it is
    // also reachable through an ordinary query, not just /status.
    let tables = node.table_names().await.expect("table_names");
    // A brand-new node has whatever sqlite_master already contains -- rqlite
    // itself creates no user tables, so this should be empty or near-empty,
    // but the call succeeding at all is the point.
    assert!(
        tables.len() < 50,
        "unexpectedly large fresh schema: {tables:?}"
    );
}

#[tokio::test]
async fn ephemeral_node_never_binds_the_live_cluster_ports() {
    let Some(node) = provision_or_skip("ephemeral_node_never_binds_the_live_cluster_ports").await
    else {
        return;
    };
    assert_ne!(node.http_port, LIVE_HTTP_PORT);
    assert_ne!(node.raft_port, LIVE_RAFT_PORT);
}

#[tokio::test]
async fn two_ephemeral_nodes_share_no_state() {
    let Some(a) = provision_or_skip("two_ephemeral_nodes_share_no_state (a)").await else {
        return;
    };
    let Some(b) = provision_or_skip("two_ephemeral_nodes_share_no_state (b)").await else {
        return;
    };
    assert_ne!(a.http_port, b.http_port);
    assert_ne!(a.data_dir, b.data_dir);

    a.raw_query("CREATE TABLE IF NOT EXISTS only_on_a (id INTEGER PRIMARY KEY)")
        .await
        .expect("create on a");
    let b_tables = b.table_names().await.expect("table_names on b");
    assert!(
        !b_tables.contains("only_on_a"),
        "node b must not see node a's tables"
    );
}

#[tokio::test]
async fn ephemeral_writes_are_invisible_to_the_live_cluster_when_reachable() {
    let Some(node) = provision_or_skip("ephemeral_writes_are_invisible_to_the_live_cluster").await
    else {
        return;
    };
    node.raw_query("CREATE TABLE IF NOT EXISTS ephemeral_marker_table (id INTEGER PRIMARY KEY)")
        .await
        .expect("create marker table on ephemeral node");

    // Only check the live cluster if it's actually reachable -- this test
    // must not require the live cluster to exist, only prove isolation when
    // it does.
    if std::net::TcpStream::connect(("127.0.0.1", LIVE_HTTP_PORT)).is_err() {
        eprintln!("live cluster not reachable; isolation check skipped (still holds structurally: no -join, refused live ports)");
        return;
    }
    let live = fabric_store_rqlite::RqliteStore::new("127.0.0.1", LIVE_HTTP_PORT, "strong");
    // Use a raw query against the live node the same way the harness does,
    // rather than going through RqliteStore's private query method.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://127.0.0.1:{LIVE_HTTP_PORT}/db/query?level=strong"
        ))
        .json(&serde_json::json!([[
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ephemeral_marker_table'"
        ]]))
        .send()
        .await
        .expect("query live cluster");
    let body: serde_json::Value = resp.json().await.expect("parse live cluster response");
    let rows = body["results"][0]["values"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        rows.is_empty(),
        "ephemeral marker table must not appear on the live cluster"
    );
    let _ = live; // constructed only to prove the type is reachable from this test module
}
