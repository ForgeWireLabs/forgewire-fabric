//! 114C.2 acceptance: "Clean database and upgraded live-schema fixtures
//! converge to the same schema" and "Reapplying migrations is safe."
//!
//! Every test here runs against an ephemeral node -- never the live cluster
//! (114C evidence plan, Rule 2).

mod support;

use fabric_store::SchemaStore;
use fabric_store_rqlite::RqliteStore;
use support::provision_or_skip;

const EXPECTED_TABLES: &[&str] = &[
    "human_accounts",
    "human_credentials",
    "human_memberships",
    "human_sessions",
    "human_refresh_uses",
    "human_recovery_codes",
    "human_auth_challenges",
    // Eighth table, added in 114C.3 (114C-name-lock.md addendum): the
    // exactly-once first-administrator bootstrap gate.
    "human_bootstrap_state",
    // Ninth table, added in 114C.3 negative-auth (114C-name-lock.md second
    // addendum): the login-attempt records backing the rolling-window throttle.
    "human_login_attempts",
];

#[tokio::test]
async fn init_human_accounts_schema_creates_all_nine_tables() {
    let Some(node) = provision_or_skip("init_human_accounts_schema_creates_all_nine_tables").await
    else {
        return;
    };
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");

    let tables = node.table_names().await.expect("table_names");
    for expected in EXPECTED_TABLES {
        assert!(
            tables.contains(*expected),
            "missing table {expected}; got {tables:?}"
        );
    }
    // `sqlite_sequence` is SQLite's own bookkeeping table, auto-created by
    // AUTOINCREMENT on human_refresh_uses -- not something this migration
    // added, so it is excluded rather than counted against the locked seven.
    let non_internal: std::collections::BTreeSet<_> = tables
        .iter()
        .filter(|t| !t.starts_with("sqlite_"))
        .collect();
    assert_eq!(
        non_internal.len(),
        EXPECTED_TABLES.len(),
        "no table beyond the locked seven should exist; got {tables:?}"
    );
}

#[tokio::test]
async fn reapplying_the_migration_is_idempotent() {
    let Some(node) = provision_or_skip("reapplying_the_migration_is_idempotent").await else {
        return;
    };
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("first apply");
    let tables_after_first = node
        .table_names()
        .await
        .expect("table_names after first apply");

    // Reapply three times -- CREATE TABLE/INDEX IF NOT EXISTS must not error
    // and must not change the resulting schema.
    for _ in 0..3 {
        store
            .init_human_accounts_schema()
            .await
            .expect("reapply must not fail");
    }
    let tables_after_reapply = node.table_names().await.expect("table_names after reapply");
    assert_eq!(tables_after_first, tables_after_reapply);
}

#[tokio::test]
async fn clean_and_staged_schema_application_converge() {
    // "Clean" — a brand-new node applies the full base schema and the human
    // accounts schema together, as a fresh 114C-aware hub would.
    let Some(clean_node) =
        provision_or_skip("clean_and_staged_schema_application_converge (clean)").await
    else {
        return;
    };
    let clean_store = RqliteStore::new(&clean_node.host, clean_node.http_port, "strong");
    clean_store.init_schema().await.expect("clean: init_schema");
    clean_store
        .init_human_accounts_schema()
        .await
        .expect("clean: init_human_accounts_schema");
    let clean_tables = clean_node.table_names().await.expect("clean table_names");

    // "Staged" — a node that started pre-114C (base schema only) and is then
    // upgraded by applying the human accounts migration afterward, as a real
    // hub upgrade would.
    let Some(staged_node) =
        provision_or_skip("clean_and_staged_schema_application_converge (staged)").await
    else {
        return;
    };
    let staged_store = RqliteStore::new(&staged_node.host, staged_node.http_port, "strong");
    staged_store
        .init_schema()
        .await
        .expect("staged: init_schema (pre-114C state)");
    let pre_upgrade_tables = staged_node
        .table_names()
        .await
        .expect("pre-upgrade table_names");
    assert!(
        !pre_upgrade_tables.contains("human_accounts"),
        "pre-upgrade node must not already have human_accounts"
    );
    staged_store
        .init_human_accounts_schema()
        .await
        .expect("staged: upgrade migration");
    let staged_tables = staged_node.table_names().await.expect("staged table_names");

    assert_eq!(
        clean_tables, staged_tables,
        "a clean install and a staged upgrade must converge to the same table set"
    );
}

#[tokio::test]
async fn human_accounts_migration_touches_no_existing_table() {
    // 114C.2 acceptance: "no change to existing tables." Snapshot the base
    // schema's table set, apply the human accounts migration, and confirm
    // every base table is still present and the migration only *added*
    // tables -- it did not replace or rename any of them.
    let Some(node) = provision_or_skip("human_accounts_migration_touches_no_existing_table").await
    else {
        return;
    };
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store.init_schema().await.expect("init_schema");
    let base_tables = node.table_names().await.expect("base table_names");

    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    let after_tables = node.table_names().await.expect("after table_names");

    for base_table in &base_tables {
        assert!(
            after_tables.contains(base_table),
            "base table {base_table} disappeared after the human accounts migration"
        );
    }
    let added: std::collections::BTreeSet<_> =
        after_tables.difference(&base_tables).cloned().collect();
    let expected_added: std::collections::BTreeSet<_> =
        EXPECTED_TABLES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        added, expected_added,
        "the migration must add exactly the seven locked tables and nothing else"
    );
}
