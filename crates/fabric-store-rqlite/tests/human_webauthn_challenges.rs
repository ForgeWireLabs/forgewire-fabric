//! `ChallengeRepository` CRUD/CAS tests (114C.6 Slice 1). Every test runs
//! against an ephemeral node -- never the live cluster (114C evidence plan,
//! Rule 2), since these tests create `human_auth_challenges` rows.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::error::AccountsError;
use fabric_accounts::webauthn::{
    ChallengeKind, ChallengePurpose, ChallengeRepository, ChallengeStatus,
};
use fabric_store_rqlite::RqliteStore;
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

const PAST: &str = "2020-01-01 00:00:00";
const NOW: &str = "2026-07-17 12:00:00";
const FUTURE: &str = "2026-07-17 12:05:00";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_webauthn_challenges test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

#[tokio::test]
async fn issuing_and_getting_a_challenge_round_trips_every_field() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let challenge_id = unique_id("chal");
    let issued = store
        .issue_challenge(
            &challenge_id,
            ChallengeKind::Webauthn,
            ChallengePurpose::Registration,
            Some("acct-1"),
            None,
            Some("client-1"),
            "hash-of-options-token",
            "{\"ceremony\":\"state\"}",
            NOW,
            FUTURE,
        )
        .await
        .expect("issue challenge");
    assert_eq!(issued.status, ChallengeStatus::Pending);
    assert_eq!(issued.attempt_count, 0);

    let fetched = store
        .get_challenge(&challenge_id)
        .await
        .expect("get challenge");
    assert_eq!(fetched.kind, ChallengeKind::Webauthn);
    assert_eq!(fetched.purpose, ChallengePurpose::Registration);
    assert_eq!(fetched.account_id.as_deref(), Some("acct-1"));
    assert_eq!(fetched.session_id, None);
    assert_eq!(fetched.client_identity_id.as_deref(), Some("client-1"));
    assert_eq!(fetched.challenge_hash, "hash-of-options-token");
    assert_eq!(fetched.ceremony_state, "{\"ceremony\":\"state\"}");
    assert_eq!(fetched.expires_at, FUTURE);
    assert_eq!(fetched.status, ChallengeStatus::Pending);
}

#[tokio::test]
async fn getting_an_unknown_challenge_id_is_challenge_invalid() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let error = store
        .get_challenge("does-not-exist")
        .await
        .expect_err("must fail");
    assert_eq!(error, AccountsError::ChallengeInvalid);
}

#[tokio::test]
async fn a_pending_unexpired_challenge_can_be_consumed_exactly_once() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let challenge_id = unique_id("chal");
    store
        .issue_challenge(
            &challenge_id,
            ChallengeKind::Webauthn,
            ChallengePurpose::Authentication,
            None,
            None,
            None,
            "hash",
            "ceremony-state-blob",
            NOW,
            FUTURE,
        )
        .await
        .expect("issue");

    let consumed = store
        .consume_challenge_if_pending(&challenge_id, NOW)
        .await
        .expect("first consume succeeds");
    assert_eq!(consumed.status, ChallengeStatus::Consumed);
    assert_eq!(consumed.consumed_at.as_deref(), Some(NOW));
    // The fields the caller actually needs to run verification survive the
    // status transition unchanged.
    assert_eq!(consumed.ceremony_state, "ceremony-state-blob");
    assert_eq!(consumed.purpose, ChallengePurpose::Authentication);

    let second_attempt = store
        .consume_challenge_if_pending(&challenge_id, NOW)
        .await
        .expect_err("a second consume of the same challenge must fail");
    assert_eq!(second_attempt, AccountsError::ChallengeInvalid);
}

#[tokio::test]
async fn an_expired_challenge_cannot_be_consumed() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let challenge_id = unique_id("chal");
    // expires_at (NOW) is already in the past relative to the consume call's
    // `now` (FUTURE) -- the challenge is expired by the time it's redeemed.
    store
        .issue_challenge(
            &challenge_id,
            ChallengeKind::Webauthn,
            ChallengePurpose::Registration,
            None,
            None,
            None,
            "hash",
            "state",
            PAST,
            NOW,
        )
        .await
        .expect("issue");

    let error = store
        .consume_challenge_if_pending(&challenge_id, FUTURE)
        .await
        .expect_err("an expired challenge must not be consumable");
    assert_eq!(error, AccountsError::ChallengeInvalid);
}

#[tokio::test]
async fn consuming_a_nonexistent_challenge_is_challenge_invalid_not_a_panic() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let error = store
        .consume_challenge_if_pending("never-issued", NOW)
        .await
        .expect_err("must fail");
    assert_eq!(error, AccountsError::ChallengeInvalid);
}

#[tokio::test]
async fn concurrent_consume_attempts_let_exactly_one_caller_win() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let challenge_id = unique_id("chal");
    store
        .issue_challenge(
            &challenge_id,
            ChallengeKind::Webauthn,
            ChallengePurpose::Authentication,
            None,
            None,
            None,
            "hash",
            "state",
            NOW,
            FUTURE,
        )
        .await
        .expect("issue");

    let (a, b) = tokio::join!(
        store.consume_challenge_if_pending(&challenge_id, NOW),
        store.consume_challenge_if_pending(&challenge_id, NOW),
    );
    let successes = [&a, &b].iter().filter(|r| r.is_ok()).count();
    let failures = [&a, &b]
        .iter()
        .filter(|r| matches!(r, Err(AccountsError::ChallengeInvalid)))
        .count();
    assert_eq!(successes, 1, "exactly one concurrent consume must win");
    assert_eq!(
        failures, 1,
        "the other must fail closed, not silently succeed too"
    );
}

#[tokio::test]
async fn attempt_count_increments_and_forces_failed_status_at_the_cap() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let challenge_id = unique_id("chal");
    store
        .issue_challenge(
            &challenge_id,
            ChallengeKind::Webauthn,
            ChallengePurpose::Authentication,
            None,
            None,
            None,
            "hash",
            "state",
            NOW,
            FUTURE,
        )
        .await
        .expect("issue");

    for expected in 1..=4 {
        let count = store
            .increment_challenge_attempt(&challenge_id, 5)
            .await
            .expect("increment");
        assert_eq!(count, expected);
        let row = store.get_challenge(&challenge_id).await.expect("get");
        assert_eq!(
            row.status,
            ChallengeStatus::Pending,
            "must stay pending below the cap"
        );
    }

    let count = store
        .increment_challenge_attempt(&challenge_id, 5)
        .await
        .expect("increment to cap");
    assert_eq!(count, 5);
    let row = store.get_challenge(&challenge_id).await.expect("get");
    assert_eq!(
        row.status,
        ChallengeStatus::Failed,
        "reaching max_attempts must force the challenge to failed"
    );

    // A challenge already forced to `failed` cannot be consumed.
    let error = store
        .consume_challenge_if_pending(&challenge_id, NOW)
        .await
        .expect_err("a failed challenge must not be consumable");
    assert_eq!(error, AccountsError::ChallengeInvalid);
}

#[tokio::test]
async fn incrementing_attempt_count_on_an_already_consumed_challenge_is_a_no_op() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let challenge_id = unique_id("chal");
    store
        .issue_challenge(
            &challenge_id,
            ChallengeKind::Webauthn,
            ChallengePurpose::Authentication,
            None,
            None,
            None,
            "hash",
            "state",
            NOW,
            FUTURE,
        )
        .await
        .expect("issue");
    store
        .consume_challenge_if_pending(&challenge_id, NOW)
        .await
        .expect("consume");

    let count = store
        .increment_challenge_attempt(&challenge_id, 5)
        .await
        .expect("increment on a consumed challenge must not error");
    assert_eq!(
        count, 0,
        "the attempt counter must not move once the challenge is no longer pending"
    );
}

#[tokio::test]
async fn pruning_deletes_only_challenges_past_the_cutoff() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let expired_id = unique_id("chal-expired");
    let live_id = unique_id("chal-live");
    store
        .issue_challenge(
            &expired_id,
            ChallengeKind::Webauthn,
            ChallengePurpose::Registration,
            None,
            None,
            None,
            "hash",
            "state",
            PAST,
            PAST,
        )
        .await
        .expect("issue expired");
    store
        .issue_challenge(
            &live_id,
            ChallengeKind::Webauthn,
            ChallengePurpose::Registration,
            None,
            None,
            None,
            "hash",
            "state",
            NOW,
            FUTURE,
        )
        .await
        .expect("issue live");

    let pruned = store.prune_expired_challenges(NOW).await.expect("prune");
    assert_eq!(pruned, 1);

    let error = store
        .get_challenge(&expired_id)
        .await
        .expect_err("the pruned row must be gone");
    assert_eq!(error, AccountsError::ChallengeInvalid);
    store
        .get_challenge(&live_id)
        .await
        .expect("the live row must survive pruning");
}
