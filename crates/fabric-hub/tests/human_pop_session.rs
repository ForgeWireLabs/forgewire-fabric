//! 114E Slice 1: server-side proof-of-possession (key-bound, signed-request)
//! human sessions. Exercises `resolve_signed_session` directly against an
//! ephemeral rqlite node with a real Ed25519 keypair
//! (`fabric_identity::generate`) signing the canonical request envelope via
//! the same `fabric_protocol` primitives the hub verifies with -- so the
//! test proves the signer and verifier agree, not just that the verifier
//! accepts its own output. Parallels `human_session_authorization.rs`'s use
//! of `resolve_human_session`. Every test runs against an ephemeral node
//! (114C evidence plan, Rule 2).

mod support;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fabric_accounts::domain::ClientKind;
use fabric_accounts::repository::{AccountOrchestration, SessionRepository};
use fabric_hub::auth::{
    resolve_human_session, resolve_signed_session, HumanSessionOutcome, DEFAULT_REALM_ID,
};
use fabric_identity::IdentityFile;
use fabric_store_rqlite::RqliteStore;
use serde_json::json;
use sha2::{Digest, Sha256};
use support::provision_or_skip;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_id(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{nanos}-{n}")
}

fn now() -> String {
    fabric_store_rqlite::utc_now()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const STRONG_PASSWORD: &str = "a genuinely strong pop-session passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_pop_session test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

/// Bootstrap an admin, log in (password), and bind `identity`'s public key to
/// the issued session. Returns `(account_id, session_id, access_secret)` --
/// the access secret lets the coexistence test still authenticate the same
/// session by bearer.
async fn seed_key_bound_session(
    store: &RqliteStore,
    identity: &IdentityFile,
) -> (String, String, String) {
    let username = unique_id("pop-admin");
    let account = store
        .bootstrap_first_administrator(
            DEFAULT_REALM_ID,
            &username,
            "PoP Admin",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    let login = store
        .authenticate_and_issue_session(
            DEFAULT_REALM_ID,
            &username,
            STRONG_PASSWORD,
            ClientKind::Desktop,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");
    store
        .bind_public_key(&login.session.session_id, &identity.public_key_hex, &now())
        .await
        .expect("bind public key");
    (
        account.account_id,
        login.session.session_id,
        login.access_secret.expose_secret().to_owned(),
    )
}

/// Sign the canonical session-request envelope exactly as a PoP client would
/// -- must stay byte-identical to `resolve_signed_session`'s reconstruction.
fn sign_request(
    identity: &IdentityFile,
    session_id: &str,
    timestamp: i64,
    nonce: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> String {
    let envelope = json!({
        "op": "session-request",
        "session_id": session_id,
        "method": method,
        "path": path,
        "body_sha256": hex::encode(Sha256::digest(body)),
        "timestamp": timestamp,
        "nonce": nonce,
    });
    fabric_protocol::sign_envelope_hex(&identity.secret_key_hex, &envelope).expect("sign envelope")
}

#[tokio::test]
async fn a_correctly_signed_request_authenticates_with_the_accounts_roles() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let identity = fabric_identity::generate("pop-session", fabric_types::KeyPurpose::Dispatcher);
    let (account_id, session_id, _access) = seed_key_bound_session(&store, &identity).await;

    let ts = now_unix();
    let nonce = unique_id("nonce");
    let sig = sign_request(&identity, &session_id, ts, &nonce, "GET", "/auth/me", b"");

    let outcome = resolve_signed_session(
        &store,
        &session_id,
        ts,
        &nonce,
        &sig,
        "GET",
        "/auth/me",
        b"",
    )
    .await;
    let HumanSessionOutcome::Authenticated(context) = outcome else {
        panic!("expected Authenticated, got a rejection");
    };
    assert_eq!(
        context.human_principal.as_deref(),
        Some(account_id.as_str())
    );
    assert_eq!(context.roles, vec!["admin"]);
}

#[tokio::test]
async fn a_signature_from_the_wrong_key_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let bound = fabric_identity::generate("bound", fabric_types::KeyPurpose::Dispatcher);
    let attacker = fabric_identity::generate("attacker", fabric_types::KeyPurpose::Dispatcher);
    let (_account, session_id, _access) = seed_key_bound_session(&store, &bound).await;

    let ts = now_unix();
    let nonce = unique_id("nonce");
    // Signed with the attacker's key, but the session is bound to `bound`.
    let sig = sign_request(&attacker, &session_id, ts, &nonce, "GET", "/auth/me", b"");

    let outcome = resolve_signed_session(
        &store,
        &session_id,
        ts,
        &nonce,
        &sig,
        "GET",
        "/auth/me",
        b"",
    )
    .await;
    assert!(matches!(
        outcome,
        HumanSessionOutcome::Rejected {
            code: "InvalidSignature",
            ..
        }
    ));
}

#[tokio::test]
async fn a_tampered_body_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let identity = fabric_identity::generate("pop", fabric_types::KeyPurpose::Dispatcher);
    let (_account, session_id, _access) = seed_key_bound_session(&store, &identity).await;

    let ts = now_unix();
    let nonce = unique_id("nonce");
    // Sign for the operator's real body, verify against a swapped one -- the
    // exact body-substitution attack `body_sha256` exists to defeat.
    let signed_body = br#"{"role":"reviewer"}"#;
    let swapped_body = br#"{"role":"admin"}"#;
    let sig = sign_request(
        &identity,
        &session_id,
        ts,
        &nonce,
        "POST",
        "/accounts/acct-1/membership",
        signed_body,
    );

    let outcome = resolve_signed_session(
        &store,
        &session_id,
        ts,
        &nonce,
        &sig,
        "POST",
        "/accounts/acct-1/membership",
        swapped_body,
    )
    .await;
    assert!(matches!(
        outcome,
        HumanSessionOutcome::Rejected {
            code: "InvalidSignature",
            ..
        }
    ));
}

#[tokio::test]
async fn a_tampered_method_or_path_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let identity = fabric_identity::generate("pop", fabric_types::KeyPurpose::Dispatcher);
    let (_account, session_id, _access) = seed_key_bound_session(&store, &identity).await;

    let ts = now_unix();
    let nonce = unique_id("nonce");
    let sig = sign_request(&identity, &session_id, ts, &nonce, "GET", "/auth/me", b"");

    // Same signature replayed against a different path must not verify.
    let outcome = resolve_signed_session(
        &store,
        &session_id,
        ts,
        &nonce,
        &sig,
        "GET",
        "/accounts",
        b"",
    )
    .await;
    assert!(matches!(
        outcome,
        HumanSessionOutcome::Rejected {
            code: "InvalidSignature",
            ..
        }
    ));
}

#[tokio::test]
async fn a_stale_timestamp_is_rejected_before_any_signature_check() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let identity = fabric_identity::generate("pop", fabric_types::KeyPurpose::Dispatcher);
    let (_account, session_id, _access) = seed_key_bound_session(&store, &identity).await;

    // Well outside the +/-300s skew window.
    let ts = now_unix() - 100_000;
    let nonce = unique_id("nonce");
    let sig = sign_request(&identity, &session_id, ts, &nonce, "GET", "/auth/me", b"");

    let outcome = resolve_signed_session(
        &store,
        &session_id,
        ts,
        &nonce,
        &sig,
        "GET",
        "/auth/me",
        b"",
    )
    .await;
    assert!(matches!(
        outcome,
        HumanSessionOutcome::Rejected {
            code: "SignatureTimestampSkew",
            ..
        }
    ));
}

#[tokio::test]
async fn a_bearer_only_session_is_rejected_on_the_signed_path() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    // Log in WITHOUT binding a key -- a plain 114C bearer session.
    let username = unique_id("bearer-only");
    store
        .bootstrap_first_administrator(
            DEFAULT_REALM_ID,
            &username,
            "Bearer Only",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    let login = store
        .authenticate_and_issue_session(
            DEFAULT_REALM_ID,
            &username,
            STRONG_PASSWORD,
            ClientKind::Desktop,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");

    let identity = fabric_identity::generate("pop", fabric_types::KeyPurpose::Dispatcher);
    let ts = now_unix();
    let nonce = unique_id("nonce");
    let sig = sign_request(
        &identity,
        &login.session.session_id,
        ts,
        &nonce,
        "GET",
        "/auth/me",
        b"",
    );

    let outcome = resolve_signed_session(
        &store,
        &login.session.session_id,
        ts,
        &nonce,
        &sig,
        "GET",
        "/auth/me",
        b"",
    )
    .await;
    assert!(matches!(
        outcome,
        HumanSessionOutcome::Rejected {
            code: "SessionNotKeyBound",
            ..
        }
    ));
}

#[tokio::test]
async fn a_revoked_session_is_rejected_on_the_signed_path() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let identity = fabric_identity::generate("pop", fabric_types::KeyPurpose::Dispatcher);
    let (_account, session_id, _access) = seed_key_bound_session(&store, &identity).await;
    store
        .revoke(&session_id, "logout", &now())
        .await
        .expect("revoke");

    let ts = now_unix();
    let nonce = unique_id("nonce");
    let sig = sign_request(&identity, &session_id, ts, &nonce, "GET", "/auth/me", b"");

    let outcome = resolve_signed_session(
        &store,
        &session_id,
        ts,
        &nonce,
        &sig,
        "GET",
        "/auth/me",
        b"",
    )
    .await;
    assert!(matches!(
        outcome,
        HumanSessionOutcome::Rejected {
            code: "SessionRevoked",
            ..
        }
    ));
}

#[tokio::test]
async fn an_unknown_session_id_is_rejected() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let identity = fabric_identity::generate("pop", fabric_types::KeyPurpose::Dispatcher);
    let ts = now_unix();
    let nonce = unique_id("nonce");
    let sig = sign_request(
        &identity,
        "no-such-session",
        ts,
        &nonce,
        "GET",
        "/auth/me",
        b"",
    );

    let outcome = resolve_signed_session(
        &store,
        "no-such-session",
        ts,
        &nonce,
        &sig,
        "GET",
        "/auth/me",
        b"",
    )
    .await;
    assert!(matches!(
        outcome,
        HumanSessionOutcome::Rejected {
            code: "SessionExpired",
            ..
        }
    ));
}

#[tokio::test]
async fn a_key_bound_sessions_bearer_secret_still_authenticates_by_bearer() {
    // Coexistence: binding a session key does not disable the bearer path.
    // (Later slices stop the client from *sending* the bearer; the server
    // still accepts it during the transition.)
    let Some((_node, store)) = setup().await else {
        return;
    };
    let identity = fabric_identity::generate("pop", fabric_types::KeyPurpose::Dispatcher);
    let (account_id, _session_id, access) = seed_key_bound_session(&store, &identity).await;

    let outcome = resolve_human_session(&store, &access, DEFAULT_REALM_ID).await;
    let HumanSessionOutcome::Authenticated(context) = outcome else {
        panic!("expected the bearer secret to still authenticate the key-bound session");
    };
    assert_eq!(
        context.human_principal.as_deref(),
        Some(account_id.as_str())
    );
}
