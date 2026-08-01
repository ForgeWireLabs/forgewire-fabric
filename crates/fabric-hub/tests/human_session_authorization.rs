//! 114C.4, `114c-4-authorization-intersection` evidence registry entry:
//! "Human role x route policy x dispatcher purpose x approval policy x
//! automation token -- including privilege-union attempts."
//!
//! Tests `resolve_human_session` (the store-facing logic) composed with the
//! pre-existing, unmodified `is_authorized`/`required_roles` gate, rather
//! than a live HTTP request through axum: `HubState` has many fields
//! (`DispatchGate`, `SecretBroker`, `StreamBuffer`, ...) unrelated to
//! authentication, and constructing one fully is out of this slice's scope.
//! `resolve_human_session` takes `&dyn FabricStore` specifically so this
//! logic is testable without any of that -- see its doc comment in
//! `src/auth.rs`. Every test runs against an ephemeral node (114C evidence
//! plan, Rule 2).

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use fabric_accounts::domain::{Account, AccountStatus, ClientKind, Role};
use fabric_accounts::repository::{
    AccountOrchestration, AccountRepository, CredentialRepository, MembershipRepository,
    SessionRepository,
};
use fabric_hub::auth::{
    is_authorized, required_roles, resolve_human_session, HumanSessionOutcome, DEFAULT_REALM_ID,
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

fn now() -> String {
    fabric_store_rqlite::utc_now()
}

const STRONG_PASSWORD: &str = "a genuinely strong hub-auth passphrase";

async fn setup() -> Option<(support::EphemeralRqlite, RqliteStore)> {
    let node = provision_or_skip("human_session_authorization test").await?;
    let store = RqliteStore::new(&node.host, node.http_port, "strong");
    store
        .init_human_accounts_schema()
        .await
        .expect("init_human_accounts_schema");
    Some((node, store))
}

fn sample_account(username: &str) -> Account {
    Account {
        account_id: unique_id("acct"),
        realm_id: DEFAULT_REALM_ID.to_owned(),
        username_normalized: username.to_owned(),
        username_display: username.to_owned(),
        display_name: "Hub Auth Test".into(),
        email_normalized: None,
        status: AccountStatus::Active,
        created_at: now(),
        updated_at: now(),
        disabled_at: None,
        deleted_at: None,
        revision: 0,
        security_version: 0,
    }
}

#[tokio::test]
async fn an_unrecognized_secret_is_not_a_session_and_falls_through() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let outcome =
        resolve_human_session(&store, "not-a-real-secret-of-any-kind", DEFAULT_REALM_ID).await;
    assert!(matches!(outcome, HumanSessionOutcome::NotASession));
}

#[tokio::test]
async fn a_valid_session_authenticates_with_exactly_its_memberships_roles() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("dispatcheruser");
    let account = store
        .bootstrap_first_administrator(
            DEFAULT_REALM_ID,
            &username,
            "Dispatcher User",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    // The bootstrap admin holds only `admin` -- grant `dispatcher` too, since
    // 114C.4 does not invent role implication (see the evidence run for why).
    let membership = fabric_accounts::domain::Membership::for_human(
        unique_id("mem"),
        account.account_id.clone(),
        DEFAULT_REALM_ID.to_owned(),
        Role::Dispatcher,
        None,
        now(),
    )
    .expect("dispatcher is human-assignable");
    store.grant(membership).await.expect("grant dispatcher");

    let login = store
        .authenticate_and_issue_session(
            DEFAULT_REALM_ID,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");

    let outcome = resolve_human_session(
        &store,
        login.access_secret.expose_secret(),
        DEFAULT_REALM_ID,
    )
    .await;
    let HumanSessionOutcome::Authenticated(context) = outcome else {
        panic!("expected Authenticated");
    };
    assert_eq!(context.subject, account.account_id);
    assert_eq!(
        context.human_principal.as_deref(),
        Some(account.account_id.as_str())
    );
    let mut roles = context.roles.clone();
    roles.sort();
    assert_eq!(roles, vec!["admin", "dispatcher"]);
}

#[tokio::test]
async fn a_human_session_cannot_exceed_its_granted_role_even_though_the_route_check_is_the_same_code_path(
) {
    // The acceptance criterion this test exists for: "A signed request
    // cannot exceed the signed-in human's role." A human holding only
    // `observer` must be denied a dispatcher-gated route by the *unmodified*
    // is_authorized/required_roles gate, exactly as a role token with only
    // "observer" would be.
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("observeronly");
    let account = store
        .create_account(sample_account(&username))
        .await
        .expect("create account");
    let credential = fabric_accounts::domain::Credential {
        credential_id: unique_id("cred"),
        account_id: account.account_id.clone(),
        kind: fabric_accounts::domain::CredentialKind::Password,
        secret_verifier: Some(fabric_accounts::secret::SecretString::new(
            fabric_accounts::password::hash_password(STRONG_PASSWORD)
                .unwrap()
                .expose_secret(),
        )),
        algorithm: Some("argon2id".into()),
        algorithm_params: None,
        version: 1,
        public_key_material: None,
        label: None,
        created_at: now(),
        last_used_at: None,
        compromised_at: None,
        revoked_at: None,
        revision: 0,
        backup_eligible: false,
        backup_state: false,
    };
    store
        .add_credential(credential)
        .await
        .expect("add credential");
    let membership = fabric_accounts::domain::Membership::for_human(
        unique_id("mem"),
        account.account_id.clone(),
        DEFAULT_REALM_ID.to_owned(),
        Role::Observer,
        None,
        now(),
    )
    .expect("observer is human-assignable");
    store.grant(membership).await.expect("grant observer");

    let login = store
        .authenticate_and_issue_session(
            DEFAULT_REALM_ID,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");
    let HumanSessionOutcome::Authenticated(context) = resolve_human_session(
        &store,
        login.access_secret.expose_secret(),
        DEFAULT_REALM_ID,
    )
    .await
    else {
        panic!("expected Authenticated");
    };

    // Read-only task listing: observer is sufficient.
    assert!(is_authorized(&context, "GET", "/tasks"));
    // Dispatching a task: observer alone must NOT be sufficient.
    assert!(!is_authorized(&context, "POST", "/tasks"));
    assert_eq!(required_roles("POST", "/tasks"), &["dispatcher"]);
    // Administration: observer must not reach it either.
    assert!(!is_authorized(&context, "GET", "/admin/role-tokens"));
}

#[tokio::test]
async fn an_expired_session_is_rejected_not_silently_downgraded() {
    let Some((node, store)) = setup().await else {
        return;
    };
    let username = unique_id("expiredsession");
    store
        .bootstrap_first_administrator(
            DEFAULT_REALM_ID,
            &username,
            "Expired Session",
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
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");

    // Backdate this session's own expiry columns into the past.
    node.raw_execute(&format!(
        "UPDATE human_sessions SET idle_expires_at='2020-01-01 00:00:00', absolute_expires_at='2020-01-01 00:00:00' WHERE session_id='{}'",
        login.session.session_id
    ))
    .await
    .expect("backdate expiry");

    let outcome = resolve_human_session(
        &store,
        login.access_secret.expose_secret(),
        DEFAULT_REALM_ID,
    )
    .await;
    match outcome {
        HumanSessionOutcome::Rejected { code, .. } => assert_eq!(code, "SessionExpired"),
        _other => panic!("expected Rejected(SessionExpired), got a different outcome"),
    }
}

#[tokio::test]
async fn a_disabled_accounts_still_live_session_is_rejected_as_a_defense_in_depth_check() {
    // disable_account_and_revoke_sessions (114C.3) always revokes sessions
    // together with disabling -- this test exercises the narrower defense-
    // in-depth path where only AccountRepository::update_status runs,
    // proving resolve_human_session does not trust a session's mere
    // existence without re-checking the account's current status.
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("disabledlivesession");
    let account = store
        .bootstrap_first_administrator(
            DEFAULT_REALM_ID,
            &username,
            "Disabled Live Session",
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
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");

    AccountRepository::update_status(&store, &account.account_id, 0, AccountStatus::Disabled)
        .await
        .expect("disable without revoking sessions");

    let outcome = resolve_human_session(
        &store,
        login.access_secret.expose_secret(),
        DEFAULT_REALM_ID,
    )
    .await;
    match outcome {
        HumanSessionOutcome::Rejected { code, .. } => assert_eq!(code, "AccountDisabled"),
        _ => panic!("expected Rejected(AccountDisabled)"),
    }
}

#[tokio::test]
async fn a_revoked_sessions_secret_is_treated_as_not_a_session_documented_limitation() {
    // See resolve_human_session's doc comment: validate_by_access_hash
    // filters revoked_at IS NULL, so a revoked session's secret is
    // indistinguishable from one that never existed at this layer. Access
    // is still correctly denied (NotASession falls through to a role-token
    // lookup that will also fail for this string) -- just via a less
    // specific error than SessionRevoked would give.
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("revokedsession");
    store
        .bootstrap_first_administrator(
            DEFAULT_REALM_ID,
            &username,
            "Revoked Session",
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
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");

    SessionRepository::revoke(&store, &login.session.session_id, "test_revoke", &now())
        .await
        .expect("revoke");

    let outcome = resolve_human_session(
        &store,
        login.access_secret.expose_secret(),
        DEFAULT_REALM_ID,
    )
    .await;
    assert!(matches!(outcome, HumanSessionOutcome::NotASession));
}

#[tokio::test]
async fn resolve_human_session_against_an_unreachable_store_fails_closed() {
    let unreachable = RqliteStore::new("127.0.0.1", 1, "strong");
    let outcome = resolve_human_session(&unreachable, "anything", DEFAULT_REALM_ID).await;
    // An unreachable store can't even determine whether the hash matches a
    // session, so it must fail closed (Rejected), not silently report
    // NotASession -- reporting NotASession here would let a store outage
    // masquerade as "this just isn't a session" and fall through to a
    // role-token lookup that is *also* unreachable, compounding the failure
    // silently instead of surfacing it.
    match outcome {
        HumanSessionOutcome::Rejected { code, .. } => assert_eq!(code, "AuthServiceUnavailable"),
        _ => panic!("expected Rejected(AuthServiceUnavailable)"),
    }
}

#[tokio::test]
async fn membership_changes_take_effect_on_the_next_resolution_without_a_new_login() {
    // "Membership changes take effect cluster-wide" -- because
    // resolve_human_session reads human_memberships fresh on every call
    // rather than caching roles inside the session row, a role grant is
    // visible to the very next request on the same still-valid session,
    // with no re-login required.
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("livemembership");
    let account = store
        .create_account(sample_account(&username))
        .await
        .expect("create account");
    let credential = fabric_accounts::domain::Credential {
        credential_id: unique_id("cred"),
        account_id: account.account_id.clone(),
        kind: fabric_accounts::domain::CredentialKind::Password,
        secret_verifier: Some(fabric_accounts::secret::SecretString::new(
            fabric_accounts::password::hash_password(STRONG_PASSWORD)
                .unwrap()
                .expose_secret(),
        )),
        algorithm: Some("argon2id".into()),
        algorithm_params: None,
        version: 1,
        public_key_material: None,
        label: None,
        created_at: now(),
        last_used_at: None,
        compromised_at: None,
        revoked_at: None,
        revision: 0,
        backup_eligible: false,
        backup_state: false,
    };
    store
        .add_credential(credential)
        .await
        .expect("add credential");
    let login = store
        .authenticate_and_issue_session(
            DEFAULT_REALM_ID,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");

    let HumanSessionOutcome::Authenticated(before) = resolve_human_session(
        &store,
        login.access_secret.expose_secret(),
        DEFAULT_REALM_ID,
    )
    .await
    else {
        panic!("expected Authenticated");
    };
    assert!(before.roles.is_empty(), "no membership granted yet");
    assert!(!is_authorized(&before, "POST", "/tasks"));

    let membership = fabric_accounts::domain::Membership::for_human(
        unique_id("mem"),
        account.account_id.clone(),
        DEFAULT_REALM_ID.to_owned(),
        Role::Dispatcher,
        None,
        now(),
    )
    .expect("dispatcher is human-assignable");
    store.grant(membership).await.expect("grant dispatcher");

    let HumanSessionOutcome::Authenticated(after) = resolve_human_session(
        &store,
        login.access_secret.expose_secret(),
        DEFAULT_REALM_ID,
    )
    .await
    else {
        panic!("expected Authenticated");
    };
    assert_eq!(after.roles, vec!["dispatcher"]);
    assert!(
        is_authorized(&after, "POST", "/tasks"),
        "the same still-valid session must reflect the new role immediately"
    );
}

#[tokio::test]
async fn a_revoked_membership_no_longer_grants_its_role_on_the_same_still_valid_session() {
    // The mirror image of the previous test: a revocation must also take
    // effect immediately, on the same session, with no re-login and no
    // window where the old role keeps working.
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("revokedmembership");
    let account = store
        .create_account(sample_account(&username))
        .await
        .expect("create account");
    let credential = fabric_accounts::domain::Credential {
        credential_id: unique_id("cred"),
        account_id: account.account_id.clone(),
        kind: fabric_accounts::domain::CredentialKind::Password,
        secret_verifier: Some(fabric_accounts::secret::SecretString::new(
            fabric_accounts::password::hash_password(STRONG_PASSWORD)
                .unwrap()
                .expose_secret(),
        )),
        algorithm: Some("argon2id".into()),
        algorithm_params: None,
        version: 1,
        public_key_material: None,
        label: None,
        created_at: now(),
        last_used_at: None,
        compromised_at: None,
        revoked_at: None,
        revision: 0,
        backup_eligible: false,
        backup_state: false,
    };
    store
        .add_credential(credential)
        .await
        .expect("add credential");
    let membership = fabric_accounts::domain::Membership::for_human(
        unique_id("mem"),
        account.account_id.clone(),
        DEFAULT_REALM_ID.to_owned(),
        Role::Dispatcher,
        None,
        now(),
    )
    .expect("dispatcher is human-assignable");
    let membership_id = membership.membership_id.clone();
    store.grant(membership).await.expect("grant dispatcher");
    let login = store
        .authenticate_and_issue_session(
            DEFAULT_REALM_ID,
            &username,
            STRONG_PASSWORD,
            ClientKind::Vsix,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");

    let HumanSessionOutcome::Authenticated(before) = resolve_human_session(
        &store,
        login.access_secret.expose_secret(),
        DEFAULT_REALM_ID,
    )
    .await
    else {
        panic!("expected Authenticated");
    };
    assert_eq!(before.roles, vec!["dispatcher"]);

    MembershipRepository::revoke(&store, &membership_id, &now())
        .await
        .expect("revoke dispatcher");

    let HumanSessionOutcome::Authenticated(after) = resolve_human_session(
        &store,
        login.access_secret.expose_secret(),
        DEFAULT_REALM_ID,
    )
    .await
    else {
        panic!("expected Authenticated");
    };
    assert!(
        after.roles.is_empty(),
        "a revoked membership must not appear in effective roles"
    );
    assert!(
        !is_authorized(&after, "POST", "/tasks"),
        "the revoked role must no longer authorize dispatch on the same session"
    );
}

// -- 114C.6 administrative step-up gate ----------------------------------------

/// Compose the same two checks `require_bearer` applies for a step-up-gated
/// route -- role authorization (`is_authorized`) AND freshness
/// (`requires_step_up` + `step_up_is_fresh` against the resolved context) --
/// so the gate's decision is tested end-to-end against a real resolved
/// session, without standing up axum. Returns true iff the request would be
/// allowed through.
fn step_up_allows(
    context: &fabric_hub::auth::AuthContext,
    method: &str,
    path: &str,
    now: &str,
    freshness_minutes: i64,
) -> bool {
    use fabric_hub::auth::{requires_step_up, step_up_is_fresh};
    if !is_authorized(context, method, path) {
        return false;
    }
    if requires_step_up(method, path) && context.human_principal.is_some() {
        let fresh = context.assurance_level.as_deref() == Some("aal2")
            && context
                .step_up_at
                .as_deref()
                .map(|at| step_up_is_fresh(at, now, freshness_minutes))
                .unwrap_or(false);
        if !fresh {
            return false;
        }
    }
    true
}

#[tokio::test]
async fn a_stale_aal1_admin_session_is_denied_a_step_up_gated_route() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("aal1admin");
    store
        .bootstrap_first_administrator(
            DEFAULT_REALM_ID,
            &username,
            "Aal1 Admin",
            STRONG_PASSWORD,
            &now(),
        )
        .await
        .expect("bootstrap");
    // Password login -> Aal1, no step_up_at.
    let login = store
        .authenticate_and_issue_session(
            DEFAULT_REALM_ID,
            &username,
            STRONG_PASSWORD,
            ClientKind::Cli,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");
    let HumanSessionOutcome::Authenticated(context) = resolve_human_session(
        &store,
        login.access_secret.expose_secret(),
        DEFAULT_REALM_ID,
    )
    .await
    else {
        panic!("expected Authenticated");
    };

    // Role check passes (this is an admin), but the step-up gate denies a
    // sensitive route because the session is Aal1 with no recent step-up.
    assert!(is_authorized(&context, "POST", "/accounts/acct-1/delete"));
    assert!(
        !step_up_allows(&context, "POST", "/accounts/acct-1/delete", &now(), 10),
        "a stale Aal1 admin session must be denied a step-up-gated route"
    );
    // A non-sensitive admin route (enable) is still allowed for the same
    // session -- step-up gates only the sensitive set.
    assert!(step_up_allows(
        &context,
        "POST",
        "/accounts/acct-1/enable",
        &now(),
        10
    ));
}

#[tokio::test]
async fn a_fresh_aal2_admin_session_passes_a_step_up_gated_route_until_the_window_lapses() {
    let Some((_node, store)) = setup().await else {
        return;
    };
    let username = unique_id("aal2admin");
    store
        .bootstrap_first_administrator(
            DEFAULT_REALM_ID,
            &username,
            "Aal2 Admin",
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
            ClientKind::Cli,
            None,
            None,
            60,
            24,
            &now(),
        )
        .await
        .expect("login");

    // Elevate this session to Aal2, stamping step_up_at at a fixed instant.
    // `elevate` rotates the access secret and returns the *new* one -- resolve
    // the (now elevated) session through it, exercising the real
    // AuthContext-population path in `resolve_human_session`, not a synthetic
    // context.
    let step_up_time = "2026-07-17 12:00:00";
    let new_secret =
        fabric_accounts::repository::SessionRepository::rotate_access_secret_and_elevate(
            &store,
            &login.session.session_id,
            step_up_time,
        )
        .await
        .expect("elevate");

    let HumanSessionOutcome::Authenticated(context) =
        resolve_human_session(&store, new_secret.expose_secret(), DEFAULT_REALM_ID).await
    else {
        panic!("expected Authenticated via the post-elevation secret");
    };
    // The resolved context reflects the elevated session: Aal2, step_up_at set.
    assert_eq!(context.assurance_level.as_deref(), Some("aal2"));
    assert_eq!(context.step_up_at.as_deref(), Some(step_up_time));

    // Within the 10-minute window: allowed on a step-up-gated route.
    assert!(step_up_allows(
        &context,
        "POST",
        "/accounts/acct-1/delete",
        "2026-07-17 12:09:59",
        10
    ));
    // Past the window: denied, even though the session is still Aal2 --
    // "administrative step-up cannot be satisfied by a stale lower-assurance
    // session" extends to a stale *higher*-assurance one too.
    assert!(!step_up_allows(
        &context,
        "POST",
        "/accounts/acct-1/delete",
        "2026-07-17 12:10:01",
        10
    ));
}
