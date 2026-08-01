//! Self-service authentication routes (114C.3 debt closeout, shipped ahead of
//! 114C.6 since passkey/step-up work is unreachable without it).
//!
//! - GET  /auth/bootstrap/status   (public)
//! - POST /auth/bootstrap          (public, loopback-only)
//! - POST /auth/login              (public)
//! - POST /auth/refresh            (public)
//! - POST /auth/logout             (authenticated)
//! - POST /auth/logout-all         (authenticated)
//! - GET  /auth/me                 (authenticated)
//!
//! `AccountOrchestration::bootstrap_first_administrator` and
//! `authenticate_and_issue_session` (114C.3) were fully implemented and
//! tested from the start -- this module is pure HTTP wiring on top of
//! already-proven orchestration logic, not new domain behavior. Named
//! `authn.rs`, not `auth.rs`: that name already belongs to
//! `crate::auth`, the authorization/bearer-resolution module every route
//! file (including this one) imports from.
//!
//! Bootstrap and login/refresh sit on the *public* router tier
//! (`public_router`, merged in `main.rs` before the `require_bearer`
//! layer applies) -- a caller with no credential yet, or a possibly-expired
//! one, cannot reach an authenticated-tier route to obtain one. Logout/
//! logout-all/me require an existing credential and stay on the
//! authenticated tier, gated at the same coarse "any authenticated human"
//! bucket `/auth/sessions*` already uses (see `crate::auth::required_roles`).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Extension, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use fabric_accounts::domain::{ClientKind, Credential, CredentialKind};
use fabric_accounts::dto::PasskeySummaryDto;
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{
    AccountOrchestration, AccountRepository, CredentialRepository, SessionRepository,
};
use fabric_accounts::secrets::{generate_opaque_secret, hash_opaque_secret};
use fabric_accounts::webauthn::{ChallengeKind, ChallengePurpose, ChallengeRepository};
use fabric_settings::SettingsSnapshot;
use webauthn_rs::prelude::{CredentialID, Passkey, Uuid};

use crate::auth::{constant_time_eq, AuthContext, DEFAULT_REALM_ID};
use crate::error::ApiError;
use crate::state::HubState;
use crate::utils::{attribution, audit_append, utc_now, utc_now_plus_secs};

use super::accounts::account_summary;

/// WebAuthn ceremony challenges are seconds-scale, much shorter than a
/// session TTL -- 5 minutes is generous for a human to complete a
/// registration/authentication prompt.
const CEREMONY_CHALLENGE_TTL_SECS: i64 = 300;

/// Fallback used when the settings document is unreadable/invalid, or a key
/// is absent -- matches `config/settings.defaults.json`'s `auth.sessions.
/// idle_timeout_minutes`. A malformed settings overlay must never make login
/// itself fail; it degrades to this compiled-in value instead.
const DEFAULT_IDLE_TIMEOUT_MINUTES: i64 = 60;
/// Fallback for `auth.sessions.absolute_timeout_hours`; see
/// [`DEFAULT_IDLE_TIMEOUT_MINUTES`]'s doc comment for why this is a fallback
/// rather than the only value.
const DEFAULT_ABSOLUTE_TIMEOUT_HOURS: i64 = 24;
/// Fallback for `auth.bootstrap.local_only`.
const DEFAULT_BOOTSTRAP_LOCAL_ONLY: bool = true;

const BOOTSTRAP_SECRET_HEADER: &str = "x-forgewire-bootstrap-secret";

/// Resolve the live `auth.*` settings overlay (defaults merged with the
/// hub's rqlite override document, per `fabric-settings`'s three-tier
/// model). Best-effort: an unreadable or invalid settings document falls
/// back to an empty object, which `setting_i64`/`setting_bool` below then
/// resolve to their own hardcoded defaults -- a settings-store hiccup must
/// degrade authentication to compiled-in defaults, never fail it outright.
async fn effective_auth_settings(state: &HubState) -> Value {
    let Ok(document) = state.store.get_settings_document().await else {
        return json!({});
    };
    SettingsSnapshot::new(document.revision, document.value, json!({}))
        .map(|snapshot| snapshot.effective)
        .unwrap_or_else(|_| json!({}))
}

fn setting_i64(effective: &Value, pointer: &str, default: i64) -> i64 {
    effective
        .pointer(pointer)
        .and_then(Value::as_i64)
        .unwrap_or(default)
}

fn setting_bool(effective: &Value, pointer: &str, default: bool) -> bool {
    effective
        .pointer(pointer)
        .and_then(Value::as_bool)
        .unwrap_or(default)
}

owned_router! {
    pub fn public_router, PUBLIC_ROUTES {
        "GET" get "/auth/bootstrap/status" => bootstrap_status;
        "POST" post "/auth/bootstrap" => bootstrap;
        "POST" post "/auth/login" => login;
        "POST" post "/auth/refresh" => refresh;
        "POST" post "/auth/passkeys/options" => passkey_login_options;
        "POST" post "/auth/passkeys/verify" => passkey_login_verify;
    }
}

owned_router! {
    pub fn router, ROUTES {
        "POST" post "/auth/logout" => logout;
        "POST" post "/auth/logout-all" => logout_all;
        "GET" get "/auth/me" => me;
        "POST" post "/auth/passkeys/register/options" => register_passkey_options;
        "POST" post "/auth/passkeys/register/verify" => register_passkey_verify;
        "DELETE" delete "/auth/passkeys/{credential_id}" => remove_passkey;
        "POST" post "/auth/step-up/options" => step_up_options;
        "POST" post "/auth/step-up/verify" => step_up_verify;
    }
}

fn parse_client_kind(raw: Option<&str>) -> ClientKind {
    match raw {
        Some("vsix") => ClientKind::Vsix,
        Some("desktop") => ClientKind::Desktop,
        Some("cli") => ClientKind::Cli,
        _ => ClientKind::Other,
    }
}

/// True if the source is an allowed bootstrap origin: when `local_only` is
/// set (the default, `auth.bootstrap.local_only`), `addr` must be loopback
/// (127.0.0.0/8 or ::1); AND, when a bootstrap secret is configured,
/// `presented` must constant-time-match it. A `None` `configured_secret`
/// means the source check alone satisfies the plan's "protected by a
/// one-time bootstrap secret or local console proof" -- the two are
/// alternatives, not both mandatory. Disabling `local_only` with no
/// configured secret allows bootstrap from any network source; that is an
/// explicit, documented operator risk-acceptance, not a default. Pure and
/// free of any store/network dependency specifically so it is unit-testable
/// without constructing a `HubState` or driving a real request through
/// axum's connect-info extraction.
fn bootstrap_source_allowed(
    addr: SocketAddr,
    local_only: bool,
    presented: Option<&str>,
    configured_secret: Option<&str>,
) -> bool {
    if local_only && !addr.ip().is_loopback() {
        return false;
    }
    match configured_secret {
        None => true,
        Some(expected) => presented
            .map(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
            .unwrap_or(false),
    }
}

/// True if `challenge` may legitimately be redeemed here: its `purpose`
/// matches `expected_purpose`, its `account_id` matches `expected_account_id`
/// (a challenge bound to no account, or a different one, is never
/// redeemable by this caller), and `presented_options_token` hashes to the
/// stored `challenge_hash`. Pure and free of any store/crypto dependency
/// specifically so it is unit-testable in isolation from a full ceremony --
/// an earlier version of this check inlined into `register_passkey_verify`
/// could not be exercised by a mutation test independent of
/// `finish_passkey_registration`'s own failure path, which happens to also
/// reject every malformed test fixture regardless of whether the binding
/// check ran at all.
fn challenge_binding_ok(
    challenge: &fabric_accounts::webauthn::AuthChallenge,
    expected_purpose: ChallengePurpose,
    expected_account_id: &str,
    presented_options_token: &str,
) -> bool {
    let presented_hash = hash_opaque_secret(presented_options_token);
    challenge.purpose == expected_purpose
        && challenge.account_id.as_deref() == Some(expected_account_id)
        && constant_time_eq(
            presented_hash.as_bytes(),
            challenge.challenge_hash.as_bytes(),
        )
}

/// The login-ceremony counterpart to [`challenge_binding_ok`]: at
/// `/auth/passkeys/verify` the caller is not yet authenticated, so there is
/// no "expected account" to check the challenge against -- the account is
/// *resolved from* the challenge itself (bound at `/auth/passkeys/options`,
/// which already required knowing a real username). Checks purpose,
/// options_token, and that the challenge is bound to *some* account (an
/// account-less challenge is never valid for login, unlike registration/
/// step-up where the caller's own identity is always the expected value).
fn login_challenge_binding_ok(
    challenge: &fabric_accounts::webauthn::AuthChallenge,
    presented_options_token: &str,
) -> bool {
    let presented_hash = hash_opaque_secret(presented_options_token);
    challenge.purpose == ChallengePurpose::Authentication
        && challenge.account_id.is_some()
        && constant_time_eq(
            presented_hash.as_bytes(),
            challenge.challenge_hash.as_bytes(),
        )
}

// ---- GET /auth/bootstrap/status --------------------------------------------------

pub async fn bootstrap_status(State(state): State<Arc<HubState>>) -> Result<Json<Value>, ApiError> {
    let bootstrap_open = AccountOrchestration::bootstrap_status(&*state.store)
        .await
        .map_err(ApiError::account)?;
    Ok(Json(json!({ "bootstrap_open": bootstrap_open })))
}

// ---- POST /auth/bootstrap --------------------------------------------------------

#[derive(Deserialize)]
pub struct BootstrapRequest {
    pub username: String,
    pub display_name: String,
    pub password: String,
}

impl std::fmt::Debug for BootstrapRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapRequest")
            .field("username", &self.username)
            .field("display_name", &self.display_name)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

pub async fn bootstrap(
    State(state): State<Arc<HubState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<BootstrapRequest>,
) -> Result<Json<Value>, ApiError> {
    let presented = headers
        .get(BOOTSTRAP_SECRET_HEADER)
        .and_then(|v| v.to_str().ok());
    let effective = effective_auth_settings(&state).await;
    let local_only = setting_bool(
        &effective,
        "/auth/bootstrap/local_only",
        DEFAULT_BOOTSTRAP_LOCAL_ONLY,
    );
    if !bootstrap_source_allowed(
        addr,
        local_only,
        presented,
        state.bootstrap_secret.as_deref(),
    ) {
        return Err(ApiError::account(AccountsError::BootstrapLocalOnly));
    }
    let now = utc_now();
    let account = AccountOrchestration::bootstrap_first_administrator(
        &*state.store,
        DEFAULT_REALM_ID,
        &request.username,
        &request.display_name,
        &request.password,
        &now,
    )
    .await
    .map_err(ApiError::account)?;
    let summary = account_summary(&state, &account).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.bootstrap_completed",
        None,
        &json!({ "account_id": account.account_id, "username": account.username_normalized }),
    )
    .await;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- POST /auth/login ------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub client_kind: Option<String>,
    #[serde(default)]
    pub client_label: Option<String>,
    /// 114E: an optional hex Ed25519 public key the client generated for
    /// this session. When present it is bound to the issued session so the
    /// client can authenticate later requests by signature (proof of
    /// possession) rather than by presenting the opaque access secret. A
    /// public key, not a secret -- omitted => a bearer-only session (114C).
    #[serde(default)]
    pub session_public_key: Option<String>,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("client_kind", &self.client_kind)
            .field("client_label", &self.client_label)
            .field("session_public_key", &self.session_public_key)
            .finish()
    }
}

pub async fn login(
    State(state): State<Arc<HubState>>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = utc_now();
    let effective = effective_auth_settings(&state).await;
    let idle_timeout_minutes = setting_i64(
        &effective,
        "/auth/sessions/idle_timeout_minutes",
        DEFAULT_IDLE_TIMEOUT_MINUTES,
    );
    let absolute_timeout_hours = setting_i64(
        &effective,
        "/auth/sessions/absolute_timeout_hours",
        DEFAULT_ABSOLUTE_TIMEOUT_HOURS,
    );
    let outcome = AccountOrchestration::authenticate_and_issue_session(
        &*state.store,
        DEFAULT_REALM_ID,
        &request.username,
        &request.password,
        parse_client_kind(request.client_kind.as_deref()),
        request.client_label.as_deref(),
        None,
        idle_timeout_minutes,
        absolute_timeout_hours,
        &now,
    )
    .await
    .map_err(ApiError::account)?;
    bind_session_key_if_present(
        &state,
        &outcome,
        request.session_public_key.as_deref(),
        &now,
    )
    .await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.login_succeeded",
        None,
        &json!({
            "account_id": outcome.session.account_id,
            "session_id": outcome.session.session_id,
            "client_kind": outcome.session.client_kind.as_str(),
        }),
    )
    .await;
    Ok(Json(json!({
        "session_id": outcome.session.session_id,
        "account_id": outcome.session.account_id,
        "assurance_level": outcome.session.assurance_level.as_str(),
        "access_secret": outcome.access_secret.expose_secret(),
        "refresh_secret": outcome.refresh_secret.expose_secret(),
        "idle_expires_at": outcome.session.idle_expires_at,
        "absolute_expires_at": outcome.session.absolute_expires_at,
    })))
}

/// 114E: bind a client-supplied session public key to a freshly-issued
/// session so it authenticates by request signature thereafter. Shared by
/// password login and passkey login. A bind failure on a fresh session
/// (which should never happen -- the key is NULL and the session is not
/// revoked) is surfaced as an error rather than silently downgrading the
/// client to a bearer-only session it did not ask for.
async fn bind_session_key_if_present(
    state: &HubState,
    outcome: &fabric_accounts::repository::LoginOutcome,
    session_public_key: Option<&str>,
    now: &str,
) -> Result<(), ApiError> {
    if let Some(public_key) = session_public_key {
        SessionRepository::bind_public_key(
            &*state.store,
            &outcome.session.session_id,
            public_key,
            now,
        )
        .await
        .map_err(ApiError::account)?;
    }
    Ok(())
}

// ---- POST /auth/refresh ----------------------------------------------------------

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub session_id: String,
    pub refresh_secret: String,
}

impl std::fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshRequest")
            .field("session_id", &self.session_id)
            .field("refresh_secret", &"[REDACTED]")
            .finish()
    }
}

pub async fn refresh(
    State(state): State<Arc<HubState>>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = utc_now();
    let presented_hash = hash_opaque_secret(&request.refresh_secret);
    let new_refresh_secret = generate_opaque_secret();
    let new_refresh_hash = hash_opaque_secret(new_refresh_secret.expose_secret());
    let result = SessionRepository::rotate_refresh(
        &*state.store,
        &request.session_id,
        &presented_hash,
        &new_refresh_hash,
        &now,
    )
    .await;
    let session = match result {
        Ok(session) => session,
        Err(error) => {
            // The store already revoked the whole refresh family on replay
            // (see `rotate_refresh`'s own doc comment) -- this only records
            // the security event, which the store deliberately leaves to
            // the HTTP layer to emit.
            if matches!(error, AccountsError::RefreshReplayDetected) {
                let _ = audit_append(
                    &*state.store,
                    &state.secrets,
                    "account.refresh_replay_detected",
                    None,
                    &json!({ "session_id": request.session_id }),
                )
                .await;
            }
            return Err(ApiError::account(error));
        }
    };
    Ok(Json(json!({
        "session_id": session.session_id,
        "refresh_secret": new_refresh_secret.expose_secret(),
        "idle_expires_at": session.idle_expires_at,
        "absolute_expires_at": session.absolute_expires_at,
    })))
}

// ---- POST /auth/logout -----------------------------------------------------------

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub session_id: String,
}

pub async fn logout(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(request): Json<LogoutRequest>,
) -> Result<Json<Value>, ApiError> {
    let session = SessionRepository::get(&*state.store, &request.session_id)
        .await
        .map_err(|error| {
            if let AccountsError::AccountPolicyViolation { ref reason } = error {
                if reason == "session_not_found" {
                    return ApiError::not_found("session not found");
                }
            }
            ApiError::account(error)
        })?;
    let is_admin = actor.roles.iter().any(|r| r == "admin");
    let is_owner = actor.human_principal.as_deref() == Some(session.account_id.as_str());
    if !is_owner && !is_admin {
        return Err(ApiError::account(AccountsError::RolePolicyViolation));
    }
    let now = utc_now();
    SessionRepository::revoke(&*state.store, &request.session_id, "logout", &now)
        .await
        .map_err(ApiError::account)?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.logout",
        None,
        &json!({ "session_id": request.session_id, "account_id": session.account_id, "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(
        json!({ "session_id": request.session_id, "revoked": true }),
    ))
}

// ---- POST /auth/logout-all -------------------------------------------------------

pub async fn logout_all(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
) -> Result<Json<Value>, ApiError> {
    let Some(account_id) = actor.human_principal.clone() else {
        return Err(ApiError::account(AccountsError::RolePolicyViolation));
    };
    let now = utc_now();
    let revoked =
        SessionRepository::revoke_all_for_account(&*state.store, &account_id, "logout_all", &now)
            .await
            .map_err(ApiError::account)?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.logout_all",
        None,
        &json!({ "account_id": account_id, "revoked_count": revoked, "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(
        json!({ "account_id": account_id, "revoked_count": revoked }),
    ))
}

// ---- GET /auth/me -----------------------------------------------------------------

pub async fn me(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
) -> Result<Json<Value>, ApiError> {
    let Some(account_id) = actor.human_principal.clone() else {
        return Err(ApiError::account(AccountsError::RolePolicyViolation));
    };
    let account = AccountRepository::get_account(&*state.store, &account_id)
        .await
        .map_err(ApiError::account)?;
    let summary = account_summary(&state, &account).await?;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- POST /auth/passkeys/register/options ------------------------------------------

fn passkeys_not_configured() -> ApiError {
    ApiError::account(AccountsError::AccountPolicyViolation {
        reason: "passkeys_not_configured".to_owned(),
    })
}

/// Deterministic WebAuthn user handle derived from `account_id` -- stable
/// across every ceremony for the same account (a fresh random handle per
/// registration would be wrong: the authenticator/platform associates a
/// discoverable credential with this handle, so it must not change).
fn webauthn_user_handle(account_id: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, account_id.as_bytes())
}

/// Existing WebAuthn credentials for `account_id`, deserialized back into
/// `Passkey`s -- used both to populate `exclude_credentials` at
/// registration (don't let the same authenticator register twice) and to
/// supply `start_passkey_authentication`'s candidate list at login (114C.6
/// Slice 3).
async fn existing_passkeys(
    state: &HubState,
    account_id: &str,
) -> Result<Vec<(Credential, Passkey)>, ApiError> {
    let credentials =
        CredentialRepository::get_active_for_account(&*state.store, &account_id.to_owned())
            .await
            .map_err(ApiError::account)?;
    Ok(credentials
        .into_iter()
        .filter(|c| c.kind == CredentialKind::Webauthn)
        .filter_map(|c| {
            let passkey: Passkey = serde_json::from_str(c.public_key_material.as_deref()?).ok()?;
            Some((c, passkey))
        })
        .collect())
}

/// Enforce the step-up requirement for passkey registration *handler-side*
/// rather than in the method/path step-up table (see
/// `crate::auth::requires_step_up`'s doc comment): registering the account's
/// *first* passkey is exempt, because step-up itself needs a passkey and
/// gating the first one would deadlock. Once the account holds >=1 passkey,
/// adding another requires a fresh, high-assurance session -- matching
/// fabric-client-core's `requiresStepUp` on `auth.addPasskey`.
async fn require_step_up_for_additional_passkey(
    state: &HubState,
    actor: &AuthContext,
    account_id: &str,
) -> Result<(), ApiError> {
    let has_passkey = !existing_passkeys(state, account_id).await?.is_empty();
    if !has_passkey {
        return Ok(());
    }
    let fresh = actor.assurance_level.as_deref() == Some("aal2")
        && actor
            .step_up_at
            .as_deref()
            .map(|at| {
                crate::auth::step_up_is_fresh(at, &utc_now(), state.step_up_freshness_minutes)
            })
            .unwrap_or(false);
    if fresh {
        Ok(())
    } else {
        Err(ApiError::account(AccountsError::StepUpRequired))
    }
}

pub async fn register_passkey_options(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
) -> Result<Json<Value>, ApiError> {
    let Some(webauthn) = state.webauthn.clone() else {
        return Err(passkeys_not_configured());
    };
    let Some(account_id) = actor.human_principal.clone() else {
        return Err(ApiError::account(AccountsError::RolePolicyViolation));
    };
    require_step_up_for_additional_passkey(&state, &actor, &account_id).await?;
    let account = AccountRepository::get_account(&*state.store, &account_id)
        .await
        .map_err(ApiError::account)?;

    let exclude_credentials: Vec<CredentialID> = existing_passkeys(&state, &account_id)
        .await?
        .into_iter()
        .map(|(_, passkey)| passkey.cred_id().clone())
        .collect();

    let (creation_challenge, registration_state) = webauthn
        .start_passkey_registration(
            webauthn_user_handle(&account_id),
            &account.username_display,
            &account.display_name,
            (!exclude_credentials.is_empty()).then_some(exclude_credentials),
        )
        .map_err(|_| passkeys_not_configured())?;
    let ceremony_state =
        serde_json::to_string(&registration_state).map_err(|_| passkeys_not_configured())?;

    let options_token = generate_opaque_secret();
    let challenge_hash = hash_opaque_secret(options_token.expose_secret());
    let now = utc_now();
    let expires_at = utc_now_plus_secs(CEREMONY_CHALLENGE_TTL_SECS);
    let challenge_id = format!("wac-{}", generate_opaque_secret().expose_secret());

    let challenge = ChallengeRepository::issue_challenge(
        &*state.store,
        &challenge_id,
        ChallengeKind::Webauthn,
        ChallengePurpose::Registration,
        Some(&account_id),
        None,
        None,
        &challenge_hash,
        &ceremony_state,
        &now,
        &expires_at,
    )
    .await
    .map_err(ApiError::account)?;

    Ok(Json(json!({
        "challenge_id": challenge.challenge_id,
        "options_token": options_token.expose_secret(),
        "public_key": creation_challenge,
    })))
}

// ---- POST /auth/passkeys/register/verify -------------------------------------------

#[derive(Deserialize)]
pub struct RegisterPasskeyVerifyRequest {
    pub challenge_id: String,
    pub options_token: String,
    pub label: Option<String>,
    pub credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
}

impl std::fmt::Debug for RegisterPasskeyVerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterPasskeyVerifyRequest")
            .field("challenge_id", &self.challenge_id)
            .field("options_token", &"[REDACTED]")
            .field("label", &self.label)
            .finish()
    }
}

/// Extract the WebAuthn "backup eligible"/"backup state" flags (BE/BS bits)
/// from a freshly registered `Passkey`. `webauthn-rs` 0.5.5 exposes no
/// public accessor for these on `Passkey` itself outside the
/// `danger-credential-internals` Cargo feature (not enabled here, to avoid
/// depending on an explicitly-named-danger API for what is purely recorded
/// metadata -- see `Credential::backup_eligible`'s doc comment). `Passkey`'s
/// plain `Serialize` derive means the same JSON Fabric already persists into
/// `webauthn_public_key` contains these values at
/// `cred.backup_eligible`/`cred.backup_state` -- this reads them from that
/// same serialization rather than a second independent source. Fails safe
/// to `(false, false)` if the shape doesn't match (e.g. a future
/// webauthn-rs upgrade renames the field): this is recorded metadata, not a
/// security gate, so a parse miss must never fail registration.
fn registration_backup_flags(passkey: &Passkey) -> (bool, bool) {
    let Ok(value) = serde_json::to_value(passkey) else {
        return (false, false);
    };
    (
        value["cred"]["backup_eligible"].as_bool().unwrap_or(false),
        value["cred"]["backup_state"].as_bool().unwrap_or(false),
    )
}

pub async fn register_passkey_verify(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(request): Json<RegisterPasskeyVerifyRequest>,
) -> Result<Json<Value>, ApiError> {
    let Some(webauthn) = state.webauthn.clone() else {
        return Err(passkeys_not_configured());
    };
    let Some(account_id) = actor.human_principal.clone() else {
        return Err(ApiError::account(AccountsError::RolePolicyViolation));
    };
    let now = utc_now();

    // Consume before any cryptographic verification (see
    // `ChallengeRepository::consume_challenge_if_pending`'s doc comment) --
    // a concurrent double-submit of the same assertion can then never both
    // succeed.
    let challenge = ChallengeRepository::consume_challenge_if_pending(
        &*state.store,
        &request.challenge_id,
        &now,
    )
    .await
    .map_err(ApiError::account)?;

    // Binding checks: wrong purpose, wrong account, or a mismatched
    // options_token are all reported as the same terminal ChallengeInvalid
    // the consume-CAS itself produces -- the challenge is already consumed
    // either way, so there is no retry to gate more precisely for, and a
    // single non-enumerating code avoids leaking which check failed.
    if !challenge_binding_ok(
        &challenge,
        ChallengePurpose::Registration,
        &account_id,
        &request.options_token,
    ) {
        return Err(ApiError::account(AccountsError::ChallengeInvalid));
    }

    let registration_state: webauthn_rs::prelude::PasskeyRegistration =
        serde_json::from_str(&challenge.ceremony_state)
            .map_err(|_| ApiError::account(AccountsError::ChallengeInvalid))?;
    let passkey = webauthn
        .finish_passkey_registration(&request.credential, &registration_state)
        .map_err(|_| ApiError::account(AccountsError::ChallengeInvalid))?;

    let public_key_blob = serde_json::to_string(&passkey).map_err(|_| passkeys_not_configured())?;
    let (backup_eligible, backup_state) = registration_backup_flags(&passkey);
    let credential = Credential {
        credential_id: format!("cred-{}", generate_opaque_secret().expose_secret()),
        account_id: account_id.clone(),
        kind: CredentialKind::Webauthn,
        secret_verifier: None,
        algorithm: None,
        algorithm_params: None,
        version: 1,
        public_key_material: Some(public_key_blob),
        label: request.label.clone(),
        created_at: now.clone(),
        last_used_at: None,
        compromised_at: None,
        revoked_at: None,
        revision: 0,
        backup_eligible,
        backup_state,
    };
    let stored = CredentialRepository::add_credential(&*state.store, credential)
        .await
        .map_err(ApiError::account)?;

    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.passkey_registered",
        None,
        &json!({ "account_id": account_id, "credential_id": stored.credential_id, "actor": attribution(&actor) }),
    )
    .await;

    Ok(Json(
        serde_json::to_value(PasskeySummaryDto::from_credential(&stored)).unwrap_or(Value::Null),
    ))
}

// ---- DELETE /auth/passkeys/{credential_id} -----------------------------------------

pub async fn remove_passkey(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    axum::extract::Path(credential_id): axum::extract::Path<String>,
) -> Result<Json<Value>, ApiError> {
    let Some(account_id) = actor.human_principal.clone() else {
        return Err(ApiError::account(AccountsError::RolePolicyViolation));
    };
    // Ownership is checked directly against the stored credential rows, not
    // via `existing_passkeys` -- that helper drops any row whose
    // `public_key_material` fails to deserialize as a full `Passkey`, which
    // would make a credential with a corrupted/legacy-format blob
    // impossible to ever remove. Removal must not depend on the blob being
    // well-formed.
    let owned = CredentialRepository::get_active_for_account(&*state.store, &account_id.clone())
        .await
        .map_err(ApiError::account)?
        .into_iter()
        .any(|c| c.kind == CredentialKind::Webauthn && c.credential_id == credential_id);
    if !owned {
        return Err(ApiError::not_found("passkey not found"));
    }
    let now = utc_now();
    CredentialRepository::revoke(&*state.store, &credential_id, &now)
        .await
        .map_err(ApiError::account)?;

    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.passkey_removed",
        None,
        &json!({ "account_id": account_id, "credential_id": credential_id, "actor": attribution(&actor) }),
    )
    .await;

    Ok(Json(
        json!({ "credential_id": credential_id, "revoked": true }),
    ))
}

// ---- POST /auth/passkeys/options ----------------------------------------------------

#[derive(Deserialize)]
pub struct PasskeyLoginOptionsRequest {
    pub username: String,
}

impl std::fmt::Debug for PasskeyLoginOptionsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyLoginOptionsRequest")
            .field("username", &self.username)
            .finish()
    }
}

pub async fn passkey_login_options(
    State(state): State<Arc<HubState>>,
    Json(request): Json<PasskeyLoginOptionsRequest>,
) -> Result<Json<Value>, ApiError> {
    let Some(webauthn) = state.webauthn.clone() else {
        return Err(passkeys_not_configured());
    };
    let username_normalized = fabric_accounts::validation::normalize_username(&request.username)
        .map_err(|_| ApiError::account(AccountsError::InvalidCredentials))?;
    let account = AccountRepository::find_by_username(
        &*state.store,
        &DEFAULT_REALM_ID.to_owned(),
        &username_normalized,
    )
    .await
    .map_err(ApiError::account)?
    .ok_or_else(|| ApiError::account(AccountsError::InvalidCredentials))?;

    let passkeys: Vec<Passkey> = existing_passkeys(&state, &account.account_id)
        .await?
        .into_iter()
        .map(|(_, passkey)| passkey)
        .collect();
    // Known gap, not fixed here: an account with zero registered passkeys
    // is distinguishable from a nonexistent one (this returns
    // InvalidCredentials immediately instead of a plausible-looking empty-
    // candidate challenge). Non-enumerating passkey options is a real
    // WebAuthn concern (webauthn-rs-core ships a purpose-built
    // WebauthnFakeCredentialGenerator for exactly this) but is meaningfully
    // more machinery than this slice's scope -- flagged for hardening, not
    // silently assumed away.
    if passkeys.is_empty() {
        return Err(ApiError::account(AccountsError::InvalidCredentials));
    }

    let (request_challenge, authentication_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| passkeys_not_configured())?;
    let ceremony_state =
        serde_json::to_string(&authentication_state).map_err(|_| passkeys_not_configured())?;

    let options_token = generate_opaque_secret();
    let challenge_hash = hash_opaque_secret(options_token.expose_secret());
    let now = utc_now();
    let expires_at = utc_now_plus_secs(CEREMONY_CHALLENGE_TTL_SECS);
    let challenge_id = format!("wac-{}", generate_opaque_secret().expose_secret());

    let challenge = ChallengeRepository::issue_challenge(
        &*state.store,
        &challenge_id,
        ChallengeKind::Webauthn,
        ChallengePurpose::Authentication,
        Some(&account.account_id),
        None,
        None,
        &challenge_hash,
        &ceremony_state,
        &now,
        &expires_at,
    )
    .await
    .map_err(ApiError::account)?;

    Ok(Json(json!({
        "challenge_id": challenge.challenge_id,
        "options_token": options_token.expose_secret(),
        "public_key": request_challenge,
    })))
}

// ---- POST /auth/passkeys/verify -----------------------------------------------------

#[derive(Deserialize)]
pub struct PasskeyLoginVerifyRequest {
    pub challenge_id: String,
    pub options_token: String,
    #[serde(default)]
    pub client_kind: Option<String>,
    #[serde(default)]
    pub client_label: Option<String>,
    pub credential: webauthn_rs::prelude::PublicKeyCredential,
    /// 114E: optional hex Ed25519 session public key -- see `LoginRequest`.
    #[serde(default)]
    pub session_public_key: Option<String>,
}

impl std::fmt::Debug for PasskeyLoginVerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyLoginVerifyRequest")
            .field("challenge_id", &self.challenge_id)
            .field("options_token", &"[REDACTED]")
            .field("client_kind", &self.client_kind)
            .field("client_label", &self.client_label)
            .field("session_public_key", &self.session_public_key)
            .finish()
    }
}

pub async fn passkey_login_verify(
    State(state): State<Arc<HubState>>,
    Json(request): Json<PasskeyLoginVerifyRequest>,
) -> Result<Json<Value>, ApiError> {
    let Some(webauthn) = state.webauthn.clone() else {
        return Err(passkeys_not_configured());
    };
    let now = utc_now();

    // Consume before any cryptographic verification, exactly like
    // registration -- see `ChallengeRepository::consume_challenge_if_pending`.
    let challenge = ChallengeRepository::consume_challenge_if_pending(
        &*state.store,
        &request.challenge_id,
        &now,
    )
    .await
    .map_err(ApiError::account)?;

    if !login_challenge_binding_ok(&challenge, &request.options_token) {
        return Err(ApiError::account(AccountsError::ChallengeInvalid));
    }
    // `login_challenge_binding_ok` already required `account_id.is_some()`.
    let account_id = challenge.account_id.clone().unwrap_or_default();

    let authentication_state: webauthn_rs::prelude::PasskeyAuthentication =
        serde_json::from_str(&challenge.ceremony_state)
            .map_err(|_| ApiError::account(AccountsError::ChallengeInvalid))?;
    let auth_result = webauthn
        .finish_passkey_authentication(&request.credential, &authentication_state)
        .map_err(|_| ApiError::account(AccountsError::ChallengeInvalid))?;

    let (credential, mut passkey) = existing_passkeys(&state, &account_id)
        .await?
        .into_iter()
        .find(|(_, passkey)| passkey.cred_id() == auth_result.cred_id())
        .ok_or_else(|| ApiError::account(AccountsError::ChallengeInvalid))?;
    // Let the library update whatever internal state it tracks (backup
    // state/eligibility, its own notion of the counter) before
    // re-serializing -- this codebase's own sign-count CAS below is the
    // actual replay defense, independent of this call's return value.
    let _ = passkey.update_credential(&auth_result);
    let updated_public_key_blob =
        serde_json::to_string(&passkey).map_err(|_| passkeys_not_configured())?;

    let result = AccountOrchestration::authenticate_with_passkey_and_issue_session(
        &*state.store,
        DEFAULT_REALM_ID,
        &account_id,
        &credential.credential_id,
        i64::from(auth_result.counter()),
        &updated_public_key_blob,
        auth_result.backup_eligible(),
        auth_result.backup_state(),
        parse_client_kind(request.client_kind.as_deref()),
        request.client_label.as_deref(),
        DEFAULT_IDLE_TIMEOUT_MINUTES,
        DEFAULT_ABSOLUTE_TIMEOUT_HOURS,
        &now,
    )
    .await;
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            // Best-effort audit; the credential row itself is left
            // untouched (see the store method's own doc comment on why
            // auto-revoke-on-anomaly is not this codebase's default).
            if matches!(error, AccountsError::CredentialReplaySuspected) {
                let _ = audit_append(
                    &*state.store,
                    &state.secrets,
                    "account.passkey_replay_suspected",
                    None,
                    &json!({ "account_id": account_id, "credential_id": credential.credential_id }),
                )
                .await;
            }
            return Err(ApiError::account(error));
        }
    };
    bind_session_key_if_present(
        &state,
        &outcome,
        request.session_public_key.as_deref(),
        &now,
    )
    .await?;

    Ok(Json(json!({
        "session_id": outcome.session.session_id,
        "account_id": outcome.session.account_id,
        "assurance_level": outcome.session.assurance_level.as_str(),
        "access_secret": outcome.access_secret.expose_secret(),
        "refresh_secret": outcome.refresh_secret.expose_secret(),
        "idle_expires_at": outcome.session.idle_expires_at,
        "absolute_expires_at": outcome.session.absolute_expires_at,
    })))
}

// ---- POST /auth/step-up/options -----------------------------------------------------

/// Start a step-up ceremony for the caller's *current* session: a passkey
/// authentication whose success elevates this session to Aal2, rather than
/// issuing a new one. Bound to the caller's own account+session (unlike
/// login, where the account is resolved from a username). Returns
/// `AssuranceTooLow` if the account has no passkey to step up with (the
/// structurally-cannot-reach-Aal2 case, distinct from the
/// `StepUpRequired`/reachable-but-not-fresh case the gate returns).
pub async fn step_up_options(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
) -> Result<Json<Value>, ApiError> {
    let Some(webauthn) = state.webauthn.clone() else {
        return Err(passkeys_not_configured());
    };
    let (Some(account_id), Some(session_id)) =
        (actor.human_principal.clone(), actor.session_id.clone())
    else {
        return Err(ApiError::account(AccountsError::RolePolicyViolation));
    };

    let passkeys: Vec<Passkey> = existing_passkeys(&state, &account_id)
        .await?
        .into_iter()
        .map(|(_, passkey)| passkey)
        .collect();
    if passkeys.is_empty() {
        return Err(ApiError::account(AccountsError::AssuranceTooLow));
    }

    let (request_challenge, authentication_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| passkeys_not_configured())?;
    let ceremony_state =
        serde_json::to_string(&authentication_state).map_err(|_| passkeys_not_configured())?;

    let options_token = generate_opaque_secret();
    let challenge_hash = hash_opaque_secret(options_token.expose_secret());
    let now = utc_now();
    let expires_at = utc_now_plus_secs(CEREMONY_CHALLENGE_TTL_SECS);
    let challenge_id = format!("wac-{}", generate_opaque_secret().expose_secret());

    let challenge = ChallengeRepository::issue_challenge(
        &*state.store,
        &challenge_id,
        ChallengeKind::Webauthn,
        ChallengePurpose::StepUp,
        Some(&account_id),
        Some(&session_id),
        None,
        &challenge_hash,
        &ceremony_state,
        &now,
        &expires_at,
    )
    .await
    .map_err(ApiError::account)?;

    Ok(Json(json!({
        "challenge_id": challenge.challenge_id,
        "options_token": options_token.expose_secret(),
        "public_key": request_challenge,
    })))
}

// ---- POST /auth/step-up/verify ------------------------------------------------------

#[derive(Deserialize)]
pub struct StepUpVerifyRequest {
    pub challenge_id: String,
    pub options_token: String,
    pub credential: webauthn_rs::prelude::PublicKeyCredential,
}

impl std::fmt::Debug for StepUpVerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StepUpVerifyRequest")
            .field("challenge_id", &self.challenge_id)
            .field("options_token", &"[REDACTED]")
            .finish()
    }
}

pub async fn step_up_verify(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(request): Json<StepUpVerifyRequest>,
) -> Result<Json<Value>, ApiError> {
    let Some(webauthn) = state.webauthn.clone() else {
        return Err(passkeys_not_configured());
    };
    let (Some(account_id), Some(session_id)) =
        (actor.human_principal.clone(), actor.session_id.clone())
    else {
        return Err(ApiError::account(AccountsError::RolePolicyViolation));
    };
    let now = utc_now();

    let challenge = ChallengeRepository::consume_challenge_if_pending(
        &*state.store,
        &request.challenge_id,
        &now,
    )
    .await
    .map_err(ApiError::account)?;

    // Bind the challenge to this caller's account, purpose, options_token,
    // AND the specific session it was issued for -- a step-up challenge
    // minted for one session must not elevate a different session.
    if !challenge_binding_ok(
        &challenge,
        ChallengePurpose::StepUp,
        &account_id,
        &request.options_token,
    ) || challenge.session_id.as_deref() != Some(session_id.as_str())
    {
        return Err(ApiError::account(AccountsError::ChallengeInvalid));
    }

    let authentication_state: webauthn_rs::prelude::PasskeyAuthentication =
        serde_json::from_str(&challenge.ceremony_state)
            .map_err(|_| ApiError::account(AccountsError::ChallengeInvalid))?;
    let auth_result = webauthn
        .finish_passkey_authentication(&request.credential, &authentication_state)
        .map_err(|_| ApiError::account(AccountsError::ChallengeInvalid))?;

    let (credential, mut passkey) = existing_passkeys(&state, &account_id)
        .await?
        .into_iter()
        .find(|(_, passkey)| passkey.cred_id() == auth_result.cred_id())
        .ok_or_else(|| ApiError::account(AccountsError::ChallengeInvalid))?;
    let _ = passkey.update_credential(&auth_result);
    let updated_public_key_blob =
        serde_json::to_string(&passkey).map_err(|_| passkeys_not_configured())?;

    // Same sign-count replay guard as login (114C.6 Slice 3), shared via
    // the orchestration trait so there is one implementation of the CAS.
    if let Err(error) = AccountOrchestration::verify_and_advance_passkey_sign_count(
        &*state.store,
        &account_id,
        &credential.credential_id,
        i64::from(auth_result.counter()),
        &updated_public_key_blob,
        auth_result.backup_eligible(),
        auth_result.backup_state(),
        &now,
    )
    .await
    {
        if matches!(error, AccountsError::CredentialReplaySuspected) {
            let _ = audit_append(
                &*state.store,
                &state.secrets,
                "account.passkey_replay_suspected",
                None,
                &json!({ "account_id": account_id, "credential_id": credential.credential_id }),
            )
            .await;
        }
        return Err(ApiError::account(error));
    }

    // Elevate *this* session in place, issuing a fresh access secret.
    let new_access_secret =
        SessionRepository::rotate_access_secret_and_elevate(&*state.store, &session_id, &now)
            .await
            .map_err(ApiError::account)?;

    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.step_up_completed",
        None,
        &json!({ "account_id": account_id, "session_id": session_id, "actor": attribution(&actor) }),
    )
    .await;

    Ok(Json(json!({
        "session_id": session_id,
        "assurance_level": "aal2",
        "access_secret": new_access_secret.expose_secret(),
        "stepped_up_at": now,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().expect("valid IP"), 12345)
    }

    fn sample_challenge(
        purpose: ChallengePurpose,
        account_id: Option<&str>,
        options_token: &str,
    ) -> fabric_accounts::webauthn::AuthChallenge {
        fabric_accounts::webauthn::AuthChallenge {
            challenge_id: "wac-1".into(),
            kind: fabric_accounts::webauthn::ChallengeKind::Webauthn,
            purpose,
            account_id: account_id.map(str::to_owned),
            session_id: None,
            client_identity_id: None,
            challenge_hash: hash_opaque_secret(options_token),
            ceremony_state: "{}".into(),
            created_at: "2026-07-17 00:00:00".into(),
            expires_at: "2026-07-17 00:05:00".into(),
            consumed_at: None,
            attempt_count: 0,
            status: fabric_accounts::webauthn::ChallengeStatus::Consumed,
        }
    }

    #[test]
    fn challenge_binding_accepts_exactly_matching_purpose_account_and_token() {
        let challenge = sample_challenge(ChallengePurpose::Registration, Some("acct-1"), "tok-1");
        assert!(challenge_binding_ok(
            &challenge,
            ChallengePurpose::Registration,
            "acct-1",
            "tok-1"
        ));
    }

    #[test]
    fn challenge_binding_rejects_a_mismatched_purpose() {
        let challenge = sample_challenge(ChallengePurpose::StepUp, Some("acct-1"), "tok-1");
        assert!(!challenge_binding_ok(
            &challenge,
            ChallengePurpose::Registration,
            "acct-1",
            "tok-1"
        ));
    }

    #[test]
    fn challenge_binding_rejects_a_mismatched_account() {
        let challenge = sample_challenge(ChallengePurpose::Registration, Some("acct-1"), "tok-1");
        assert!(!challenge_binding_ok(
            &challenge,
            ChallengePurpose::Registration,
            "acct-2",
            "tok-1"
        ));
    }

    #[test]
    fn challenge_binding_rejects_a_challenge_bound_to_no_account() {
        let challenge = sample_challenge(ChallengePurpose::Registration, None, "tok-1");
        assert!(!challenge_binding_ok(
            &challenge,
            ChallengePurpose::Registration,
            "acct-1",
            "tok-1"
        ));
    }

    #[test]
    fn challenge_binding_rejects_the_wrong_options_token() {
        let challenge = sample_challenge(ChallengePurpose::Registration, Some("acct-1"), "tok-1");
        assert!(!challenge_binding_ok(
            &challenge,
            ChallengePurpose::Registration,
            "acct-1",
            "wrong-token"
        ));
    }

    #[test]
    fn loopback_alone_is_sufficient_when_no_secret_is_configured() {
        assert!(bootstrap_source_allowed(
            addr("127.0.0.1"),
            true,
            None,
            None
        ));
        assert!(bootstrap_source_allowed(addr("::1"), true, None, None));
    }

    #[test]
    fn non_loopback_is_rejected_when_local_only_regardless_of_secret() {
        assert!(!bootstrap_source_allowed(
            addr("10.0.0.5"),
            true,
            None,
            None
        ));
        assert!(!bootstrap_source_allowed(
            addr("10.0.0.5"),
            true,
            Some("correct"),
            Some("correct")
        ));
    }

    #[test]
    fn a_configured_secret_must_be_presented_and_must_match() {
        assert!(!bootstrap_source_allowed(
            addr("127.0.0.1"),
            true,
            None,
            Some("expected-secret")
        ));
        assert!(!bootstrap_source_allowed(
            addr("127.0.0.1"),
            true,
            Some("wrong-secret"),
            Some("expected-secret")
        ));
        assert!(bootstrap_source_allowed(
            addr("127.0.0.1"),
            true,
            Some("expected-secret"),
            Some("expected-secret")
        ));
    }

    #[test]
    fn disabling_local_only_permits_a_non_loopback_source_with_the_correct_secret() {
        assert!(bootstrap_source_allowed(
            addr("10.0.0.5"),
            false,
            Some("expected-secret"),
            Some("expected-secret")
        ));
        assert!(!bootstrap_source_allowed(
            addr("10.0.0.5"),
            false,
            Some("wrong-secret"),
            Some("expected-secret")
        ));
    }

    #[test]
    fn setting_helpers_fall_back_to_the_default_when_absent_or_wrong_type() {
        assert_eq!(
            setting_i64(&json!({}), "/auth/sessions/idle_timeout_minutes", 60),
            60
        );
        assert_eq!(
            setting_i64(
                &json!({ "auth": { "sessions": { "idle_timeout_minutes": "not-a-number" } } }),
                "/auth/sessions/idle_timeout_minutes",
                60
            ),
            60
        );
        assert_eq!(
            setting_i64(
                &json!({ "auth": { "sessions": { "idle_timeout_minutes": 30 } } }),
                "/auth/sessions/idle_timeout_minutes",
                60
            ),
            30
        );
        assert!(setting_bool(&json!({}), "/auth/bootstrap/local_only", true));
        assert!(!setting_bool(
            &json!({ "auth": { "bootstrap": { "local_only": false } } }),
            "/auth/bootstrap/local_only",
            true
        ));
    }

    #[test]
    fn client_kind_parses_known_values_and_falls_back_to_other() {
        assert_eq!(parse_client_kind(Some("vsix")), ClientKind::Vsix);
        assert_eq!(parse_client_kind(Some("desktop")), ClientKind::Desktop);
        assert_eq!(parse_client_kind(Some("cli")), ClientKind::Cli);
        assert_eq!(parse_client_kind(Some("garbage")), ClientKind::Other);
        assert_eq!(parse_client_kind(None), ClientKind::Other);
    }

    #[test]
    fn request_debug_impls_never_leak_secrets() {
        let bootstrap = BootstrapRequest {
            username: "alice".into(),
            display_name: "Alice".into(),
            password: "sekrit-bootstrap-password".into(),
        };
        assert!(!format!("{bootstrap:?}").contains("sekrit-bootstrap-password"));

        let login = LoginRequest {
            username: "alice".into(),
            password: "sekrit-login-password".into(),
            client_kind: Some("cli".into()),
            client_label: None,
            session_public_key: None,
        };
        assert!(!format!("{login:?}").contains("sekrit-login-password"));

        let refresh = RefreshRequest {
            session_id: "sess-1".into(),
            refresh_secret: "sekrit-refresh-value".into(),
        };
        assert!(!format!("{refresh:?}").contains("sekrit-refresh-value"));
    }
}
