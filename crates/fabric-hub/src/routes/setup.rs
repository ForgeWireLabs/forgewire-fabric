//! `GET /setup/status` + `POST /setup/complete` (114D D.2) -- the genesis
//! setup backend that mints the realm's founding identity and the real
//! Master, atomically, before any steady-state gate exists to check against.
//!
//! Both routes are public and reachable only in the narrow pre-gate window
//! `bootstrap_open ∧ ¬realm_established` (114D sec 6, sec 14.1): the same
//! trust primitive `/auth/bootstrap` already uses (loopback + an optional
//! shared secret, `auth.bootstrap.local_only`/`X-Forgewire-Bootstrap-Secret`)
//! authorizes `/setup/complete`, reused verbatim via
//! `super::authn::bootstrap_source_allowed` rather than reimplemented --
//! "genesis setup is the pre-gate phase," sitting *above* `POST
//! /auth/bootstrap`, which remains the low-level primitive it composes (114D
//! sec 15.2).
//!
//! `POST /setup/complete` composes two already-proven operations into one
//! HTTP round-trip: `AccountOrchestration::complete_genesis` (one atomic SQL
//! transaction -- realm + Master account/credential/admin-membership/durable
//! recovery codes) followed by `AccountOrchestration::authenticate_and_issue_session`
//! (the same call `/auth/login` makes) so the response lands the operator
//! signed-in with a session, optionally proof-of-possession-bound (114E) if
//! the caller supplies `session_public_key`. These are deliberately two
//! separate calls, not one bigger transaction: if session issuance somehow
//! fails after the Master was already atomically created, the Master still
//! exists and the operator can retry via the normal `/auth/login` (now
//! correctly gated, since `bootstrap_open` is closed by that point) --
//! there is no window where genesis half-succeeds into a broken realm.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{AccountOrchestration, RealmRepository};

use crate::auth::DEFAULT_REALM_ID;
use crate::error::ApiError;
use crate::state::HubState;
use crate::utils::{audit_append, utc_now};

use super::accounts::account_summary;
use super::authn::{
    bind_session_key_if_present, bootstrap_source_allowed, effective_auth_settings,
    parse_client_kind, setting_bool, setting_i64, BOOTSTRAP_SECRET_HEADER,
    DEFAULT_ABSOLUTE_TIMEOUT_HOURS, DEFAULT_BOOTSTRAP_LOCAL_ONLY, DEFAULT_IDLE_TIMEOUT_MINUTES,
};

owned_router! {
    pub fn public_router, PUBLIC_ROUTES {
        "GET" get "/setup/status" => setup_status;
        "POST" post "/setup/complete" => setup_complete;
    }
}

/// The realm identity's `key_alg`, fixed for every genesis in this
/// increment. Describes the fabric-wide PoP session/machine-identity
/// standard (Ed25519) -- it does not yet describe WebAuthn credential
/// algorithms (authenticator-negotiated, out of the realm record's scope),
/// which is a D.3 concern once native passkey enrollment lands.
const GENESIS_KEY_ALG: &str = "ed25519";

/// Default recovery-code batch size for a fresh Master -- the same cap
/// `MAX_RECOVERY_CODES_PER_BATCH` in `fabric-store-rqlite` enforces server-side;
/// mirrored here only as the route's own default when the caller does not
/// override it.
const DEFAULT_GENESIS_RECOVERY_CODE_COUNT: i64 = 10;

/// `rp_id`'s decided default (114D sec 5): `localhost`, loopback-origin
/// ceremonies, the single override point being the realm record's own
/// stored field -- a caller may still override it explicitly.
const DEFAULT_RP_ID: &str = "localhost";

// ---- GET /setup/status ------------------------------------------------------

/// Drives the client setup FSM (114D sec 14.1): `bootstrap_open ∧
/// ¬realm_established` means enter Genesis Setup; otherwise show normal
/// sign-in. `sealing` is always `false` in this increment -- `complete_genesis`
/// is one SQL transaction (`?transaction`), which SQLite either applies
/// whole or not at all, so there is no partial-seal window at the database
/// layer for a `sealing` state to observe between. The field is included now
/// (rather than added later as a breaking response-shape change) because a
/// future increment may need it if a step that cannot fit in one transaction
/// (e.g. a WebAuthn root-credential-set ceremony, 114D sec 19) is added to
/// the flow -- reserved, not yet load-bearing.
pub async fn setup_status(State(state): State<Arc<HubState>>) -> Result<Json<Value>, ApiError> {
    let bootstrap_open = AccountOrchestration::bootstrap_status(&*state.store)
        .await
        .map_err(ApiError::account)?;
    let realm_established = RealmRepository::get_realm_identity(&*state.store)
        .await
        .map_err(ApiError::account)?
        .is_some();
    Ok(Json(json!({
        "bootstrap_open": bootstrap_open,
        "realm_established": realm_established,
        "sealing": false,
    })))
}

// ---- POST /setup/complete ---------------------------------------------------

#[derive(Deserialize)]
pub struct SetupCompleteRequest {
    pub realm_name: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    /// Non-empty required: the hub cannot safely guess which origins the
    /// wizard/CLI caller's own client(s) will actually present a WebAuthn
    /// ceremony from (114D sec 5) -- `auth.passkeys.allowed_origins` is
    /// likewise always operator-configured today, never auto-derived.
    pub origins: Vec<String>,
    pub username: String,
    pub display_name: String,
    pub password: String,
    #[serde(default)]
    pub client_kind: Option<String>,
    #[serde(default)]
    pub client_label: Option<String>,
    /// 114E: optional hex Ed25519 public key bound to the session this
    /// response returns, same contract as `LoginRequest::session_public_key`.
    #[serde(default)]
    pub session_public_key: Option<String>,
}

impl std::fmt::Debug for SetupCompleteRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupCompleteRequest")
            .field("realm_name", &self.realm_name)
            .field("rp_id", &self.rp_id)
            .field("origins", &self.origins)
            .field("username", &self.username)
            .field("display_name", &self.display_name)
            .field("password", &"[REDACTED]")
            .field("client_kind", &self.client_kind)
            .field("client_label", &self.client_label)
            .field("session_public_key", &self.session_public_key)
            .finish()
    }
}

/// The machine that ran genesis, for `realm_identity.genesis_node`
/// (informational only -- the head is mobile, 114D sec 2/3). Mirrors
/// `main.rs`'s identical `COMPUTERNAME`/`HOSTNAME` fallback for the cluster
/// manager's own `local_node_id`.
fn local_node_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

pub async fn setup_complete(
    State(state): State<Arc<HubState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SetupCompleteRequest>,
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

    // Cheap preconditions before any Argon2id/transaction work: genesis is
    // only applicable in the bootstrap_open ∧ ¬realm_established window
    // (114D sec 14.1) -- complete_genesis's own CAS is still the real
    // safety net for a concurrent race, but a request that arrives outside
    // this window (a legacy admin already exists with no realm, or a realm
    // already exists) gets a precise typed error instead of paying for
    // password hashing first.
    if !AccountOrchestration::bootstrap_status(&*state.store)
        .await
        .map_err(ApiError::account)?
    {
        return Err(ApiError::account(AccountsError::BootstrapClosed));
    }
    if RealmRepository::get_realm_identity(&*state.store)
        .await
        .map_err(ApiError::account)?
        .is_some()
    {
        return Err(ApiError::account(AccountsError::RealmAlreadyEstablished));
    }
    if request.origins.is_empty() {
        return Err(ApiError::account(AccountsError::AccountPolicyViolation {
            reason: "setup_complete_origins_required".to_string(),
        }));
    }

    let now = utc_now();
    let rp_id = request.rp_id.as_deref().unwrap_or(DEFAULT_RP_ID);
    let genesis_node = local_node_name();
    let outcome = AccountOrchestration::complete_genesis(
        &*state.store,
        &request.realm_name,
        rp_id,
        &request.origins,
        GENESIS_KEY_ALG,
        Some(&genesis_node),
        DEFAULT_REALM_ID,
        &request.username,
        &request.display_name,
        &request.password,
        DEFAULT_GENESIS_RECOVERY_CODE_COUNT,
        &now,
    )
    .await
    .map_err(ApiError::account)?;

    // The Master's own recovery codes never cross the wire again after this
    // response -- capture the plaintext for the response body before it is
    // dropped with `outcome`.
    let recovery_codes: Vec<String> = outcome
        .recovery_codes
        .iter()
        .map(|c| c.expose_secret().to_string())
        .collect();
    // `outcome.account.realm_id` (== DEFAULT_REALM_ID, the value just passed
    // to complete_genesis above), NOT `outcome.realm.realm_id` -- the
    // realm_identity record's own id is a distinct concept (114D sec 15.1)
    // from the pre-existing account-scoping realm every other route reads.
    // Conflating them was a real live bug: genesis's own login below would
    // still have worked (both sides would agree on whatever was passed), but
    // every *subsequent* /auth/login uses DEFAULT_REALM_ID unconditionally
    // and would never find an account scoped to a different value.
    let account_realm_id = outcome.account.realm_id.clone();
    let realm_id = outcome.realm.realm_id.clone();
    let realm_name = outcome.realm.name.clone();
    let realm_rp_id = outcome.realm.rp_id.clone();
    let realm_origins = outcome.realm.origins.clone();

    // Land the operator signed-in: the same authenticate_and_issue_session
    // call /auth/login makes, using the password just set. A failure here
    // (store hiccup, throttle -- unreachable in practice immediately after
    // a just-completed genesis) does not roll back the Master; it is
    // surfaced as an error and the caller retries via /auth/login instead
    // of re-running genesis (which is now correctly closed).
    let now2 = utc_now();
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
    let login_outcome = AccountOrchestration::authenticate_and_issue_session(
        &*state.store,
        &account_realm_id,
        &request.username,
        &request.password,
        parse_client_kind(request.client_kind.as_deref()),
        request.client_label.as_deref(),
        None,
        idle_timeout_minutes,
        absolute_timeout_hours,
        &now2,
    )
    .await
    .map_err(ApiError::account)?;
    bind_session_key_if_present(
        &state,
        &login_outcome,
        request.session_public_key.as_deref(),
        &now2,
    )
    .await?;

    let summary = account_summary(&state, &outcome.account).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "realm.genesis_completed",
        None,
        &json!({
            "realm_id": realm_id,
            "account_id": outcome.account.account_id,
            "username": outcome.account.username_normalized,
        }),
    )
    .await;

    Ok(Json(json!({
        "realm": {
            "realm_id": realm_id,
            "name": realm_name,
            "rp_id": realm_rp_id,
            "origins": realm_origins,
        },
        "account": summary,
        "recovery_codes": recovery_codes,
        "session_id": login_outcome.session.session_id,
        "account_id": login_outcome.session.account_id,
        "assurance_level": login_outcome.session.assurance_level.as_str(),
        "access_secret": login_outcome.access_secret.expose_secret(),
        "refresh_secret": login_outcome.refresh_secret.expose_secret(),
        "idle_expires_at": login_outcome.session.idle_expires_at,
        "absolute_expires_at": login_outcome.session.absolute_expires_at,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rp_id_matches_the_decided_114d_default() {
        assert_eq!(DEFAULT_RP_ID, "localhost");
    }

    #[test]
    fn local_node_name_never_panics_and_is_never_empty() {
        assert!(!local_node_name().is_empty());
    }
}
