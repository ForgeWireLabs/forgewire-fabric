//! Role-separated bearer authentication and authorization (M2.5.6).
//!
//! The installed cluster bearer remains a compatibility bootstrap during the
//! migration window. It maps explicitly to dispatcher+runner+observer only
//! and every successful response carries a warning header; it is not an
//! unlabelled or implicit "admin" credential. New credentials are resolved by
//! SHA-256 hash from rqlite and are denied unless their roles authorize the
//! concrete method/path pair.

use std::sync::Arc;

use axum::{
    extract::Request,
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use fabric_accounts::domain::AccountStatus;
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{AccountRepository, MembershipRepository, SessionRepository};
use fabric_store::{FabricStore, RoleTokenRow};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::state::HubState;
use crate::utils::{attribution, audit_append};

pub const VALID_ROLES: &[&str] = &["dispatcher", "runner", "observer", "approver", "reviewer"];

/// Historical cluster-bearer authority. Approval, review, secret access, and
/// general administration are intentionally excluded.
pub const LEGACY_COMPAT_ROLES: &[&str] = &["dispatcher", "runner", "observer"];
const LEGACY_WARNING: &str =
    "299 ForgeWire \"legacy cluster bearer compatibility bundle in use; migrate to a role token\"";

/// 114C implements one account realm per Fabric cluster (see the plan's
/// "Account scope" section); there is no per-request realm negotiation.
/// This is the fixed value every hub on this cluster uses -- bootstrap must
/// be called with the same value.
pub const DEFAULT_REALM_ID: &str = "default";

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub subject: String,
    pub roles: Vec<String>,
    pub legacy_compat: bool,
    /// `Some(account_id)` when this request was authenticated by a human
    /// session (114C.4) rather than a role token or the legacy bearer.
    /// There is no separate "human roles" field: `roles` above is that
    /// human's resolved effective membership roles, and the existing
    /// `is_authorized`/`required_roles` gate below runs completely
    /// unchanged against them -- a human session structurally cannot
    /// exceed what a role token could do at the same route, because it is
    /// evaluated by the identical code path with no widening.
    pub human_principal: Option<String>,
    /// The literal session that authenticated this request (114C.6).
    /// `None` for a role token / legacy bearer (they own no session).
    /// Previously discarded; carrying it lets `list_sessions`/`revoke_session`
    /// determine "current", and step-up elevate *this specific* session.
    pub session_id: Option<String>,
    /// The session's assurance level string ("aal1"/"aal2"/"recovery_limited")
    /// and the timestamp of its last step-up, both `None` for non-human
    /// callers. The step-up freshness gate (114C.6) reads these.
    pub assurance_level: Option<String>,
    pub step_up_at: Option<String>,
}

impl AuthContext {
    fn from_role_token(row: RoleTokenRow) -> Self {
        Self {
            subject: row.token_id,
            roles: row.roles,
            legacy_compat: false,
            human_principal: None,
            session_id: None,
            assurance_level: None,
            step_up_at: None,
        }
    }

    fn legacy() -> Self {
        Self {
            subject: "legacy-cluster-bearer".into(),
            roles: LEGACY_COMPAT_ROLES
                .iter()
                .map(|role| (*role).to_owned())
                .collect(),
            legacy_compat: true,
            human_principal: None,
            session_id: None,
            assurance_level: None,
            step_up_at: None,
        }
    }

    fn from_human_session(
        account_id: String,
        roles: Vec<String>,
        session_id: String,
        assurance_level: String,
        step_up_at: Option<String>,
    ) -> Self {
        Self {
            subject: account_id.clone(),
            roles,
            legacy_compat: false,
            human_principal: Some(account_id),
            session_id: Some(session_id),
            assurance_level: Some(assurance_level),
            step_up_at,
        }
    }

    /// Test-only builder: a human-session `AuthContext` with the given
    /// subject/account and roles, and no session/assurance context. Exists
    /// so tests (in this crate and its integration tests) construct an
    /// `AuthContext` without spelling out every field -- adding a field to
    /// the struct then does not fan out into dozens of test-literal edits.
    /// `pub` + `#[doc(hidden)]`: reachable from integration tests, not part
    /// of the intended public API.
    #[doc(hidden)]
    pub fn for_test(subject: &str, roles: &[&str], human_principal: Option<&str>) -> Self {
        Self {
            subject: subject.to_owned(),
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            legacy_compat: false,
            human_principal: human_principal.map(str::to_owned),
            session_id: None,
            assurance_level: None,
            step_up_at: None,
        }
    }

    /// Test-only: set session/assurance/step-up context on a `for_test`
    /// actor, for exercising the step-up gate.
    #[doc(hidden)]
    pub fn with_test_session(
        mut self,
        session_id: &str,
        assurance_level: &str,
        step_up_at: Option<&str>,
    ) -> Self {
        self.session_id = Some(session_id.to_owned());
        self.assurance_level = Some(assurance_level.to_owned());
        self.step_up_at = step_up_at.map(str::to_owned);
        self
    }
}

/// The outcome of attempting to resolve a presented bearer value as a human
/// session. `NotASession` is the *only* variant that falls through to the
/// existing role-token/legacy bearer path -- every other outcome (expired,
/// or the account is disabled/locked/recovery-required) is terminal, so
/// `require_bearer` never lets a failed human session silently retry the
/// same mutation on a broader automation credential.
///
/// Known imprecision, documented rather than hidden: `SessionRepository::
/// validate_by_access_hash` (114C.2) filters `WHERE revoked_at IS NULL`, so
/// a *revoked* session's secret is indistinguishable at that query from a
/// secret that never belonged to any session -- both produce `NotASession`
/// here. This still denies access correctly (the fallen-through role-token
/// lookup will not match a session secret either, so the request ends in
/// `InvalidBearer`), just with a less specific error code than
/// `SessionRevoked` would give. Giving `SessionRevoked` its own precise
/// terminal path requires a lookup that finds a session by hash regardless
/// of `revoked_at`; that is not built yet.
pub enum HumanSessionOutcome {
    NotASession,
    Authenticated(AuthContext),
    Rejected {
        status: StatusCode,
        code: &'static str,
        message: &'static str,
    },
}

/// Resolve a presented bearer value as a human session, or determine it
/// isn't one. Takes `&dyn FabricStore` rather than `&HubState` specifically
/// so it is testable against an ephemeral rqlite-backed `RqliteStore`
/// directly, without constructing a full `HubState` or running axum.
pub async fn resolve_human_session(
    store: &(dyn FabricStore + Send + Sync),
    presented: &str,
    realm_id: &str,
) -> HumanSessionOutcome {
    let access_hash = fabric_accounts::secrets::hash_opaque_secret(presented);
    let session = match SessionRepository::validate_by_access_hash(store, &access_hash).await {
        Ok(session) => session,
        Err(AccountsError::SessionExpired) => return HumanSessionOutcome::NotASession,
        Err(_) => {
            return HumanSessionOutcome::Rejected {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "AuthServiceUnavailable",
                message: "human-session authorization is temporarily unavailable",
            }
        }
    };
    // Memberships are already account-scoped by foreign key; realm_id is
    // accepted for call-site clarity and reserved for the multi-realm
    // filtering federation would need, which 114C does not implement.
    let _ = realm_id;
    authenticate_validated_session(store, session).await
}

/// Given a session row that has already been matched by some credential
/// (an opaque access-secret hash for bearer sessions, or a verified
/// request signature for 114E proof-of-possession sessions), run the
/// identical downstream checks and build the `AuthContext`: expiry →
/// account status → live memberships → roles. Extracted so the bearer path
/// (`resolve_human_session`) and the PoP path (`resolve_signed_session`)
/// produce a byte-identical `AuthContext` and therefore identical
/// authorization/step-up behavior. Every outcome here is terminal.
async fn authenticate_validated_session(
    store: &(dyn FabricStore + Send + Sync),
    session: fabric_accounts::domain::Session,
) -> HumanSessionOutcome {
    let now = crate::utils::utc_now();
    if session.idle_expires_at < now || session.absolute_expires_at < now {
        return HumanSessionOutcome::Rejected {
            status: StatusCode::UNAUTHORIZED,
            code: "SessionExpired",
            message: "the session has expired",
        };
    }
    let Ok(account) = AccountRepository::get_account(store, &session.account_id).await else {
        return HumanSessionOutcome::Rejected {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "AuthServiceUnavailable",
            message: "human-session authorization is temporarily unavailable",
        };
    };
    if !account.status.may_authenticate_normally() {
        let code = match account.status {
            AccountStatus::Disabled => "AccountDisabled",
            AccountStatus::Locked => "AccountLocked",
            AccountStatus::RecoveryRequired => "RecoveryRequired",
            // invited/deletion_pending/deleted_tombstone: a still-live
            // session against one of these states should not exist by
            // construction (disablement revokes sessions), but fail closed
            // rather than authorize on an unrecognized combination.
            _ => "AccountDisabled",
        };
        return HumanSessionOutcome::Rejected {
            status: StatusCode::FORBIDDEN,
            code,
            message: "the account cannot authenticate in its current state",
        };
    }
    let Ok(memberships) = MembershipRepository::list_for_account(store, &account.account_id).await
    else {
        return HumanSessionOutcome::Rejected {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "AuthServiceUnavailable",
            message: "human-session authorization is temporarily unavailable",
        };
    };
    let roles: Vec<String> = memberships
        .iter()
        .filter(|membership| membership.revoked_at.is_none())
        .map(|membership| membership.role.as_str().to_owned())
        .collect();
    HumanSessionOutcome::Authenticated(AuthContext::from_human_session(
        account.account_id,
        roles,
        session.session_id,
        session.assurance_level.as_str().to_owned(),
        session.step_up_at,
    ))
}

/// Resolve a 114E proof-of-possession request: the caller presented the
/// four `X-Forgewire-*` session headers and (for a body-bearing method) the
/// raw request body. Verifies the Ed25519 signature over the canonical
/// request envelope against the session's bound public key, then runs the
/// same downstream checks as the bearer path. Any failure is terminal
/// (there is no fall-through to a broader credential for a signed request).
#[allow(clippy::too_many_arguments)]
pub async fn resolve_signed_session(
    store: &(dyn FabricStore + Send + Sync),
    session_id: &str,
    timestamp: i64,
    nonce: &str,
    signature_hex: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> HumanSessionOutcome {
    // Timestamp skew first (cheap, no store hit): reuse the same ±300s
    // window the Ed25519 agent paths enforce.
    if crate::utils::check_skew(timestamp).is_err() {
        return HumanSessionOutcome::Rejected {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "SignatureTimestampSkew",
            message: "the request timestamp is outside the allowed skew window",
        };
    }
    // Missing session id, or a store error -- do not distinguish (no oracle
    // for whether a session id exists).
    let Ok(session) = SessionRepository::get(store, &session_id.to_owned()).await else {
        return HumanSessionOutcome::Rejected {
            status: StatusCode::UNAUTHORIZED,
            code: "SessionExpired",
            message: "the session has expired",
        };
    };
    if session.revoked_at.is_some() {
        return HumanSessionOutcome::Rejected {
            status: StatusCode::UNAUTHORIZED,
            code: "SessionRevoked",
            message: "the session has been revoked",
        };
    }
    let Some(bound_key) = session.bound_public_key.as_deref() else {
        // A bearer-only session presented via the signed path -- it has no
        // key to verify against. Reject rather than silently accept.
        return HumanSessionOutcome::Rejected {
            status: StatusCode::UNAUTHORIZED,
            code: "SessionNotKeyBound",
            message: "this session does not support signed requests",
        };
    };
    let body_sha256 = hex::encode(Sha256::digest(body));
    let envelope = json!({
        "op": "session-request",
        "session_id": session_id,
        "method": method,
        "path": path,
        "body_sha256": body_sha256,
        "timestamp": timestamp,
        "nonce": nonce,
    });
    if crate::utils::verify_sig(bound_key, &envelope, signature_hex).is_err() {
        return HumanSessionOutcome::Rejected {
            status: StatusCode::UNAUTHORIZED,
            code: "InvalidSignature",
            message: "the request signature did not verify",
        };
    }
    authenticate_validated_session(store, session).await
}

pub fn normalize_roles(roles: &[String]) -> Result<Vec<String>, String> {
    if roles.is_empty() {
        return Err("at least one role is required".into());
    }
    let mut normalized = Vec::with_capacity(roles.len());
    for role in roles {
        let role = role.trim().to_ascii_lowercase();
        if !VALID_ROLES.contains(&role.as_str()) {
            return Err(format!(
                "unknown role {role:?}; expected one of {}",
                VALID_ROLES.join(", ")
            ));
        }
        if !normalized.contains(&role) {
            normalized.push(role);
        }
    }
    normalized.sort();
    Ok(normalized)
}

// 114E proof-of-possession request headers. `X-Forgewire-Signature` present
// selects the signed path (verify against the session's bound key); absent
// selects the bearer path. Lowercase because `http::HeaderMap` lookups are
// case-insensitive but stored lowercased.
const POP_SIGNATURE_HEADER: &str = "x-forgewire-signature";
const POP_SESSION_HEADER: &str = "x-forgewire-session";
const POP_TIMESTAMP_HEADER: &str = "x-forgewire-timestamp";
const POP_NONCE_HEADER: &str = "x-forgewire-nonce";
/// Bound on the body a signed request may carry -- account/settings JSON is
/// tiny; this only caps the buffering the PoP path performs. 1 MiB.
const POP_MAX_BODY: usize = 1024 * 1024;

struct SignedRequestHeaders {
    session_id: String,
    timestamp: i64,
    nonce: String,
    signature: String,
}

/// Parse the four `X-Forgewire-*` signed-request headers. `None` on any
/// missing/malformed header (the caller then rejects with 401) -- callers
/// only reach here after confirming `X-Forgewire-Signature` is present.
fn parse_signed_request_headers(headers: &header::HeaderMap) -> Option<SignedRequestHeaders> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let session_id = get(POP_SESSION_HEADER)?.to_owned();
    let timestamp = get(POP_TIMESTAMP_HEADER)?.parse::<i64>().ok()?;
    let nonce = get(POP_NONCE_HEADER)?.to_owned();
    let signature = get(POP_SIGNATURE_HEADER)?.to_owned();
    if session_id.is_empty() || nonce.is_empty() || signature.is_empty() {
        return None;
    }
    Some(SignedRequestHeaders {
        session_id,
        timestamp,
        nonce,
        signature,
    })
}

pub async fn require_bearer(
    axum::extract::State(state): axum::extract::State<Arc<HubState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    // Exactly one `AuthContext` is produced per request. A request carrying
    // the 114E `X-Forgewire-Signature` header authenticates by Ed25519
    // request signature against the session's bound public key (no reusable
    // secret on the wire); this is the *only* branch that buffers the body
    // (to bind `body_sha256`), so the bearer path below -- and the
    // high-throughput dispatch/stream routes it also guards -- never touch
    // the body. A signed session takes precedence over a simultaneously
    // present `Authorization: Bearer`.
    let context = if req.headers().get(POP_SIGNATURE_HEADER).is_some() {
        let Some(signed) = parse_signed_request_headers(req.headers()) else {
            audit_denial(&state, "auth.signed_session_denied", &method, &path, None).await;
            return auth_error(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "the signed-session headers are missing or malformed",
            );
        };
        let (parts, body) = req.into_parts();
        let Ok(body_bytes) = axum::body::to_bytes(body, POP_MAX_BODY).await else {
            return auth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "RequestBodyTooLarge",
                "the request body exceeded the signed-request size limit",
            );
        };
        let outcome = resolve_signed_session(
            &*state.store,
            &signed.session_id,
            signed.timestamp,
            &signed.nonce,
            &signed.signature,
            &method,
            &path,
            &body_bytes,
        )
        .await;
        // Rebuild the request with the buffered body so the handler sees it.
        req = Request::from_parts(parts, axum::body::Body::from(body_bytes));
        match outcome {
            HumanSessionOutcome::Authenticated(context) => context,
            HumanSessionOutcome::Rejected {
                status,
                code,
                message,
            } => {
                audit_denial(&state, "auth.signed_session_denied", &method, &path, None).await;
                return auth_error(status, code, message);
            }
            // `resolve_signed_session` never returns `NotASession` (a signed
            // request has no broader credential to fall through to); fail
            // closed if that invariant is ever violated.
            HumanSessionOutcome::NotASession => {
                return auth_error(
                    StatusCode::UNAUTHORIZED,
                    "SessionExpired",
                    "the session has expired",
                );
            }
        }
    } else {
        let Some(presented) = bearer_value(req.headers().get(header::AUTHORIZATION)) else {
            audit_denial(&state, "auth.missing_bearer_denied", &method, &path, None).await;
            return auth_error(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "a bearer token is required",
            );
        };

        // Credential precedence (114C.4): a presented human session is
        // resolved and validated first. Only "this secret matches no session
        // at all" falls through to the pre-existing role-token/legacy path --
        // every other human-session outcome is terminal (see
        // `HumanSessionOutcome`'s doc comment), so a client cannot silently
        // retry a failed human-session mutation on a broader automation
        // credential. There is no code path that merges a human session's
        // roles with a role token's.
        match resolve_human_session(&*state.store, presented, DEFAULT_REALM_ID).await {
            HumanSessionOutcome::Authenticated(context) => context,
            HumanSessionOutcome::Rejected {
                status,
                code,
                message,
            } => {
                audit_denial(&state, "auth.human_session_denied", &method, &path, None).await;
                return auth_error(status, code, message);
            }
            HumanSessionOutcome::NotASession => {
                if constant_time_eq(presented.as_bytes(), state.token.as_bytes()) {
                    AuthContext::legacy()
                } else {
                    let token_hash = hex::encode(Sha256::digest(presented.as_bytes()));
                    match state.store.role_token_by_hash(&token_hash).await {
                        Ok(Some(row)) => AuthContext::from_role_token(row),
                        Ok(None) => {
                            audit_denial(
                                &state,
                                "auth.invalid_bearer_denied",
                                &method,
                                &path,
                                None,
                            )
                            .await;
                            return auth_error(
                                StatusCode::FORBIDDEN,
                                "InvalidBearer",
                                "the bearer token is invalid or revoked",
                            );
                        }
                        Err(error) => {
                            tracing::error!(error = %error, "role token lookup failed");
                            return auth_error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "AuthStoreUnavailable",
                                "role-token authorization is temporarily unavailable",
                            );
                        }
                    }
                }
            }
        }
    };

    let required = required_roles(&method, &path);
    if !is_authorized(&context, &method, &path) {
        let payload = json!({
            "subject": context.subject,
            "roles": context.roles,
            "method": method,
            "path": path,
            "required_roles": required,
            "actor": attribution(&context),
        });
        if let Err(error) = audit_append(
            &*state.store,
            &state.secrets,
            "auth.role_denied",
            None,
            &payload,
        )
        .await
        {
            tracing::error!(error = %error, "failed to append role-token denial audit event");
        }
        return role_policy_violation(&method, &path, required, &context.roles);
    }

    // Step-up gate (114C.6): checked *after* role authorization succeeds, so
    // a caller who is not even role-authorized never learns whether the
    // route additionally requires step-up. Only human sessions can satisfy
    // (or be subject to) step-up -- a role token / legacy bearer reaching a
    // step-up route would already have been denied by the role gate above
    // (every step-up-gated route is admin-only), so this branch only ever
    // meaningfully runs for a human session.
    if requires_step_up(&method, &path) && context.human_principal.is_some() {
        let fresh = context.assurance_level.as_deref() == Some("aal2")
            && context
                .step_up_at
                .as_deref()
                .map(|at| {
                    step_up_is_fresh(
                        at,
                        &crate::utils::utc_now(),
                        state.step_up_freshness_minutes,
                    )
                })
                .unwrap_or(false);
        if !fresh {
            audit_denial(
                &state,
                "auth.step_up_denied",
                &method,
                &path,
                Some(&context),
            )
            .await;
            return auth_error(
                StatusCode::FORBIDDEN,
                "StepUpRequired",
                "a fresh high-assurance authentication (step-up) is required for this operation",
            );
        }
    }

    let legacy = context.legacy_compat;
    req.extensions_mut().insert(context);
    let mut response = next.run(req).await;
    if legacy {
        response
            .headers_mut()
            .insert(header::WARNING, HeaderValue::from_static(LEGACY_WARNING));
        response.headers_mut().insert(
            "x-forgewire-auth-warning",
            HeaderValue::from_static("legacy-compatibility-role-bundle"),
        );
    }
    response
}

async fn audit_denial(
    state: &HubState,
    kind: &str,
    method: &str,
    path: &str,
    // 114C.4 dual attribution: `None` when authentication itself failed
    // before any actor was ever resolved (missing/invalid bearer, a
    // rejected human session) -- there is no identity to attribute in that
    // case, not even "known automation", so both `subject` and `actor`
    // serialize to `null` rather than a guessed value. `Some` only when a
    // real `AuthContext` already exists and the denial is a downstream
    // authorization/step-up check against it (role_denied, step_up_denied).
    actor: Option<&AuthContext>,
) {
    let payload = json!({
        "method": method,
        "path": path,
        "subject": actor.map(|a| a.subject.as_str()),
        "actor": actor.map(attribution),
    });
    if let Err(error) = audit_append(&*state.store, &state.secrets, kind, None, &payload).await {
        tracing::error!(error = %error, kind, "failed to append authentication denial audit event");
    }
}

/// `pub` (rather than crate-private, like most of this module's internals)
/// specifically so 114C.4's authorization-intersection tests can compose it
/// with `resolve_human_session` directly, proving a human session's roles
/// pass through this *exact*, unmodified gate rather than a parallel check
/// that merely resembles it.
pub fn is_authorized(context: &AuthContext, method: &str, path: &str) -> bool {
    // Bootstrap is the sole admin-shaped legacy exception. It lets an existing
    // installation split/migrate its credential without granting the legacy
    // bearer approval, secret, token list/revoke, or the `admin`-gated
    // role-token-lifecycle authority `required_roles` now requires for those
    // same three paths (see the role-token-mutation comment there) -- this
    // bypass covers strictly less than that gate, not the same power reached
    // a different way.
    if context.legacy_compat
        && method == "POST"
        && matches!(
            path,
            "/admin/role-tokens" | "/admin/role-tokens/split" | "/admin/role-tokens/migrate"
        )
    {
        return true;
    }
    required_roles(method, path)
        .iter()
        .any(|required_role| context.roles.iter().any(|role| role == required_role))
}

fn bearer_value(header: Option<&HeaderValue>) -> Option<&str> {
    let raw = header?.to_str().ok()?.trim();
    let (scheme, value) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || value.trim().is_empty() {
        return None;
    }
    Some(value.trim())
}

fn auth_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "code": code,
                "message": message,
            }
        })),
    )
        .into_response()
}

fn role_policy_violation(
    method: &str,
    path: &str,
    required_roles: &[&str],
    granted_roles: &[String],
) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": {
                "code": "RolePolicyViolation",
                "message": "the bearer token role does not authorize this operation",
                "method": method,
                "path": path,
                "required_roles": required_roles,
                "granted_roles": granted_roles,
            }
        })),
    )
        .into_response()
}

/// Return the least-privilege role alternatives for an authenticated route.
/// Unknown authenticated routes fail closed to reviewer authority.
pub fn required_roles(method: &str, path: &str) -> &'static [&'static str] {
    const REVIEWER: &[&str] = &["reviewer"];
    const OBSERVE: &[&str] = &["observer", "reviewer"];
    const OBSERVE_DISPATCH: &[&str] = &["observer", "dispatcher", "reviewer"];
    // Any authenticated *human*, whatever role(s) they hold, must be able to
    // reach their own identity/session/credential self-service routes. These
    // enforce per-caller ownership inside the handler (via
    // `AuthContext.human_principal`), not through this role gate, so the gate's
    // only job is "an authenticated principal, not the anonymous public tier."
    // `OBSERVE = [observer, reviewer]` wrongly excluded a human who holds only
    // `admin` (EVERY bootstrap first admin -- see
    // `bootstrap_first_administrator`, which grants `admin` alone), or only
    // `approver`/`dispatcher`, locking them out of `/auth/me`, session listing/
    // revocation, logout, step-up, and -- most damaging -- passkey
    // registration, the deadlock 114D began resolving for settings. Includes
    // every human-assignable role; `runner` is machine-only (no human holds
    // it), and a runner/legacy token that reaches these still owns no session
    // and is denied by the handler's ownership check.
    const SELF_SERVICE: &[&str] = &["observer", "dispatcher", "approver", "reviewer", "admin"];
    const TASK_READ: &[&str] = &["observer", "dispatcher", "runner", "reviewer"];
    const APPROVAL_READ: &[&str] = &["observer", "dispatcher", "approver", "reviewer"];
    const APPROVE: &[&str] = &["approver", "reviewer"];
    const DISPATCH: &[&str] = &["dispatcher"];
    const DISPATCH_REVIEW: &[&str] = &["dispatcher", "reviewer"];
    const RUN: &[&str] = &["runner"];
    const RUN_OR_DISPATCH: &[&str] = &["runner", "dispatcher"];
    // Host infrastructure self-report (POST /hosts/roles): the active cluster
    // participants (runner, dispatcher) plus the operator (reviewer). Mirrors
    // the host_roles writes that runner/dispatcher enrolment already performs,
    // so it adds no capability a runner/dispatcher token lacks; it exists so a
    // node's install-time role report on the legacy cluster bearer is not
    // denied. Observer is deliberately excluded (read-only).
    const HOST_REPORT: &[&str] = &["runner", "dispatcher", "reviewer"];
    // "admin" is deliberately absent from VALID_ROLES (a role-token vocabulary):
    // it can only ever reach `context.roles` through a human session's
    // resolved memberships (114C.4/114C.5), never through automation. A
    // route gated on ADMIN alone is therefore unreachable by any role token
    // or the legacy bearer, by construction, not by a separate check.
    const ADMIN: &[&str] = &["admin"];
    const ADMIN_REVIEW: &[&str] = &["admin", "reviewer"];
    // Settings reads include `admin`: a human admin holds only `admin` after
    // bootstrap (never `observer`/`reviewer`), and must be able to read the
    // settings document -- e.g. to obtain the compare-and-set revision -- to
    // configure `auth.*` (see the `/settings/auth*` write branch below). No
    // read access is removed; `observer`/`reviewer` are preserved.
    const SETTINGS_READ: &[&str] = &["observer", "reviewer", "admin"];

    if path == "/accounts" {
        return if method == "GET" { ADMIN_REVIEW } else { ADMIN };
    }
    if path.starts_with("/accounts/") {
        // Membership grant/revoke and enable/disable are always
        // administration, regardless of method. Everything else under
        // /accounts/{id} (the account record itself, its safe metadata) is
        // readable by reviewer alongside admin.
        if path.contains("/membership") || path.ends_with("/disable") || path.ends_with("/enable") {
            return ADMIN;
        }
        return if method == "GET" { ADMIN_REVIEW } else { ADMIN };
    }
    if path == "/auth-policy" {
        // Reading the auth-method policy is a plain authenticated read every
        // human client needs to render its login/credential UI -- gate it the
        // same as the self-service routes so an `admin`-only first admin is not
        // 403'd out of discovering what auth methods exist.
        return SELF_SERVICE;
    }
    if path == "/auth/sessions" || path.starts_with("/auth/sessions/") {
        // Coarse gate only (any authenticated human): the handler enforces
        // "my session, or I am admin" via AuthContext.human_principal, so this
        // gate only distinguishes an authenticated principal from the
        // anonymous public tier. A legacy/role-token bearer can technically
        // reach it but owns no session and is denied by that ownership check.
        return SELF_SERVICE;
    }
    if path == "/auth/logout"
        || path == "/auth/logout-all"
        || path == "/auth/me"
        || path == "/auth/step-up/options"
        || path == "/auth/step-up/verify"
        || path.starts_with("/auth/passkeys/")
    {
        // Same coarse-gate-plus-handler-side-ownership pattern as
        // /auth/sessions* above: any authenticated human may reach these
        // self-service routes regardless of which role(s) they hold; the
        // handlers resolve "my own session(s)/account"/"my own passkey" from
        // AuthContext.human_principal, not a query parameter.
        //
        // Step-up (114C.6 Slice 4) layers on TOP of this role gate, not
        // instead of it: `requires_step_up(method, path)` is checked
        // separately in `require_bearer` after this role check succeeds.
        // Passkey *removal* (DELETE /auth/passkeys/{id}) is in that step-up
        // table; passkey *registration* enforces its step-up handler-side
        // (first-passkey exemption -- see `requires_step_up`'s doc comment).
        // The step-up ceremony routes (/auth/step-up/*) themselves must be
        // reachable by a not-yet-Aal2 session, so they are deliberately NOT
        // in the step-up table.
        return SELF_SERVICE;
    }

    if path == "/admin/update" || path.starts_with("/admin/binaries/") {
        return DISPATCH_REVIEW;
    }
    if path == "/state/snapshot" {
        return ADMIN_REVIEW;
    }
    if path == "/state/import" {
        return ADMIN;
    }

    // Role-token *lifecycle* (issue/split/migrate/revoke) mints or destroys
    // the very credentials the rest of this route table gates on -- a bare
    // `reviewer` token minting itself a fresh `dispatcher`/`runner`/`approver`
    // token is a privilege-escalation path, not merely "reviewer manages
    // automation," so these mutations require `admin` (a human-only role by
    // construction -- see the ADMIN doc comment above). Reading the list
    // stays `ADMIN_REVIEW`, mirroring `/accounts`'s identical read/write
    // split: an admin who holds no `reviewer` grant must still be able to
    // see what automation credentials exist. The legacy bearer's own narrow
    // bootstrap exception (`is_authorized`, above) is unaffected -- it does
    // not route through this table at all.
    if path == "/admin/role-tokens" {
        return if method == "GET" { ADMIN_REVIEW } else { ADMIN };
    }
    if path == "/admin/role-tokens/split" || path == "/admin/role-tokens/migrate" {
        return ADMIN;
    }
    if path.starts_with("/admin/role-tokens/") {
        // DELETE /admin/role-tokens/{token_id} (revoke).
        return ADMIN;
    }
    if path.starts_with("/admin/") || path == "/admin" {
        return REVIEWER;
    }
    if path == "/secrets" || path.starts_with("/secrets/") {
        return REVIEWER;
    }
    if path == "/labels" {
        return if method == "GET" { OBSERVE } else { REVIEWER };
    }
    if path == "/policy" {
        return OBSERVE;
    }
    if path == "/history/status" {
        return OBSERVE;
    }
    if path == "/settings" || path == "/settings/schema" {
        return SETTINGS_READ;
    }
    if path.starts_with("/settings/") {
        if method == "GET" {
            return SETTINGS_READ;
        }
        // Authentication policy (`auth.bootstrap`, `auth.passkeys`,
        // `auth.sessions`) is admin territory: a human admin may write it
        // without first holding `reviewer`, which resolves the first-admin
        // passkey-setup deadlock (114D groundwork). The trailing-dot prefix
        // matches every `auth.<key>` without false-matching a hypothetical
        // `/settings/authx`; the exact `/settings/auth` covers a whole-subtree
        // write. Every other settings key stays `reviewer`-only.
        if path == "/settings/auth" || path.starts_with("/settings/auth.") {
            return ADMIN_REVIEW;
        }
        return REVIEWER;
    }
    if path == "/hosts/roles" {
        // A node self-reports its own infrastructure roles (command_runner,
        // hub_head, dispatch) at install/enrolment time using its cluster
        // credential. This is the *same* `host_roles` write that runner and
        // dispatcher enrolment already perform under RUN/DISPATCH gates
        // (`routes::runners` registers host_runner/agent_runner on
        // POST /runners/register; `routes::dispatchers` registers dispatch on
        // POST /dispatchers/register), so a runner/dispatcher role token can
        // already write host_roles today -- gating this route at the same
        // tier grants no new capability, it just stops the installer's
        // host-role self-report (which travels on the legacy cluster bearer's
        // dispatcher/runner/observer bundle) from failing closed to
        // `reviewer`. It stays distinct from the reviewer-gated rename/drain/
        // promote operations under `fabric.hosts.write`. A pure `observer`
        // (read-only) still cannot write.
        return HOST_REPORT;
    }
    if path.starts_with("/labels/") {
        return REVIEWER;
    }
    if path == "/tasks" || path == "/tasks/v2" {
        return if method == "GET" { TASK_READ } else { DISPATCH };
    }
    if path == "/tasks/claim" || path == "/tasks/claim-loom" || path == "/tasks/claim-fabric" {
        return RUN;
    }
    if path.starts_with("/tasks/") {
        if path.ends_with("/input") {
            return if method == "GET" { RUN } else { DISPATCH };
        }
        if method == "GET" {
            return TASK_READ;
        }
        if path.ends_with("/cancel") {
            return DISPATCH;
        }
        if path.ends_with("/notes") {
            return RUN_OR_DISPATCH;
        }
        return RUN;
    }
    if path == "/runners" {
        return TASK_READ;
    }
    if path.starts_with("/runners/") {
        if path.ends_with("-by-dispatcher") {
            return DISPATCH;
        }
        if method == "DELETE" {
            return DISPATCH_REVIEW;
        }
        return RUN;
    }
    if path == "/dispatchers/register" {
        return DISPATCH;
    }
    if path.starts_with("/dispatchers/") && method == "DELETE" {
        return REVIEWER;
    }
    if path == "/dispatchers" {
        return OBSERVE_DISPATCH;
    }
    if path == "/approvals" || path.starts_with("/approvals/") {
        if method == "POST" {
            return APPROVE;
        }
        return APPROVAL_READ;
    }
    if path == "/agents" || path.starts_with("/capabilities/") {
        return OBSERVE_DISPATCH;
    }
    if path == "/cluster/health"
        || path == "/hosts"
        || path.starts_with("/audit/")
        || path.starts_with("/cost/")
    {
        return OBSERVE;
    }
    // Identity self-inspection: every authenticated caller (any valid role,
    // and the legacy bearer's dispatcher/runner/observer bundle) must be able
    // to ask the hub what it may do. Falling through to the default REVIEWER
    // would wrongly deny a dispatcher-only role token the very answer the
    // clients need to gate their own UI, so this is enumerated explicitly.
    if path == "/whoami" {
        return VALID_ROLES;
    }
    REVIEWER
}

/// The `fabric.*.write`-style capability vocabulary the operator clients
/// (`fabric-client-core`'s `CommandContext.authorities`) gate their command
/// surface on. It exists nowhere in the hub's own enforcement -- the hub gates
/// by method/path role via [`required_roles`] -- so this table is the single
/// authoritative translation from a caller's resolved roles to that client
/// vocabulary, emitted by `GET /whoami`. Clients trust this answer rather than
/// maintaining a second, driftable copy of the role->capability decision.
///
/// A caller *has* an authority when its roles intersect the authority's role
/// set (union semantics): the client vocabulary is deliberately coarser than
/// the hub's per-route roles -- e.g. `fabric.hosts.write` covers both renaming
/// a runner (a `reviewer` label write) and draining one (a `dispatcher`
/// action), so either role grants the shared authority. Authorities whose
/// commands have no hub route at all (local OS service control, local/CLI DR
/// actions) carry an explicit documented role policy instead of a route.
///
/// `authorities_role_sets_match_required_roles` (below) pins every
/// route-backed entry against [`required_roles`] for its representative
/// route(s), so this table cannot silently drift from real enforcement.
const AUTHORITY_ROLES: &[(&str, &[&str])] = &[
    // POST /tasks/v2 (dispatch), POST /tasks/{id}/cancel -> dispatcher
    ("fabric.tasks.write", &["dispatcher"]),
    // POST /approvals/{id}/approve -> approver, reviewer
    ("fabric.approvals.write", &["approver", "reviewer"]),
    // PUT /labels/runners/{id} (rename, reviewer) UNION
    // POST /runners/{id}/drain-by-dispatcher (drain, dispatcher)
    ("fabric.hosts.write", &["dispatcher", "reviewer"]),
    // PUT /labels/hub (rename) -> reviewer; cluster promote/demote is an
    // operator action governed by the same reviewer authority.
    ("fabric.hub.write", &["reviewer"]),
    // Runner OS-service control has no hub route (the clients act on the
    // local service manager); reviewer is the governing operator policy.
    ("fabric.hosts.service", &["reviewer"]),
    // DR chaos/backup install/run are local/CLI actions with no hub route;
    // reviewer is the governing operator policy.
    ("fabric.dr.write", &["reviewer"]),
    // GET /secrets (join-token material) -> reviewer.
    ("fabric.connection.read-secret", &["reviewer"]),
    // No descriptor gates on this today; carried for vocabulary completeness
    // so a future connection-write command has a defined authority. reviewer
    // matches the settings/connection write posture.
    ("fabric.connection.write", &["reviewer"]),
];

/// Translate a caller's resolved roles into the client capability vocabulary
/// (see [`AUTHORITY_ROLES`]). Returned sorted for a stable `GET /whoami`
/// payload. Pure and dependency-free so it is unit-testable without a store
/// or a running request.
pub fn authorities_for(roles: &[String]) -> Vec<String> {
    let mut granted: Vec<String> = AUTHORITY_ROLES
        .iter()
        .filter(|(_, authority_roles)| {
            authority_roles
                .iter()
                .any(|needed| roles.iter().any(|held| held == needed))
        })
        .map(|(authority, _)| (*authority).to_owned())
        .collect();
    granted.sort();
    granted
}

/// Whether a route requires a recent high-assurance authentication (114C.6),
/// table-driven exactly like [`required_roles`] and pinned by the same
/// golden-fixture discipline (`human_account_step_up_baseline.json`). Lists
/// the plan's "Sensitive-action step-up" set, restricted to the actions that
/// exist as routes today:
///
/// - granting/removing a membership (may be `admin`);
/// - disabling an account (the last-admin case is the plan's concern);
/// - deleting/tombstoning an account;
/// - viewing/changing recovery policy (recovery-code issuance/completion);
/// - removing a passkey.
///
/// Deliberately *not* here, though the plan's list names them, and why:
///
/// - `POST /auth/passkeys/register/*`: gating registration on step-up would
///   deadlock an account's *first* passkey (step-up itself needs a passkey).
///   That route enforces "step-up only if the account already holds >=1
///   passkey" inside its handler instead -- the same handler-side pattern
///   `/auth/sessions` uses for ownership, which a purely method/path table
///   cannot express.
/// - break-glass / export / import / cluster-wide revoke / auth-mode change:
///   no route exists yet; nothing to gate.
pub fn requires_step_up(method: &str, path: &str) -> bool {
    if path.starts_with("/accounts/") {
        return path.contains("/membership")
            || path.ends_with("/disable")
            || path.ends_with("/delete")
            || path.ends_with("/tombstone")
            || path.ends_with("/recovery-codes")
            || path.ends_with("/recovery/complete")
            // "exporting account data" / "importing ForgeWire account data"
            // are both on the plan's explicit sensitive-action step-up list.
            || path.ends_with("/export")
            || path.ends_with("/import");
    }
    // Passkey *removal* is step-up-gated (matching fabric-client-core's
    // requiresStepUp on auth.removePasskey); registration is handled
    // handler-side (see this function's doc comment).
    if method == "DELETE" && path.starts_with("/auth/passkeys/") {
        return true;
    }
    false
}

/// True if a step-up performed at `step_up_at` is still within the
/// `freshness_minutes` window relative to `now`. Both timestamps are the
/// codebase's `"YYYY-MM-DD HH:MM:SS"` UTC strings; parsed to epoch seconds
/// for a real duration comparison rather than lexical string math (a lexical
/// `>=` would wrongly treat "2026-01-01 00:00:00" + 10min as a simple string
/// prefix). Pure and dependency-free specifically so the window boundary is
/// unit-testable without a running clock or store.
pub fn step_up_is_fresh(step_up_at: &str, now: &str, freshness_minutes: i64) -> bool {
    let (Some(then), Some(current)) = (parse_utc_to_epoch(step_up_at), parse_utc_to_epoch(now))
    else {
        // Unparseable timestamp: fail closed (not fresh) rather than
        // silently treating a malformed stamp as within the window.
        return false;
    };
    let elapsed = current - then;
    (0..=freshness_minutes.saturating_mul(60)).contains(&elapsed)
}

/// Parse `"YYYY-MM-DD HH:MM:SS"` (UTC) to epoch seconds. Returns `None` on
/// any malformed field. Kept private to this module -- it is the inverse of
/// `crate::utils::utc_now`'s formatting, only needed for the step-up
/// duration comparison.
fn parse_utc_to_epoch(s: &str) -> Option<i64> {
    let (date, time) = s.split_once(' ')?;
    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    let mut t = time.split(':');
    let hour: i64 = t.next()?.parse().ok()?;
    let min: i64 = t.next()?.parse().ok()?;
    let sec: i64 = t.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days since 1970-01-01 via a day count over whole years and months.
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    let md: [i64; 12] = [
        31,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    // `month` is validated to 1..=12 above, so `month - 1` is 0..=11;
    // iterate the slice rather than index-casting to usize (keeps clippy's
    // truncation/sign-loss lints satisfied without an allow).
    let months_before = usize::try_from(month - 1).unwrap_or(0);
    for &m in md.iter().take(months_before) {
        days += m;
    }
    days += day - 1;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_normalization_is_closed_and_deterministic() {
        assert_eq!(
            normalize_roles(&[" Runner ".into(), "observer".into(), "runner".into(),])
                .expect("valid roles"),
            vec!["observer", "runner"]
        );
        assert!(normalize_roles(&["admin".into()]).is_err());
        assert!(normalize_roles(&[]).is_err());
    }

    #[test]
    fn method_path_policy_separates_operator_roles() {
        assert_eq!(required_roles("POST", "/tasks/v2"), &["dispatcher"]);
        assert_eq!(required_roles("POST", "/tasks/claim-fabric"), &["runner"]);
        assert_eq!(required_roles("GET", "/tasks/42/input"), &["runner"]);
        assert_eq!(
            required_roles("POST", "/approvals/a-1/approve"),
            &["approver", "reviewer"]
        );
        assert_eq!(
            required_roles("GET", "/admin/role-tokens"),
            &["admin", "reviewer"]
        );
        assert_eq!(required_roles("POST", "/admin/role-tokens"), &["admin"]);
        assert_eq!(
            required_roles("POST", "/admin/role-tokens/split"),
            &["admin"]
        );
        assert_eq!(
            required_roles("POST", "/admin/role-tokens/migrate"),
            &["admin"]
        );
        assert_eq!(
            required_roles("DELETE", "/admin/role-tokens/rt_x"),
            &["admin"]
        );
        // Every other /admin/* path is untouched by the role-token-specific
        // branches above and still falls through to the generic reviewer gate.
        assert_eq!(
            required_roles("POST", "/admin/anything-else"),
            &["reviewer"]
        );
        assert_eq!(required_roles("GET", "/policy"), &["observer", "reviewer"]);
        assert_eq!(
            required_roles("GET", "/settings"),
            &["observer", "reviewer", "admin"]
        );
        assert_eq!(required_roles("PUT", "/settings/ha.mode"), &["reviewer"]);
        assert_eq!(required_roles("POST", "/unknown"), &["reviewer"]);
    }

    #[test]
    fn admin_may_read_settings_and_write_auth_but_not_other_settings() {
        // 114D groundwork: authentication policy is admin territory, so a
        // human admin (who holds only `admin` after bootstrap, never
        // `reviewer`) can read settings and write the `auth.*` subtree without
        // first obtaining `reviewer` -- this is what resolves the first-admin
        // passkey-setup deadlock. Every other settings key stays
        // `reviewer`-only.
        let admin = AuthContext::for_test("acct-1", &["admin"], Some("acct-1"));
        assert!(is_authorized(&admin, "GET", "/settings"));
        assert!(is_authorized(&admin, "GET", "/settings/auth.passkeys"));
        assert!(is_authorized(&admin, "PUT", "/settings/auth.passkeys"));
        // Whole-subtree write (`PUT /settings/auth`) is covered too.
        assert!(is_authorized(&admin, "PUT", "/settings/auth"));
        // Non-auth settings stay reviewer-only: admin alone cannot write them.
        assert!(!is_authorized(&admin, "PUT", "/settings/budget.daily_usd"));
        assert!(!is_authorized(&admin, "PUT", "/settings/ha.mode"));
        // The `auth.` carve-out must not leak to a lookalike prefix.
        assert!(!is_authorized(&admin, "PUT", "/settings/authx.thing"));

        // A reviewer keeps write access to every settings key, auth.* included.
        let reviewer = AuthContext::for_test("acct-2", &["reviewer"], Some("acct-2"));
        assert!(is_authorized(&reviewer, "PUT", "/settings/auth.passkeys"));
        assert!(is_authorized(
            &reviewer,
            "PUT",
            "/settings/budget.daily_usd"
        ));
    }

    #[test]
    fn a_bare_reviewer_token_cannot_mint_or_revoke_role_tokens() {
        // Regression: a reviewer-role token could previously issue itself a
        // fresh dispatcher/runner/approver/reviewer token via POST
        // /admin/role-tokens -- a privilege-escalation path (reviewer, a role
        // no route otherwise treats as a superset of dispatcher/runner/
        // approver, could freely mint tokens holding exactly those roles).
        // Caught live 2026-07-28 during a 114C.8 drill re-run: a probe of
        // this reviewer token's boundaries, expected to be denied, succeeded
        // instead. Role-token lifecycle mutation now requires `admin` (a
        // human-only role by construction -- see `required_roles`'s ADMIN
        // doc comment), mirroring the identical read/write split
        // `/accounts` already uses.
        let reviewer = AuthContext::for_test("token-reviewer-1", &["reviewer"], None);
        assert!(
            !is_authorized(&reviewer, "POST", "/admin/role-tokens"),
            "a bare reviewer token must not be able to mint a new role token"
        );
        assert!(
            !is_authorized(&reviewer, "POST", "/admin/role-tokens/split"),
            "a bare reviewer token must not be able to split the legacy bundle"
        );
        assert!(
            !is_authorized(&reviewer, "POST", "/admin/role-tokens/migrate"),
            "a bare reviewer token must not be able to migrate a bearer into a role token"
        );
        assert!(
            !is_authorized(&reviewer, "DELETE", "/admin/role-tokens/rt_x"),
            "a bare reviewer token must not be able to revoke another role token"
        );
        // Visibility is unaffected: reviewer can still list what exists.
        assert!(is_authorized(&reviewer, "GET", "/admin/role-tokens"));

        // A human admin session (never itself a role token, per ADMIN's own
        // construction guarantee) is exactly who this is gated to now.
        let admin = AuthContext::for_test("acct-admin-1", &["admin"], Some("acct-admin-1"));
        assert!(is_authorized(&admin, "POST", "/admin/role-tokens"));
        assert!(is_authorized(&admin, "POST", "/admin/role-tokens/split"));
        assert!(is_authorized(&admin, "POST", "/admin/role-tokens/migrate"));
        assert!(is_authorized(&admin, "DELETE", "/admin/role-tokens/rt_x"));
        assert!(is_authorized(&admin, "GET", "/admin/role-tokens"));
    }

    #[test]
    fn legacy_bundle_is_narrow_and_only_bootstraps_role_tokens() {
        let legacy = AuthContext::legacy();
        assert_eq!(legacy.roles, vec!["dispatcher", "runner", "observer"]);
        assert!(is_authorized(&legacy, "POST", "/admin/role-tokens"));
        assert!(is_authorized(&legacy, "POST", "/admin/role-tokens/migrate"));
        assert!(is_authorized(&legacy, "POST", "/admin/role-tokens/split"));
        assert!(!is_authorized(&legacy, "GET", "/admin/role-tokens"));
        assert!(is_authorized(&legacy, "GET", "/admin/binaries/manifest"));
        assert!(!is_authorized(&legacy, "GET", "/secrets"));
        assert!(is_authorized(&legacy, "GET", "/settings"));
        assert!(!is_authorized(&legacy, "PUT", "/settings/ha.mode"));
        assert!(!is_authorized(&legacy, "POST", "/approvals/a-1/approve"));
        // The cluster bearer may self-report its node's infrastructure roles
        // (POST /hosts/roles) -- it already writes host_roles via runner/
        // dispatcher enrolment, so this is no new capability -- but it still
        // cannot rename/relabel a host (reviewer-gated /labels/*).
        assert!(is_authorized(&legacy, "POST", "/hosts/roles"));
        assert!(!is_authorized(&legacy, "PUT", "/labels/runners/r-1"));
        // A read-only observer must not be able to write host roles.
        let observer = AuthContext::for_test("acct-obs", &["observer"], Some("acct-obs"));
        assert!(!is_authorized(&observer, "POST", "/hosts/roles"));
    }

    #[test]
    fn authorities_reflect_role_membership_with_union_semantics() {
        let has = |roles: &[&str], authority: &str| {
            authorities_for(&roles.iter().map(|r| (*r).to_owned()).collect::<Vec<_>>())
                .iter()
                .any(|a| a == authority)
        };
        // A dispatcher-only role token can write tasks and act on hosts (drain),
        // but cannot approve, rename the hub, or read secret material.
        assert!(has(&["dispatcher"], "fabric.tasks.write"));
        assert!(has(&["dispatcher"], "fabric.hosts.write"));
        assert!(!has(&["dispatcher"], "fabric.approvals.write"));
        assert!(!has(&["dispatcher"], "fabric.hub.write"));
        assert!(!has(&["dispatcher"], "fabric.connection.read-secret"));
        // An approver gets approvals but not task write.
        assert!(has(&["approver"], "fabric.approvals.write"));
        assert!(!has(&["approver"], "fabric.tasks.write"));
        // reviewer gets the reviewer-governed authorities, plus hosts.write via
        // the rename half of its union.
        assert!(has(&["reviewer"], "fabric.hub.write"));
        assert!(has(&["reviewer"], "fabric.hosts.write"));
        assert!(has(&["reviewer"], "fabric.hosts.service"));
        assert!(has(&["reviewer"], "fabric.dr.write"));
        assert!(has(&["reviewer"], "fabric.connection.read-secret"));
        // observer alone (a read role) grants no write authority.
        assert!(authorities_for(&["observer".to_owned()]).is_empty());
        // No roles -> no authorities (fail-closed).
        assert!(authorities_for(&[]).is_empty());
        // Output is sorted and deduplicated even for a broad role set.
        let all = authorities_for(
            &VALID_ROLES
                .iter()
                .map(|r| (*r).to_owned())
                .collect::<Vec<_>>(),
        );
        let mut sorted = all.clone();
        sorted.sort();
        assert_eq!(all, sorted);
        assert_eq!(
            all.len(),
            all.iter().collect::<std::collections::BTreeSet<_>>().len()
        );
    }

    #[test]
    fn authorities_role_sets_match_required_roles() {
        // Every route-backed authority's role set must equal the union of
        // required_roles() for its representative route(s); this is what keeps
        // the client capability vocabulary from drifting from real enforcement.
        let role_set = |authority: &str| -> std::collections::BTreeSet<String> {
            AUTHORITY_ROLES
                .iter()
                .find(|(a, _)| *a == authority)
                .map(|(_, roles)| roles.iter().map(|r| (*r).to_owned()).collect())
                .expect("authority present in table")
        };
        let union = |routes: &[(&str, &str)]| -> std::collections::BTreeSet<String> {
            routes
                .iter()
                .flat_map(|(m, p)| required_roles(m, p).iter().map(|r| (*r).to_owned()))
                .collect()
        };
        assert_eq!(
            role_set("fabric.tasks.write"),
            union(&[("POST", "/tasks/v2"), ("POST", "/tasks/42/cancel")])
        );
        assert_eq!(
            role_set("fabric.approvals.write"),
            union(&[("POST", "/approvals/a-1/approve")])
        );
        assert_eq!(
            role_set("fabric.hosts.write"),
            union(&[
                ("PUT", "/labels/runners/r-1"),
                ("POST", "/runners/r-1/drain-by-dispatcher"),
            ])
        );
        assert_eq!(
            role_set("fabric.hub.write"),
            union(&[("PUT", "/labels/hub")])
        );
        assert_eq!(
            role_set("fabric.connection.read-secret"),
            union(&[("GET", "/secrets")])
        );
    }

    #[test]
    fn whoami_is_reachable_by_every_valid_role() {
        // /whoami must not fall through to the default REVIEWER gate, or a
        // dispatcher-only token could not read its own capabilities.
        assert_eq!(required_roles("GET", "/whoami"), VALID_ROLES);
        for role in VALID_ROLES {
            let ctx = AuthContext::for_test("subj", &[role], None);
            assert!(is_authorized(&ctx, "GET", "/whoami"), "role {role} denied");
        }
        // The legacy compatibility bundle can also reach it.
        assert!(is_authorized(&AuthContext::legacy(), "GET", "/whoami"));
    }

    #[test]
    fn bearer_parser_does_not_transform_the_credential() {
        let value = HeaderValue::from_static("bEaReR CaSe-Sensitive-Value");
        assert_eq!(bearer_value(Some(&value)), Some("CaSe-Sensitive-Value"));
    }

    #[tokio::test]
    async fn role_misuse_is_a_structured_policy_violation_without_credentials() {
        let response = role_policy_violation(
            "POST",
            "/approvals/a-1/approve",
            &["approver", "reviewer"],
            &["observer".into()],
        );
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("read response body");
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).expect("structured JSON denial");
        assert_eq!(value["error"]["code"], "RolePolicyViolation");
        assert_eq!(value["error"]["granted_roles"], json!(["observer"]));
        assert!(!String::from_utf8_lossy(&bytes).contains("CaSe-Sensitive-Value"));
    }

    #[test]
    fn step_up_required_covers_the_sensitive_admin_actions() {
        assert!(requires_step_up("POST", "/accounts/acct-1/membership"));
        assert!(requires_step_up(
            "DELETE",
            "/accounts/acct-1/membership/admin"
        ));
        assert!(requires_step_up("POST", "/accounts/acct-1/disable"));
        assert!(requires_step_up("POST", "/accounts/acct-1/delete"));
        assert!(requires_step_up("POST", "/accounts/acct-1/tombstone"));
        assert!(requires_step_up("POST", "/accounts/acct-1/recovery-codes"));
        assert!(requires_step_up(
            "POST",
            "/accounts/acct-1/recovery/complete"
        ));
        assert!(requires_step_up("DELETE", "/auth/passkeys/cred-1"));
    }

    #[test]
    fn step_up_not_required_for_reads_and_ceremony_routes() {
        // Reading an account or its history is not a sensitive mutation.
        assert!(!requires_step_up("GET", "/accounts/acct-1"));
        assert!(!requires_step_up(
            "GET",
            "/accounts/acct-1/security-history"
        ));
        // Enabling is not on the plan's sensitive list (disabling is).
        assert!(!requires_step_up("POST", "/accounts/acct-1/enable"));
        // The step-up ceremony itself must be reachable by a not-yet-Aal2
        // session, so it is deliberately not step-up-gated.
        assert!(!requires_step_up("POST", "/auth/step-up/options"));
        assert!(!requires_step_up("POST", "/auth/step-up/verify"));
        // Ordinary self-service.
        assert!(!requires_step_up("GET", "/auth/me"));
        assert!(!requires_step_up("POST", "/auth/logout"));
    }

    #[test]
    fn step_up_freshness_window_is_inclusive_at_both_ends_and_rejects_beyond() {
        // Exactly at issuance: fresh.
        assert!(step_up_is_fresh(
            "2026-07-17 12:00:00",
            "2026-07-17 12:00:00",
            10
        ));
        // 9m59s later: still within a 10-minute window.
        assert!(step_up_is_fresh(
            "2026-07-17 12:00:00",
            "2026-07-17 12:09:59",
            10
        ));
        // Exactly 10 minutes: the boundary is inclusive.
        assert!(step_up_is_fresh(
            "2026-07-17 12:00:00",
            "2026-07-17 12:10:00",
            10
        ));
        // 10m01s: just past the window.
        assert!(!step_up_is_fresh(
            "2026-07-17 12:00:00",
            "2026-07-17 12:10:01",
            10
        ));
    }

    #[test]
    fn step_up_freshness_rejects_a_future_or_unparseable_stamp() {
        // A step_up_at in the future (clock skew / tampering) is not "fresh".
        assert!(!step_up_is_fresh(
            "2026-07-17 12:05:00",
            "2026-07-17 12:00:00",
            10
        ));
        // Garbage timestamps fail closed.
        assert!(!step_up_is_fresh("not-a-date", "2026-07-17 12:00:00", 10));
        assert!(!step_up_is_fresh("2026-07-17 12:00:00", "garbage", 10));
    }

    #[test]
    fn parse_utc_round_trips_a_known_epoch() {
        // 2026-07-17 12:00:00 UTC. Cross-check a one-minute difference is 60s
        // (the property step_up_is_fresh actually depends on), rather than
        // hardcoding an absolute epoch that is easy to get wrong by hand.
        let a = parse_utc_to_epoch("2026-07-17 12:00:00").unwrap();
        let b = parse_utc_to_epoch("2026-07-17 12:01:00").unwrap();
        assert_eq!(b - a, 60);
        let c = parse_utc_to_epoch("2026-07-18 12:00:00").unwrap();
        assert_eq!(c - a, 86400);
        assert!(parse_utc_to_epoch("2026-13-01 00:00:00").is_none());
    }
}
