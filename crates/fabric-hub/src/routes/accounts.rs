//! Human-account administration routes (114C.5).
//!
//! - GET    /accounts
//! - POST   /accounts
//! - GET    /accounts/{id}
//! - PATCH  /accounts/{id}
//! - POST   /accounts/{id}/membership
//! - DELETE /accounts/{id}/membership/{role}
//! - POST   /accounts/{id}/disable
//! - POST   /accounts/{id}/enable
//! - POST   /accounts/{id}/recovery-codes
//! - POST   /accounts/{id}/recovery/complete
//! - POST   /accounts/{id}/delete
//! - POST   /accounts/{id}/tombstone
//! - GET    /accounts/{id}/security-history
//! - GET    /accounts/export
//! - POST   /accounts/import
//! - GET    /auth-policy
//! - GET    /auth/sessions
//! - DELETE /auth/sessions/{id}
//!
//! Role gating for every route above lives in `crate::auth::required_roles`
//! (pinned by `tests/human_account_route_policy_baseline.rs`); this module
//! implements the handlers those routes dispatch to. `/auth/sessions*` is a
//! coarse role gate only -- ownership ("my session, or I am admin") is
//! enforced inside the handlers below using `AuthContext.human_principal`.

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use fabric_accounts::domain::{AccountStatus, Role};
use fabric_accounts::dto::{AccountExportDto, AccountSummaryDto, SessionSummaryDto};
use fabric_accounts::error::AccountsError;
use fabric_accounts::repository::{
    AccountOrchestration, AccountRepository, MembershipRepository, SessionRepository,
};
use fabric_accounts::validation;

use crate::auth::{AuthContext, DEFAULT_REALM_ID, VALID_ROLES};
use crate::error::ApiError;
use crate::state::HubState;
use crate::utils::{attribution, audit_append, utc_now};

owned_router! {
    pub fn router, ROUTES {
        "GET" get "/accounts" => list_accounts;
        "POST" post "/accounts" => create_account;
        "GET" get "/accounts/{account_id}" => get_account;
        "PATCH" patch "/accounts/{account_id}" => update_account_status;
        "POST" post "/accounts/{account_id}/membership" => grant_membership;
        "DELETE" delete "/accounts/{account_id}/membership/{role}" => revoke_membership;
        "POST" post "/accounts/{account_id}/disable" => disable_account;
        "POST" post "/accounts/{account_id}/enable" => enable_account;
        "POST" post "/accounts/{account_id}/recovery-codes" => generate_recovery_codes;
        "POST" post "/accounts/{account_id}/recovery/complete" => complete_recovery;
        "POST" post "/accounts/{account_id}/delete" => initiate_deletion;
        "POST" post "/accounts/{account_id}/tombstone" => complete_deletion;
        "GET" get "/accounts/{account_id}/security-history" => security_history;
        "GET" get "/accounts/export" => export_accounts;
        "POST" post "/accounts/import" => import_accounts;
        "GET" get "/auth-policy" => auth_policy;
        "GET" get "/auth/sessions" => list_sessions;
        "DELETE" delete "/auth/sessions/{session_id}" => revoke_session;
    }
}

/// `AccountRepository::get_account`'s "account_not_found" case is a generic
/// `AccountPolicyViolation` (400) in the typed-error baseline; refine it to
/// a 404 for these read/lookup call sites without inventing a new wire code
/// -- `error.code()` is still `AccountPolicyViolation` either way, only the
/// HTTP status improves.
fn account_lookup_error(error: AccountsError) -> ApiError {
    if let AccountsError::AccountPolicyViolation { ref reason } = error {
        if reason == "account_not_found" {
            return ApiError::not_found("account not found");
        }
    }
    ApiError::account(error)
}

fn parse_role(raw: &str) -> Result<Role, ApiError> {
    match raw {
        "observer" => Ok(Role::Observer),
        "dispatcher" => Ok(Role::Dispatcher),
        "approver" => Ok(Role::Approver),
        "reviewer" => Ok(Role::Reviewer),
        "admin" => Ok(Role::Admin),
        "runner" => Err(ApiError::account(AccountsError::AccountPolicyViolation {
            reason: "human_runner_membership_forbidden".to_owned(),
        })),
        other => Err(ApiError::account(AccountsError::AccountPolicyViolation {
            reason: format!("unrecognized_role:{other}"),
        })),
    }
}

fn parse_status(raw: &str) -> Result<AccountStatus, ApiError> {
    match raw {
        "active" => Ok(AccountStatus::Active),
        "locked" => Ok(AccountStatus::Locked),
        "recovery_required" => Ok(AccountStatus::RecoveryRequired),
        other => Err(ApiError::account(AccountsError::AccountPolicyViolation {
            reason: format!("unrecognized_or_unsupported_target_status:{other}"),
        })),
    }
}

/// `PATCH /accounts/{id}` is deliberately narrow: it exists to cover the two
/// 114C.5 deliverables that are not their own dedicated route --"unlock"
/// (`locked` -> `active`) and admin-forced/completed recovery (`active` <->
/// `recovery_required`). `active` <-> `disabled` has its own dedicated
/// routes below with their own guards (last-administrator protection on
/// disable); allowing PATCH to also reach `disabled` would create two
/// differently-guarded paths to the same transition.
fn transition_allowed(current: AccountStatus, target: AccountStatus) -> bool {
    matches!(
        (current, target),
        (AccountStatus::Locked, AccountStatus::Active)
            | (AccountStatus::RecoveryRequired, AccountStatus::Active)
            | (AccountStatus::Active, AccountStatus::RecoveryRequired)
    )
}

pub(crate) async fn account_summary(
    state: &HubState,
    account: &fabric_accounts::domain::Account,
) -> Result<AccountSummaryDto, ApiError> {
    let memberships = MembershipRepository::list_for_account(&*state.store, &account.account_id)
        .await
        .map_err(ApiError::account)?;
    Ok(AccountSummaryDto::from_account_and_memberships(
        account,
        &memberships,
    ))
}

// ---- GET /accounts ----------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListAccountsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}
fn default_limit() -> i64 {
    200
}

pub async fn list_accounts(
    State(state): State<Arc<HubState>>,
    Query(q): Query<ListAccountsQuery>,
) -> Result<Json<Value>, ApiError> {
    let realm_id = DEFAULT_REALM_ID.to_owned();
    let accounts = AccountRepository::list_accounts(&*state.store, &realm_id, q.limit, q.offset)
        .await
        .map_err(ApiError::account)?;
    let mut summaries = Vec::with_capacity(accounts.len());
    for account in &accounts {
        summaries.push(account_summary(&state, account).await?);
    }
    Ok(Json(json!({ "accounts": summaries })))
}

// ---- POST /accounts ----------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateAccountRequest {
    pub username: String,
    pub display_name: String,
    pub password: String,
    pub role: String,
}

pub async fn create_account(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(request): Json<CreateAccountRequest>,
) -> Result<Json<Value>, ApiError> {
    let role = parse_role(&request.role)?;
    let now = utc_now();
    let granted_by = actor
        .human_principal
        .clone()
        .unwrap_or_else(|| actor.subject.clone());
    let account = AccountOrchestration::create_account_with_password(
        &*state.store,
        DEFAULT_REALM_ID,
        &request.username,
        &request.display_name,
        &request.password,
        role,
        &granted_by,
        &now,
    )
    .await
    .map_err(ApiError::account)?;
    let summary = account_summary(&state, &account).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.created",
        None,
        &json!({
            "account_id": account.account_id,
            "username": account.username_normalized,
            "role": role.as_str(),
            "actor": attribution(&actor),
        }),
    )
    .await;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- GET /accounts/{id} -------------------------------------------------------

pub async fn get_account(
    State(state): State<Arc<HubState>>,
    Path(account_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let account = AccountRepository::get_account(&*state.store, &account_id)
        .await
        .map_err(account_lookup_error)?;
    let summary = account_summary(&state, &account).await?;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- PATCH /accounts/{id} ------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UpdateAccountStatusRequest {
    pub status: String,
    pub expected_revision: i64,
}

pub async fn update_account_status(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(account_id): Path<String>,
    Json(request): Json<UpdateAccountStatusRequest>,
) -> Result<Json<Value>, ApiError> {
    let target = parse_status(&request.status)?;
    let current = AccountRepository::get_account(&*state.store, &account_id)
        .await
        .map_err(account_lookup_error)?;
    if !transition_allowed(current.status, target) {
        return Err(ApiError::account(AccountsError::AccountPolicyViolation {
            reason: "status_transition_not_permitted".to_owned(),
        }));
    }
    let updated = AccountRepository::update_status(
        &*state.store,
        &account_id,
        request.expected_revision,
        target,
    )
    .await
    .map_err(ApiError::account)?;
    let summary = account_summary(&state, &updated).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.status_changed",
        None,
        &json!({
            "account_id": account_id,
            "from": current.status.as_str(),
            "to": target.as_str(),
            "actor": attribution(&actor),
        }),
    )
    .await;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- POST /accounts/{id}/membership ---------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GrantMembershipRequest {
    pub role: String,
}

pub async fn grant_membership(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(account_id): Path<String>,
    Json(request): Json<GrantMembershipRequest>,
) -> Result<Json<Value>, ApiError> {
    let role = parse_role(&request.role)?;
    let account = AccountRepository::get_account(&*state.store, &account_id)
        .await
        .map_err(account_lookup_error)?;
    let now = utc_now();
    let granted_by = actor
        .human_principal
        .clone()
        .unwrap_or_else(|| actor.subject.clone());
    AccountOrchestration::grant_membership(
        &*state.store,
        &account_id,
        &account.realm_id,
        role,
        &granted_by,
        &now,
    )
    .await
    .map_err(ApiError::account)?;
    let summary = account_summary(&state, &account).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.membership_granted",
        None,
        &json!({ "account_id": account_id, "role": role.as_str(), "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- DELETE /accounts/{id}/membership/{role} ------------------------------------

pub async fn revoke_membership(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path((account_id, role_str)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let role = parse_role(&role_str)?;
    let account = AccountRepository::get_account(&*state.store, &account_id)
        .await
        .map_err(account_lookup_error)?;
    let memberships = MembershipRepository::list_for_account(&*state.store, &account_id)
        .await
        .map_err(ApiError::account)?;
    let target = memberships
        .into_iter()
        .find(|m| m.revoked_at.is_none() && m.role == role)
        .ok_or_else(|| ApiError::not_found("the account does not hold that role"))?;
    let now = utc_now();
    AccountOrchestration::revoke_membership_protecting_last_admin(
        &*state.store,
        &target.membership_id,
        &now,
    )
    .await
    .map_err(ApiError::account)?;
    let summary = account_summary(&state, &account).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.membership_revoked",
        None,
        &json!({ "account_id": account_id, "role": role.as_str(), "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- POST /accounts/{id}/disable ------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RevisionGuardedRequest {
    pub expected_revision: i64,
}

pub async fn disable_account(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(account_id): Path<String>,
    Json(request): Json<RevisionGuardedRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = utc_now();
    let updated = AccountOrchestration::disable_account_protecting_last_admin(
        &*state.store,
        &account_id,
        request.expected_revision,
        &now,
    )
    .await
    .map_err(ApiError::account)?;
    let summary = account_summary(&state, &updated).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.disabled",
        None,
        &json!({ "account_id": account_id, "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- POST /accounts/{id}/enable -------------------------------------------------

pub async fn enable_account(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(account_id): Path<String>,
    Json(request): Json<RevisionGuardedRequest>,
) -> Result<Json<Value>, ApiError> {
    let current = AccountRepository::get_account(&*state.store, &account_id)
        .await
        .map_err(account_lookup_error)?;
    if current.status != AccountStatus::Disabled {
        return Err(ApiError::account(AccountsError::AccountPolicyViolation {
            reason: "status_transition_not_permitted".to_owned(),
        }));
    }
    let updated = AccountRepository::update_status(
        &*state.store,
        &account_id,
        request.expected_revision,
        AccountStatus::Active,
    )
    .await
    .map_err(ApiError::account)?;
    let summary = account_summary(&state, &updated).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.enabled",
        None,
        &json!({ "account_id": account_id, "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- POST /accounts/{id}/recovery-codes -----------------------------------------

#[derive(Debug, Deserialize)]
pub struct GenerateRecoveryCodesRequest {
    #[serde(default = "default_recovery_code_count")]
    pub count: i64,
}
fn default_recovery_code_count() -> i64 {
    5
}

/// Returns the generated codes in plaintext exactly once -- this response
/// body is the only place they ever exist outside the database's hashed
/// form (see `AccountOrchestration::generate_recovery_codes`'s doc comment).
/// Never logged, never included in the audit payload below (only the count
/// is), per the plan's "reset/recovery tokens do not appear in events or
/// audit payloads."
pub async fn generate_recovery_codes(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(account_id): Path<String>,
    Json(request): Json<GenerateRecoveryCodesRequest>,
) -> Result<Json<Value>, ApiError> {
    AccountRepository::get_account(&*state.store, &account_id)
        .await
        .map_err(account_lookup_error)?;
    let now = utc_now();
    let codes = AccountOrchestration::generate_recovery_codes(
        &*state.store,
        &account_id,
        request.count,
        &now,
    )
    .await
    .map_err(ApiError::account)?;
    let plaintext: Vec<&str> = codes
        .iter()
        .map(fabric_accounts::secret::SecretString::expose_secret)
        .collect();
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.recovery_codes_generated",
        None,
        &json!({ "account_id": account_id, "count": plaintext.len(), "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(
        json!({ "account_id": account_id, "codes": plaintext }),
    ))
}

// ---- POST /accounts/{id}/recovery/complete ---------------------------------------

#[derive(Deserialize)]
pub struct CompleteRecoveryRequest {
    pub code: String,
    pub new_password: String,
}

// Manual Debug: never print `code`/`new_password` even in a panic/log line
// that happens to Debug-format the extracted request body.
impl std::fmt::Debug for CompleteRecoveryRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompleteRecoveryRequest")
            .field("code", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .finish()
    }
}

pub async fn complete_recovery(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(account_id): Path<String>,
    Json(request): Json<CompleteRecoveryRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = utc_now();
    let updated = AccountOrchestration::complete_recovery_with_code(
        &*state.store,
        &account_id,
        &request.code,
        &request.new_password,
        &now,
    )
    .await
    .map_err(ApiError::account)?;
    let summary = account_summary(&state, &updated).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.recovery_completed",
        None,
        &json!({ "account_id": account_id, "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- POST /accounts/{id}/delete, /accounts/{id}/tombstone -----------------------

/// Step one of the plan's two-step deletion lifecycle: marks the account
/// `deletion_pending` and revokes its sessions, protecting the realm's last
/// enabled administrator the same way `disable_account` does. Known gap,
/// still not fixed here: the plan lists "deleting an account" under sensitive
/// actions requiring a recent high-assurance step-up authentication. The
/// step-up primitive now exists and works end to end (114C.6's
/// `/auth/step-up/*` + `step_up_is_fresh`; the VSIX drives it in 114C.7 Slice
/// 4c-3), but this route still enforces only the `admin` role check every
/// other mutation here enforces -- it does not yet require a fresh step-up.
/// The 114C.7 clients demand a fresh step-up client-side before offering
/// deletion, so they are not laxer than the intent; wiring hub-side
/// enforcement here (reject unless `step_up_is_fresh`) is a tracked
/// fast-follow, not built yet.
pub async fn initiate_deletion(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(account_id): Path<String>,
    Json(request): Json<RevisionGuardedRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = utc_now();
    let updated = AccountOrchestration::initiate_account_deletion_protecting_last_admin(
        &*state.store,
        &account_id,
        request.expected_revision,
        &now,
    )
    .await
    .map_err(ApiError::account)?;
    let summary = account_summary(&state, &updated).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.deletion_initiated",
        None,
        &json!({ "account_id": account_id, "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

/// Step two: irreversible. Requires the account to already be
/// `deletion_pending` (set by [`initiate_deletion`]).
pub async fn complete_deletion(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(account_id): Path<String>,
    Json(request): Json<RevisionGuardedRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = utc_now();
    let updated = AccountOrchestration::complete_account_deletion(
        &*state.store,
        &account_id,
        request.expected_revision,
        &now,
    )
    .await
    .map_err(ApiError::account)?;
    let summary = account_summary(&state, &updated).await?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.deletion_completed",
        None,
        &json!({ "account_id": account_id, "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(serde_json::to_value(summary).unwrap_or(Value::Null)))
}

// ---- GET /accounts/{id}/security-history -----------------------------------------

#[derive(Debug, Deserialize)]
pub struct SecurityHistoryQuery {
    #[serde(default = "default_security_history_limit")]
    pub limit: i64,
}
fn default_security_history_limit() -> i64 {
    50
}

/// 114C.5's "bounded login/session security history" deliverable: an
/// account's most recent login attempts and most recent sessions (including
/// revoked ones), each bounded by `limit` (default 50, capped at 200 --
/// see `AccountOrchestration::account_security_history`). Read access
/// matches every other `GET /accounts/{id}/*` route (`admin` or `reviewer`)
/// -- unlike `/auth/sessions`, this is not a self-service route.
pub async fn security_history(
    State(state): State<Arc<HubState>>,
    Path(account_id): Path<String>,
    Query(q): Query<SecurityHistoryQuery>,
) -> Result<Json<Value>, ApiError> {
    AccountRepository::get_account(&*state.store, &account_id)
        .await
        .map_err(account_lookup_error)?;
    let (login_attempts, sessions) =
        AccountOrchestration::account_security_history(&*state.store, &account_id, q.limit)
            .await
            .map_err(ApiError::account)?;
    let session_summaries: Vec<SessionSummaryDto> = sessions
        .iter()
        .map(|s| SessionSummaryDto::from_session(s, false))
        .collect();
    Ok(Json(json!({
        "account_id": account_id,
        "login_attempts": login_attempts,
        "sessions": session_summaries,
    })))
}

// ---- GET /accounts/export ---------------------------------------------------------

/// 114C.5's account-export deliverable: a safe, redacted snapshot of every
/// account's profile fields in the realm. Step-up gated (`requires_step_up`
/// lists this route explicitly, matching the plan's sensitive-action list
/// "exporting account data") -- `admin`/`reviewer` role alone is not
/// enough. Structurally cannot leak a credential or session: `AccountExportDto`
/// is built only from `Account`/`Membership` fields, the same
/// explicit-field-extraction guarantee every other DTO in `fabric-accounts`
/// has.
pub async fn export_accounts(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
) -> Result<Json<Value>, ApiError> {
    let realm_id = DEFAULT_REALM_ID.to_owned();
    let accounts = AccountRepository::list_accounts(&*state.store, &realm_id, 500, 0)
        .await
        .map_err(ApiError::account)?;
    let mut exports = Vec::with_capacity(accounts.len());
    for account in &accounts {
        let memberships =
            MembershipRepository::list_for_account(&*state.store, &account.account_id)
                .await
                .map_err(ApiError::account)?;
        exports.push(AccountExportDto::from_account_and_memberships(
            account,
            &memberships,
        ));
    }
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.exported",
        None,
        &json!({ "count": exports.len(), "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(json!({
        "schema_version": 1,
        "exported_at": utc_now(),
        "accounts": exports,
    })))
}

// ---- POST /accounts/import --------------------------------------------------------

/// One record of a ForgeWire account-interchange document (114C.5). `roles`
/// is expressed directly in Fabric role names, not a legacy vocabulary --
/// per the plan's migration flow ("Fabric imports stable profile fields and
/// **mapped** human roles"), role mapping is an explicit step the operator
/// performs before this document reaches Fabric; Fabric has no ground truth
/// for ForgeWire's own internal role identifiers to guess from. Only the
/// first human-assignable, non-`admin` entry in `roles` is applied -- import
/// must never auto-grant `admin` (a binding rule stated explicitly in the
/// plan's migration section), and multiple roles per imported account is
/// not a 114C.5 deliverable. `deny_unknown_fields` is the type-level
/// enforcement of "excludes secrets by default": a document smuggling an
/// unexpected field (e.g. a legacy password hash) is rejected at parse
/// time, not silently ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgeWireAccountRecord {
    pub username: String,
    pub display_name: String,
    #[serde(default)]
    pub email: Option<String>,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountImportDocument {
    pub schema_version: u32,
    pub source: String,
    pub accounts: Vec<ForgeWireAccountRecord>,
}

fn default_dry_run_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct ImportAccountsRequest {
    pub document: AccountImportDocument,
    /// Defaults to `true` (preview only) so a bare call can never write --
    /// the caller must explicitly pass `false` to apply. Matches the plan's
    /// "explicit" requirement for this operation.
    #[serde(default = "default_dry_run_true")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportRowOutcome {
    WouldCreate,
    SkipExistingUsername,
    /// Covers both an unusable username (fails `validation::normalize_username`)
    /// and a `roles` list with no human-assignable, non-`admin` entry --
    /// grouped under one outcome since both mean "this record cannot be
    /// applied as written," not two operator-actionable distinctions.
    RejectInvalidRecord,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportPreviewRow {
    pub username: String,
    pub outcome: ImportRowOutcome,
}

/// Resolve one record's outcome without writing anything -- shared by both
/// the preview pass and the apply pass (apply only calls
/// `create_invited_account` for rows this function marks `WouldCreate`), so
/// preview and apply can never structurally disagree about which rows would
/// be created.
async fn resolve_import_row(
    state: &HubState,
    realm_id: &str,
    record: &ForgeWireAccountRecord,
) -> (ImportPreviewRow, Option<(String, Role)>) {
    let role = record
        .roles
        .iter()
        .find_map(|raw| parse_role(raw).ok().filter(|role| *role != Role::Admin));
    let Some(role) = role else {
        return (
            ImportPreviewRow {
                username: record.username.clone(),
                outcome: ImportRowOutcome::RejectInvalidRecord,
            },
            None,
        );
    };
    let Ok(username_normalized) = validation::normalize_username(&record.username) else {
        return (
            ImportPreviewRow {
                username: record.username.clone(),
                outcome: ImportRowOutcome::RejectInvalidRecord,
            },
            None,
        );
    };
    let exists = AccountRepository::find_by_username(
        &*state.store,
        &realm_id.to_owned(),
        &username_normalized,
    )
    .await;
    match exists {
        Ok(Some(_)) => (
            ImportPreviewRow {
                username: record.username.clone(),
                outcome: ImportRowOutcome::SkipExistingUsername,
            },
            None,
        ),
        Ok(None) => (
            ImportPreviewRow {
                username: record.username.clone(),
                outcome: ImportRowOutcome::WouldCreate,
            },
            Some((username_normalized, role)),
        ),
        // Fail-safe: a lookup failure must never be treated as "does not
        // exist, safe to create" -- skip rather than risk a duplicate.
        Err(_) => (
            ImportPreviewRow {
                username: record.username.clone(),
                outcome: ImportRowOutcome::SkipExistingUsername,
            },
            None,
        ),
    }
}

/// Preview (`dry_run: true`, the default) or apply (`dry_run: false`) a
/// ForgeWire account-import document. Step-up gated (plan's sensitive-action
/// list: "importing ForgeWire account data"). Idempotent by construction:
/// a username that already exists is always `SkipExistingUsername`, so
/// re-running the same apply a second time creates nothing new. Newly
/// created accounts start `Invited` with no credential (nothing is
/// imported by default -- see `AccountOrchestration::create_invited_account`'s
/// doc comment) and are immediately given a batch of recovery codes so the
/// operator has a real, already-shipped enrollment path to hand the new
/// user, exactly like `POST /accounts/{id}/recovery-codes`.
pub async fn import_accounts(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Json(request): Json<ImportAccountsRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = utc_now();
    let realm_id = DEFAULT_REALM_ID.to_owned();
    let granted_by = actor
        .human_principal
        .clone()
        .unwrap_or_else(|| actor.subject.clone());

    let mut rows = Vec::with_capacity(request.document.accounts.len());
    let mut created = Vec::new();

    for record in &request.document.accounts {
        let (row, candidate) = resolve_import_row(&state, &realm_id, record).await;
        if !request.dry_run {
            if let Some((_, role)) = &candidate {
                let result = AccountOrchestration::create_invited_account(
                    &*state.store,
                    &realm_id,
                    &record.username,
                    &record.display_name,
                    record.email.as_deref(),
                    *role,
                    &granted_by,
                    &now,
                )
                .await;
                match result {
                    Ok(account) => {
                        let codes = AccountOrchestration::generate_recovery_codes(
                            &*state.store,
                            &account.account_id,
                            5,
                            &now,
                        )
                        .await
                        .map_err(ApiError::account)?;
                        created.push(json!({
                            "account_id": account.account_id,
                            "username": account.username_normalized,
                            "codes": codes.iter().map(|c| c.expose_secret()).collect::<Vec<_>>(),
                        }));
                        rows.push(row);
                        continue;
                    }
                    // A race since resolve_import_row's read: someone else
                    // created this username in between. Downgrade to a skip
                    // rather than failing the whole batch -- idempotency
                    // means "already exists" is never an error.
                    Err(AccountsError::UsernameConflict) => {
                        rows.push(ImportPreviewRow {
                            username: row.username,
                            outcome: ImportRowOutcome::SkipExistingUsername,
                        });
                        continue;
                    }
                    Err(error) => return Err(ApiError::account(error)),
                }
            }
        }
        rows.push(row);
    }

    let mut would_create = 0i64;
    let mut skip_existing = 0i64;
    let mut reject_invalid = 0i64;
    for row in &rows {
        match row.outcome {
            ImportRowOutcome::WouldCreate => would_create += 1,
            ImportRowOutcome::SkipExistingUsername => skip_existing += 1,
            ImportRowOutcome::RejectInvalidRecord => reject_invalid += 1,
        }
    }

    let _ = audit_append(
        &*state.store,
        &state.secrets,
        if request.dry_run {
            "account.import_previewed"
        } else {
            "account.import_applied"
        },
        None,
        &json!({
            "would_create": would_create,
            "skip_existing_username": skip_existing,
            "reject_invalid_record": reject_invalid,
            "created_account_ids": created.iter().map(|c| c["account_id"].clone()).collect::<Vec<_>>(),
            "actor": attribution(&actor),
        }),
    )
    .await;

    Ok(Json(json!({
        "dry_run": request.dry_run,
        "rows": rows,
        "summary": {
            "would_create": would_create,
            "skip_existing_username": skip_existing,
            "reject_invalid_record": reject_invalid,
        },
        "created": created,
    })))
}

// ---- GET /auth-policy ----------------------------------------------------------

/// Structural policy facts a client needs to render account administration
/// UI correctly: the realm this hub enforces, whether bootstrap has already
/// completed, and the full role vocabulary including `admin` (which,
/// deliberately, `crate::auth::VALID_ROLES` itself does not list -- see that
/// constant's doc comment). Login-throttle threshold/window are internal to
/// `fabric-store-rqlite` and are not duplicated here to avoid a second
/// source of truth that could silently drift from the enforced values.
pub async fn auth_policy(State(state): State<Arc<HubState>>) -> Result<Json<Value>, ApiError> {
    let bootstrap_open = AccountOrchestration::bootstrap_status(&*state.store)
        .await
        .map_err(ApiError::account)?;
    let mut roles: Vec<&str> = VALID_ROLES.to_vec();
    roles.push("admin");
    Ok(Json(json!({
        "realm_id": DEFAULT_REALM_ID,
        "bootstrap_open": bootstrap_open,
        "roles": roles,
    })))
}

// ---- GET /auth/sessions ---------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct ListSessionsQuery {
    /// Admin-only: view another account's sessions. Omitted (or supplied by
    /// a non-admin caller, which is rejected) means "my own sessions."
    #[serde(default)]
    pub account_id: Option<String>,
}

pub async fn list_sessions(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Query(q): Query<ListSessionsQuery>,
) -> Result<Json<Value>, ApiError> {
    let is_admin = actor.roles.iter().any(|r| r == "admin");
    let target_account_id = match q.account_id {
        Some(requested) if requested != actor.human_principal.clone().unwrap_or_default() => {
            if !is_admin {
                return Err(ApiError::account(AccountsError::RolePolicyViolation));
            }
            requested
        }
        Some(requested) => requested,
        None => actor.human_principal.clone().unwrap_or_default(),
    };
    // A non-human caller (role token / legacy bearer) with no account_id
    // owns no session by construction; querying with an empty account_id
    // correctly returns no rows rather than requiring a special case here.
    let sessions = SessionRepository::list_for_account(&*state.store, &target_account_id)
        .await
        .map_err(ApiError::account)?;
    // `current` marks the literal session that issued this request, now that
    // `AuthContext` carries `session_id` (114C.6 Slice 4). `None` (a
    // role-token/legacy caller) matches no session, so every entry is
    // correctly `current: false` for those callers.
    let summaries: Vec<SessionSummaryDto> = sessions
        .iter()
        .map(|s| {
            let current = actor.session_id.as_deref() == Some(s.session_id.as_str());
            SessionSummaryDto::from_session(s, current)
        })
        .collect();
    Ok(Json(json!({ "sessions": summaries })))
}

// ---- DELETE /auth/sessions/{id} --------------------------------------------------

pub async fn revoke_session(
    State(state): State<Arc<HubState>>,
    Extension(actor): Extension<AuthContext>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = SessionRepository::get(&*state.store, &session_id)
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
    SessionRepository::revoke(&*state.store, &session_id, "revoked_by_operator", &now)
        .await
        .map_err(ApiError::account)?;
    let _ = audit_append(
        &*state.store,
        &state.secrets,
        "account.session_revoked",
        None,
        &json!({ "session_id": session_id, "account_id": session.account_id, "actor": attribution(&actor) }),
    )
    .await;
    Ok(Json(json!({ "session_id": session_id, "revoked": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_role_accepts_every_human_assignable_role() {
        for (raw, expected) in [
            ("observer", Role::Observer),
            ("dispatcher", Role::Dispatcher),
            ("approver", Role::Approver),
            ("reviewer", Role::Reviewer),
            ("admin", Role::Admin),
        ] {
            assert_eq!(parse_role(raw).unwrap(), expected);
        }
    }

    #[test]
    fn parse_role_rejects_runner_and_garbage() {
        assert!(parse_role("runner").is_err());
        assert!(parse_role("not-a-role").is_err());
        assert!(parse_role("").is_err());
    }

    #[test]
    fn parse_status_accepts_only_the_three_client_settable_targets() {
        assert_eq!(parse_status("active").unwrap(), AccountStatus::Active);
        assert_eq!(parse_status("locked").unwrap(), AccountStatus::Locked);
        assert_eq!(
            parse_status("recovery_required").unwrap(),
            AccountStatus::RecoveryRequired
        );
        // disabled/invited/deletion_pending/deleted_tombstone all have
        // dedicated routes or are not reachable via PATCH at all.
        assert!(parse_status("disabled").is_err());
        assert!(parse_status("invited").is_err());
        assert!(parse_status("deletion_pending").is_err());
        assert!(parse_status("deleted_tombstone").is_err());
        assert!(parse_status("garbage").is_err());
    }

    #[test]
    fn transition_allowed_covers_exactly_unlock_and_recovery_toggling() {
        let legal = [
            (AccountStatus::Locked, AccountStatus::Active),
            (AccountStatus::RecoveryRequired, AccountStatus::Active),
            (AccountStatus::Active, AccountStatus::RecoveryRequired),
        ];
        for (from, to) in legal {
            assert!(
                transition_allowed(from, to),
                "{from:?} -> {to:?} should be legal"
            );
        }
        let illegal = [
            (AccountStatus::Active, AccountStatus::Locked),
            (AccountStatus::Active, AccountStatus::Active),
            (AccountStatus::Disabled, AccountStatus::Active),
            (AccountStatus::Invited, AccountStatus::Active),
            (AccountStatus::Locked, AccountStatus::RecoveryRequired),
            (
                AccountStatus::RecoveryRequired,
                AccountStatus::RecoveryRequired,
            ),
        ];
        for (from, to) in illegal {
            assert!(
                !transition_allowed(from, to),
                "{from:?} -> {to:?} should be illegal"
            );
        }
    }

    #[test]
    fn account_lookup_error_refines_not_found_to_a_404_but_leaves_other_reasons_alone() {
        let not_found = account_lookup_error(AccountsError::AccountPolicyViolation {
            reason: "account_not_found".to_owned(),
        });
        assert_eq!(not_found.status_code(), axum::http::StatusCode::NOT_FOUND);

        let other = account_lookup_error(AccountsError::AccountPolicyViolation {
            reason: "revision_conflict".to_owned(),
        });
        assert_ne!(other.status_code(), axum::http::StatusCode::NOT_FOUND);

        let last_admin = account_lookup_error(AccountsError::LastAdministratorViolation);
        assert_eq!(last_admin.status_code(), axum::http::StatusCode::CONFLICT);
    }
}
