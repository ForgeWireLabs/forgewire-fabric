use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
    remediation: Option<String>,
}

impl ApiError {
    // Takes ownership (not `&SecretError`) so every call site can stay the
    // ergonomic `.map_err(ApiError::secret)` (a `FnOnce(SecretError) -> _`)
    // instead of a closure at each of its several call sites.
    #[allow(clippy::needless_pass_by_value)]
    pub fn secret(error: fabric_secrets::SecretError) -> Self {
        let status = match error {
            fabric_secrets::SecretError::MissingSecret(_)
            | fabric_secrets::SecretError::LegacyUnsealed { .. }
            | fabric_secrets::SecretError::InvalidEnvelope { .. } => StatusCode::CONFLICT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        Self {
            status,
            code: error.code().into(),
            message: error.to_string(),
            remediation: Some(error.remediation().into()),
        }
    }
}

impl ApiError {
    /// Maps `fabric_accounts::error::AccountsError`'s stable typed codes
    /// (the plan's "Typed error baseline") onto HTTP status codes. The
    /// `code` string on the wire is always the enum's own `.code()` --
    /// clients "must not infer these states by parsing prose" (the plan's
    /// own rule), so this function's HTTP status choice is advisory framing
    /// only, never the thing a client is meant to switch on.
    // Takes ownership (not `&AccountsError`) so every call site can stay the
    // ergonomic `.map_err(ApiError::account)` (a `FnOnce(AccountsError) -> _`)
    // instead of a closure at each of its many call sites.
    #[allow(clippy::needless_pass_by_value)]
    pub fn account(error: fabric_accounts::error::AccountsError) -> Self {
        use fabric_accounts::error::AccountsError;
        let status = match &error {
            AccountsError::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            AccountsError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AccountsError::SessionExpired => StatusCode::UNAUTHORIZED,
            AccountsError::SessionRevoked => StatusCode::UNAUTHORIZED,
            AccountsError::RefreshReplayDetected => StatusCode::UNAUTHORIZED,
            AccountsError::AccountDisabled => StatusCode::FORBIDDEN,
            AccountsError::AccountLocked { .. } => StatusCode::FORBIDDEN,
            AccountsError::RecoveryRequired => StatusCode::FORBIDDEN,
            AccountsError::StepUpRequired => StatusCode::FORBIDDEN,
            AccountsError::AssuranceTooLow => StatusCode::FORBIDDEN,
            AccountsError::AccountPolicyViolation { .. } => StatusCode::BAD_REQUEST,
            AccountsError::LastAdministratorViolation => StatusCode::CONFLICT,
            AccountsError::UsernameConflict => StatusCode::CONFLICT,
            AccountsError::CredentialConflict => StatusCode::CONFLICT,
            AccountsError::BootstrapClosed => StatusCode::CONFLICT,
            AccountsError::BootstrapLocalOnly => StatusCode::FORBIDDEN,
            AccountsError::AuthServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            AccountsError::RolePolicyViolation => StatusCode::FORBIDDEN,
            AccountsError::ChallengeInvalid => StatusCode::BAD_REQUEST,
            AccountsError::CredentialReplaySuspected => StatusCode::FORBIDDEN,
            AccountsError::RealmAlreadyEstablished => StatusCode::CONFLICT,
        };
        Self {
            status,
            code: error.code().to_owned(),
            message: error.to_string(),
            remediation: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "NotFound".into(),
            message: message.into(),
            remediation: None,
        }
    }

    /// The mapped HTTP status. `pub` so callers (including tests asserting
    /// on the mapped status, not just "an error occurred") can inspect it
    /// without constructing a full `Response`.
    pub fn status_code(&self) -> StatusCode {
        self.status
    }

    /// The stable wire `code` (see [`ApiError::account`]'s doc comment on
    /// why this, not the HTTP status, is what a client should switch on).
    pub fn code(&self) -> &str {
        &self.code
    }
}

impl From<(StatusCode, String)> for ApiError {
    fn from((status, message): (StatusCode, String)) -> Self {
        Self {
            status,
            code: "request_failed".into(),
            message,
            remediation: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": {
                    "code": self.code,
                    "message": self.message,
                    "remediation": self.remediation,
                }
            })),
        )
            .into_response()
    }
}
