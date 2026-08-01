//! WebAuthn ceremony-challenge domain types and repository contract (114C.6
//! Slice 1). `human_auth_challenges` has existed in the rqlite schema since
//! 114C.2, but had zero domain type, trait, or repository implementation
//! until now -- this module is genuinely greenfield, not a partial build.
//!
//! The actual `webauthn_rs::Webauthn` ceremony machinery -- COSE/CBOR
//! parsing, signature verification, attestation -- lives in `fabric-hub`,
//! not here, matching this crate's own "no crypto verification" boundary
//! (see `Cargo.toml`'s package description and this crate's `password.rs`/
//! `secrets.rs`, which only ever hash, never verify an asymmetric
//! signature). `ceremony_state` below is an opaque string as far as this
//! crate is concerned: `fabric-hub` is the only caller that ever knows it is
//! a serialized `PasskeyRegistration`/`PasskeyAuthentication`.

use crate::error::{AccountsError, AccountsResult};

pub type ChallengeId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeKind {
    Webauthn,
}

impl ChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Webauthn => "webauthn",
        }
    }

    pub fn from_str_opt(raw: &str) -> Option<Self> {
        match raw {
            "webauthn" => Some(Self::Webauthn),
            _ => None,
        }
    }
}

/// What a challenge may legitimately be redeemed for. Bound into every
/// issued row and checked by the caller at consumption -- a registration
/// challenge must be structurally rejected against a step-up verify, and
/// vice versa, even before any cryptographic verification runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengePurpose {
    Registration,
    Authentication,
    StepUp,
}

impl ChallengePurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Authentication => "authentication",
            Self::StepUp => "step_up",
        }
    }

    pub fn from_str_opt(raw: &str) -> Option<Self> {
        match raw {
            "registration" => Some(Self::Registration),
            "authentication" => Some(Self::Authentication),
            "step_up" => Some(Self::StepUp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeStatus {
    Pending,
    Consumed,
    Failed,
}

impl ChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Consumed => "consumed",
            Self::Failed => "failed",
        }
    }

    pub fn from_str_opt(raw: &str) -> Option<Self> {
        match raw {
            "pending" => Some(Self::Pending),
            "consumed" => Some(Self::Consumed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// A durable, single-use WebAuthn ceremony challenge row. `challenge_hash`
/// guards a correlation secret (an `options_token` the caller must echo
/// back at `/verify`) -- it is not itself the WebAuthn challenge bytes,
/// which live inside `ceremony_state` and are not independently sensitive
/// (knowing them alone cannot forge a signed assertion). See this module's
/// header comment for why `ceremony_state` is opaque here.
#[derive(Debug, Clone)]
pub struct AuthChallenge {
    pub challenge_id: ChallengeId,
    pub kind: ChallengeKind,
    pub purpose: ChallengePurpose,
    pub account_id: Option<String>,
    pub session_id: Option<String>,
    pub client_identity_id: Option<String>,
    pub challenge_hash: String,
    pub ceremony_state: String,
    pub created_at: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub attempt_count: i64,
    pub status: ChallengeStatus,
}

/// Repository contract for `human_auth_challenges`. Every method's atomicity
/// contract is load-bearing, not incidental -- see each method's own doc
/// comment for the specific race it closes.
#[async_trait::async_trait]
pub trait ChallengeRepository: Send + Sync {
    /// Insert a new challenge row. Callers choose `challenge_id` (a fresh
    /// random ID, not derived from anything guessable) and a short
    /// `expires_at` (WebAuthn ceremonies are seconds-scale, much shorter
    /// than a session TTL) -- this method performs no validation of either,
    /// it is a pure durable insert.
    #[allow(clippy::too_many_arguments)]
    async fn issue_challenge(
        &self,
        challenge_id: &str,
        kind: ChallengeKind,
        purpose: ChallengePurpose,
        account_id: Option<&str>,
        session_id: Option<&str>,
        client_identity_id: Option<&str>,
        challenge_hash: &str,
        ceremony_state: &str,
        now: &str,
        expires_at: &str,
    ) -> AccountsResult<AuthChallenge>;

    /// Read a challenge without mutating it. Returns
    /// [`AccountsError::ChallengeInvalid`] if no row exists with this ID --
    /// deliberately the same code a caller gets from every other invalid-
    /// challenge outcome (see that variant's doc comment), so this lookup
    /// alone cannot be used to probe which challenge IDs are real.
    async fn get_challenge(&self, challenge_id: &str) -> AccountsResult<AuthChallenge>;

    /// Atomically transition a still-`pending`, not-yet-expired challenge to
    /// `consumed` (`status`/`consumed_at` reflect that transition in the
    /// returned row) and return it so the caller can read `ceremony_state`
    /// -- unchanged from issuance, along with `purpose`/`account_id`/
    /// `session_id`/`challenge_hash` -- to run the actual cryptographic
    /// verification afterward. This must run *before* any such
    /// verification: a concurrent double-submit of the same valid assertion
    /// can then never both succeed, because the second caller's CAS finds
    /// the row already consumed and fails closed here, independent of
    /// whether the crypto check itself is idempotent. Returns
    /// [`AccountsError::ChallengeInvalid`] if the row does not exist, is
    /// not `pending`, or has already expired.
    async fn consume_challenge_if_pending(
        &self,
        challenge_id: &str,
        now: &str,
    ) -> AccountsResult<AuthChallenge>;

    /// Increment a still-`pending` challenge's attempt counter, forcing it
    /// to `failed` once `max_attempts` is reached -- independent of
    /// `expires_at`, this bounds a client hammering malformed assertions
    /// against a not-yet-consumed challenge. Returns the attempt count
    /// after incrementing. A no-op (returns the current count unchanged) if
    /// the challenge is not `pending`.
    async fn increment_challenge_attempt(
        &self,
        challenge_id: &str,
        max_attempts: i64,
    ) -> AccountsResult<i64>;

    /// Bound `human_auth_challenges`' growth without deleting anything from
    /// the audit chain (this table is not the audit chain itself), mirroring
    /// [`crate::repository::AccountOrchestration::prune_login_attempts`].
    async fn prune_expired_challenges(&self, older_than: &str) -> AccountsResult<i64>;
}

/// Shared by every `ChallengeRepository` implementation's "not found"
/// lookup path -- kept here so the constructor for this specific outcome
/// has one call site's worth of intent attached to it, rather than each
/// implementation independently deciding what error a missing row means.
pub fn challenge_invalid() -> AccountsError {
    AccountsError::ChallengeInvalid
}
