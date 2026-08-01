//! `ChallengeRepository` implementation over `human_auth_challenges` (114C.6
//! Slice 1). Kept in its own file rather than folded into `human_accounts.rs`
//! (already 1650+ lines and framed by its own header comment as "the seven
//! `human_*` tables") so this genuinely-greenfield addition reviews
//! independently.

use async_trait::async_trait;
use serde_json::{json, Value};

use fabric_accounts::error::{AccountsError, AccountsResult};
use fabric_accounts::webauthn::{
    AuthChallenge, ChallengeKind, ChallengePurpose, ChallengeRepository, ChallengeStatus,
};

use crate::human_accounts::map_backend_error;
use crate::{opt_str, str_val, RqliteStore};

fn parse_kind(s: &str) -> Result<ChallengeKind, AccountsError> {
    ChallengeKind::from_str_opt(s).ok_or(AccountsError::ChallengeInvalid)
}

fn parse_purpose(s: &str) -> Result<ChallengePurpose, AccountsError> {
    ChallengePurpose::from_str_opt(s).ok_or(AccountsError::ChallengeInvalid)
}

fn parse_status(s: &str) -> Result<ChallengeStatus, AccountsError> {
    ChallengeStatus::from_str_opt(s).ok_or(AccountsError::ChallengeInvalid)
}

fn row_to_challenge(row: &Value) -> Result<AuthChallenge, AccountsError> {
    Ok(AuthChallenge {
        challenge_id: str_val(row, "challenge_id"),
        kind: parse_kind(&str_val(row, "kind"))?,
        purpose: parse_purpose(&str_val(row, "purpose"))?,
        account_id: opt_str(row, "account_id"),
        session_id: opt_str(row, "session_id"),
        client_identity_id: opt_str(row, "client_identity_id"),
        challenge_hash: str_val(row, "challenge_hash"),
        ceremony_state: opt_str(row, "ceremony_state").unwrap_or_default(),
        created_at: str_val(row, "created_at"),
        expires_at: str_val(row, "expires_at"),
        consumed_at: opt_str(row, "consumed_at"),
        attempt_count: row["attempt_count"].as_i64().unwrap_or(0),
        status: parse_status(&str_val(row, "status"))?,
    })
}

#[async_trait]
impl ChallengeRepository for RqliteStore {
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
    ) -> AccountsResult<AuthChallenge> {
        self.execute_one(
            "INSERT INTO human_auth_challenges (challenge_id,kind,account_id,session_id,client_identity_id,challenge_hash,ceremony_state,purpose,created_at,expires_at,attempt_count,status) VALUES (?,?,?,?,?,?,?,?,?,?,0,'pending')",
            &[
                json!(challenge_id), json!(kind.as_str()), json!(account_id), json!(session_id),
                json!(client_identity_id), json!(challenge_hash), json!(ceremony_state),
                json!(purpose.as_str()), json!(now), json!(expires_at),
            ],
        )
        .await
        .map_err(map_backend_error)?;
        Ok(AuthChallenge {
            challenge_id: challenge_id.to_owned(),
            kind,
            purpose,
            account_id: account_id.map(str::to_owned),
            session_id: session_id.map(str::to_owned),
            client_identity_id: client_identity_id.map(str::to_owned),
            challenge_hash: challenge_hash.to_owned(),
            ceremony_state: ceremony_state.to_owned(),
            created_at: now.to_owned(),
            expires_at: expires_at.to_owned(),
            consumed_at: None,
            attempt_count: 0,
            status: ChallengeStatus::Pending,
        })
    }

    async fn get_challenge(&self, challenge_id: &str) -> AccountsResult<AuthChallenge> {
        let rows = self
            .query(
                "SELECT * FROM human_auth_challenges WHERE challenge_id=?",
                &[json!(challenge_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows.first().ok_or(AccountsError::ChallengeInvalid)?;
        row_to_challenge(row)
    }

    async fn consume_challenge_if_pending(
        &self,
        challenge_id: &str,
        now: &str,
    ) -> AccountsResult<AuthChallenge> {
        // Single-statement CAS, run before any cryptographic verification by
        // every caller of this method (see the trait doc comment): a
        // concurrent double-submit of the same valid assertion can never
        // both succeed, because only one caller's UPDATE can match
        // `status='pending' AND expires_at>now`.
        let affected = self
            .execute_one(
                "UPDATE human_auth_challenges SET consumed_at=?,status='consumed' WHERE challenge_id=? AND status='pending' AND expires_at>?",
                &[json!(now), json!(challenge_id), json!(now)],
            )
            .await
            .map_err(map_backend_error)?;
        if affected != 1 {
            return Err(AccountsError::ChallengeInvalid);
        }
        // Safe to read back now: the CAS above already established exclusive
        // ownership of this row's terminal transition, and no other column
        // this reads (`ceremony_state`, `purpose`, `account_id`, ...) is
        // mutated by that UPDATE.
        let rows = self
            .query(
                "SELECT * FROM human_auth_challenges WHERE challenge_id=?",
                &[json!(challenge_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows.first().ok_or(AccountsError::ChallengeInvalid)?;
        row_to_challenge(row)
    }

    async fn increment_challenge_attempt(
        &self,
        challenge_id: &str,
        max_attempts: i64,
    ) -> AccountsResult<i64> {
        self.execute_one(
            "UPDATE human_auth_challenges SET attempt_count=attempt_count+1 WHERE challenge_id=? AND status='pending'",
            &[json!(challenge_id)],
        )
        .await
        .map_err(map_backend_error)?;
        let rows = self
            .query(
                "SELECT attempt_count, status FROM human_auth_challenges WHERE challenge_id=?",
                &[json!(challenge_id)],
            )
            .await
            .map_err(map_backend_error)?;
        let row = rows.first().ok_or(AccountsError::ChallengeInvalid)?;
        let count = row["attempt_count"].as_i64().unwrap_or(0);
        if str_val(row, "status") == "pending" && count >= max_attempts {
            // Best-effort: force-fail once the cap is reached. If this loses
            // a race to a legitimate concurrent consume, that consume's own
            // CAS already succeeded first (status left 'pending' only long
            // enough for both to have been in flight), which is the correct
            // outcome -- a real ceremony completing is not something this
            // throttle should retroactively invalidate.
            let _ = self
                .execute_one(
                    "UPDATE human_auth_challenges SET status='failed' WHERE challenge_id=? AND status='pending'",
                    &[json!(challenge_id)],
                )
                .await;
        }
        Ok(count)
    }

    async fn prune_expired_challenges(&self, older_than: &str) -> AccountsResult<i64> {
        self.execute_one(
            "DELETE FROM human_auth_challenges WHERE expires_at < ?",
            &[json!(older_than)],
        )
        .await
        .map_err(map_backend_error)
    }
}
