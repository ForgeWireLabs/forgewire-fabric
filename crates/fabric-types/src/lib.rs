//! Shared domain types for ForgeWire Fabric.
//!
//! This crate owns the type vocabulary shared across the hub, runner, CLI,
//! and store crates. No HTTP framework, no database, no async runtime.

#![deny(rust_2018_idioms)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Task status values matching the Python hub's `tasks.status` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Claimed,
    Running,
    Reporting,
    Done,
    Failed,
    Cancelled,
    TimedOut,
}

impl TaskStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Done | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }
}

/// Task routing class matching the Python hub's `tasks.kind` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Agent,
    Command,
}

/// Stream channel types matching the Python hub's `task_streams.channel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamChannel {
    Stdout,
    Stderr,
    Info,
}

/// The frozen v2 signed dispatch payload. These fields and only these fields
/// are covered by the ed25519 dispatcher signature. Do not add or remove
/// fields during the migration window — new fields belong in protocol v3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDispatchV2 {
    pub op: String,
    pub dispatcher_id: String,
    pub title: String,
    pub prompt: String,
    pub scope_globs: Vec<String>,
    pub base_commit: String,
    pub branch: String,
    pub timestamp: i64,
    pub nonce: String,
}

/// Audit event kinds matching the Python hub's `audit_event.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    Dispatch,
    Claim,
    Result,
}

impl std::fmt::Display for AuditKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dispatch => write!(f, "dispatch"),
            Self::Claim => write!(f, "claim"),
            Self::Result => write!(f, "result"),
        }
    }
}

/// Maximum allowed clock skew for signed envelopes (seconds).
pub const SIGNATURE_MAX_SKEW_SECONDS: i64 = 300;

/// Timestamp validation errors.
#[derive(Debug, Error)]
pub enum TimestampError {
    #[error("timestamp out of skew window: delta={delta}s, max={max}s")]
    OutOfSkew { delta: i64, max: i64 },
}

/// Check that `timestamp` is within ±[`SIGNATURE_MAX_SKEW_SECONDS`] of `now`.
pub fn check_timestamp_skew(timestamp: i64, now: i64) -> Result<(), TimestampError> {
    let delta = (now - timestamp).abs();
    if delta > SIGNATURE_MAX_SKEW_SECONDS {
        return Err(TimestampError::OutOfSkew {
            delta,
            max: SIGNATURE_MAX_SKEW_SECONDS,
        });
    }
    Ok(())
}

/// Key purpose tags for identity files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    Dispatcher,
    Runner,
    Hub,
    Node,
}

impl std::fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dispatcher => write!(f, "dispatcher"),
            Self::Runner => write!(f, "runner"),
            Self::Hub => write!(f, "hub"),
            Self::Node => write!(f, "node"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_status_terminal_check() {
        assert!(TaskStatus::Done.is_terminal());
        assert!(TaskStatus::Failed.is_terminal());
        assert!(TaskStatus::Cancelled.is_terminal());
        assert!(TaskStatus::TimedOut.is_terminal());
        assert!(!TaskStatus::Queued.is_terminal());
        assert!(!TaskStatus::Running.is_terminal());
    }

    #[test]
    fn timestamp_skew_accept() {
        assert!(check_timestamp_skew(1000, 1000).is_ok());
        assert!(check_timestamp_skew(1000, 1299).is_ok());
        assert!(check_timestamp_skew(1000, 701).is_ok());
    }

    #[test]
    fn timestamp_skew_reject() {
        assert!(check_timestamp_skew(1000, 1301).is_err());
        assert!(check_timestamp_skew(1000, 699).is_err());
    }

    #[test]
    fn signed_dispatch_v2_round_trips() {
        let d = SignedDispatchV2 {
            op: "dispatch".into(),
            dispatcher_id: "d-001".into(),
            title: "Test".into(),
            prompt: "Do it".into(),
            scope_globs: vec!["core/**".into()],
            base_commit: "abc1234".into(),
            branch: "agent/test".into(),
            timestamp: 1748649600,
            nonce: "nonce-001".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let d2: SignedDispatchV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(d, d2);
    }
}
