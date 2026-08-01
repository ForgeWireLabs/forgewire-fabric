//! Human account, credential, membership, and session domain contracts for
//! ForgeWire Fabric (114C.1).
//!
//! ## Scope
//!
//! This crate is domain types, validation, safe serialization, and
//! repository *traits* only. It has no rqlite dependency, no HTTP framework
//! dependency, and performs no cryptographic verification of its own --
//! those are 114C.2 (store), 114C.3 (bootstrap/password/session services),
//! and 114C.4 (hub authorization integration) respectively, per the crate
//! boundaries locked in `114C-name-lock.md`.
//!
//! ## What this crate structurally guarantees
//!
//! - A human account can never hold the machine-only `runner` role
//!   ([`domain::Membership::for_human`] rejects it; see also
//!   `domain::Role::human_assignable`).
//! - Secret material ([`secret::SecretString`]) cannot be serialized: the
//!   type has no `Serialize` impl, so a struct that derives `Serialize` and
//!   contains one does not compile. Only the explicit-extraction DTOs in
//!   [`dto`] cross the API boundary.
//! - An automation-authenticated request can never carry a human principal
//!   ([`auth_context::AccountAuthContext::automation`] has no account-id
//!   parameter).
//! - Every typed error the API can produce is one of the 19 stable codes in
//!   [`error::AccountsError::ALL_CODES`] -- checked against the
//!   cross-language fixture in `tests/cross_language_fixtures.rs`.

#![deny(rust_2018_idioms)]

pub mod auth_context;
pub mod domain;
pub mod dto;
pub mod error;
pub mod password;
pub mod repository;
pub mod secret;
pub mod secrets;
pub mod validation;
pub mod webauthn;

pub use auth_context::{AccountAuthContext, PrincipalKind};
pub use domain::{Account, AccountStatus, Credential, CredentialKind, Membership, Role, Session};
pub use dto::{AccountSummaryDto, SessionSummaryDto, TypedAuthErrorDto};
pub use error::{AccountsError, AccountsResult};
pub use secret::SecretString;
