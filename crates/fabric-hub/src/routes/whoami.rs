//! `GET /whoami` -- the authenticated caller's own identity and capabilities.
//!
//! Unlike `GET /auth/me` (which is human-account-only and returns an
//! `AccountSummary`), this route answers for *any* authenticated credential --
//! a role token, the legacy cluster bearer, or a human session -- and is the
//! authoritative source for the `fabric.*.write` capability vocabulary the
//! operator clients (`fabric-client-core`'s `CommandContext.authorities`) gate
//! their command surface on. The clients trust this answer rather than keeping
//! a second, driftable copy of the role->capability decision. See
//! [`crate::auth::authorities_for`] for the mapping and its drift-guard test.

use axum::{Extension, Json};
use serde_json::{json, Value};

use crate::auth::{authorities_for, AuthContext};

owned_router! {
    pub fn router, ROUTES {
        "GET" get "/whoami" => whoami;
    }
}

pub async fn whoami(Extension(actor): Extension<AuthContext>) -> Json<Value> {
    Json(json!({
        "subject": actor.subject,
        "roles": actor.roles,
        "authorities": authorities_for(&actor.roles),
        "legacy_compat": actor.legacy_compat,
        "human_principal": actor.human_principal,
    }))
}
