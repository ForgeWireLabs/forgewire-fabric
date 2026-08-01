//! `GET /auth/webauthn/doctor` (114C.6 Slice 7) -- explains *why* passkeys
//! are or are not ready, for an operator debugging a deployment rather than
//! a client running a ceremony.
//!
//! Public, no authentication, matching `/healthz`: `rp_id` and
//! `allowed_origins` are operator-configured routing values, not secrets --
//! a ceremony already reveals the RP ID to any browser that reaches the
//! bridge page, and the allowed origins are by definition the origins meant
//! to be publicly reachable. There is nothing here a network-adjacent
//! observer could not already infer.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;
use serde_json::json;

use crate::state::HubState;
use crate::webauthn::WebauthnDoctorReport;

owned_router! {
    pub fn public_router, PUBLIC_ROUTES {
        "GET" get "/auth/webauthn/doctor" => webauthn_doctor;
    }
}

#[derive(Debug, Serialize)]
pub struct WebauthnDoctorResponse {
    #[serde(flatten)]
    report: WebauthnDoctorReport,
    /// Whether the *running* hub process currently has a live WebAuthn
    /// instance -- built once at startup from the realm identity if one was
    /// established then, else the settings document as it was then (see
    /// `main.rs`'s "built once at startup" comment beside
    /// `build_from_realm_or_settings`), not re-built on every settings/realm
    /// change.
    running: bool,
    /// True when `report.ready` (computed from the *current* realm identity
    /// or settings document, re-read live) disagrees with `running` (the
    /// *startup-time* snapshot). An operator who just fixed their config, or
    /// just completed genesis, sees `ready: true` here well before the
    /// running instance catches up -- this field is what tells them a
    /// restart, not another config edit, is what's left.
    restart_required: bool,
}

/// Whether the running instance needs to be restarted to match the current
/// config. `ready`/`running` disagreeing is the only case that matters --
/// pulled out of the handler as its own named, tested function rather than
/// an inline comparison, so the one bit of logic this route adds beyond
/// `diagnose()` is independently testable without an axum test harness.
fn restart_required(ready: bool, running: bool) -> bool {
    ready != running
}

pub async fn webauthn_doctor(State(state): State<Arc<HubState>>) -> Json<WebauthnDoctorResponse> {
    let effective_auth = match state.store.get_settings_document().await {
        Ok(document) => {
            fabric_settings::SettingsSnapshot::new(document.revision, document.value, json!({}))
                .map(|snapshot| snapshot.effective)
                // A currently-invalid settings document is itself worth a
                // problem entry, not a silent fallback -- diagnose() reports
                // it as "disabled" via the same path an absent auth.passkeys
                // block takes, since an unreadable document means every
                // sub-setting is effectively unset.
                .unwrap_or_else(|_| json!({}))
        }
        Err(_) => json!({}),
    };
    // 114D D.1: diagnose from the realm identity when one is established,
    // matching `main.rs`'s `build_from_realm_or_settings` precedence exactly
    // -- otherwise `report.ready` here could disagree with what the running
    // instance was actually built from, corrupting `restart_required` below.
    let realm_identity =
        fabric_accounts::repository::RealmRepository::get_realm_identity(&*state.store)
            .await
            .unwrap_or(None);
    let report =
        crate::webauthn::diagnose_realm_or_settings(realm_identity.as_ref(), &effective_auth);
    let running = state.webauthn.is_some();
    Json(WebauthnDoctorResponse {
        restart_required: restart_required(report.ready, running),
        report,
        running,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_is_required_exactly_when_ready_and_running_disagree() {
        assert!(!restart_required(true, true));
        assert!(!restart_required(false, false));
        assert!(
            restart_required(true, false),
            "config now valid, running instance is stale"
        );
        assert!(
            restart_required(false, true),
            "config now broken, but the old instance is still live"
        );
    }

    #[test]
    fn response_serializes_the_report_flattened_alongside_running_fields() {
        let response = WebauthnDoctorResponse {
            report: crate::webauthn::diagnose(&json!({
                "auth": { "passkeys": { "enabled": true, "rp_id": "fabric.example", "rp_name": "Test", "allowed_origins": ["https://fabric.example/"] } }
            })),
            running: false,
            restart_required: true,
        };
        let value = serde_json::to_value(&response).expect("serializes");
        // Flattened, not nested under a "report" key -- confirms #[serde(flatten)]
        // is doing what it looks like it's doing rather than silently no-op-ing.
        assert!(value.get("report").is_none());
        assert_eq!(value["ready"], json!(true));
        assert_eq!(value["running"], json!(false));
        assert_eq!(value["restart_required"], json!(true));
        assert_eq!(value["rp_id"], json!("fabric.example"));
    }
}
