//! Native platform-authenticator (Windows Hello) passkey enrollment (114D
//! D.3), driven directly from this backend via `webauthn-authenticator-rs`'s
//! `Win10` authenticator, instead of opening the system browser
//! (`webauthn_bridge`, which remains the deliberate fallback for
//! roaming/cross-device passkeys and providerless platforms -- 114D sec 7).
//!
//! The Tauri webview never enters this flow at all: unlike the browser
//! bridge (whose whole reason for existing is that `navigator.credentials`
//! needs a real browser context Tauri's webview cannot provide), the native
//! Windows WebAuthn API is called directly from Rust, so there is no
//! webview-origin problem to route around -- the origin is a parameter this
//! backend supplies itself (`derive_loopback_origin` below), not something
//! inherited from wherever a page happened to be served.
//!
//! **Why this genuinely forces Windows Hello and not a USB key**, verified by
//! reading `webauthn-authenticator-rs`'s own `win10` backend source (not
//! assumed): `Win10::perform_register` maps
//! `options.authenticator_selection.authenticator_attachment` through
//! `attachment_to_native()` directly into
//! `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS::dwAuthenticatorAttachment`
//! -- the real parameter `WebAuthNAuthenticatorMakeCredential` uses to decide
//! which authenticators Windows even offers. `force_platform_attachment`
//! below sets that field to `Platform` before the ceremony runs (the
//! `webauthn-rs-proto` struct's own doc comment calls this field merely an
//! unenforced "hint" -- true for a *browser* user agent, not for this native
//! path, where the crate's own source confirms it is faithfully translated
//! into the OS-level filter).
//!
//! **Loopback-only, by design, not by accident**: per 114D sec 5's accepted
//! tradeoffs, a realm's WebAuthn origin is `http://localhost:PORT` -- the
//! ceremony can only succeed against a *local* hub. `derive_loopback_origin`
//! refuses a non-loopback `hub_url` outright rather than silently building an
//! origin that could never verify (or, worse, one that claims `localhost`
//! while the actual request goes to a different machine).
//!
//! Only *registration* (enrollment) is wired in this increment, matching
//! AC-114D-3's own text ("turns enrollment... into one Hello prompt").
//! Native *login* is a natural follow-up using the same `Win10` backend's
//! `do_authentication`, not built here.

use std::sync::Arc;

use webauthn_authenticator_rs::prelude::Url;

use crate::webauthn_bridge::PasskeyBridgeResult;

/// Matches `webauthn_bridge`'s identical constant -- both session-store
/// lookups must agree on which profile they read.
const DEFAULT_SESSION_PROFILE_ID: &str = "default";

/// True if `host` is a loopback host per the same widened definition
/// `fabric-hub::webauthn::origin_is_secure_context` uses server-side:
/// `127.0.0.1`, `localhost`, or any `.localhost` subdomain. Kept in sync by
/// hand (cross-language/cross-crate, cannot share a source of truth) --
/// mirrors that function's own doc comment on why the `.localhost` widening
/// is safe (RFC 6761 + the secure-contexts spec treat the whole namespace as
/// loopback).
fn is_loopback_host(host: &str) -> bool {
    host == "127.0.0.1" || host == "localhost" || host.ends_with(".localhost")
}

/// Derive the WebAuthn ceremony origin from `hub_url`: same scheme and port,
/// host forced to literally `localhost` (the realm's decided default RP ID,
/// 114D sec 5) -- **not** copied from `hub_url` as-is, and **not** the
/// `127.0.0.1` form `sanitize_url` uses for transport (a realm's registered
/// origins are keyed on the literal hostname `localhost`, which
/// `rp_id_matches_origin_host` requires exactly; `127.0.0.1` would never
/// match). Refuses outright when `hub_url`'s own host is not already
/// loopback: a remote hub cannot be reached this way at all (114D sec 5's
/// accepted tradeoff), so there is no origin this function could honestly
/// construct for one.
fn derive_loopback_origin(hub_url: &str) -> Result<Url, String> {
    let parsed = Url::parse(hub_url).map_err(|error| format!("invalid hub URL: {error}"))?;
    let host_is_loopback = parsed.host_str().is_some_and(is_loopback_host);
    if !host_is_loopback {
        return Err(format!(
            "native passkey enrollment requires a local hub; {hub_url} is not a loopback \
             address -- use browser-based enrollment for a remote hub"
        ));
    }
    let mut origin = parsed;
    origin
        .set_host(Some("localhost"))
        .map_err(|error| format!("build ceremony origin: {error}"))?;
    origin.set_path("");
    origin.set_query(None);
    Ok(origin)
}

#[cfg(windows)]
mod backend {
    use webauthn_authenticator_rs::prelude::{
        CreationChallengeResponse, RegisterPublicKeyCredential, Url, WebauthnAuthenticator,
        WebauthnCError,
    };
    use webauthn_authenticator_rs::win10::Win10;
    // Not re-exported by webauthn_authenticator_rs::prelude -- see this
    // crate's Cargo.toml comment on why webauthn-rs-proto is a direct
    // dependency here, pinned to the identical =0.5.5 the authenticator
    // crate itself uses internally.
    use webauthn_rs_proto::{AuthenticatorAttachment, UserVerificationPolicy};

    /// Force the platform authenticator + required user verification on a
    /// registration challenge, in place, before the ceremony runs -- see this
    /// module's parent doc comment for why this genuinely forces Windows
    /// Hello rather than merely hinting at it. Also forces
    /// `require_resident_key: false`/`resident_key: None` (unset) when no
    /// selection criteria were present at all, matching the struct's own
    /// `Default` for every field this function does not itself set.
    pub(super) fn force_platform_attachment(challenge: &mut CreationChallengeResponse) {
        let mut selection = challenge
            .public_key
            .authenticator_selection
            .take()
            .unwrap_or_default();
        selection.authenticator_attachment = Some(AuthenticatorAttachment::Platform);
        selection.user_verification = UserVerificationPolicy::Required;
        challenge.public_key.authenticator_selection = Some(selection);
    }

    /// Run the actual Windows Hello ceremony. Blocking (the Windows WebAuthn
    /// API call blocks the calling thread until the user completes or
    /// cancels the prompt) -- the caller must run this via
    /// `tokio::task::spawn_blocking`, never directly on an async task, or it
    /// would stall every other task on that runtime thread for as long as
    /// the operator takes to respond to the prompt.
    pub(super) fn perform_registration_blocking(
        origin: Url,
        challenge: CreationChallengeResponse,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        let mut authenticator = WebauthnAuthenticator::new(Win10::default());
        authenticator.do_registration(origin, challenge)
    }
}

#[cfg(not(windows))]
mod backend {
    use webauthn_authenticator_rs::prelude::{
        CreationChallengeResponse, RegisterPublicKeyCredential, Url, WebauthnCError,
    };

    pub(super) fn force_platform_attachment(_challenge: &mut CreationChallengeResponse) {}

    pub(super) fn perform_registration_blocking(
        _origin: Url,
        _challenge: CreationChallengeResponse,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        Err(WebauthnCError::NotSupported)
    }
}

async fn register_native(hub_url: &str) -> PasskeyBridgeResult {
    let origin = match derive_loopback_origin(hub_url) {
        Ok(origin) => origin,
        Err(message) => return PasskeyBridgeResult::error(message),
    };
    let session = match crate::load_session_secrets(DEFAULT_SESSION_PROFILE_ID.to_string()) {
        Ok(Some(session)) => session,
        Ok(None) => return PasskeyBridgeResult::error("sign in first".to_string()),
        Err(message) => return PasskeyBridgeResult::error(message),
    };
    let sanitized_hub_url = match crate::sanitize_url(hub_url) {
        Ok(url) => url,
        Err(message) => return PasskeyBridgeResult::error(message),
    };
    let client = Arc::new(crate::hub_client_public(&sanitized_hub_url));

    let options_response = match client
        .register_passkey_options(&session.access_secret)
        .await
    {
        Ok(response) => response,
        Err(error) => return PasskeyBridgeResult::error(format!("register options: {error}")),
    };
    let Some(challenge_id) = options_response["challenge_id"].as_str().map(str::to_owned) else {
        return PasskeyBridgeResult::error(
            "register options response missing challenge_id".to_string(),
        );
    };
    let Some(options_token) = options_response["options_token"]
        .as_str()
        .map(str::to_owned)
    else {
        return PasskeyBridgeResult::error(
            "register options response missing options_token".to_string(),
        );
    };
    let mut creation_challenge: webauthn_authenticator_rs::prelude::CreationChallengeResponse =
        match serde_json::from_value(options_response["public_key"].clone()) {
            Ok(parsed) => parsed,
            Err(error) => {
                return PasskeyBridgeResult::error(format!("parse register options: {error}"))
            }
        };
    backend::force_platform_attachment(&mut creation_challenge);

    let ceremony = tokio::task::spawn_blocking(move || {
        backend::perform_registration_blocking(origin, creation_challenge)
    })
    .await;
    let credential = match ceremony {
        Ok(Ok(credential)) => credential,
        Ok(Err(error)) => {
            return PasskeyBridgeResult::error(format!(
                "Windows Hello registration failed: {error}"
            ))
        }
        Err(error) => {
            return PasskeyBridgeResult::error(format!("ceremony task did not complete: {error}"))
        }
    };
    let credential_json = match serde_json::to_value(&credential) {
        Ok(value) => value,
        Err(error) => return PasskeyBridgeResult::error(format!("serialize credential: {error}")),
    };

    match client
        .register_passkey_verify(
            &session.access_secret,
            &challenge_id,
            &options_token,
            None,
            &credential_json,
        )
        .await
    {
        Ok(verified) => PasskeyBridgeResult::ok_with_credential(
            verified["credential_id"].as_str().map(str::to_owned),
        ),
        Err(error) => PasskeyBridgeResult::error(format!("register verify: {error}")),
    }
}

#[tauri::command]
pub(crate) async fn register_passkey_native(hub_url: String) -> PasskeyBridgeResult {
    register_native(&hub_url).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_localhost_origin_preserving_scheme_and_port() {
        let origin = derive_loopback_origin("http://localhost:8765").expect("loopback origin");
        assert_eq!(origin.as_str(), "http://localhost:8765/");
    }

    #[test]
    fn derives_localhost_origin_from_127_0_0_1() {
        // The transport address may be 127.0.0.1 (sanitize_url's own form),
        // but the ceremony origin must still be the literal hostname
        // "localhost" -- rp_id matching requires it exactly.
        let origin = derive_loopback_origin("http://127.0.0.1:8765").expect("loopback origin");
        assert_eq!(origin.as_str(), "http://localhost:8765/");
    }

    /// The historical bug this pins against: `CreationChallengeResponse`
    /// (from `webauthn-rs-proto`, `#[serde(rename_all = "camelCase")]`)
    /// serializes to `{"publicKey": {...}}`; the hub then wraps *that* under
    /// its own literal `"public_key"` key (`json!({ "public_key":
    /// creation_challenge, ... })` in `routes/authn.rs`), so the real wire
    /// shape from `POST /auth/passkeys/register/options` is the *double*
    /// nesting `{"public_key": {"publicKey": {...}}}` -- confirmed by reading
    /// both sides' actual source, not assumed (a prior bridge-JS bug was
    /// exactly a wrong navigation of this same shape, 114D sec 7's own doc
    /// comment). `register_native`'s extraction
    /// (`options_response["public_key"].clone()` fed straight into
    /// `serde_json::from_value::<CreationChallengeResponse>`) is exercised
    /// here directly against a fixture built in that exact real shape.
    #[test]
    fn the_hub_register_options_response_shape_deserializes_into_creation_challenge_response() {
        let hub_response = serde_json::json!({
            "challenge_id": "wac-abc123",
            "options_token": "tok-abc123",
            "public_key": {
                "publicKey": {
                    "rp": { "name": "Test Realm", "id": "localhost" },
                    "user": { "id": "AAAA", "name": "u", "displayName": "U" },
                    "challenge": "AAAA",
                    "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
                }
            }
        });

        let parsed: Result<webauthn_authenticator_rs::prelude::CreationChallengeResponse, _> =
            serde_json::from_value(hub_response["public_key"].clone());
        let challenge = parsed.expect(
            "the hub's actual (double-nested) register-options response shape must \
             deserialize into CreationChallengeResponse",
        );
        assert_eq!(challenge.public_key.rp.id, "localhost");
    }

    #[test]
    fn accepts_a_dot_localhost_subdomain() {
        let origin =
            derive_loopback_origin("http://tauri.localhost:8765").expect("loopback origin");
        assert_eq!(origin.as_str(), "http://localhost:8765/");
    }

    #[test]
    fn refuses_a_remote_lan_hub_url() {
        let result = derive_loopback_origin("http://192.168.1.50:8765");
        assert!(
            result.is_err(),
            "a non-loopback hub URL must be refused, never silently given a localhost origin"
        );
    }

    #[test]
    fn refuses_a_public_dns_hub_url() {
        let result = derive_loopback_origin("https://fabric.example");
        assert!(result.is_err());
    }

    #[test]
    fn refuses_an_unparseable_hub_url() {
        let result = derive_loopback_origin("not a url");
        assert!(result.is_err());
    }

    // ---- Windows-only: the attachment-forcing invariant itself -----------

    #[cfg(windows)]
    #[test]
    fn force_platform_attachment_sets_platform_and_required_uv_from_empty() {
        use webauthn_authenticator_rs::prelude::CreationChallengeResponse;
        use webauthn_rs_proto::{AuthenticatorAttachment, UserVerificationPolicy};

        let mut challenge: CreationChallengeResponse = serde_json::from_value(serde_json::json!({
            "publicKey": {
                "rp": { "name": "Test", "id": "localhost" },
                "user": { "id": "AAAA", "name": "u", "displayName": "U" },
                "challenge": "AAAA",
                "pubKeyCredParams": [],
            }
        }))
        .expect("minimal creation challenge parses");
        assert!(challenge.public_key.authenticator_selection.is_none());

        backend::force_platform_attachment(&mut challenge);

        let selection = challenge
            .public_key
            .authenticator_selection
            .expect("selection criteria must be set");
        assert_eq!(
            selection.authenticator_attachment,
            Some(AuthenticatorAttachment::Platform)
        );
        assert_eq!(
            selection.user_verification,
            UserVerificationPolicy::Required
        );
    }

    #[cfg(windows)]
    #[test]
    fn force_platform_attachment_overrides_a_pre_existing_cross_platform_hint() {
        use webauthn_authenticator_rs::prelude::CreationChallengeResponse;
        use webauthn_rs_proto::{AuthenticatorAttachment, UserVerificationPolicy};

        let mut challenge: CreationChallengeResponse = serde_json::from_value(serde_json::json!({
            "publicKey": {
                "rp": { "name": "Test", "id": "localhost" },
                "user": { "id": "AAAA", "name": "u", "displayName": "U" },
                "challenge": "AAAA",
                "pubKeyCredParams": [],
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "userVerification": "discouraged",
                    "requireResidentKey": false,
                },
            }
        }))
        .expect("creation challenge with a cross-platform hint parses");
        assert_eq!(
            challenge
                .public_key
                .authenticator_selection
                .as_ref()
                .unwrap()
                .authenticator_attachment,
            Some(AuthenticatorAttachment::CrossPlatform),
            "fixture sanity check before the override"
        );

        backend::force_platform_attachment(&mut challenge);

        let selection = challenge.public_key.authenticator_selection.unwrap();
        assert_eq!(
            selection.authenticator_attachment,
            Some(AuthenticatorAttachment::Platform),
            "a pre-existing cross-platform hint must never survive -- a USB key must not be \
             silently substituted for Hello"
        );
        assert_eq!(
            selection.user_verification,
            UserVerificationPolicy::Required
        );
    }
}
