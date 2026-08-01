//! Desktop side of the hub-served WebAuthn bridge (114C.6 Slice 5d).
//!
//! The Tauri webview has a real DOM but two constraints rule out running the
//! ceremony there: on macOS/Linux it serves from `tauri://localhost`, a
//! custom scheme WebAuthn does not accept as an origin; and everywhere, its
//! CSP (`connect-src ipc: http://ipc.localhost`) forbids the webview from
//! reaching the hub directly regardless. So, like the VS Code extension host
//! (114C.6 Slice 5c), this opens the hub's bridge page (Slice 5b) in the
//! system browser and listens on a loopback port for the result -- except
//! here the listener, the browser launch, and the reply parsing all live in
//! the Rust backend rather than the webview, and deliberately so: this
//! crate's own contract (`test_desktop_uses_typed_native_transport_without_
//! webview_bearer_fetch` in the Python test suite) already treats the
//! webview as untrusted with the hub bearer token, and that same property
//! should hold for human-session secrets. A successful login therefore
//! writes straight into the OS keyring via `crate::save_session_secrets`
//! from here; the webview is told only whether it worked.
//!
//! The pure functions below intentionally mirror
//! `packages/fabric-client-core/src/webauthnBridge.ts` field-for-field and
//! check-for-check. `fabric-client-core` is TypeScript-only and unusable
//! from Rust, so this is a second implementation of the same narrow
//! contract, not a shared one -- the same shape of duplication fabric-hub's
//! own `routes/webauthn_bridge.rs` already accepts for the equivalent
//! loopback-callback validation on the server side, for the same reason:
//! each side of a trust boundary needs its own enforcement, not a shared
//! library assumed to run on both.

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BridgeMode {
    Login,
    Register,
    /// 114C.7 Slice 5b: mirrors VSIX's "step-up" bridge mode. The bridge
    /// page only relays a `navigator.credentials.get` assertion here -- the
    /// session bearer never enters the browser (see `step_up` below).
    StepUp,
}

impl BridgeMode {
    fn as_query_value(self) -> &'static str {
        match self {
            BridgeMode::Login => "login",
            BridgeMode::Register => "register",
            BridgeMode::StepUp => "step-up",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BridgeSessionPayload {
    pub session_id: String,
    pub account_id: String,
    pub assurance_level: String,
    pub access_secret: String,
    pub refresh_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BridgeOutcome {
    LoginOk(BridgeSessionPayload),
    RegisterOk {
        credential_id: Option<String>,
    },
    /// 114C.7 Slice 5b: the raw WebAuthn assertion the bridge page relayed.
    /// Never a session -- the caller (`step_up` below) feeds this to
    /// `HubClient::step_up_verify` itself.
    StepUpOk {
        credential: Value,
    },
    Error {
        message: String,
    },
}

/// The one path the loopback listener answers on -- see the identical
/// constant and comment in webauthnBridge.ts. Kept in exact sync by hand
/// since the two cannot share a source of truth across languages; a mismatch
/// here would fail the ceremony at its very last step, after the user had
/// already completed an authenticator prompt.
pub(crate) const BRIDGE_CALLBACK_PATH: &str = "/callback";

/// Matches `BRIDGE_FLOW_TIMEOUT_MS` in webauthnBridge.ts.
pub(crate) const BRIDGE_FLOW_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Matches `MAX_BRIDGE_CALLBACK_BYTES` in webauthnBridge.ts.
pub(crate) const MAX_BRIDGE_CALLBACK_BYTES: usize = 64 * 1024;

/// Matches `BRIDGE_CALLBACK_ACK_HTML` in webauthnBridge.ts byte-for-byte.
pub(crate) const BRIDGE_CALLBACK_ACK_HTML: &str = "<!doctype html><meta charset=utf-8><title>Done</title><p style=\"font-family:system-ui;margin:3rem\">You can close this tab and return to the app.</p>";

/// A random per-attempt nonce, echoed back by the bridge page. Mirrors
/// `generateBridgeState` -- 16 bytes, hex-encoded with zero-padding so a
/// short byte does not shorten (and collide) the nonce.
pub(crate) fn generate_bridge_state() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| format!("generate state nonce: {error}"))?;
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Mirrors `buildBridgeUrl`. Builds only a loopback callback, never derived
/// from `hub_url`: session secrets come back over this URL, so it must stay
/// on the machine that started the flow even when the hub itself is remote.
pub(crate) fn build_bridge_url(
    hub_url: &str,
    mode: BridgeMode,
    callback_port: u16,
    state: &str,
    // 114C.7 Slice 5b: the step-up WebAuthn request options (the
    // `public_key` from `step_up_options`), JSON-stringified. Only step-up
    // mode sets it -- see `buildBridgeUrl`'s identical `challenge` param in
    // webauthnBridge.ts for the same not-a-secret / privacy-note reasoning.
    challenge: Option<&str>,
) -> String {
    let base = hub_url.trim_end_matches('/');
    let callback = format!("http://127.0.0.1:{callback_port}{BRIDGE_CALLBACK_PATH}");
    let mut params = format!(
        "mode={}&callback={}&state={}",
        urlencode(mode.as_query_value()),
        urlencode(&callback),
        urlencode(state)
    );
    if let Some(challenge) = challenge {
        params.push_str(&format!("&challenge={}", urlencode(challenge)));
    }
    format!("{base}/auth/webauthn/bridge?{params}")
}

/// Minimal percent-encoding for the three query values above -- all are
/// already known-safe alphabets (a fixed mode string, a loopback URL built
/// entirely from digits/letters/`.:/-`, and a hex nonce) but this stays
/// correct even if that ever changes, rather than assuming it always will.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Mirrors `bridgeCallbackRequestIsAcceptable`: a cheap first filter on
/// method/path before reading a body at all, so the listener does no work
/// for the CORS preflights and stray probes any loopback port attracts. Not
/// the security boundary itself -- the state check in `parse_bridge_callback`
/// is -- just the cheap first one.
fn bridge_callback_request_is_acceptable(method: &str, path: &str) -> bool {
    method.eq_ignore_ascii_case("POST") && path == BRIDGE_CALLBACK_PATH
}

/// Mirrors `parseBridgeCallback`. Returns `None` when the reply does not
/// belong to this attempt (state mismatch or malformed) -- the caller keeps
/// waiting rather than treating that as failure. A malformed *success* is
/// still `Some(Error)`, never dropped: a client must never report "signed
/// in" without a usable session.
pub(crate) fn parse_bridge_callback(
    body: &Value,
    expected_state: &str,
    mode: BridgeMode,
) -> Option<BridgeOutcome> {
    let object = body.as_object()?;

    let presented_state = object.get("state")?.as_str()?;
    if presented_state != expected_state {
        return None;
    }

    let status = object.get("status").and_then(Value::as_str);
    if status == Some("error") {
        let message = object
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("The ceremony failed.")
            .to_string();
        return Some(BridgeOutcome::Error { message });
    }
    if status != Some("ok") {
        return None;
    }

    if mode == BridgeMode::Register {
        let credential_id = object
            .get("credential_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        return Some(BridgeOutcome::RegisterOk { credential_id });
    }

    if mode == BridgeMode::StepUp {
        // Only the raw WebAuthn assertion crosses back -- the caller feeds
        // it to step_up_verify itself. A success with no assertion is an
        // error, never a silent "stepped up", mirroring the
        // incomplete-session handling below.
        return Some(match object.get("credential") {
            Some(value) if value.is_object() => BridgeOutcome::StepUpOk {
                credential: value.clone(),
            },
            _ => BridgeOutcome::Error {
                message: "The hub reported success but returned no assertion.".to_string(),
            },
        });
    }

    let Some(session) = object.get("session").and_then(Value::as_object) else {
        return Some(BridgeOutcome::Error {
            message: "The hub reported success but returned no session.".to_string(),
        });
    };
    let non_empty_str = |key: &str| {
        session
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    let (Some(session_id), Some(account_id), Some(access_secret), Some(refresh_secret)) = (
        non_empty_str("session_id"),
        non_empty_str("account_id"),
        non_empty_str("access_secret"),
        non_empty_str("refresh_secret"),
    ) else {
        return Some(BridgeOutcome::Error {
            message: "The hub returned an incomplete session.".to_string(),
        });
    };
    let assurance_level = session
        .get("assurance_level")
        .and_then(Value::as_str)
        .unwrap_or("aal1")
        .to_string();

    Some(BridgeOutcome::LoginOk(BridgeSessionPayload {
        session_id: session_id.to_string(),
        account_id: account_id.to_string(),
        assurance_level,
        access_secret: access_secret.to_string(),
        refresh_secret: refresh_secret.to_string(),
    }))
}

/// Bind an ephemeral loopback listener, wait up to `BRIDGE_FLOW_TIMEOUT` for
/// a matching reply, and return the outcome.
///
/// A wrong-state or malformed request does not end the flow -- the loop
/// keeps accepting connections until either a matching reply arrives or the
/// deadline passes, matching the "keep waiting, don't fail" contract of
/// `parse_bridge_callback` returning `None`.
///
/// Takes an already-bound listener rather than binding one itself: the
/// caller needs the port *before* this can run, to put it in the URL it
/// opens in the browser, so binding has to happen in the caller regardless
/// -- this only owns the accept loop.
async fn run_loopback_listener(
    listener: &TcpListener,
    mode: BridgeMode,
    state: &str,
) -> Result<BridgeOutcome, String> {
    let deadline = Instant::now() + BRIDGE_FLOW_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("Timed out waiting for the browser to report back.".to_string());
        }
        let accepted = match timeout(remaining, listener.accept()).await {
            Ok(Ok((stream, _))) => stream,
            Ok(Err(_)) => continue, // a broken individual connection is not a flow failure
            Err(_) => return Err("Timed out waiting for the browser to report back.".to_string()),
        };
        if let Some(outcome) = handle_connection(accepted, mode, state).await {
            return Ok(outcome);
        }
    }
}

/// Handles one accepted connection to completion. Returns `Some(outcome)`
/// only for a reply that belongs to this attempt; every other case (bad
/// method/path, malformed body, wrong state, oversized body) responds and
/// returns `None` so the caller keeps listening.
async fn handle_connection(
    mut stream: TcpStream,
    mode: BridgeMode,
    state: &str,
) -> Option<BridgeOutcome> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.unwrap_or(0) == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    // Compare only the path component: a query string or fragment on the
    // request line must not cause a false reject (mirrors
    // bridgeCallbackRequestIsAcceptable's use of the same rule).
    let path_only = path.split(['?', '#']).next().unwrap_or("");

    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
            return None;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }

    if !bridge_callback_request_is_acceptable(method, path_only) {
        let _ = respond(&mut writer, 404, "").await;
        return None;
    }
    if content_length > MAX_BRIDGE_CALLBACK_BYTES {
        let _ = respond(&mut writer, 413, "").await;
        return None;
    }

    let mut body = vec![0u8; content_length];
    if reader.read_exact(&mut body).await.is_err() {
        return None;
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(&body) else {
        let _ = respond(&mut writer, 400, "").await;
        return None;
    };

    let outcome = parse_bridge_callback(&parsed, state, mode);
    let _ = respond(&mut writer, 200, BRIDGE_CALLBACK_ACK_HTML).await;
    outcome
}

async fn respond(
    writer: &mut (impl AsyncWriteExt + Unpin),
    status: u16,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    writer.write_all(response.as_bytes()).await?;
    writer.flush().await
}

/// Result shape returned to the webview -- deliberately not `BridgeOutcome`
/// itself: a login success carries session secrets, and those must never
/// cross the IPC boundary into the webview (see the module doc comment).
/// This carries only what a UI could legitimately show.
#[derive(Debug, Serialize)]
pub(crate) struct PasskeyBridgeResult {
    pub ok: bool,
    pub message: Option<String>,
    pub credential_id: Option<String>,
}

impl PasskeyBridgeResult {
    fn ok() -> Self {
        Self {
            ok: true,
            message: None,
            credential_id: None,
        }
    }
    fn ok_with_credential(credential_id: Option<String>) -> Self {
        Self {
            ok: true,
            message: None,
            credential_id,
        }
    }
    fn error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: Some(message.into()),
            credential_id: None,
        }
    }
}

/// Bind a fresh loopback listener, open the bridge page for `mode`, and wait
/// for its reply. Shared by every bridge command (`run_bridge` below, and
/// `step_up`'s own caller); `challenge` is only set by step-up (see
/// `build_bridge_url`'s own doc comment).
async fn open_bridge_and_await(
    hub_url: &str,
    mode: BridgeMode,
    challenge: Option<&str>,
) -> Result<BridgeOutcome, String> {
    let state = generate_bridge_state()?;

    // Bound once, here: the port has to be known before the browser can be
    // opened (it goes in the URL), so there is no way to spawn the accept
    // loop ahead of binding -- this function owns the listener for its whole
    // lifetime instead.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("start loopback listener: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("read loopback listener port: {error}"))?
        .port();

    let url = build_bridge_url(hub_url, mode, port, &state, challenge);
    tauri_plugin_opener::open_url(&url, None::<&str>)
        .map_err(|error| format!("The system browser was not opened: {error}"))?;

    run_loopback_listener(&listener, mode, &state).await
}

/// Shared by the login/register Tauri commands: run one bridge flow and turn
/// whatever comes back into a webview-safe result. `on_login` is where a
/// caller stores session secrets -- kept out of this function so a
/// register-mode caller cannot accidentally be handed a code path that
/// expects one. Step-up (114C.7 Slice 5b) does not use this: unlike
/// login/register, it needs an authenticated hub call (`step_up_verify`)
/// *between* the bridge reply and the final result, so `step_up` below calls
/// `open_bridge_and_await` directly instead.
async fn run_bridge(
    hub_url: &str,
    mode: BridgeMode,
    on_login: impl FnOnce(&BridgeSessionPayload) -> Result<(), String>,
) -> PasskeyBridgeResult {
    let outcome = match open_bridge_and_await(hub_url, mode, None).await {
        Ok(outcome) => outcome,
        Err(message) => return PasskeyBridgeResult::error(message),
    };

    match outcome {
        BridgeOutcome::Error { message } => PasskeyBridgeResult::error(message),
        BridgeOutcome::RegisterOk { credential_id } => {
            PasskeyBridgeResult::ok_with_credential(credential_id)
        }
        BridgeOutcome::LoginOk(session) => match on_login(&session) {
            Ok(()) => PasskeyBridgeResult::ok(),
            Err(error) => PasskeyBridgeResult::error(error),
        },
        BridgeOutcome::StepUpOk { .. } => PasskeyBridgeResult::error(
            "unreachable: a login/register bridge flow returned a step-up outcome".to_string(),
        ),
    }
}

/// The profile id under which the bridge stores a login session. Matches the
/// VSIX side's `DEFAULT_SESSION_PROFILE_ID` in humanSession.ts -- both
/// clients are single-profile today (see `TauriSessionCredentialStore`'s own
/// doc comment), so this is the one key a future multi-profile Slice 6 UI
/// must also use to find what this command stored.
const DEFAULT_SESSION_PROFILE_ID: &str = "default";

#[tauri::command]
pub(crate) async fn sign_in_with_passkey(hub_url: String) -> PasskeyBridgeResult {
    run_bridge(&hub_url, BridgeMode::Login, |session| {
        crate::save_session_secrets(
            DEFAULT_SESSION_PROFILE_ID.to_string(),
            crate::SessionSecrets {
                session_id: session.session_id.clone(),
                access_secret: session.access_secret.clone(),
                refresh_secret: session.refresh_secret.clone(),
                // Passkey-login PoP binding is a later Slice 2 step (the bridge
                // would mint + bind a session key through the WebAuthn verify);
                // for now a passkey session stays bearer-only.
                session_signing_key: None,
            },
        )
    })
    .await
}

#[tauri::command]
pub(crate) async fn register_passkey(hub_url: String) -> PasskeyBridgeResult {
    // Register mode signs in inside the browser page itself and does not
    // return a session (see webauthn_bridge.js's runRegister) -- there is
    // nothing to store, only to report, so `on_login` is unreachable here.
    run_bridge(&hub_url, BridgeMode::Register, |_session| {
        Err("unreachable: register mode never yields a login session".to_string())
    })
    .await
}

/// 114C.7 Slice 5b: the Desktop step-up ceremony. Mirrors VSIX's `stepUp()`
/// in extension.ts exactly: this backend holds the session bearer and makes
/// both authenticated step-up calls itself (`fabric_client::HubClient`'s
/// `step_up_options`/`step_up_verify`); the bridge page only relays
/// `navigator.credentials.get` on the public challenge, so the access secret
/// never enters the browser. On success the hub elevates the session in
/// place and rotates its access secret, persisted here (same session_id/
/// refresh_secret) before the result -- which does carry the new
/// `access_secret` -- returns to the webview. That's consistent with how
/// every other authenticated command already works on Desktop (unlike the
/// login/register bridge above, whose whole reason for existing is that a
/// *brand new* session must never pass through webview state even
/// transiently): `TauriSessionCredentialStore` already round-trips a
/// session's access secret through the webview on every account-page call.
#[tauri::command]
pub(crate) async fn step_up(hub_url: String) -> Result<crate::AuthResult, String> {
    let hub_url = crate::sanitize_url(&hub_url)?;
    let session = crate::load_session_secrets(DEFAULT_SESSION_PROFILE_ID.to_string())?
        .ok_or_else(|| "sign in first".to_string())?;
    let client = crate::hub_client_public(&hub_url);

    let options = match client.step_up_options(&session.access_secret).await {
        Ok(data) => data,
        Err(error) => return Ok(crate::AuthResult::from_error(&error)),
    };
    let challenge_id = options
        .get("challenge_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let options_token = options
        .get("options_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let public_key = options.get("public_key").cloned().unwrap_or(Value::Null);

    let outcome =
        match open_bridge_and_await(&hub_url, BridgeMode::StepUp, Some(&public_key.to_string()))
            .await
        {
            Ok(outcome) => outcome,
            Err(message) => return Ok(crate::AuthResult::plain_error(message)),
        };
    let credential = match outcome {
        BridgeOutcome::Error { message } => return Ok(crate::AuthResult::plain_error(message)),
        BridgeOutcome::StepUpOk { credential } => credential,
        BridgeOutcome::LoginOk(_) | BridgeOutcome::RegisterOk { .. } => {
            return Ok(crate::AuthResult::plain_error(
                "unreachable: a step-up bridge flow returned a login/register outcome".to_string(),
            ))
        }
    };

    let verified = match client
        .step_up_verify(
            &session.access_secret,
            &challenge_id,
            &options_token,
            &credential,
        )
        .await
    {
        Ok(data) => data,
        Err(error) => return Ok(crate::AuthResult::from_error(&error)),
    };
    let access_secret = verified
        .get("access_secret")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if access_secret.is_empty() {
        return Ok(crate::AuthResult::plain_error(
            "The hub returned an incomplete step-up result.".to_string(),
        ));
    }
    crate::save_session_secrets(
        DEFAULT_SESSION_PROFILE_ID.to_string(),
        crate::SessionSecrets {
            session_id: session.session_id,
            access_secret,
            refresh_secret: session.refresh_secret,
            // Step-up rotates the session's assurance and access secret, not its
            // PoP binding: preserve the stored signing key so a key-bound
            // session keeps signing after stepping up (writing `None` here would
            // silently downgrade it to bearer).
            session_signing_key: crate::load_session_secrets(
                DEFAULT_SESSION_PROFILE_ID.to_string(),
            )
            .ok()
            .flatten()
            .and_then(|existing| existing.session_signing_key),
        },
    )?;
    Ok(crate::AuthResult::ok(verified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn state_is_32_lowercase_hex_chars() {
        let state = generate_bridge_state().expect("state generation succeeds");
        assert_eq!(state.len(), 32);
        assert!(state
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn two_states_are_not_equal() {
        // Not a proof of randomness, just a smoke test that the RNG is wired
        // up at all rather than e.g. returning a fixed buffer.
        assert_ne!(
            generate_bridge_state().unwrap(),
            generate_bridge_state().unwrap()
        );
    }

    #[test]
    fn build_bridge_url_targets_the_bridge_route_with_a_loopback_callback() {
        let url = build_bridge_url(
            "http://localhost:8765",
            BridgeMode::Login,
            53123,
            "abc123",
            None,
        );
        assert!(url.starts_with("http://localhost:8765/auth/webauthn/bridge?"));
        assert!(url.contains("mode=login"));
        assert!(url.contains("state=abc123"));
        assert!(url.contains("callback=http%3A%2F%2F127.0.0.1%3A53123%2Fcallback"));
    }

    #[test]
    fn build_bridge_url_strips_trailing_slashes() {
        let url = build_bridge_url(
            "http://localhost:8765///",
            BridgeMode::Register,
            1,
            "s",
            None,
        );
        assert!(url.starts_with("http://localhost:8765/auth/webauthn/bridge?"));
    }

    #[test]
    fn build_bridge_url_callback_is_always_loopback_regardless_of_hub_host() {
        // The callback is where session secrets are returned; it must never
        // follow the hub's own host, even for a remote hub.
        let url = build_bridge_url(
            "https://fabric.example:8765",
            BridgeMode::Login,
            4321,
            "s",
            None,
        );
        assert!(url.contains("callback=http%3A%2F%2F127.0.0.1%3A4321%2Fcallback"));
    }

    #[test]
    fn build_bridge_url_omits_challenge_when_absent() {
        let url = build_bridge_url("http://localhost:8765", BridgeMode::Login, 1, "s", None);
        assert!(!url.contains("challenge="));
    }

    #[test]
    fn build_bridge_url_includes_and_encodes_challenge_when_present() {
        let url = build_bridge_url(
            "http://localhost:8765",
            BridgeMode::StepUp,
            1,
            "s",
            Some(r#"{"a":"b c"}"#),
        );
        assert!(url.contains("mode=step-up"));
        assert!(url.contains("challenge=%7B%22a%22%3A%22b%20c%22%7D"));
    }

    fn ok_login_session() -> Value {
        json!({
            "state": "s",
            "status": "ok",
            "session": {
                "session_id": "sess-1",
                "account_id": "acct-1",
                "assurance_level": "aal2",
                "access_secret": "access-value",
                "refresh_secret": "refresh-value",
            }
        })
    }

    #[test]
    fn accepts_a_well_formed_login_reply() {
        let outcome = parse_bridge_callback(&ok_login_session(), "s", BridgeMode::Login);
        assert_eq!(
            outcome,
            Some(BridgeOutcome::LoginOk(BridgeSessionPayload {
                session_id: "sess-1".to_string(),
                account_id: "acct-1".to_string(),
                assurance_level: "aal2".to_string(),
                access_secret: "access-value".to_string(),
                refresh_secret: "refresh-value".to_string(),
            }))
        );
    }

    #[test]
    fn rejects_a_reply_whose_state_does_not_match() {
        // Another local process racing the loopback port must not be able to
        // feed this client a session for a flow it did not start.
        let mut body = ok_login_session();
        body["state"] = json!("different");
        assert_eq!(parse_bridge_callback(&body, "s", BridgeMode::Login), None);
    }

    #[test]
    fn surfaces_an_error_reply_with_its_message() {
        let body = json!({ "state": "s", "status": "error", "message": "The passkey prompt was dismissed." });
        assert_eq!(
            parse_bridge_callback(&body, "s", BridgeMode::Login),
            Some(BridgeOutcome::Error {
                message: "The passkey prompt was dismissed.".to_string()
            })
        );
    }

    #[test]
    fn error_reply_without_a_message_gets_a_fallback() {
        let body = json!({ "state": "s", "status": "error" });
        assert_eq!(
            parse_bridge_callback(&body, "s", BridgeMode::Login),
            Some(BridgeOutcome::Error {
                message: "The ceremony failed.".to_string()
            })
        );
    }

    #[test]
    fn success_with_missing_session_is_an_error_not_dropped() {
        let body = json!({ "state": "s", "status": "ok" });
        assert_eq!(
            parse_bridge_callback(&body, "s", BridgeMode::Login),
            Some(BridgeOutcome::Error {
                message: "The hub reported success but returned no session.".to_string()
            })
        );
    }

    #[test]
    fn success_with_incomplete_session_is_an_error() {
        for missing in [
            "session_id",
            "account_id",
            "access_secret",
            "refresh_secret",
        ] {
            let mut body = ok_login_session();
            body["session"].as_object_mut().unwrap().remove(missing);
            assert_eq!(
                parse_bridge_callback(&body, "s", BridgeMode::Login),
                Some(BridgeOutcome::Error {
                    message: "The hub returned an incomplete session.".to_string()
                }),
                "missing {missing}"
            );
        }
    }

    #[test]
    fn empty_string_secret_is_incomplete_not_usable() {
        let mut body = ok_login_session();
        body["session"]["access_secret"] = json!("");
        assert_eq!(
            parse_bridge_callback(&body, "s", BridgeMode::Login),
            Some(BridgeOutcome::Error {
                message: "The hub returned an incomplete session.".to_string()
            })
        );
    }

    #[test]
    fn step_up_reply_accepts_a_well_formed_assertion() {
        let body = json!({ "state": "s", "status": "ok", "credential": { "id": "cred-1" } });
        assert_eq!(
            parse_bridge_callback(&body, "s", BridgeMode::StepUp),
            Some(BridgeOutcome::StepUpOk {
                credential: json!({ "id": "cred-1" })
            })
        );
    }

    #[test]
    fn step_up_reply_without_a_credential_is_an_error_not_dropped() {
        let body = json!({ "state": "s", "status": "ok" });
        assert_eq!(
            parse_bridge_callback(&body, "s", BridgeMode::StepUp),
            Some(BridgeOutcome::Error {
                message: "The hub reported success but returned no assertion.".to_string()
            })
        );
    }

    #[test]
    fn step_up_reply_with_a_non_object_credential_is_an_error() {
        let body = json!({ "state": "s", "status": "ok", "credential": "not-an-object" });
        assert_eq!(
            parse_bridge_callback(&body, "s", BridgeMode::StepUp),
            Some(BridgeOutcome::Error {
                message: "The hub reported success but returned no assertion.".to_string()
            })
        );
    }

    #[test]
    fn step_up_reply_never_expects_a_session() {
        // A step-up outcome must not fall through to the login-session
        // parsing path even when a `session` key happens to be present.
        let mut body = ok_login_session();
        body["credential"] = json!({ "id": "cred-1" });
        assert_eq!(
            parse_bridge_callback(&body, "s", BridgeMode::StepUp),
            Some(BridgeOutcome::StepUpOk {
                credential: json!({ "id": "cred-1" })
            })
        );
    }

    #[test]
    fn register_reply_never_expects_a_session() {
        let body = json!({ "state": "s", "status": "ok", "credential_id": "cred-1" });
        assert_eq!(
            parse_bridge_callback(&body, "s", BridgeMode::Register),
            Some(BridgeOutcome::RegisterOk {
                credential_id: Some("cred-1".to_string())
            })
        );
    }

    #[test]
    fn register_reply_without_a_credential_id_is_still_ok() {
        let body = json!({ "state": "s", "status": "ok" });
        assert_eq!(
            parse_bridge_callback(&body, "s", BridgeMode::Register),
            Some(BridgeOutcome::RegisterOk {
                credential_id: None
            })
        );
    }

    #[test]
    fn rejects_non_object_bodies_and_unknown_statuses() {
        for body in [json!(null), json!("ok"), json!(42), json!([])] {
            assert_eq!(parse_bridge_callback(&body, "s", BridgeMode::Login), None);
        }
        assert_eq!(
            parse_bridge_callback(
                &json!({ "state": "s", "status": "weird" }),
                "s",
                BridgeMode::Login
            ),
            None
        );
    }

    #[test]
    fn callback_request_acceptability_matches_method_and_path() {
        assert!(bridge_callback_request_is_acceptable("POST", "/callback"));
        assert!(bridge_callback_request_is_acceptable("post", "/callback"));
        assert!(!bridge_callback_request_is_acceptable("GET", "/callback"));
        assert!(!bridge_callback_request_is_acceptable("POST", "/"));
        assert!(!bridge_callback_request_is_acceptable(
            "POST",
            "/callback/../admin"
        ));
    }

    /// Binds a real listener and hands it to `run_loopback_listener` on a
    /// background task, matching how `run_bridge` actually drives it (bind
    /// first so the port is known, then run the accept loop).
    async fn spawn_listener(
        mode: BridgeMode,
        state: String,
    ) -> (u16, tokio::task::JoinHandle<Result<BridgeOutcome, String>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("read local addr").port();
        let task =
            tokio::spawn(async move { run_loopback_listener(&listener, mode, &state).await });
        (port, task)
    }

    async fn post(port: u16, body: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to loopback listener");
        let request = format!(
            "POST /callback HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn loopback_listener_round_trips_a_real_connection() {
        let (port, task) = spawn_listener(BridgeMode::Login, "round-trip-state".to_string()).await;
        let body = json!({
            "state": "round-trip-state",
            "status": "ok",
            "session": {
                "session_id": "sess-1",
                "account_id": "acct-1",
                "assurance_level": "aal2",
                "access_secret": "access-value",
                "refresh_secret": "refresh-value",
            }
        })
        .to_string();

        let response = post(port, &body).await;
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
        assert!(response.contains("close this tab"));

        let outcome = task
            .await
            .expect("task did not panic")
            .expect("listener resolves with an outcome");
        assert_eq!(
            outcome,
            BridgeOutcome::LoginOk(BridgeSessionPayload {
                session_id: "sess-1".to_string(),
                account_id: "acct-1".to_string(),
                assurance_level: "aal2".to_string(),
                access_secret: "access-value".to_string(),
                refresh_secret: "refresh-value".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn wrong_state_reply_does_not_resolve_the_flow() {
        // Another local process racing the loopback port must not be able to
        // end the flow for an attempt it did not start.
        let (port, mut task) = spawn_listener(BridgeMode::Login, "real-state".to_string()).await;
        let body = json!({ "state": "wrong-state", "status": "ok" }).to_string();

        let response = post(port, &body).await;
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");

        let finished = tokio::time::timeout(Duration::from_millis(100), &mut task).await;
        assert!(
            finished.is_err(),
            "a wrong-state reply must not settle the flow"
        );
        task.abort();
    }

    #[tokio::test]
    async fn wrong_method_or_path_is_rejected_without_resolving() {
        let (port, mut task) = spawn_listener(BridgeMode::Login, "real-state".to_string()).await;

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        stream
            .write_all(b"GET /callback HTTP/1.1\r\n\r\n")
            .await
            .expect("write");
        let mut response = [0u8; 128];
        let n = stream.read(&mut response).await.expect("read");
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 404"));

        let finished = tokio::time::timeout(Duration::from_millis(100), &mut task).await;
        assert!(
            finished.is_err(),
            "a rejected method/path must not settle the flow"
        );
        task.abort();
    }

    #[tokio::test]
    async fn oversized_content_length_is_rejected_without_resolving() {
        let (port, mut task) = spawn_listener(BridgeMode::Login, "real-state".to_string()).await;

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let oversized = MAX_BRIDGE_CALLBACK_BYTES + 10;
        let request = format!("POST /callback HTTP/1.1\r\nContent-Length: {oversized}\r\n\r\n");
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut response = [0u8; 128];
        // Bounded, deliberately: if the size-cap guard regresses, the server
        // falls through to `read_exact`-ing a body the client never sends and
        // blocks forever -- confirmed by hand while writing this test, which
        // hung `cargo test` until killed. An unbounded `.await` here would
        // turn that regression into a hung CI job instead of a failing
        // assertion, which is a worse outcome than either.
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut response))
            .await
            .expect("the listener never responded to an oversized body -- did the size guard get removed?")
            .expect("read");
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 413"));

        let finished = tokio::time::timeout(Duration::from_millis(100), &mut task).await;
        assert!(
            finished.is_err(),
            "an oversized body must not settle the flow"
        );
        task.abort();
    }
}
