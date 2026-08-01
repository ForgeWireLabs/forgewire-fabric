//! Hub-served WebAuthn bridge page (114C.6 Slice 5b).
//!
//! ## Why a hub-served page exists at all
//!
//! Neither client can run a WebAuthn ceremony in its own UI:
//!
//! - The VS Code extension host is Node -- no `navigator.credentials` -- and
//!   its one webview runs at a `vscode-webview://<uuid>` origin that cannot
//!   be a meaningful RP-bound origin.
//! - The Tauri desktop app *does* have a DOM, but serves from
//!   `tauri://localhost` on macOS/Linux (a custom scheme browsers reject as a
//!   WebAuthn origin), and its CSP (`connect-src ipc:`) forbids the webview
//!   from reaching the hub directly anyway.
//!
//! Serving the ceremony from the hub sidesteps both: the page's origin *is*
//! the hub's origin, so it is same-origin with `/auth/passkeys/*` and is a
//! real WebAuthn-eligible origin whenever the hub itself is (loopback or
//! HTTPS -- 114C.6's accepted scope). One implementation serves both clients.
//!
//! ## Shape
//!
//! The client opens `/auth/webauthn/bridge?mode=…&callback=…&state=…` in the
//! *system browser*, completes the ceremony there, and the page reports back
//! to a loopback URL the client is listening on.
//!
//! Three deliberate security properties:
//!
//! 1. **The server injects nothing into the page.** The JS reads its own
//!    query string via `location.search`, so there is no server-side
//!    template interpolation and therefore no injection surface. The HTML and
//!    JS are static `include_str!` assets.
//! 2. **The script is a separate route**, so the CSP can be `script-src
//!    'self'` -- no `'unsafe-inline'`, no nonce plumbing.
//! 3. **`callback` is validated as loopback before the page is served.**
//!    Without this the bridge would be an open redirect that could hand a
//!    freshly minted session to an attacker-controlled host. Validated again
//!    in the page's JS, because defense that only exists on one side of a
//!    trust boundary is one bug away from not existing.

use axum::extract::Query;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

const BRIDGE_HTML: &str = include_str!("../assets/webauthn_bridge.html");
const BRIDGE_JS: &str = include_str!("../assets/webauthn_bridge.js");

/// Strict policy for the bridge page: no external anything, script only from
/// this origin, XHR only back to this origin, and no form posts or base-URI
/// rewriting at all.
const BRIDGE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; \
     connect-src 'self'; img-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'";

owned_router! {
    pub fn public_router, PUBLIC_ROUTES {
        "GET" get "/auth/webauthn/bridge" => bridge_page;
        "GET" get "/auth/webauthn/bridge.js" => bridge_script;
    }
}

#[derive(Debug, Deserialize)]
pub struct BridgeQuery {
    pub mode: Option<String>,
    pub callback: Option<String>,
}

/// True if `callback` is a URL the bridge may report back to: HTTP on a
/// loopback host, nothing else.
///
/// This is the single most security-relevant check in this module. The login
/// flow returns real session secrets to the callback, so a callback pointing
/// at an arbitrary host would be a credential-exfiltration channel dressed up
/// as a feature. Restricting to loopback keeps the reply inside the machine
/// that started the flow.
///
/// `127.0.0.0/8` and `::1` are accepted, as is the `localhost` name and any
/// `.localhost` subdomain (RFC 6761 reserves the whole namespace for
/// loopback). A bare hostname that merely *ends in* the letters "localhost"
/// (`evillocalhost`) is not loopback and is rejected -- the suffix match is
/// on the dotted label, not the substring.
///
/// Pure and dependency-free so the boundary cases are unit- and
/// mutation-testable without standing up axum.
pub fn callback_is_loopback(callback: &str) -> bool {
    let Ok(url) = url_parse(callback) else {
        return false;
    };
    if url.scheme != "http" {
        return false;
    }
    match url.host.as_str() {
        "localhost" | "127.0.0.1" | "[::1]" | "::1" => true,
        host if host.ends_with(".localhost") => true,
        // Any other 127.x.y.z literal is still loopback.
        host => host
            .split_once('.')
            .is_some_and(|(first, _)| first == "127" && host.parse::<std::net::Ipv4Addr>().is_ok()),
    }
}

/// Minimal scheme/host split. Deliberately not pulling in a URL crate for
/// this one check: `webauthn-rs` re-exports `url`, but this module is about
/// refusing anything that is not a plain `http://<loopback>[:port]/...`, and
/// a tiny explicit parser is easier to audit for that narrow purpose than a
/// permissive general one.
struct ParsedCallback {
    scheme: String,
    host: String,
}

fn url_parse(raw: &str) -> Result<ParsedCallback, ()> {
    let (scheme, rest) = raw.split_once("://").ok_or(())?;
    if rest.is_empty() {
        return Err(());
    }
    // Reject embedded credentials (`http://user@evil/`) outright -- they are
    // never needed here and are a classic host-confusion vector.
    //
    // Belt-and-braces, not load-bearing: mutation testing showed removing this
    // check does not open a bypass, because every `@`-bearing authority that
    // could reach the loopback match either fails the `Ipv4Addr` parse or has
    // its real host (the part after `@`) inside `.localhost` anyway. Kept
    // because an explicit rejection is easier to audit than that argument.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(());
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        // IPv6 literal: keep the brackets off but stop at the closing one.
        let (inner, _) = bracketed.split_once(']').ok_or(())?;
        inner.to_ascii_lowercase()
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(h, _)| h)
            .to_ascii_lowercase()
    };
    if host.is_empty() {
        return Err(());
    }
    Ok(ParsedCallback {
        scheme: scheme.to_ascii_lowercase(),
        host,
    })
}

fn bridge_error(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, message.to_owned()).into_response()
}

pub async fn bridge_page(Query(query): Query<BridgeQuery>) -> Response {
    let mode = query.mode.as_deref().unwrap_or("");
    // 114C.7 Slice 4c-3: "step-up" is a credential-relay ceremony -- the page
    // runs navigator.credentials.get on a challenge the client passes in the
    // query and returns only the (public, single-use) assertion; it makes no
    // hub call and receives no session secret. The server still injects
    // nothing into the page (the JS reads mode/challenge from location.search).
    if mode != "login" && mode != "register" && mode != "step-up" {
        return bridge_error("mode must be 'login', 'register', or 'step-up'");
    }
    // Validated here so a bad callback fails fast with an explanation rather
    // than after the user has already completed an authenticator prompt.
    match query.callback.as_deref() {
        Some(callback) if callback_is_loopback(callback) => {}
        Some(_) => return bridge_error(
            "callback must be an http:// URL on a loopback host (127.0.0.0/8, ::1, or localhost)",
        ),
        None => return bridge_error("callback is required"),
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(BRIDGE_CSP),
    );
    // A ceremony page must never be cached: it is single-use and its query
    // string carries the callback/state for one specific attempt.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    (headers, BRIDGE_HTML).into_response()
}

pub async fn bridge_script() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    (headers, BRIDGE_JS).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_callbacks_are_accepted() {
        for callback in [
            "http://127.0.0.1:53123/callback",
            "http://localhost:53123/callback",
            "http://127.0.0.1/cb",
            "http://127.5.6.7:9/cb",
            "http://[::1]:53123/callback",
            "http://tauri.localhost:53123/cb",
        ] {
            assert!(
                callback_is_loopback(callback),
                "{callback} should be accepted"
            );
        }
    }

    #[test]
    fn non_loopback_callbacks_are_rejected() {
        // The exfiltration cases this check exists to stop.
        for callback in [
            "http://evil.example/cb",
            "http://192.168.1.50:53123/cb",
            "http://10.0.0.5/cb",
            "http://evillocalhost/cb",
            "http://localhost.evil.example/cb",
            "http://128.0.0.1/cb",
        ] {
            assert!(
                !callback_is_loopback(callback),
                "{callback} must be rejected"
            );
        }
    }

    #[test]
    fn non_http_schemes_are_rejected_even_on_loopback() {
        // https on loopback is harmless but unnecessary; file:/javascript:
        // would be actively dangerous. Only plain http is in scope.
        for callback in [
            "https://127.0.0.1/cb",
            "file:///etc/passwd",
            "javascript://127.0.0.1/%0aalert(1)",
            "data:text/html,hi",
        ] {
            assert!(
                !callback_is_loopback(callback),
                "{callback} must be rejected"
            );
        }
    }

    #[test]
    fn credential_bearing_and_malformed_authorities_are_rejected() {
        // `http://127.0.0.1@evil.example/` resolves to evil.example -- a
        // classic host-confusion trick that a naive "starts with 127.0.0.1"
        // check would wave through.
        for callback in [
            "http://127.0.0.1@evil.example/cb",
            "http://user:pass@127.0.0.1/cb",
            "http://",
            "not-a-url",
            "",
        ] {
            assert!(
                !callback_is_loopback(callback),
                "{callback} must be rejected"
            );
        }
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        assert!(callback_is_loopback("http://LOCALHOST:1234/cb"));
        assert!(callback_is_loopback("http://Tauri.LocalHost/cb"));
    }

    #[test]
    fn the_served_page_references_only_the_same_origin_script() {
        // Guards the CSP contract: if someone inlines a script or adds a CDN
        // tag, `script-src 'self'` would silently break the page in a way a
        // route-level test would not otherwise catch.
        assert!(BRIDGE_HTML.contains("/auth/webauthn/bridge.js"));
        assert!(
            !BRIDGE_HTML.contains("<script>"),
            "the bridge page must not inline script (CSP is script-src 'self')"
        );
        assert!(
            !BRIDGE_HTML.contains("http://") && !BRIDGE_HTML.contains("https://"),
            "the bridge page must not reference any external origin"
        );
    }

    #[test]
    fn the_page_fails_closed_when_its_script_does_not_run() {
        // Regression: the form shipped visible, so opening the file outside
        // the hub (the absolute /auth/webauthn/bridge.js path 404s) rendered a
        // fully interactive credential prompt -- password field included, in
        // register mode -- with no handler behind it. Every guard that would
        // have caught that lives inside the script that failed to load, so the
        // page must start in the safe state and be opened up by the script,
        // never the reverse.
        let form_tag = BRIDGE_HTML
            .split_once("<form")
            .and_then(|(_, rest)| rest.split_once('>'))
            .map(|(tag, _)| tag)
            .expect("the bridge page has a form");
        assert!(
            form_tag.contains("hidden"),
            "the form must ship hidden and be revealed by the script"
        );
        let reveal = BRIDGE_JS
            .find("form.hidden = false")
            .expect("the script must be what reveals the form");
        // ...and only after every precondition, never before.
        for guard in [
            "mode !== \"login\"",
            "!callbackIsLoopback(callback)",
            "!window.PublicKeyCredential",
            "!window.isSecureContext",
        ] {
            let at = BRIDGE_JS.find(guard).expect("guard is present");
            assert!(
                at < reveal,
                "guard `{guard}` must run before the form is shown"
            );
        }
    }

    #[test]
    fn the_page_explains_itself_when_its_script_does_not_run() {
        // The seeded status is the entire user-facing story in that failure
        // case; an empty one leaves a blank page with no stated next step.
        let status = BRIDGE_HTML
            .split_once("id=\"status\"")
            .and_then(|(_, rest)| rest.split_once("</p>"))
            .map(|(body, _)| body)
            .expect("the bridge page has a status element");
        assert!(
            status.contains("could not start"),
            "the status element must ship with the failure message, not empty"
        );
        assert!(
            BRIDGE_JS.contains("setStatus(\"\")"),
            "the script must clear the seeded failure message once it is running"
        );
        assert!(BRIDGE_HTML.contains("<noscript>"));
    }

    #[test]
    fn the_script_never_puts_secrets_in_a_url() {
        // The login flow POSTs its session payload to the loopback callback.
        // A regression to `location = callback + "?secret=..."` would leak
        // secrets into browser history, the loopback server's access log, and
        // the Referer header.
        assert!(
            BRIDGE_JS.contains("method: \"POST\""),
            "the callback must be reported via POST body, not a URL"
        );
    }

    #[tokio::test]
    async fn bridge_page_accepts_step_up_and_still_rejects_unknown_modes() {
        // 114C.7 Slice 4c-3: step-up is a valid mode; a typo/unknown mode still
        // fails fast rather than serving a page for a ceremony the JS can't run.
        let cb = "http://127.0.0.1:1/callback";
        let ok = bridge_page(Query(BridgeQuery {
            mode: Some("step-up".to_owned()),
            callback: Some(cb.to_owned()),
        }))
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        let bad = bridge_page(Query(BridgeQuery {
            mode: Some("delete-everything".to_owned()),
            callback: Some(cb.to_owned()),
        }))
        .await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn step_up_is_a_pure_credential_relay_that_returns_only_the_assertion() {
        // The load-bearing security property of the step-up mode: the page
        // makes NO authenticated hub call (no postJson with a bearer) -- the
        // client holds the session secret and calls step_up_options/verify
        // itself. The page only runs the authenticator and returns the
        // (public, single-use) assertion. A regression that reintroduced a
        // hub call here would mean the session secret had to reach the page.
        let step_up = BRIDGE_JS
            .split_once("function runStepUp()")
            .and_then(|(_, rest)| rest.split_once("// ---- wiring"))
            .map(|(body, _)| body)
            .expect("runStepUp is defined before the wiring section");
        assert!(
            !step_up.contains("postJson"),
            "step-up must make no authenticated hub call -- it is a pure credential relay"
        );
        assert!(
            step_up.contains("navigator.credentials") && step_up.contains("decodeRequest"),
            "step-up runs the authenticator on the request challenge"
        );
        assert!(
            step_up.contains("credential: encodeAssertion"),
            "step-up returns only the assertion"
        );
        assert!(
            !step_up.contains("access_secret"),
            "step-up never handles a session secret"
        );
    }
}
