//! WebAuthn relying-party construction from settings (114C.6 Slice 1). The
//! only module in this crate that touches `webauthn_rs` directly --
//! `fabric-accounts` stays free of it (see that crate's `webauthn` module
//! doc comment: "no crypto verification" is this codebase's crate-boundary
//! rule, and running a WebAuthn ceremony is squarely crypto verification).

use std::sync::Arc;

use webauthn_rs::prelude::*;

/// True if `origin` satisfies 114C.6's loopback-or-HTTPS secure-context
/// scope decision -- anything else (in particular a plain-HTTP LAN address,
/// the common real deployment shape this milestone deliberately does not
/// support yet) cannot run a real WebAuthn ceremony regardless of what an
/// operator configures, so it is rejected here at config-load time rather
/// than left to fail confusingly mid-ceremony.
///
/// `http://` is accepted for `127.0.0.1` and for `localhost` *and any
/// `.localhost` subdomain*. The subdomain case is not hypothetical: a Tauri
/// v2 app on Windows serves its webview from `http://tauri.localhost`
/// (verified in tauri 2.11's `manager::tauri_protocol_url`), and WebAuthn
/// binds the ceremony to that *page* origin, not to the hub's own URL -- so
/// the Desktop client's origin must be configurable here or the Desktop
/// passkey path cannot work at all. Browsers treat the whole `.localhost`
/// namespace as loopback/potentially-trustworthy (RFC 6761 + the
/// secure-contexts spec), so this widening does not weaken the check.
fn origin_is_secure_context(origin: &Url) -> bool {
    if origin.scheme() == "https" {
        return true;
    }
    if origin.scheme() != "http" {
        return false;
    }
    match origin.host_str() {
        Some("127.0.0.1" | "localhost") => true,
        Some(host) => host.ends_with(".localhost"),
        None => false,
    }
}

/// Build the hub's `Webauthn` ceremony instance from the effective settings
/// document's `auth.passkeys` block, or `None` if disabled, unconfigured, or
/// every configured origin fails the secure-context check. Never fails hub
/// startup on a misconfiguration -- an operator error here degrades to
/// passkey routes returning `AccountPolicyViolation`, not a crashed hub
/// (matches the plan's "hub health remains healthy when only an account
/// resource is restricted").
pub fn build_from_settings(effective: &serde_json::Value) -> Option<Arc<Webauthn>> {
    let passkeys = effective.pointer("/auth/passkeys")?;
    if !passkeys.get("enabled")?.as_bool().unwrap_or(false) {
        return None;
    }
    let rp_id = passkeys.get("rp_id")?.as_str()?;
    if rp_id.is_empty() {
        return None;
    }
    let rp_name = passkeys
        .get("rp_name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("ForgeWire Fabric");
    let origins: Vec<Url> = passkeys
        .get("allowed_origins")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .filter_map(|s| Url::parse(s).ok())
        .filter(origin_is_secure_context)
        .collect();
    let (first_origin, remaining_origins) = origins.split_first()?;

    let mut builder = WebauthnBuilder::new(rp_id, first_origin)
        .ok()?
        .rp_name(rp_name);
    for origin in remaining_origins {
        builder = builder.append_allowed_origin(origin);
    }
    builder.build().ok().map(Arc::new)
}

/// True if `host` is `rp_id` itself or a subdomain of it, on a label
/// boundary: `evilexample.com` does not match `rp_id = "example.com"` even
/// though it ends with the same characters, because there is no `.`
/// immediately before the suffix.
fn rp_id_matches_origin_host(rp_id: &str, host: &str) -> bool {
    host == rp_id || host.ends_with(&format!(".{rp_id}"))
}

/// Diagnostic report for `GET /auth/webauthn/doctor` and `fabric-cli
/// doctor` (114C.6 Slice 7).
///
/// `build_from_settings` above already enforces every rule that matters --
/// including the RP-ID-vs-origin domain match, confirmed by testing it
/// directly with a deliberately mismatched pair (`rp_id: "totally-different.
/// example"` against `origin: "https://fabric.example/"`): it returns `None`
/// there too, via `webauthn_rs`'s own `WebauthnBuilder::build()`. So this is
/// not closing a security gap. What it closes is a *diagnostic* one:
/// `build_from_settings` collapses every failure mode -- disabled, no RP ID,
/// no origins, every origin insecure, or an RP ID that matches none of
/// them -- into the same silent `None`, and every passkey route then returns
/// the same generic `passkeys_not_configured`. An operator gets no signal
/// about which of those five things to actually fix. `ready` here always
/// agrees with `build_from_settings(effective).is_some()`; `problems`
/// explains why when it does not.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WebauthnDoctorReport {
    pub enabled: bool,
    pub rp_id: Option<String>,
    pub rp_name: String,
    pub configured_origins: Vec<String>,
    pub secure_context_origins: Vec<String>,
    pub rp_matched_origins: Vec<String>,
    pub ready: bool,
    pub problems: Vec<String>,
}

pub fn diagnose(effective: &serde_json::Value) -> WebauthnDoctorReport {
    let passkeys = effective.pointer("/auth/passkeys");
    let enabled = passkeys
        .and_then(|p| p.get("enabled"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let rp_id = passkeys
        .and_then(|p| p.get("rp_id"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let rp_name = passkeys
        .and_then(|p| p.get("rp_name"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("ForgeWire Fabric")
        .to_string();
    let configured_origins: Vec<String> = passkeys
        .and_then(|p| p.get("allowed_origins"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .map(str::to_string)
        .collect();

    let mut problems = Vec::new();
    if !enabled {
        problems.push("passkeys are disabled (auth.passkeys.enabled is false)".to_string());
    }
    if enabled && rp_id.is_none() {
        problems.push("auth.passkeys.rp_id is not configured".to_string());
    }
    if configured_origins.is_empty() {
        problems.push("auth.passkeys.allowed_origins is empty".to_string());
    }

    let parsed_origins: Vec<Url> = configured_origins
        .iter()
        .filter_map(|s| Url::parse(s).ok())
        .collect();
    for raw in &configured_origins {
        if Url::parse(raw).is_err() {
            problems.push(format!("{raw} is not a valid URL and will be ignored"));
        }
    }
    let secure_context_origins: Vec<Url> = parsed_origins
        .into_iter()
        .filter(origin_is_secure_context)
        .collect();
    for origin in &configured_origins {
        let parses_but_is_insecure =
            Url::parse(origin).is_ok_and(|u| !origin_is_secure_context(&u));
        if parses_but_is_insecure {
            problems.push(format!(
                "{origin} is not a secure context (needs https://, or http:// on 127.0.0.1/localhost/*.localhost) and will be ignored"
            ));
        }
    }

    let rp_matched_origins: Vec<String> = match &rp_id {
        Some(rp_id) => secure_context_origins
            .iter()
            .filter(|origin| {
                origin
                    .host_str()
                    .is_some_and(|host| rp_id_matches_origin_host(rp_id, host))
            })
            .map(std::string::ToString::to_string)
            .collect(),
        None => Vec::new(),
    };
    if let Some(rp_id) = &rp_id {
        for origin in &secure_context_origins {
            let matched = origin
                .host_str()
                .is_some_and(|host| rp_id_matches_origin_host(rp_id, host));
            if !matched {
                problems.push(format!("{origin} does not match rp_id \"{rp_id}\" and cannot complete a ceremony there"));
            }
        }
    }

    WebauthnDoctorReport {
        enabled,
        rp_id,
        rp_name,
        configured_origins,
        secure_context_origins: secure_context_origins
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        rp_matched_origins,
        ready: build_from_settings(effective).is_some(),
        problems,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn settings(passkeys: &serde_json::Value) -> serde_json::Value {
        json!({ "auth": { "passkeys": passkeys } })
    }

    #[test]
    fn disabled_by_default_produces_no_instance() {
        assert!(build_from_settings(&settings(&json!({
            "enabled": false, "rp_id": null, "rp_name": "Test", "allowed_origins": []
        })))
        .is_none());
    }

    #[test]
    fn enabled_with_no_rp_id_produces_no_instance() {
        assert!(build_from_settings(&settings(&json!({
            "enabled": true, "rp_id": null, "rp_name": "Test", "allowed_origins": ["https://fabric.example/"]
        })))
        .is_none());
    }

    #[test]
    fn enabled_with_only_lan_http_origins_produces_no_instance() {
        assert!(build_from_settings(&settings(&json!({
            "enabled": true, "rp_id": "fabric.example", "rp_name": "Test",
            "allowed_origins": ["http://192.168.1.50:8765/"]
        })))
        .is_none());
    }

    #[test]
    fn enabled_with_a_valid_https_origin_builds_an_instance() {
        assert!(build_from_settings(&settings(&json!({
            "enabled": true, "rp_id": "fabric.example", "rp_name": "Test",
            "allowed_origins": ["https://fabric.example/"]
        })))
        .is_some());
    }

    #[test]
    fn enabled_with_a_loopback_http_origin_and_localhost_rp_id_builds_an_instance() {
        assert!(build_from_settings(&settings(&json!({
            "enabled": true, "rp_id": "localhost", "rp_name": "Test",
            "allowed_origins": ["http://localhost:8765/"]
        })))
        .is_some());
    }

    /// `origin_is_secure_context` allows `http://127.0.0.1` (the WebAuthn
    /// secure-context loopback carve-out applies to IP literals), but
    /// `webauthn-rs`'s own `WebauthnBuilder::new` separately rejects an IP
    /// address as an `rp_id` -- the spec's RP ID must be a registrable
    /// domain, which an IP literal never is. Loopback-by-IP deployments
    /// must use `rp_id: "localhost"` (matching a `127.0.0.1` origin is
    /// still fine; RP ID need not equal the origin's host), not
    /// `rp_id: "127.0.0.1"`. Documented via a failing case, not assumed.
    #[test]
    fn an_ip_literal_rp_id_is_rejected_even_though_its_origin_is_a_secure_context() {
        assert!(build_from_settings(&settings(&json!({
            "enabled": true, "rp_id": "127.0.0.1", "rp_name": "Test",
            "allowed_origins": ["http://127.0.0.1:8765/"]
        })))
        .is_none());
    }

    /// The Desktop (Tauri v2 on Windows) path: the webview serves from
    /// `http://tauri.localhost`, and WebAuthn binds the ceremony to that
    /// *page* origin rather than the hub's URL -- so this origin must be
    /// configurable or the Desktop passkey path cannot work at all.
    #[test]
    fn a_dot_localhost_subdomain_origin_is_accepted_for_the_tauri_desktop_path() {
        assert!(build_from_settings(&settings(&json!({
            "enabled": true, "rp_id": "localhost", "rp_name": "Test",
            "allowed_origins": ["http://tauri.localhost/"]
        })))
        .is_some());
    }

    /// The `.localhost` widening must match on the dotted suffix, not a bare
    /// substring: an attacker-registrable `evil-localhost.com` (or a host
    /// merely *ending in* the letters "localhost") is not loopback and must
    /// still be rejected over plain HTTP.
    #[test]
    fn a_lookalike_host_ending_in_localhost_is_not_treated_as_loopback() {
        for origin in [
            "http://evillocalhost/",
            "http://notlocalhost/",
            "http://localhost.evil.com/",
        ] {
            assert!(
                build_from_settings(&settings(&json!({
                    "enabled": true, "rp_id": "localhost", "rp_name": "Test",
                    "allowed_origins": [origin]
                })))
                .is_none(),
                "{origin} must not be accepted as a loopback origin"
            );
        }
    }

    #[test]
    fn a_mix_of_valid_and_invalid_origins_keeps_only_the_valid_ones() {
        // Two origins configured, one loopback-valid and one LAN-HTTP
        // (rejected); the instance still builds using the valid one alone.
        assert!(build_from_settings(&settings(&json!({
            "enabled": true, "rp_id": "localhost", "rp_name": "Test",
            "allowed_origins": ["http://192.168.1.50:8765/", "http://localhost:8765/"]
        })))
        .is_some());
    }

    // ---- rp_id_matches_origin_host -----------------------------------

    #[test]
    fn rp_id_matches_itself_and_subdomains_but_not_lookalikes() {
        assert!(rp_id_matches_origin_host("example.com", "example.com"));
        assert!(rp_id_matches_origin_host("example.com", "app.example.com"));
        assert!(!rp_id_matches_origin_host("example.com", "evilexample.com"));
        assert!(!rp_id_matches_origin_host(
            "example.com",
            "example.com.evil.com"
        ));
        assert!(!rp_id_matches_origin_host("example.com", "notexample.com"));
    }

    // ---- diagnose -------------------------------------------------------

    #[test]
    fn diagnose_ready_always_agrees_with_build_from_settings() {
        // Both sides of every fixture already used above, re-run through
        // diagnose(): `ready` must never disagree with the function it
        // exists to explain.
        for passkeys in [
            json!({ "enabled": false, "rp_id": null, "rp_name": "Test", "allowed_origins": [] }),
            json!({ "enabled": true, "rp_id": null, "rp_name": "Test", "allowed_origins": ["https://fabric.example/"] }),
            json!({ "enabled": true, "rp_id": "fabric.example", "rp_name": "Test", "allowed_origins": ["http://192.168.1.50:8765/"] }),
            json!({ "enabled": true, "rp_id": "fabric.example", "rp_name": "Test", "allowed_origins": ["https://fabric.example/"] }),
            json!({ "enabled": true, "rp_id": "127.0.0.1", "rp_name": "Test", "allowed_origins": ["http://127.0.0.1:8765/"] }),
            json!({ "enabled": true, "rp_id": "totally-different.example", "rp_name": "Test", "allowed_origins": ["https://fabric.example/"] }),
        ] {
            let effective = settings(&passkeys);
            let report = diagnose(&effective);
            assert_eq!(
                report.ready,
                build_from_settings(&effective).is_some(),
                "diagnose() disagreed with build_from_settings() for {passkeys}"
            );
        }
    }

    #[test]
    fn diagnose_names_each_problem_separately_rather_than_collapsing_them() {
        // The whole point: build_from_settings collapses every one of these
        // into the same None. diagnose must not do the same.
        let disabled = diagnose(&settings(&json!({
            "enabled": false, "rp_id": null, "rp_name": "Test", "allowed_origins": []
        })));
        assert!(disabled.problems.iter().any(|p| p.contains("disabled")));

        let no_rp_id = diagnose(&settings(&json!({
            "enabled": true, "rp_id": null, "rp_name": "Test", "allowed_origins": ["https://fabric.example/"]
        })));
        assert!(no_rp_id
            .problems
            .iter()
            .any(|p| p.contains("rp_id is not configured")));

        let no_origins = diagnose(&settings(&json!({
            "enabled": true, "rp_id": "fabric.example", "rp_name": "Test", "allowed_origins": []
        })));
        assert!(no_origins
            .problems
            .iter()
            .any(|p| p.contains("allowed_origins is empty")));

        let insecure_origin = diagnose(&settings(&json!({
            "enabled": true, "rp_id": "fabric.example", "rp_name": "Test",
            "allowed_origins": ["http://192.168.1.50:8765/"]
        })));
        assert!(insecure_origin
            .problems
            .iter()
            .any(|p| p.contains("not a secure context")));
        assert!(insecure_origin.secure_context_origins.is_empty());

        let mismatched_rp_id = diagnose(&settings(&json!({
            "enabled": true, "rp_id": "totally-different.example", "rp_name": "Test",
            "allowed_origins": ["https://fabric.example/"]
        })));
        assert!(mismatched_rp_id
            .problems
            .iter()
            .any(|p| p.contains("does not match rp_id")));
        assert!(mismatched_rp_id.rp_matched_origins.is_empty());
        // The origin passed the secure-context check on its own -- the
        // problem is specifically the RP ID mismatch, and the report must
        // keep those two facts distinguishable.
        assert_eq!(
            mismatched_rp_id.secure_context_origins,
            vec!["https://fabric.example/"]
        );
    }

    #[test]
    fn diagnose_reports_no_problems_for_a_healthy_configuration() {
        let healthy = diagnose(&settings(&json!({
            "enabled": true, "rp_id": "fabric.example", "rp_name": "Test",
            "allowed_origins": ["https://fabric.example/"]
        })));
        assert!(healthy.ready);
        assert!(
            healthy.problems.is_empty(),
            "problems: {:?}",
            healthy.problems
        );
        assert_eq!(healthy.rp_matched_origins, vec!["https://fabric.example/"]);
    }

    #[test]
    fn diagnose_matches_a_subdomain_origin_against_its_apex_rp_id() {
        // The Desktop/Tauri shape: rp_id "localhost" against an origin whose
        // host is a *subdomain*, "tauri.localhost".
        let report = diagnose(&settings(&json!({
            "enabled": true, "rp_id": "localhost", "rp_name": "Test",
            "allowed_origins": ["http://tauri.localhost/"]
        })));
        assert!(report.ready);
        assert_eq!(report.rp_matched_origins, vec!["http://tauri.localhost/"]);
    }

    // ---- user-verification policy (follow-up to 114C.6 Slice 7, GH #1883) --
    //
    // `start_passkey_registration`/`start_passkey_authentication` -- the only
    // ceremony-start functions `routes/authn.rs` calls -- hardcode
    // `UserVerificationPolicy::Required` inside `webauthn-rs` 0.5.5 itself
    // (verified by reading `webauthn-rs-0.5.5/src/lib.rs:568,1181` in the
    // vendored registry source), enforced in `webauthn-rs-core-0.5.5/src/
    // core.rs:855-866` via `Err(WebauthnError::UserNotVerified)`. So a
    // biometric/PIN-skipping assertion is rejected today, but that rejection
    // is entirely `webauthn-rs`'s own tested behavior, not Fabric's --
    // `webauthn-rs-core`'s own negative-case fixtures for this are pre-
    // recorded byte captures from real hardware authenticators (real ECDSA
    // signatures over real CBOR/COSE-encoded authenticator data), not
    // something reproducible with a lightweight in-repo helper, and there is
    // no dev-dependency in `webauthn-rs` itself offering a soft/virtual
    // authenticator to synthesize one. Building that here would mean this
    // crate re-implementing WebAuthn ceremony cryptography to test a policy
    // it does not itself enforce -- squarely the "no crypto verification"
    // boundary this module's own doc comment names. So instead of a
    // ceremony-level test, this guards the one thing actually within
    // Fabric's control: that its own code never overrides the safe default.
    #[test]
    fn passkey_routes_never_override_the_required_user_verification_policy() {
        let source = include_str!("routes/authn.rs");
        assert!(
            source.contains(".start_passkey_registration("),
            "authn.rs must call start_passkey_registration (not a lower-level \
             builder API) so UserVerificationPolicy::Required stays webauthn-rs's \
             own default rather than something Fabric has to get right itself"
        );
        assert!(
            source.contains(".start_passkey_authentication("),
            "authn.rs must call start_passkey_authentication for the same reason"
        );
        assert!(
            !source.contains(".user_verification_policy("),
            "authn.rs must never call .user_verification_policy(...) directly -- \
             doing so would silently take over from webauthn-rs's Required \
             default, and Discouraged_DO_NOT_USE is a real, selectable value of \
             that enum, named that way by webauthn-rs's own maintainers"
        );
    }

    // ---- origin/RP-ID mismatch rejection (114C.6 acceptance closeout) ------
    //
    // Same shape of question as user-verification above: is there a Fabric-
    // side risk here at all, distinct from webauthn-rs's own ceremony
    // correctness? The origin/RP-ID check itself is fully delegated --
    // `finish_passkey_registration`/`finish_passkey_authentication` verify
    // `clientDataJSON.origin` and the authenticator data's RP ID hash against
    // whichever `Webauthn` instance they are called on, and reproducing that
    // check here (or testing it end to end) would mean hand-constructing a
    // signed ceremony fixture, the same wall the user-verification guard
    // above already ran into and decided against re-climbing.
    //
    // But there IS a distinct Fabric-side risk worth guarding: a mismatch
    // check is only as good as always being evaluated against the *one*
    // correctly-configured instance. If registration's start and finish (or
    // authentication's) ever read from two different `Webauthn` values --
    // one built fresh with different origins/rp_id, say, by a future
    // refactor -- the origin/RP check would still run, but against the
    // wrong configuration, and could pass things it should reject. Confirmed
    // by inspection that this cannot happen today: `authn.rs` never
    // constructs a `Webauthn` instance itself (`grep -c "WebauthnBuilder\|
    // Webauthn::new" routes/authn.rs` is 0); every one of its six ceremony
    // entry points reads `state.webauthn.clone()`, the single instance
    // `build_from_settings` builds once at hub startup. This test pins that
    // fact so a future edit that reconstructs a second instance somewhere
    // fails loudly instead of silently reopening the substitution risk.
    #[test]
    fn passkey_routes_never_construct_a_second_webauthn_instance() {
        let source = include_str!("routes/authn.rs");
        assert!(
            !source.contains("WebauthnBuilder") && !source.contains("Webauthn::new"),
            "authn.rs must never build its own Webauthn instance -- every ceremony \
             entry point must read state.webauthn, the single instance \
             build_from_settings constructs at startup, or origin/RP-ID matching \
             could silently run against the wrong configuration"
        );
        let state_webauthn_reads = source.matches("state.webauthn").count();
        assert!(
            state_webauthn_reads >= 6,
            "expected at least 6 reads of state.webauthn (one per ceremony entry \
             point: register options/verify, login options/verify, step-up \
             options/verify) -- found {state_webauthn_reads}; a dropped read is as \
             much a regression here as an added second instance would be"
        );
    }
}
