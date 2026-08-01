//! 114C.7 Slice 2: representative transport coverage for the 22 new
//! `HubClient` auth/account methods (`login` through
//! `account_security_history`), plus (114C.7 Slice 5b) `step_up_options`/
//! `step_up_verify`. Not exhaustive per-route -- the plan itself frames
//! Slice 2 as "mechanical breadth, not new design risk": every one of these
//! methods shares the identical `request_auth` helper proven by the first
//! four tests below (GET vs POST vs DELETE, with vs without a bearer, with
//! vs without a JSON body, and query-string/path-segment construction), so
//! the step-up tests exist for their own novel body shape (a nested
//! `credential` object), not to re-prove that plumbing again.
//!
//! The mock server is a raw `TcpListener` on its own OS thread, not an
//! async server: it only needs to accept one connection, read one request,
//! and write one canned response, so no test-only web framework dependency
//! is worth adding for it. The client under test is exercised through its
//! real async `reqwest`-backed methods via `#[tokio::test]`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

use fabric_client::HubClient;

struct RecordedRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    body: String,
}

/// Accept exactly one connection, record the request, reply with
/// `(status, json_body)`, then exit. Returns the server's base URL and a
/// receiver that yields the recorded request once the client's call
/// completes.
fn start_mock_server(
    status: u16,
    response_body: &'static str,
) -> (String, mpsc::Receiver<RecordedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let port = listener.local_addr().expect("local_addr").port();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 16384];
            let n = stream.read(&mut buf).unwrap_or(0);
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let mut lines = raw.split("\r\n");
            let request_line = lines.next().unwrap_or_default().to_owned();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_owned();
            let path = parts.next().unwrap_or_default().to_owned();

            let mut authorization = None;
            let mut body = String::new();
            let mut in_body = false;
            for line in lines {
                if in_body {
                    body.push_str(line);
                    continue;
                }
                if line.is_empty() {
                    in_body = true;
                    continue;
                }
                // reqwest/hyper write header names lowercase on the wire
                // regardless of the case passed to `.header(...)`.
                if line.len() > 15 && line[..15].eq_ignore_ascii_case("authorization: ") {
                    authorization = Some(line[15..].to_owned());
                }
            }

            let response = format!(
                "HTTP/1.1 {status} status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = tx.send(RecordedRequest {
                method,
                path,
                authorization,
                body,
            });
        }
    });

    (format!("http://127.0.0.1:{port}"), rx)
}

#[tokio::test]
async fn login_sends_no_bearer_and_a_json_body_and_parses_the_session_response() {
    let (url, rx) = start_mock_server(
        200,
        r#"{"session_id":"sess-1","account_id":"acct-1","assurance_level":"aal1","access_secret":"a","refresh_secret":"r","idle_expires_at":"t1","absolute_expires_at":"t2"}"#,
    );
    let client = HubClient::new(&url, "");
    let result = client
        .login(
            "operator1",
            "correct horse battery staple",
            Some("desktop"),
            None,
            None,
        )
        .await
        .expect("login should succeed");

    assert_eq!(result["session_id"], "sess-1");
    assert_eq!(result["access_secret"], "a");

    let recorded = rx.recv().expect("server recorded a request");
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.path, "/auth/login");
    assert!(
        recorded.authorization.is_none(),
        "login is a public route -- no bearer expected"
    );
    assert!(recorded.body.contains("\"username\":\"operator1\""));
    assert!(recorded.body.contains("\"client_kind\":\"desktop\""));
}

#[tokio::test]
async fn list_accounts_sends_the_access_secret_as_a_bearer_and_builds_the_query_string() {
    let (url, rx) = start_mock_server(200, r#"{"accounts":[]}"#);
    let client = HubClient::new(&url, "unused-automation-token");
    let result = client
        .list_accounts("human-session-access-secret", 50, 10)
        .await
        .expect("list_accounts should succeed");

    assert_eq!(result["accounts"], serde_json::json!([]));

    let recorded = rx.recv().expect("server recorded a request");
    assert_eq!(recorded.method, "GET");
    assert_eq!(recorded.path, "/accounts?limit=50&offset=10");
    assert_eq!(
        recorded.authorization.as_deref(),
        Some("Bearer human-session-access-secret"),
        "must use the session access secret, never the automation hub token this client also holds"
    );
}

#[tokio::test]
async fn revoke_membership_is_a_delete_with_url_encoded_path_segments() {
    let (url, rx) = start_mock_server(200, r#"{"account_id":"acct 1","roles":[]}"#);
    let client = HubClient::new(&url, "");
    client
        .revoke_membership("secret", "acct 1", "dispatcher")
        .await
        .expect("revoke_membership should succeed");

    let recorded = rx.recv().expect("server recorded a request");
    assert_eq!(recorded.method, "DELETE");
    assert_eq!(recorded.path, "/accounts/acct%201/membership/dispatcher");
    assert_eq!(recorded.authorization.as_deref(), Some("Bearer secret"));
}

#[tokio::test]
async fn step_up_options_sends_the_session_bearer_with_an_empty_body() {
    let (url, rx) = start_mock_server(
        200,
        r#"{"challenge_id":"chal-1","options_token":"tok-1","public_key":{"challenge":"c"}}"#,
    );
    let client = HubClient::new(&url, "unused-automation-token");
    let result = client
        .step_up_options("human-session-access-secret")
        .await
        .expect("step_up_options should succeed");

    assert_eq!(result["challenge_id"], "chal-1");

    let recorded = rx.recv().expect("server recorded a request");
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.path, "/auth/step-up/options");
    assert_eq!(
        recorded.authorization.as_deref(),
        Some("Bearer human-session-access-secret"),
        "must use the session access secret, never the automation hub token this client also holds"
    );
}

#[tokio::test]
async fn step_up_verify_sends_the_bearer_and_the_relayed_assertion() {
    let (url, rx) = start_mock_server(
        200,
        r#"{"session_id":"sess-1","assurance_level":"aal2","access_secret":"rotated-secret"}"#,
    );
    let client = HubClient::new(&url, "");
    let credential = serde_json::json!({ "id": "cred-1", "rawId": "raw" });
    let result = client
        .step_up_verify("secret", "chal-1", "tok-1", &credential)
        .await
        .expect("step_up_verify should succeed");

    assert_eq!(result["access_secret"], "rotated-secret");

    let recorded = rx.recv().expect("server recorded a request");
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.path, "/auth/step-up/verify");
    assert_eq!(recorded.authorization.as_deref(), Some("Bearer secret"));
    assert!(recorded.body.contains("\"challenge_id\":\"chal-1\""));
    assert!(recorded.body.contains("\"options_token\":\"tok-1\""));
    assert!(recorded.body.contains("\"credential\":{\"id\":\"cred-1\""));
}

#[tokio::test]
async fn a_non_2xx_response_becomes_a_client_error_hub_carrying_the_typed_code() {
    let (url, rx) = start_mock_server(
        409,
        r#"{"error":{"code":"LastAdministratorViolation","message":"cannot disable the last administrator"}}"#,
    );
    let client = HubClient::new(&url, "");
    let error = client
        .disable_account("secret", "acct-1", 3)
        .await
        .expect_err("disabling the last admin must fail");

    assert_eq!(error.status_code(), 409);
    let typed = error
        .typed_auth_error()
        .expect("body matches a known typed code");
    assert_eq!(typed.code, "LastAdministratorViolation");
    assert_eq!(typed.message, "cannot disable the last administrator");

    let recorded = rx.recv().expect("server recorded a request");
    assert_eq!(recorded.method, "POST");
    // `encode_path_segment` percent-encodes every non-alphanumeric byte
    // (`NON_ALPHANUMERIC`), so even a plain hyphen in an account id becomes
    // `%2D` -- functionally identical on the wire (axum's path extractor
    // decodes it back to `-`), just more conservative than strictly
    // necessary.
    assert_eq!(recorded.path, "/accounts/acct%2D1/disable");
    assert!(recorded.body.contains("\"expected_revision\":3"));
}
