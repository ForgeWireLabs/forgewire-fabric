//! Per-task userspace egress enforcement.
//!
//! A declared task policy always creates a loopback-only SOCKS5 proxy, including
//! an empty policy (which therefore denies every destination). DNS names are
//! resolved by the proxy after the requested hostname passes the allowlist.

#![deny(rust_2018_idioms)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

const SOCKS_VERSION: u8 = 5;
const SOCKS_NO_AUTH: u8 = 0;
const SOCKS_CONNECT: u8 = 1;
const REPLY_SUCCEEDED: u8 = 0;
const REPLY_POLICY_DENIED: u8 = 2;
const REPLY_HOST_UNREACHABLE: u8 = 4;
const REPLY_COMMAND_UNSUPPORTED: u8 = 7;
const REPLY_ADDRESS_UNSUPPORTED: u8 = 8;

/// Ambient variables runners may copy into a clean child environment. Service
/// credentials, ForgeWire token paths, and proxy settings are intentionally not
/// present.
pub const SAFE_CHILD_ENV_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "COMPUTERNAME",
    "USERNAME",
];

#[derive(Debug, Error)]
pub enum EgressError {
    #[error("network_egress must be an object")]
    PolicyNotObject,
    #[error("network_egress.allow must be an array")]
    AllowNotArray,
    #[error("network_egress.allow[{index}] must be a string")]
    AllowEntryNotString { index: usize },
    #[error("invalid egress host rule: {0}")]
    InvalidHostRule(String),
    #[error("cannot bind task egress proxy: {0}")]
    Bind(#[source] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostRule {
    Exact(String),
    Suffix(String),
}

/// A validated hostname-only allowlist. Ports are deliberately not widened or
/// inferred: the milestone contract scopes destinations by host.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    rules: Vec<HostRule>,
}

impl EgressPolicy {
    /// Parse a declared `network_egress` object. Missing `allow` means an empty
    /// allowlist and therefore default-deny.
    pub fn from_value(value: &Value) -> Result<Self, EgressError> {
        let object = value.as_object().ok_or(EgressError::PolicyNotObject)?;
        let Some(allow) = object.get("allow") else {
            return Ok(Self::default());
        };
        let entries = allow.as_array().ok_or(EgressError::AllowNotArray)?;
        let mut rules = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let raw = entry
                .as_str()
                .ok_or(EgressError::AllowEntryNotString { index })?;
            let normalized = normalize_rule(raw)?;
            if !rules.contains(&normalized) {
                rules.push(normalized);
            }
        }
        Ok(Self { rules })
    }

    pub fn allows(&self, requested_host: &str) -> bool {
        let Ok(host) = normalize_requested_host(requested_host) else {
            return false;
        };
        let requested_is_ip = host.parse::<IpAddr>().is_ok();
        self.rules.iter().any(|rule| match rule {
            HostRule::Exact(exact) => exact == &host,
            HostRule::Suffix(suffix) => {
                !requested_is_ip
                    && host.len() > suffix.len() + 1
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
        })
    }
}

fn normalize_rule(raw: &str) -> Result<HostRule, EgressError> {
    let trimmed = raw.trim();
    if let Some(suffix) = trimmed.strip_prefix("*.") {
        if suffix.contains('*') {
            return Err(EgressError::InvalidHostRule(raw.to_owned()));
        }
        let suffix =
            normalize_dns_name(suffix).map_err(|_| EgressError::InvalidHostRule(raw.to_owned()))?;
        return Ok(HostRule::Suffix(suffix));
    }
    if trimmed.contains('*') {
        return Err(EgressError::InvalidHostRule(raw.to_owned()));
    }
    let host = normalize_requested_host(trimmed)
        .map_err(|_| EgressError::InvalidHostRule(raw.to_owned()))?;
    Ok(HostRule::Exact(host))
}

fn normalize_requested_host(raw: &str) -> Result<String, ()> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.parse::<IpAddr>().is_ok() {
        return Ok(trimmed);
    }
    normalize_dns_name(&trimmed)
}

fn normalize_dns_name(raw: &str) -> Result<String, ()> {
    if raw.is_empty() || raw.len() > 253 || !raw.is_ascii() {
        return Err(());
    }
    for label in raw.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(());
        }
    }
    Ok(raw.to_ascii_lowercase())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressDenial {
    pub task_id: i64,
    pub protocol: &'static str,
    pub command: &'static str,
    pub reason: &'static str,
    pub destination: Option<String>,
    pub port: Option<u16>,
}

impl EgressDenial {
    fn record(self, denials: &Arc<Mutex<Vec<Self>>>) {
        tracing::warn!(
            target: "fabric_egress",
            task_id = self.task_id,
            protocol = self.protocol,
            command = self.command,
            reason = self.reason,
            destination = self.destination.as_deref().unwrap_or(""),
            port = self.port.unwrap_or(0),
            "egress_denied"
        );
        denials.lock().unwrap_or_else(|e| e.into_inner()).push(self);
    }
}

/// A loopback-only SOCKS5 proxy owned by one task.
pub struct EgressProxy {
    local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<()>>,
    denials: Arc<Mutex<Vec<EgressDenial>>>,
}

impl EgressProxy {
    /// Start enforcement only when the task declares a non-null policy. A
    /// declared empty object is intentionally different from absence: it starts
    /// a proxy with an empty allowlist and denies every request.
    pub async fn start_for_task(
        task_id: i64,
        policy: Option<&Value>,
    ) -> Result<Option<Self>, EgressError> {
        let Some(policy) = policy.filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        let policy = EgressPolicy::from_value(policy)?;
        Self::start(task_id, policy).await.map(Some)
    }

    pub async fn start(task_id: i64, policy: EgressPolicy) -> Result<Self, EgressError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(EgressError::Bind)?;
        let local_addr = listener.local_addr().map_err(EgressError::Bind)?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let denials = Arc::new(Mutex::new(Vec::new()));
        let server_denials = denials.clone();

        let server = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _peer)) => {
                                let policy = policy.clone();
                                let denials = server_denials.clone();
                                connections.spawn(async move {
                                    serve_connection(stream, task_id, policy, denials).await;
                                });
                            }
                            Err(error) => {
                                tracing::warn!(target: "fabric_egress", task_id, %error, "egress_accept_failed");
                                break;
                            }
                        }
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });

        Ok(Self {
            local_addr,
            shutdown_tx: Some(shutdown_tx),
            server: Some(server),
            denials,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn proxy_url(&self) -> String {
        format!("socks5h://{}", self.local_addr)
    }

    pub fn proxy_env(&self) -> [(String, String); 6] {
        let url = self.proxy_url();
        [
            ("HTTP_PROXY".into(), url.clone()),
            ("HTTPS_PROXY".into(), url.clone()),
            ("ALL_PROXY".into(), url.clone()),
            ("http_proxy".into(), url.clone()),
            ("https_proxy".into(), url.clone()),
            ("all_proxy".into(), url),
        ]
    }

    /// Stop accepting and abort every in-flight tunnel. Returned denials are a
    /// task-local audit record and contain only destination metadata.
    pub async fn shutdown(mut self) -> Vec<EgressDenial> {
        self.signal_shutdown();
        if let Some(server) = self.server.take() {
            let _ = server.await;
        }
        self.denials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn signal_shutdown(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.signal_shutdown();
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

#[derive(Debug)]
struct Target {
    host: String,
    port: u16,
}

async fn serve_connection(
    mut inbound: TcpStream,
    task_id: i64,
    policy: EgressPolicy,
    denials: Arc<Mutex<Vec<EgressDenial>>>,
) {
    if let Err(reason) = negotiate_no_auth(&mut inbound).await {
        EgressDenial {
            task_id,
            protocol: "socks5",
            command: "NEGOTIATE",
            reason,
            destination: None,
            port: None,
        }
        .record(&denials);
        return;
    }

    let (command, target) = match read_request(&mut inbound).await {
        Ok(request) => request,
        Err((reply, reason)) => {
            let _ = send_reply(&mut inbound, reply).await;
            EgressDenial {
                task_id,
                protocol: "socks5",
                command: "CONNECT",
                reason,
                destination: None,
                port: None,
            }
            .record(&denials);
            return;
        }
    };

    if command != SOCKS_CONNECT {
        let _ = send_reply(&mut inbound, REPLY_COMMAND_UNSUPPORTED).await;
        EgressDenial {
            task_id,
            protocol: "socks5",
            command: "UNSUPPORTED",
            reason: "command_not_connect",
            destination: Some(target.host),
            port: Some(target.port),
        }
        .record(&denials);
        return;
    }

    if !policy.allows(&target.host) {
        let _ = send_reply(&mut inbound, REPLY_POLICY_DENIED).await;
        EgressDenial {
            task_id,
            protocol: "socks5",
            command: "CONNECT",
            reason: "host_not_allowed",
            destination: Some(target.host),
            port: Some(target.port),
        }
        .record(&denials);
        return;
    }

    let mut outbound = match connect_target(&target).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::debug!(target: "fabric_egress", task_id, %error, "egress_connect_failed");
            let _ = send_reply(&mut inbound, REPLY_HOST_UNREACHABLE).await;
            return;
        }
    };
    if send_reply(&mut inbound, REPLY_SUCCEEDED).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
}

async fn negotiate_no_auth(stream: &mut TcpStream) -> Result<(), &'static str> {
    let mut header = [0_u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| "incomplete_greeting")?;
    if header[0] != SOCKS_VERSION {
        return Err("unsupported_socks_version");
    }
    let mut methods = vec![0_u8; usize::from(header[1])];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|_| "incomplete_greeting")?;
    if !methods.contains(&SOCKS_NO_AUTH) {
        let _ = stream.write_all(&[SOCKS_VERSION, 0xff]).await;
        return Err("no_supported_auth_method");
    }
    stream
        .write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH])
        .await
        .map_err(|_| "greeting_reply_failed")
}

async fn read_request(stream: &mut TcpStream) -> Result<(u8, Target), (u8, &'static str)> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| (REPLY_ADDRESS_UNSUPPORTED, "incomplete_request"))?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        return Err((REPLY_ADDRESS_UNSUPPORTED, "malformed_request"));
    }
    let host = match header[3] {
        1 => {
            let mut octets = [0_u8; 4];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|_| (REPLY_ADDRESS_UNSUPPORTED, "incomplete_ipv4"))?;
            IpAddr::V4(Ipv4Addr::from(octets)).to_string()
        }
        3 => {
            let length = stream
                .read_u8()
                .await
                .map_err(|_| (REPLY_ADDRESS_UNSUPPORTED, "missing_domain_length"))?;
            if length == 0 {
                return Err((REPLY_ADDRESS_UNSUPPORTED, "empty_domain"));
            }
            let mut bytes = vec![0_u8; usize::from(length)];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|_| (REPLY_ADDRESS_UNSUPPORTED, "incomplete_domain"))?;
            String::from_utf8(bytes).map_err(|_| (REPLY_ADDRESS_UNSUPPORTED, "non_utf8_domain"))?
        }
        4 => {
            let mut octets = [0_u8; 16];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|_| (REPLY_ADDRESS_UNSUPPORTED, "incomplete_ipv6"))?;
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        _ => return Err((REPLY_ADDRESS_UNSUPPORTED, "address_type_unsupported")),
    };
    let port = stream
        .read_u16()
        .await
        .map_err(|_| (REPLY_ADDRESS_UNSUPPORTED, "missing_port"))?;
    Ok((header[1], Target { host, port }))
}

async fn connect_target(target: &Target) -> std::io::Result<TcpStream> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return TcpStream::connect(SocketAddr::new(ip, target.port)).await;
    }
    let addresses = tokio::net::lookup_host((target.host.as_str(), target.port)).await?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "hostname resolved to no addresses",
        )
    }))
}

async fn send_reply(stream: &mut TcpStream, reply: u8) -> std::io::Result<()> {
    stream
        .write_all(&[SOCKS_VERSION, reply, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connect_domain(proxy: SocketAddr, host: &str, port: u16) -> (TcpStream, u8) {
        let mut stream = TcpStream::connect(proxy).await.expect("connect proxy");
        stream
            .write_all(&[SOCKS_VERSION, 1, SOCKS_NO_AUTH])
            .await
            .expect("write greeting");
        let mut greeting = [0_u8; 2];
        stream
            .read_exact(&mut greeting)
            .await
            .expect("read greeting");
        assert_eq!(greeting, [SOCKS_VERSION, SOCKS_NO_AUTH]);
        let host_bytes = host.as_bytes();
        // SOCKS5's domain-length prefix is a single byte (RFC 1928); a test
        // hostname exceeding 255 bytes is a broken test, not a runtime
        // condition to handle gracefully.
        let host_len = u8::try_from(host_bytes.len())
            .expect("test hostname must fit in a SOCKS5 domain length byte");
        let mut request = vec![SOCKS_VERSION, SOCKS_CONNECT, 0, 3, host_len];
        request.extend_from_slice(host_bytes);
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.expect("write request");
        let mut reply = [0_u8; 10];
        stream.read_exact(&mut reply).await.expect("read reply");
        (stream, reply[1])
    }

    async fn connect_ipv4(proxy: SocketAddr, ip: Ipv4Addr, port: u16) -> (TcpStream, u8) {
        let mut stream = TcpStream::connect(proxy).await.expect("connect proxy");
        stream
            .write_all(&[SOCKS_VERSION, 1, SOCKS_NO_AUTH])
            .await
            .expect("write greeting");
        let mut greeting = [0_u8; 2];
        stream
            .read_exact(&mut greeting)
            .await
            .expect("read greeting");
        let mut request = vec![SOCKS_VERSION, SOCKS_CONNECT, 0, 1];
        request.extend_from_slice(&ip.octets());
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.expect("write request");
        let mut reply = [0_u8; 10];
        stream.read_exact(&mut reply).await.expect("read reply");
        (stream, reply[1])
    }

    async fn echo_server() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo");
        let address = listener.local_addr().expect("echo address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept echo");
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.expect("read echo");
            stream.write_all(&bytes).await.expect("write echo");
        });
        (address, server)
    }

    #[test]
    fn policy_is_exact_or_leading_wildcard_only() {
        let policy = EgressPolicy::from_value(&serde_json::json!({
            "allow": ["example.com", "*.allowed.example", "127.0.0.1"]
        }))
        .expect("valid policy");
        assert!(policy.allows("example.com"));
        assert!(!policy.allows("www.example.com"));
        assert!(policy.allows("api.allowed.example"));
        assert!(!policy.allows("allowed.example"));
        assert!(!policy.allows("notallowed.example"));
        assert!(policy.allows("127.0.0.1"));
        assert!(!policy.allows("127.0.0.2"));
        assert!(EgressPolicy::from_value(&serde_json::json!({"allow": ["api.*.com"]})).is_err());
    }

    #[tokio::test]
    async fn allowed_domain_connect_uses_real_sockets() {
        let (echo, echo_task) = echo_server().await;
        let policy =
            EgressPolicy::from_value(&serde_json::json!({"allow": ["localhost"]})).expect("policy");
        let proxy = EgressProxy::start(41, policy).await.expect("proxy");
        let (mut stream, reply) =
            connect_domain(proxy.local_addr(), "localhost", echo.port()).await;
        assert_eq!(reply, REPLY_SUCCEEDED);
        stream.write_all(b"ping").await.expect("send through proxy");
        let mut echoed = [0_u8; 4];
        stream
            .read_exact(&mut echoed)
            .await
            .expect("receive through proxy");
        assert_eq!(&echoed, b"ping");
        drop(stream);
        echo_task.await.expect("echo task");
        assert!(proxy.shutdown().await.is_empty());
    }

    #[tokio::test]
    async fn ip_literal_bypass_is_denied_and_structured() {
        let policy =
            EgressPolicy::from_value(&serde_json::json!({"allow": ["localhost"]})).expect("policy");
        let proxy = EgressProxy::start(42, policy).await.expect("proxy");
        let (_stream, reply) = connect_ipv4(proxy.local_addr(), Ipv4Addr::LOCALHOST, 9).await;
        assert_eq!(reply, REPLY_POLICY_DENIED);
        let denials = proxy.shutdown().await;
        assert_eq!(denials.len(), 1);
        assert_eq!(
            denials[0],
            EgressDenial {
                task_id: 42,
                protocol: "socks5",
                command: "CONNECT",
                reason: "host_not_allowed",
                destination: Some("127.0.0.1".into()),
                port: Some(9),
            }
        );
    }

    #[tokio::test]
    async fn explicitly_listed_ip_literal_can_connect() {
        let (echo, echo_task) = echo_server().await;
        let policy =
            EgressPolicy::from_value(&serde_json::json!({"allow": ["127.0.0.1"]})).expect("policy");
        let proxy = EgressProxy::start(43, policy).await.expect("proxy");
        let (mut stream, reply) =
            connect_ipv4(proxy.local_addr(), Ipv4Addr::LOCALHOST, echo.port()).await;
        assert_eq!(reply, REPLY_SUCCEEDED);
        stream.write_all(b"safe").await.expect("send through proxy");
        let mut echoed = [0_u8; 4];
        stream
            .read_exact(&mut echoed)
            .await
            .expect("receive through proxy");
        assert_eq!(&echoed, b"safe");
        drop(stream);
        echo_task.await.expect("echo task");
        assert!(proxy.shutdown().await.is_empty());
    }

    #[tokio::test]
    async fn empty_declared_policy_defaults_to_deny() {
        let proxy = EgressProxy::start(44, EgressPolicy::default())
            .await
            .expect("proxy");
        let (_stream, reply) = connect_domain(proxy.local_addr(), "example.com", 443).await;
        assert_eq!(reply, REPLY_POLICY_DENIED);
        let denials = proxy.shutdown().await;
        assert_eq!(denials[0].reason, "host_not_allowed");
    }

    #[tokio::test]
    async fn shutdown_closes_the_ephemeral_listener() {
        let proxy = EgressProxy::start(45, EgressPolicy::default())
            .await
            .expect("proxy");
        let address = proxy.local_addr();
        assert!(proxy
            .proxy_env()
            .iter()
            .all(|(_, value)| value.starts_with("socks5h://127.0.0.1:")));
        proxy.shutdown().await;
        assert!(TcpStream::connect(address).await.is_err());
    }
}
