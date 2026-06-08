//! Zero-dependency LAN hub discovery for ForgeWire Fabric.
//!
//! The Rust rewrite dropped the Python mDNS advertisement, which left every
//! node depending on a statically configured hub address. When DHCP moved a
//! machine to a new subnet, every pinned address broke. This crate restores
//! out-of-the-box discovery using only `std::net` — no mDNS crate, no external
//! dependency.
//!
//! ## Model: request/response over UDP broadcast
//!
//! - The **hub** binds a well-known UDP port (default 48765) and:
//!   - periodically broadcasts an *announce* datagram to the LAN, and
//!   - replies (unicast) to any *query* datagram it receives.
//! - A **client** (runner, CLI, extension) binds an *ephemeral* port, broadcasts
//!   a query, and collects replies for a short window.
//!
//! Clients never bind the well-known port, so a runner, a CLI `discover`, and
//! the VS Code extension can all discover concurrently on one machine without
//! `SO_REUSEADDR` (which `std` cannot set).
//!
//! ## Why this is subnet-proof
//!
//! The hub never announces its own IP. The client derives the hub URL from the
//! **source address of the datagram** plus the advertised port. Whatever address
//! the hub currently has — after a reboot, a DHCP lease change, a move to a new
//! subnet — is exactly the address the packet arrives from. Nothing is pinned.
//!
//! ## Security
//!
//! The beacon never carries the bearer token, only `sha256(token)[..16]`. A
//! client that holds the token can confirm a discovered hub belongs to its
//! cluster by comparing hashes; it still authenticates every real request with
//! the full token over the existing signed/bearer API. Discovery is
//! observational — it never auto-trusts; the token remains the admission gate.

#![deny(rust_2018_idioms)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default UDP port the hub listens on for discovery.
pub const DEFAULT_BEACON_PORT: u16 = 48765;
/// Guards against unrelated UDP traffic on the port.
pub const MAGIC: &str = "FWBEACON";
/// Beacon wire-format version.
pub const BEACON_VERSION: u32 = 1;

const ROLE_HUB: &str = "hub";
const ROLE_QUERY: &str = "query";
const MAX_DATAGRAM: usize = 2048;

/// A discovery datagram. The same struct is used for hub announces/replies
/// (`role = "hub"`) and client queries (`role = "query"`); only `magic`, `v`,
/// and `role` are meaningful on a query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Beacon {
    pub magic: String,
    pub v: u32,
    pub role: String,
    #[serde(default)]
    pub hub_id: String,
    /// The hub's HTTP port (the IP is taken from the datagram source).
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub proto: i64,
    #[serde(default)]
    pub name: String,
    /// `sha256(token)[..16]` — never the token itself.
    #[serde(default)]
    pub token_hash: String,
    #[serde(default)]
    pub ts: u64,
    /// rqlite Raft port on this hub's host. Joining nodes use
    /// `<beacon source IP>:<raft_port>` to join the rqlite cluster.
    /// Default 4002; 0 means not advertised (legacy hub).
    #[serde(default)]
    pub raft_port: u16,
    /// rqlite HTTP port on this hub's host.
    /// Default 4001; 0 means not advertised (legacy hub).
    #[serde(default)]
    pub rqlite_http_port: u16,
    /// Number of rqlite voter nodes currently in the cluster.
    /// Installing nodes use this to decide voter vs non-voter role.
    #[serde(default)]
    pub rqlite_voters: u16,
    /// Number of rqlite nodes total (voters + non-voters).
    #[serde(default)]
    pub rqlite_nodes: u16,
}

impl Beacon {
    fn query() -> Self {
        Beacon {
            magic: MAGIC.to_owned(),
            v: BEACON_VERSION,
            role: ROLE_QUERY.to_owned(),
            hub_id: String::new(),
            port: 0,
            proto: 0,
            name: String::new(),
            token_hash: String::new(),
            ts: now_unix(),
            raft_port: 0,
            rqlite_http_port: 0,
            rqlite_voters: 0,
            rqlite_nodes: 0,
        }
    }

    fn is_valid(&self) -> bool {
        self.magic == MAGIC && self.v == BEACON_VERSION
    }
    fn is_query(&self) -> bool {
        self.is_valid() && self.role == ROLE_QUERY
    }
    fn is_hub(&self) -> bool {
        self.is_valid() && self.role == ROLE_HUB && self.port != 0
    }
}

/// `sha256(token)` truncated to 16 hex chars. Used to confirm a discovered hub
/// belongs to the caller's cluster without exposing the token.
pub fn token_hash(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())[..16].to_owned()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Best-effort primary IPv4 of this host, discovered by asking the OS which
/// local address it would route a packet to a public address from. No packet is
/// actually sent. Returns `None` if it cannot be determined.
fn primary_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    // connect() on a UDP socket only sets the default peer + picks a source
    // address via the routing table; nothing is transmitted.
    s.connect("8.8.8.8:80").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// Broadcast targets for the given port: the limited broadcast address plus, if
/// the primary IPv4 is known, the directed /24 broadcast of that subnet (covers
/// networks that drop 255.255.255.255 but pass directed broadcasts).
fn broadcast_targets(port: u16) -> Vec<SocketAddr> {
    let mut out = vec![SocketAddr::from((Ipv4Addr::BROADCAST, port))];
    if let Some(ip) = primary_ipv4() {
        let o = ip.octets();
        let directed = Ipv4Addr::new(o[0], o[1], o[2], 255);
        let addr = SocketAddr::from((directed, port));
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

fn parse(buf: &[u8]) -> Option<Beacon> {
    serde_json::from_slice::<Beacon>(buf).ok().filter(Beacon::is_valid)
}

// ---------------------------------------------------------------------------
// Hub side: the responder
// ---------------------------------------------------------------------------

/// Static facts a hub announces. The IP is intentionally absent — receivers use
/// the datagram source address.
#[derive(Debug, Clone)]
pub struct HubAdvert {
    pub hub_id: String,
    pub http_port: u16,
    pub proto: i64,
    pub name: String,
    pub token_hash: String,
    /// rqlite Raft port — joining nodes use `<source_ip>:<raft_port>` to join.
    pub raft_port: u16,
    /// rqlite HTTP port — joining nodes use this to probe the cluster.
    pub rqlite_http_port: u16,
    /// Current voter count in the rqlite cluster (for join-role auto-detection).
    pub rqlite_voters: u16,
    /// Total node count in the rqlite cluster.
    pub rqlite_nodes: u16,
}

impl HubAdvert {
    fn beacon(&self) -> Beacon {
        Beacon {
            magic: MAGIC.to_owned(),
            v: BEACON_VERSION,
            role: ROLE_HUB.to_owned(),
            hub_id: self.hub_id.clone(),
            port: self.http_port,
            proto: self.proto,
            name: self.name.clone(),
            token_hash: self.token_hash.clone(),
            ts: now_unix(),
            raft_port: self.raft_port,
            rqlite_http_port: self.rqlite_http_port,
            rqlite_voters: self.rqlite_voters,
            rqlite_nodes: self.rqlite_nodes,
        }
    }
}

/// Run the hub discovery responder forever on `udp_port`. Binds the well-known
/// port, replies to queries, and re-announces every `announce_interval`.
///
/// Returns `Err` only if the port cannot be bound (caller logs and continues
/// without discovery — it is never fatal to the hub). The loop itself never
/// returns; spawn it on a dedicated thread.
pub fn serve(advert: HubAdvert, udp_port: u16, announce_interval: Duration) -> io::Result<()> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, udp_port)))?;
    socket.set_broadcast(true)?;
    // Drives periodic announce even when no queries arrive.
    socket.set_read_timeout(Some(Duration::from_millis(1000)))?;

    let targets = broadcast_targets(udp_port);
    let mut buf = [0u8; MAX_DATAGRAM];
    let mut last_announce = Instant::now()
        .checked_sub(announce_interval)
        .unwrap_or_else(Instant::now);

    loop {
        if last_announce.elapsed() >= announce_interval {
            announce(&socket, &advert, &targets);
            last_announce = Instant::now();
        }
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(b) = parse(&buf[..n]) {
                    if b.is_query() {
                        // Reply directly to the querier with a fresh beacon.
                        if let Ok(bytes) = serde_json::to_vec(&advert.beacon()) {
                            let _ = socket.send_to(&bytes, src);
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                // read timeout — loop to re-check the announce clock
            }
            Err(_) => {
                // transient error; avoid a hot spin
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// Announce once and handle incoming queries for ~1 s, then return.
///
/// Used by the hub's beacon thread to refresh the cluster-state payload each
/// cycle without blocking forever on a single socket binding.
pub fn serve_once(advert: HubAdvert, udp_port: u16) -> io::Result<()> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, udp_port)))?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(900)))?;

    let targets = broadcast_targets(udp_port);
    announce(&socket, &advert, &targets);

    let mut buf = [0u8; MAX_DATAGRAM];
    let deadline = Instant::now() + Duration::from_millis(1000);
    loop {
        if Instant::now() >= deadline {
            break;
        }
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(b) = parse(&buf[..n]) {
                    if b.is_query() {
                        if let Ok(bytes) = serde_json::to_vec(&advert.beacon()) {
                            let _ = socket.send_to(&bytes, src);
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    Ok(())
}

fn announce(socket: &UdpSocket, advert: &HubAdvert, targets: &[SocketAddr]) {
    if let Ok(bytes) = serde_json::to_vec(&advert.beacon()) {
        for t in targets {
            let _ = socket.send_to(&bytes, *t);
        }
    }
}

// ---------------------------------------------------------------------------
// Client side: discovery
// ---------------------------------------------------------------------------

/// A hub found on the LAN. `url` is built from the datagram source IP and the
/// advertised port, so it is always the hub's current address.
#[derive(Debug, Clone)]
pub struct DiscoveredHub {
    pub url: String,
    pub hub_id: String,
    pub name: String,
    pub proto: i64,
    pub token_hash: String,
    pub source: IpAddr,
}

/// Discover hubs on the LAN within `timeout`. If `want_token_hash` is `Some`,
/// only hubs whose advertised hash matches are returned (same-cluster filter).
///
/// Returns hubs in arrival order, de-duplicated by `url`. An empty vec means
/// nothing answered (hub down, different broadcast domain, or firewalled).
pub fn discover(
    udp_port: u16,
    timeout: Duration,
    want_token_hash: Option<&str>,
) -> io::Result<Vec<DiscoveredHub>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;

    let targets = broadcast_targets(udp_port);
    let query = serde_json::to_vec(&Beacon::query()).unwrap_or_default();
    let send_query = |s: &UdpSocket| {
        for t in &targets {
            let _ = s.send_to(&query, *t);
        }
    };
    send_query(&socket);

    let deadline = Instant::now() + timeout;
    let mut last_query = Instant::now();
    let mut found: HashMap<String, DiscoveredHub> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut buf = [0u8; MAX_DATAGRAM];

    while Instant::now() < deadline {
        // Re-query periodically to tolerate UDP loss.
        if last_query.elapsed() >= Duration::from_millis(600) {
            send_query(&socket);
            last_query = Instant::now();
        }
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(b) = parse(&buf[..n]).filter(Beacon::is_hub) {
                    if let Some(want) = want_token_hash {
                        if !b.token_hash.is_empty() && b.token_hash != want {
                            continue; // different cluster
                        }
                    }
                    let url = format!("http://{}:{}", src.ip(), b.port);
                    if !found.contains_key(&url) {
                        order.push(url.clone());
                        found.insert(
                            url.clone(),
                            DiscoveredHub {
                                url,
                                hub_id: b.hub_id,
                                name: b.name,
                                proto: b.proto,
                                token_hash: b.token_hash,
                                source: src.ip(),
                            },
                        );
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }
    }

    Ok(order.into_iter().filter_map(|k| found.remove(&k)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_is_16_hex() {
        let h = token_hash("super-secret-token");
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // stable + not the token
        assert_eq!(h, token_hash("super-secret-token"));
        assert_ne!(h, token_hash("other"));
    }

    #[test]
    fn query_roundtrips_and_classifies() {
        let q = Beacon::query();
        let bytes = serde_json::to_vec(&q).unwrap();
        let parsed = parse(&bytes).unwrap();
        assert!(parsed.is_query());
        assert!(!parsed.is_hub());
    }

    #[test]
    fn hub_beacon_classifies() {
        let advert = HubAdvert {
            hub_id: "node-x".into(),
            http_port: 8765,
            proto: 3,
            name: "lab".into(),
            token_hash: token_hash("t"),
        };
        let b = advert.beacon();
        let bytes = serde_json::to_vec(&b).unwrap();
        let parsed = parse(&bytes).unwrap();
        assert!(parsed.is_hub());
        assert!(!parsed.is_query());
        assert_eq!(parsed.port, 8765);
    }

    #[test]
    fn foreign_magic_rejected() {
        let junk = br#"{"magic":"OTHER","v":1,"role":"hub","port":1}"#;
        assert!(parse(junk).is_none());
        let wrong_ver = br#"{"magic":"FWBEACON","v":99,"role":"hub","port":1}"#;
        assert!(parse(wrong_ver).is_none());
    }

    #[test]
    fn hub_with_zero_port_is_not_a_hub() {
        let b = Beacon {
            magic: MAGIC.into(),
            v: BEACON_VERSION,
            role: ROLE_HUB.into(),
            port: 0,
            ..Beacon::query()
        };
        assert!(!b.is_hub());
    }

    /// End-to-end on loopback: a responder thread answers a discover() query.
    #[test]
    fn loopback_discover_finds_responder() {
        // Use an uncommon port to avoid clashing with a real hub on the test box.
        let port = 49321;
        let advert = HubAdvert {
            hub_id: "loopback-hub".into(),
            http_port: 8765,
            proto: 3,
            name: "test".into(),
            token_hash: token_hash("cluster-token"),
        };
        std::thread::spawn(move || {
            let _ = serve(advert, port, Duration::from_millis(200));
        });
        std::thread::sleep(Duration::from_millis(150));

        let hubs = discover(port, Duration::from_millis(1500), Some(&token_hash("cluster-token")))
            .expect("discover ok");
        assert!(
            hubs.iter().any(|h| h.hub_id == "loopback-hub" && h.url.ends_with(":8765")),
            "expected to discover the loopback responder, got {hubs:?}"
        );

        // Wrong token hash filters it out.
        let none = discover(port, Duration::from_millis(800), Some("0000000000000000"))
            .expect("discover ok");
        assert!(none.is_empty(), "wrong-cluster filter should hide it, got {none:?}");
    }
}
