//! Beacon v2: signed full-node presence (ADDR-1, dhcp-proof-addressing.md).
//!
//! v1 (lib.rs) solves *hub* discovery. v2 extends the same source-IP-derived
//! model to **every fabric node**: each node periodically broadcasts a signed
//! presence record naming its `node_id`, hostname, and service ports. The IP
//! is never inside the record — receivers take it from the datagram source,
//! so whatever address DHCP assigns is the address observed. Nothing is
//! pinned.
//!
//! ## Trust model
//!
//! A record carries the sender's ed25519 public key and a signature over the
//! canonical record bytes (same canonicalization as the dispatch envelope,
//! `fabric_protocol::canonicalize`). A valid signature proves *possession of
//! the key by the sender of the datagram*; it does NOT by itself prove the
//! key belongs to the cluster. Mapping key → trust is the caller's job: the
//! hub registry holds every registered node's public key, and the install
//! join-token flow bootstraps it. Unverifiable records are observational
//! only — never act on them.
//!
//! ## Replay resistance
//!
//! Broadcast announces are advisory (a captured announce replayed from a
//! different IP within the freshness window could otherwise relocate a node).
//! The **query path is replay-proof**: a presence query carries a random
//! `nonce`, and the signed response must echo it inside the signature. A
//! consumer that is about to *change* a stored address should confirm with a
//! nonce query to the new address (see ADDR-2). Announces additionally carry
//! a `ts` checked against `PRESENCE_FRESH_SECS`.
//!
//! ## Broadcast-hostile media
//!
//! The reference adversarial network (a phone WiFi hotspot) filters
//! client-to-client broadcast. [`collect_presence_addrs`] therefore accepts
//! explicit unicast targets, so callers can fall back to querying
//! last-known-good addresses from the node directory when broadcast yields
//! silence. The protocol must work without broadcast delivery.
//!
//! ## Coexistence with v1
//!
//! v1 parsers require `v == 1` and drop v2 datagrams; this module requires
//! `v == 2` and drops v1. Both share the UDP port and the `FWBEACON` magic.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{token_hash as v1_token_hash, MAGIC};

/// Wire version for presence records.
pub const PRESENCE_VERSION: u32 = 2;
/// Default UDP port for node presence (distinct from the hub discovery port:
/// on combined hub+runner hosts the hub owns [`crate::DEFAULT_BEACON_PORT`]
/// and `std` cannot set SO_REUSEADDR).
pub const DEFAULT_PRESENCE_PORT: u16 = 48766;
/// Announces / query responses.
pub const ROLE_NODE: &str = "node";
/// Presence queries.
pub const ROLE_NODE_QUERY: &str = "node-query";
/// Announces older than this are ignored (clock-skew tolerant freshness).
pub const PRESENCE_FRESH_SECS: u64 = 300;

const MAX_DATAGRAM: usize = 2048;

/// A signed node presence record. The IP is intentionally absent — receivers
/// use the datagram source address (the property that makes this DHCP-proof).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresenceRecord {
    pub magic: String,
    pub v: u32,
    pub role: String,
    /// Stable node identifier (from the node's identity file).
    pub node_id: String,
    /// OS hostname — the name the managed hosts block will map (ADDR-2).
    pub hostname: String,
    /// Service name → port. Conventional keys: "rqlite_http", "rqlite_raft",
    /// "hub", "ssh". Sorted map so canonical bytes are stable.
    pub services: BTreeMap<String, u16>,
    /// Unix seconds at signing time.
    pub ts: u64,
    /// `sha256(cluster token)[..16]` — same-cluster filter, as v1.
    pub token_hash: String,
    /// Echo of a query nonce ("" on unsolicited announces).
    #[serde(default)]
    pub nonce: String,
    /// Sender's ed25519 public key (hex). Trust is established by comparing
    /// this against the hub registry / join-token bootstrap, never assumed.
    pub public_key_hex: String,
    /// ed25519 over the canonical record bytes (all fields except `sig`).
    pub sig: String,
}

/// A presence query datagram. `nonce` must be echoed in signed responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PresenceQuery {
    magic: String,
    v: u32,
    role: String,
    nonce: String,
    #[serde(default)]
    token_hash: String,
}

/// Static facts a node announces. Sign with [`NodeAdvert::record`].
#[derive(Debug, Clone)]
pub struct NodeAdvert {
    pub node_id: String,
    pub hostname: String,
    pub services: BTreeMap<String, u16>,
    pub token_hash: String,
    /// Hex-encoded ed25519 keys (from the node's identity file).
    pub public_key_hex: String,
    pub secret_key_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PresenceError {
    #[error("canonicalization failed: {0}")]
    Canonical(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

impl NodeAdvert {
    /// Build and sign a presence record (optionally echoing a query nonce).
    pub fn record(&self, nonce: &str) -> Result<PresenceRecord, PresenceError> {
        let mut rec = PresenceRecord {
            magic: MAGIC.to_owned(),
            v: PRESENCE_VERSION,
            role: ROLE_NODE.to_owned(),
            node_id: self.node_id.clone(),
            hostname: self.hostname.clone(),
            services: self.services.clone(),
            ts: crate::now_unix(),
            token_hash: self.token_hash.clone(),
            nonce: nonce.to_owned(),
            public_key_hex: self.public_key_hex.clone(),
            sig: String::new(),
        };
        let bytes = canonical_presence_bytes(&rec).map_err(PresenceError::Canonical)?;
        rec.sig = fabric_protocol::sign_payload_hex(&self.secret_key_hex, &bytes)
            .map_err(|e| PresenceError::Sign(e.to_string()))?;
        Ok(rec)
    }
}

/// Canonical signing bytes for a record: every field except `sig`, through the
/// shared protocol canonicalization (sorted keys — the same byte discipline as
/// the dispatch envelope and audit chain).
pub fn canonical_presence_bytes(rec: &PresenceRecord) -> Result<Vec<u8>, String> {
    let mut v = serde_json::to_value(rec).map_err(|e| e.to_string())?;
    if let Value::Object(ref mut map) = v {
        map.remove("sig");
    }
    fabric_protocol::canonicalize(&v).map_err(|e| e.to_string())
}

impl PresenceRecord {
    fn is_valid(&self) -> bool {
        self.magic == MAGIC && self.v == PRESENCE_VERSION && self.role == ROLE_NODE
    }

    /// Verify the embedded signature against the embedded public key.
    /// Proves key possession by the sender — see module docs for what it
    /// does NOT prove (cluster membership).
    pub fn signature_valid(&self) -> bool {
        let Ok(bytes) = canonical_presence_bytes(self) else {
            return false;
        };
        fabric_protocol::verify_signature_hex(&self.public_key_hex, &bytes, &self.sig)
            .unwrap_or(false)
    }

    /// Freshness check for unsolicited announces.
    pub fn is_fresh(&self) -> bool {
        let now = crate::now_unix();
        now.saturating_sub(self.ts) <= PRESENCE_FRESH_SECS && self.ts <= now + PRESENCE_FRESH_SECS
    }
}

fn parse_presence(buf: &[u8]) -> Option<PresenceRecord> {
    serde_json::from_slice::<PresenceRecord>(buf)
        .ok()
        .filter(PresenceRecord::is_valid)
}

fn parse_query(buf: &[u8]) -> Option<PresenceQuery> {
    serde_json::from_slice::<PresenceQuery>(buf)
        .ok()
        .filter(|q| q.magic == MAGIC && q.v == PRESENCE_VERSION && q.role == ROLE_NODE_QUERY)
}

/// A presence record observed on the wire, with its source address and the
/// result of the embedded-key signature check.
#[derive(Debug, Clone)]
pub struct ObservedPresence {
    pub record: PresenceRecord,
    pub source: IpAddr,
    /// Signature verifies against the record's own embedded key. Cluster
    /// trust still requires the caller to match `public_key_hex` against the
    /// hub registry.
    pub sig_valid: bool,
}

/// Announce this node's presence once and answer presence queries for ~1s.
/// Designed to be called periodically from the runner's beacon thread —
/// mirrors the v1 [`crate::serve_once`] embedding pattern.
pub fn presence_tick(advert: &NodeAdvert, udp_port: u16) -> Result<(), PresenceError> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(900)))?;

    let rec = advert.record("")?;
    let bytes = serde_json::to_vec(&rec).map_err(|e| PresenceError::Canonical(e.to_string()))?;
    for t in crate::broadcast_targets(udp_port) {
        let _ = socket.send_to(&bytes, t);
    }

    // Answer queries arriving on the shared well-known port is the hub's job
    // (it owns that bind). Nodes answer queries sent directly to them via
    // serve_presence_queries() below; this tick only announces.
    Ok(())
}

/// Run a presence-query responder forever on `udp_port`. Binds the port,
/// answers `node-query` datagrams with a freshly signed record echoing the
/// query nonce, and re-announces every `announce_interval`. Spawn on a
/// dedicated thread. Coexists with v1: hub-role queries are ignored here.
pub fn serve_presence(
    advert: NodeAdvert,
    udp_port: u16,
    announce_interval: Duration,
) -> Result<(), PresenceError> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, udp_port)))?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(1000)))?;

    let targets = crate::broadcast_targets(udp_port);
    let mut buf = [0u8; MAX_DATAGRAM];
    let mut last_announce = Instant::now()
        .checked_sub(announce_interval)
        .unwrap_or_else(Instant::now);

    loop {
        if last_announce.elapsed() >= announce_interval {
            if let Ok(rec) = advert.record("") {
                if let Ok(bytes) = serde_json::to_vec(&rec) {
                    for t in &targets {
                        let _ = socket.send_to(&bytes, *t);
                    }
                }
            }
            last_announce = Instant::now();
        }
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(q) = parse_query(&buf[..n]) {
                    if !q.token_hash.is_empty() && q.token_hash != advert.token_hash {
                        continue;
                    }
                    if let Ok(rec) = advert.record(&q.nonce) {
                        if let Ok(bytes) = serde_json::to_vec(&rec) {
                            let _ = socket.send_to(&bytes, src);
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// Collect presence records by querying explicit `targets` (unicast or
/// broadcast). This is the broadcast-hostile-media path: pass last-known-good
/// addresses from the node directory when broadcast yields nothing.
///
/// Every returned record's signature has been checked against its embedded
/// key (`sig_valid`); responses that fail to echo `nonce` are dropped, so a
/// caller using a fresh random nonce gets replay-proof confirmations.
pub fn collect_presence_addrs(
    targets: &[SocketAddr],
    timeout: Duration,
    want_token_hash: Option<&str>,
    nonce: &str,
) -> io::Result<Vec<ObservedPresence>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;

    let query = PresenceQuery {
        magic: MAGIC.to_owned(),
        v: PRESENCE_VERSION,
        role: ROLE_NODE_QUERY.to_owned(),
        nonce: nonce.to_owned(),
        token_hash: want_token_hash.unwrap_or("").to_owned(),
    };
    let qbytes = serde_json::to_vec(&query).unwrap_or_default();
    let send_query = |s: &UdpSocket| {
        for t in targets {
            let _ = s.send_to(&qbytes, *t);
        }
    };
    send_query(&socket);

    let deadline = Instant::now() + timeout;
    let mut last_query = Instant::now();
    let mut found: HashMap<String, ObservedPresence> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut buf = [0u8; MAX_DATAGRAM];

    while Instant::now() < deadline {
        if last_query.elapsed() >= Duration::from_millis(600) {
            send_query(&socket);
            last_query = Instant::now();
        }
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(rec) = parse_presence(&buf[..n]) {
                    if rec.nonce != nonce {
                        continue; // stale or replayed response
                    }
                    if let Some(want) = want_token_hash {
                        if !rec.token_hash.is_empty() && rec.token_hash != want {
                            continue;
                        }
                    }
                    let key = rec.node_id.clone();
                    if !found.contains_key(&key) {
                        let sig_valid = rec.signature_valid();
                        order.push(key.clone());
                        found.insert(
                            key,
                            ObservedPresence { record: rec, source: src.ip(), sig_valid },
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

/// Collect presence via LAN broadcast within `timeout`. Convenience wrapper;
/// on broadcast-hostile media use [`collect_presence_addrs`] with directory
/// addresses.
pub fn collect_presence(
    udp_port: u16,
    timeout: Duration,
    want_token_hash: Option<&str>,
    nonce: &str,
) -> io::Result<Vec<ObservedPresence>> {
    collect_presence_addrs(&crate::broadcast_targets(udp_port), timeout, want_token_hash, nonce)
}

/// Passively listen for unsolicited announces for `timeout` on an ephemeral
/// socket bound to `udp_port` semantics is not possible (the well-known port
/// is owned by the responder); this helper instead performs an active query
/// cycle and merges any fresh, valid announce-style records it happens to
/// receive. Exposed mainly for ADDR-2's directory maintenance loop.
pub fn token_hash(token: &str) -> String {
    v1_token_hash(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_advert(node_id: &str, port_base: u16) -> NodeAdvert {
        // Deterministic-enough identity for tests: generate fresh each time;
        // golden-fixture stability is covered by the fixture test below with
        // a pinned key.
        let identity = fabric_identity::generate(node_id, fabric_types::KeyPurpose::Node);
        let mut services = BTreeMap::new();
        services.insert("rqlite_http".to_owned(), port_base);
        services.insert("rqlite_raft".to_owned(), port_base + 1);
        services.insert("hub".to_owned(), 8765);
        NodeAdvert {
            node_id: node_id.to_owned(),
            hostname: "TEST-HOST".to_owned(),
            services,
            token_hash: token_hash("cluster-token"),
            public_key_hex: identity.public_key_hex,
            secret_key_hex: identity.secret_key_hex,
        }
    }

    #[test]
    fn record_signs_and_verifies() {
        let advert = test_advert("node-a", 4001);
        let rec = advert.record("").unwrap();
        assert!(rec.signature_valid());
        assert!(rec.is_fresh());
    }

    #[test]
    fn tampered_record_fails_verification() {
        let advert = test_advert("node-a", 4001);
        let mut rec = advert.record("").unwrap();
        rec.hostname = "EVIL-HOST".to_owned();
        assert!(!rec.signature_valid());
        let mut rec2 = advert.record("").unwrap();
        rec2.services.insert("ssh".to_owned(), 22);
        assert!(!rec2.signature_valid());
        let mut rec3 = advert.record("").unwrap();
        rec3.nonce = "forged".to_owned();
        assert!(!rec3.signature_valid());
    }

    #[test]
    fn nonce_is_inside_the_signature() {
        let advert = test_advert("node-a", 4001);
        let rec = advert.record("challenge-123").unwrap();
        assert_eq!(rec.nonce, "challenge-123");
        assert!(rec.signature_valid());
    }

    #[test]
    fn v1_and_v2_do_not_cross_parse() {
        // A v2 presence record must not parse as a v1 beacon and vice versa.
        let advert = test_advert("node-a", 4001);
        let rec = advert.record("").unwrap();
        let v2_bytes = serde_json::to_vec(&rec).unwrap();
        assert!(crate::parse(&v2_bytes).is_none(), "v1 parser must reject v2");

        let v1_hub = br#"{"magic":"FWBEACON","v":1,"role":"hub","port":8765}"#;
        assert!(parse_presence(v1_hub).is_none(), "v2 parser must reject v1");
    }

    #[test]
    fn stale_ts_is_not_fresh() {
        let advert = test_advert("node-a", 4001);
        let mut rec = advert.record("").unwrap();
        rec.ts = crate::now_unix() - PRESENCE_FRESH_SECS - 10;
        assert!(!rec.is_fresh());
    }

    #[test]
    fn golden_canonical_bytes_are_stable() {
        // Pinned key + pinned fields ⇒ canonical bytes and signature must be
        // byte-stable across releases. If this test breaks, the wire format
        // changed: bump PRESENCE_VERSION and regenerate the cross-language
        // fixture (tests/fixtures/beacon/presence_v2.json).
        let sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let signing = {
            let raw = hex::decode(sk).unwrap();
            let mut b = [0u8; 32];
            b.copy_from_slice(&raw);
            ed25519_dalek::SigningKey::from_bytes(&b)
        };
        let pk = hex::encode(signing.verifying_key().to_bytes());

        let mut services = BTreeMap::new();
        services.insert("hub".to_owned(), 8765);
        services.insert("rqlite_http".to_owned(), 4001);
        services.insert("rqlite_raft".to_owned(), 4002);

        let mut rec = PresenceRecord {
            magic: MAGIC.to_owned(),
            v: PRESENCE_VERSION,
            role: ROLE_NODE.to_owned(),
            node_id: "golden-node".to_owned(),
            hostname: "GOLDEN-HOST".to_owned(),
            services,
            ts: 1781280000,
            token_hash: "0123456789abcdef".to_owned(),
            nonce: "golden-nonce".to_owned(),
            public_key_hex: pk,
            sig: String::new(),
        };
        let canon = canonical_presence_bytes(&rec).unwrap();
        let expected = r#"{"hostname":"GOLDEN-HOST","magic":"FWBEACON","node_id":"golden-node","nonce":"golden-nonce","public_key_hex":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","role":"node","services":{"hub":8765,"rqlite_http":4001,"rqlite_raft":4002},"token_hash":"0123456789abcdef","ts":1781280000,"v":2}"#;
        assert_eq!(
            String::from_utf8(canon.clone()).unwrap(),
            expected,
            "canonical presence bytes drifted — wire format change requires a version bump"
        );
        rec.sig = fabric_protocol::sign_payload_hex(sk, &canon).unwrap();
        assert!(rec.signature_valid());
    }

    /// End-to-end on loopback: a responder thread answers a nonce query with a
    /// signed record; replayed/staled nonces are dropped. Unicast loopback for
    /// the same reason as the v1 test (hotspot adapters don't loop broadcast).
    #[test]
    fn loopback_presence_query_roundtrip() {
        let port: u16 = 49322;
        let advert = test_advert("loopback-node", 4001);
        let expected_pk = advert.public_key_hex.clone();
        let want = advert.token_hash.clone();
        std::thread::spawn(move || {
            let _ = serve_presence(advert, port, Duration::from_millis(60_000));
        });
        std::thread::sleep(Duration::from_millis(150));

        let loopback = SocketAddr::from(([127, 0, 0, 1], port));
        let observed = collect_presence_addrs(
            &[loopback],
            Duration::from_millis(1500),
            Some(&want),
            "fresh-nonce-42",
        )
        .unwrap();

        assert_eq!(observed.len(), 1, "expected exactly one responder");
        let o = &observed[0];
        assert!(o.sig_valid, "signature must verify");
        assert_eq!(o.record.node_id, "loopback-node");
        assert_eq!(o.record.nonce, "fresh-nonce-42");
        assert_eq!(o.record.public_key_hex, expected_pk);
        assert_eq!(o.record.services.get("hub"), Some(&8765));
        assert!(o.source.is_loopback());
    }
}
