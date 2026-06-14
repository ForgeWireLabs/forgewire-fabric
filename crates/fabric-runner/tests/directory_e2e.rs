//! ADDR-2 end-to-end: a live signed presence responder → active query →
//! verified merge → managed-hosts reconcile, through real sockets and a real
//! (temp) hosts file. The unicast-target path is exercised explicitly because
//! the reference adversarial network (a phone hotspot) eats broadcast.

use std::net::SocketAddr;
use std::time::Duration;

use fabric_beacon::{collect_presence_addrs, serve_presence, token_hash, NodeAdvert};
use fabric_runner::directory::{reconcile_hosts_file, NodeDirectory};

fn advert(node_id: &str, hostname: &str) -> NodeAdvert {
    let id = fabric_identity::generate(node_id, fabric_types::KeyPurpose::Node);
    let mut services = std::collections::BTreeMap::new();
    services.insert("rqlite_http".to_owned(), 4001u16);
    services.insert("rqlite_raft".to_owned(), 4002u16);
    NodeAdvert {
        node_id: node_id.to_owned(),
        hostname: hostname.to_owned(),
        services,
        token_hash: token_hash("e2e-cluster-token"),
        public_key_hex: id.public_key_hex,
        secret_key_hex: id.secret_key_hex,
    }
}

#[test]
fn presence_to_managed_hosts_block_end_to_end() {
    let port: u16 = 49340;
    let peer = advert("e2e-peer", "E2E-PEER");
    std::thread::spawn(move || {
        let _ = serve_presence(peer, port, Duration::from_secs(3600));
    });
    std::thread::sleep(Duration::from_millis(150));

    // Active query via the unicast path (hotspot-safe), fresh nonce.
    let target = SocketAddr::from(([127, 0, 0, 1], port));
    let observed = collect_presence_addrs(
        &[target],
        Duration::from_millis(1500),
        Some(&token_hash("e2e-cluster-token")),
        "e2e-nonce-1",
    )
    .expect("collect failed");
    assert_eq!(observed.len(), 1, "expected the live responder");
    assert!(observed[0].sig_valid, "signature must verify");

    // Merge into a directory (we are a different node than the responder).
    let mut dir = NodeDirectory::default();
    let changed = dir.merge(&observed, "e2e-self");
    assert_eq!(changed, vec!["E2E-PEER"]);
    let entry = &dir.entries["E2E-PEER"];
    assert_eq!(entry.node_id, "e2e-peer");
    assert!(entry.ip == "127.0.0.1", "IP comes from the datagram source");

    // Reconcile a real (temp) hosts file with pre-existing foreign content.
    let tmp = std::env::temp_dir().join(format!(
        "fw_e2e_hosts_{}.txt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&tmp, "127.0.0.1 localhost\n203.0.113.7 someprinter\n").unwrap();

    let changed = reconcile_hosts_file(&tmp, &dir).unwrap();
    assert!(changed, "hosts file should be updated");

    let content = std::fs::read_to_string(&tmp).unwrap();
    assert!(content.contains("127.0.0.1 localhost"), "foreign line preserved");
    assert!(content.contains("203.0.113.7 someprinter"), "foreign line preserved");
    assert!(
        content.contains("127.0.0.1 E2E-PEER E2E-PEER.local"),
        "managed entry present with .local alias:\n{content}"
    );

    // Idempotent: a second reconcile with the same directory is a no-op.
    assert!(!reconcile_hosts_file(&tmp, &dir).unwrap());

    let _ = std::fs::remove_file(&tmp);
}
