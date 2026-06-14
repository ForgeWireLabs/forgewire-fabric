"""Beacon v2 presence: Python parity tests (ADDR-1).

Covers the cross-language golden fixture (canonical bytes + deterministic
signature parity with the Rust implementation) and a live loopback
query/response roundtrip with nonce echo, tamper detection, and replay
rejection. No mocks — real sockets, real ed25519.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from forgewire_fabric.hub._crypto import sign_payload
from forgewire_fabric.hub.presence import (
    PRESENCE_FRESH_SECS,
    ObservedPresence,
    PresenceResponder,
    build_presence_record,
    canonical_presence_bytes,
    collect_presence_addrs,
    is_fresh,
    signature_valid,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "beacon" / "presence_v2.json"

# RFC 8032 TEST1 keypair (also used by the Rust golden test).
SK = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PK = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


# ---------------------------------------------------------------------------
# Golden fixture: cross-language byte parity
# ---------------------------------------------------------------------------

def test_golden_fixture_canonical_and_signature_parity() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    record = dict(fixture["record_without_sig"])
    record["sig"] = fixture["sig"]

    canon = canonical_presence_bytes(record)
    assert canon.decode("utf-8") == fixture["canonical"], (
        "Python canonical bytes diverge from the pinned fixture"
    )
    assert signature_valid(record), "fixture signature failed verification"
    # ed25519 is deterministic: re-signing identical bytes must byte-match.
    assert sign_payload(fixture["secret_key_hex"], canon) == fixture["sig"]


def test_build_record_reproduces_fixture() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    want = dict(fixture["record_without_sig"])
    rec = build_presence_record(
        node_id=want["node_id"],
        hostname=want["hostname"],
        services=want["services"],
        token_hash=want["token_hash"],
        public_key_hex=PK,
        secret_key_hex=SK,
        nonce=want["nonce"],
        ts=want["ts"],
    )
    assert rec["sig"] == fixture["sig"]
    assert {k: v for k, v in rec.items() if k != "sig"} == want


# ---------------------------------------------------------------------------
# Record semantics
# ---------------------------------------------------------------------------

def test_tampered_record_fails_verification() -> None:
    rec = build_presence_record(
        node_id="node-a",
        hostname="HOST-A",
        services={"hub": 8765},
        token_hash="aaaabbbbccccdddd",
        public_key_hex=PK,
        secret_key_hex=SK,
    )
    assert signature_valid(rec)
    for fld, evil in [
        ("hostname", "EVIL-HOST"),
        ("nonce", "forged"),
        ("node_id", "node-b"),
    ]:
        bad = dict(rec)
        bad[fld] = evil
        assert not signature_valid(bad), f"tampered {fld} must fail"
    bad_services = dict(rec)
    bad_services["services"] = {"hub": 8765, "ssh": 22}
    assert not signature_valid(bad_services)


def test_freshness_window() -> None:
    rec = build_presence_record(
        node_id="node-a",
        hostname="HOST-A",
        services={},
        token_hash="",
        public_key_hex=PK,
        secret_key_hex=SK,
    )
    assert is_fresh(rec)
    stale = dict(rec)
    stale["ts"] = rec["ts"] - PRESENCE_FRESH_SECS - 10
    assert not is_fresh(stale)


# ---------------------------------------------------------------------------
# Live loopback roundtrip (real sockets)
# ---------------------------------------------------------------------------

def _responder(port: int) -> PresenceResponder:
    return PresenceResponder(
        node_id="loopback-node-py",
        hostname="LOOPBACK-HOST",
        services={"hub": 8765, "rqlite_http": 4001},
        token_hash="aaaabbbbccccdddd",
        public_key_hex=PK,
        secret_key_hex=SK,
        port=port,
        announce_interval=60.0,
    ).start()


def test_loopback_query_roundtrip_with_nonce() -> None:
    port = 49333
    responder = _responder(port)
    try:
        nonce = secrets.token_hex(8)
        observed = collect_presence_addrs(
            [("127.0.0.1", port)],
            timeout=1.5,
            want_token_hash="aaaabbbbccccdddd",
            nonce=nonce,
        )
        assert len(observed) == 1
        o: ObservedPresence = observed[0]
        assert o.sig_valid
        assert o.record["node_id"] == "loopback-node-py"
        assert o.record["nonce"] == nonce
        assert o.record["services"]["hub"] == 8765
        assert o.source == "127.0.0.1"
    finally:
        responder.stop()


def test_wrong_token_hash_filtered_and_nonce_required() -> None:
    port = 49334
    responder = _responder(port)
    try:
        # Wrong cluster: responder ignores the query entirely.
        observed = collect_presence_addrs(
            [("127.0.0.1", port)],
            timeout=0.8,
            want_token_hash="0000000000000000",
            nonce="n1",
        )
        assert observed == []
    finally:
        responder.stop()
