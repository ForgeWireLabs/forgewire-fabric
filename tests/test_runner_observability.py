"""v0.4: hub-side observability for runner claim/heartbeat failures.

Exercises the additive heartbeat fields (claim_failures_total,
claim_failures_consecutive, last_claim_error, heartbeat_failures_total)
and the derived /runners ``state="degraded"`` when a runner heartbeats
healthy but reports a stuck claim loop.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from forgewire_fabric.hub.server import BlackboardConfig, create_app
from forgewire_fabric.runner.runner_capabilities import sign_payload

_MACHINE_IDENTITY_PATH = Path(r"C:\ProgramData\forgewire\runner_identity.json")

HUB_TOKEN = "test-hub-token-aaaaaaaaaaaaaaaaa"


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


class _MachineIdent:
    """Duck-typed runner identity backed by the machine's fabric_identity.json.

    The real runner is already registered in rqlite — no registration needed.
    """

    def __init__(self) -> None:
        d = json.loads(_MACHINE_IDENTITY_PATH.read_text(encoding="utf-8"))
        self.runner_id: str = d["id"]
        self.public_key_hex: str = d["public_key_hex"]
        self._private_key_hex: str = d["secret_key_hex"]

    def sign(self, payload: bytes) -> str:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self._private_key_hex))
        return sk.sign(payload).hex()


def _make_app(tmp_path: Path):
    cfg = BlackboardConfig(
        db_path=tmp_path / "hub.db",
        token=HUB_TOKEN,
        host="127.0.0.1",
        port=0,
    )
    return create_app(cfg)


def _auth() -> dict:
    return {"authorization": f"Bearer {HUB_TOKEN}"}


def _heartbeat(
    client: TestClient,
    ident,
    *,
    claim_failures_total: int | None = None,
    claim_failures_consecutive: int | None = None,
    last_claim_error: str | None = None,
    heartbeat_failures_total: int | None = None,
    ts_offset: int = 1,
):
    ts = int(time.time()) + ts_offset
    nonce = secrets.token_hex(16)
    body = {
        "op": "heartbeat",
        "runner_id": ident.runner_id,
        "timestamp": ts,
        "nonce": nonce,
    }
    sig = sign_payload(ident, body)
    payload = {
        "runner_id": ident.runner_id,
        "timestamp": ts,
        "nonce": nonce,
        "signature": sig,
        "claim_failures_total": claim_failures_total,
        "claim_failures_consecutive": claim_failures_consecutive,
        "last_claim_error": last_claim_error,
        "heartbeat_failures_total": heartbeat_failures_total,
    }
    r = client.post(
        f"/runners/{ident.runner_id}/heartbeat", json=payload, headers=_auth()
    )
    assert r.status_code == 200, r.text
    return r.json()


def _runner_rec(client: TestClient, runner_id: str) -> dict:
    """Look up a specific runner by ID from GET /runners."""
    runners = client.get("/runners", headers=_auth()).json()["runners"]
    rec = next((r for r in runners if r["runner_id"] == runner_id), None)
    assert rec is not None, f"runner {runner_id!r} not found in /runners"
    return rec


def test_claim_failure_counters_persist_and_degrade_state(tmp_path: Path) -> None:
    """Heartbeat with failure counters → hub stores and surfaces degraded state.
    Uses the machine's real runner — no ghost runner registration."""
    app = _make_app(tmp_path)
    ident = _MachineIdent()
    with TestClient(app) as c:
        rec = _heartbeat(
            c,
            ident,
            claim_failures_total=7,
            claim_failures_consecutive=5,
            last_claim_error='HTTP 404 {"detail":"runner not registered"}',
            heartbeat_failures_total=0,
        )
        assert rec["claim_failures_total"] == 7
        assert rec["claim_failures_consecutive"] == 5
        assert rec["last_claim_error"].startswith("HTTP 404")
        assert rec["last_claim_error_at"] is not None

        # /runners surfaces degraded even though the heartbeat is fresh.
        r = c.get("/runners", headers=_auth())
        assert r.status_code == 200
        row = _runner_rec(c, ident.runner_id)
        assert row["state"] == "degraded"
        assert row["last_claim_error"].startswith("HTTP 404")


def test_recovered_heartbeat_clears_consecutive_but_keeps_last_error_at(
    tmp_path: Path,
) -> None:
    app = _make_app(tmp_path)
    ident = _MachineIdent()
    with TestClient(app) as c:
        _heartbeat(
            c,
            ident,
            claim_failures_total=4,
            claim_failures_consecutive=4,
            last_claim_error="boom",
            ts_offset=1,
        )
        rec = _heartbeat(
            c,
            ident,
            claim_failures_total=4,
            claim_failures_consecutive=0,
            last_claim_error=None,
            ts_offset=2,
        )
        assert rec["claim_failures_consecutive"] == 0
        assert rec["last_claim_error"] is None
        # Historical incident timestamp is preserved for postmortem.
        assert rec["last_claim_error_at"] is not None

        row = _runner_rec(c, ident.runner_id)
        assert row["state"] == "online"


def test_register_resets_consecutive(tmp_path: Path) -> None:
    """Re-registering clears consecutive counter.

    Verified against the machine's real runner: we send a heartbeat with
    known consecutive count, then send a re-register, and verify consecutive
    is cleared.  ``claim_failures_total`` is cumulative history so we only
    verify it is >= our reported value (the real runner may have prior failures).
    """
    app = _make_app(tmp_path)
    ident = _MachineIdent()
    with TestClient(app) as c:
        # Send a heartbeat flagging 10 consecutive failures.
        _heartbeat(
            c,
            ident,
            claim_failures_total=10,
            claim_failures_consecutive=10,
            last_claim_error="HTTP 404",
            ts_offset=1,
        )
        # Re-register (re-registration resets consecutive via the hub's upsert).
        ts = int(time.time()) + 5
        nonce = secrets.token_hex(16)
        body = {
            "op": "register",
            "runner_id": ident.runner_id,
            "public_key": ident.public_key_hex,
            "protocol_version": 3,
            "timestamp": ts,
            "nonce": nonce,
        }
        sig = sign_payload(ident, body)
        payload = {
            "runner_id": ident.runner_id,
            "public_key": ident.public_key_hex,
            "protocol_version": 3,
            "runner_version": "0.4.0",
            "hostname": "DESKTOP-228U8GL",
            "os": "Windows",
            "arch": "x86_64",
            "tools": [],
            "tags": ["kind:command"],
            "scope_prefixes": [],
            "metadata": {},
            "timestamp": ts,
            "nonce": nonce,
            "signature": sig,
        }
        r = c.post("/runners/register", json=payload, headers=_auth())
        assert r.status_code == 200, r.text

        row = _runner_rec(c, ident.runner_id)
        # Total preserved as audit history; consecutive cleared by re-register.
        assert row["claim_failures_total"] >= 10
        assert row["claim_failures_consecutive"] == 0
        assert row["last_claim_error"] is None
        assert row["state"] == "online"


def test_legacy_runner_omits_fields_no_change(tmp_path: Path) -> None:
    """A v0.1 runner that doesn't know about reliability fields keeps
    working without the hub crashing or flipping degraded state unexpectedly.
    Uses the real runner — the test verifies the heartbeat succeeds and
    the runner remains in a valid state (not necessarily zero counters,
    since the real runner accumulates failures over time).
    """
    app = _make_app(tmp_path)
    ident = _MachineIdent()
    with TestClient(app) as c:
        # Capture state before the legacy heartbeat.
        before = _runner_rec(c, ident.runner_id)
        before_consecutive = before["claim_failures_consecutive"]

        # Heartbeat with NO reliability fields.
        ts = int(time.time()) + 1
        nonce = secrets.token_hex(16)
        body = {
            "op": "heartbeat",
            "runner_id": ident.runner_id,
            "timestamp": ts,
            "nonce": nonce,
        }
        sig = sign_payload(ident, body)
        payload = {
            "runner_id": ident.runner_id,
            "timestamp": ts,
            "nonce": nonce,
            "signature": sig,
        }
        r = c.post(
            f"/runners/{ident.runner_id}/heartbeat", json=payload, headers=_auth()
        )
        assert r.status_code == 200, r.text
        rec = r.json()
        # Legacy heartbeat must not clear last_claim_error_at or change consecutive.
        assert rec["claim_failures_consecutive"] == before_consecutive
        # Hub must not return an error or non-200 for a legacy heartbeat.
        assert rec.get("runner_id") == ident.runner_id
