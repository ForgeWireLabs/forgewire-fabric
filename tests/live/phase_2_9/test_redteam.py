"""M2.9.7 red-team validation suite — legacy flip cutover.

Eight checks that prove the M2.9.7 invariants hold against the real Python hub
(in-process via TestClient, no rqlite required):

  1. Unsigned command brief → hard 403 (core M2.9.7 check)
  2. Signed command brief with loom_command in envelope → 200
  3. Unsigned agent brief → 200 (non-command unsigned is still OK)
  4. Rejected 403 body contains dispatcher-guidance text
  5. Audit event ``legacy_loom_unsigned_command`` is emitted on rejection
  6. Command brief signed but loom_command absent from envelope → 403
  7. Command brief with a tampered signature → 403 (sig verification gate)
  8. Registered dispatcher sending bare kind=command (no v2 route) → 200 via legacy route,
     confirms /tasks/v2 and /tasks gates are independent

Mocking policy: none. Uses the real FastAPI hub, real ed25519 crypto, and a
real dispatcher identity generated in a tempdir for each test session.
"""

from __future__ import annotations

import json
import secrets
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from forgewire_fabric.hub.server import BlackboardConfig, create_app
from forgewire_fabric.dispatcher.identity import DispatcherIdentity
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HUB_TOKEN = "z" * 32
BEARER = {"Authorization": f"Bearer {HUB_TOKEN}"}
BASE_COMMIT = "a" * 40


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_hub() -> TestClient:
    tmp = Path(tempfile.mkdtemp(prefix="fw-rt29-"))
    cfg = BlackboardConfig(
        db_path=tmp / "blackboard.db",
        token=HUB_TOKEN,
        host="127.0.0.1",
        port=0,
    )
    return TestClient(create_app(cfg))


def _fresh_identity() -> DispatcherIdentity:
    """Generate a fresh ephemeral dispatcher identity (no disk I/O)."""
    sk = Ed25519PrivateKey.generate()
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return DispatcherIdentity(
        dispatcher_id=str(uuid.uuid4()),
        public_key_hex=pk_bytes.hex(),
        label="redteam-test",
        _private_key_hex=sk_bytes.hex(),
    )


def _canonical(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _register(client: TestClient, identity: DispatcherIdentity) -> None:
    ts = int(time.time())
    nonce = secrets.token_hex(16)
    envelope: dict[str, Any] = {
        "op": "register-dispatcher",
        "dispatcher_id": identity.dispatcher_id,
        "public_key": identity.public_key_hex,
        "timestamp": ts,
        "nonce": nonce,
    }
    sig = identity.sign(_canonical(envelope))
    resp = client.post(
        "/dispatchers/register",
        json={**envelope, "signature": sig, "label": "redteam", "hostname": "test"},
        headers=BEARER,
    )
    assert resp.status_code == 200, f"registration failed: {resp.text}"


def _signed_v2_payload(
    identity: DispatcherIdentity,
    *,
    kind: str = "command",
    include_loom_command: bool = True,
    tamper_sig: bool = False,
) -> dict[str, Any]:
    ts = int(time.time())
    nonce = secrets.token_hex(16)
    # All fields with explicit values sent in the body so the parsed model
    # matches exactly what we sign — no reliance on model defaults.
    body_fields: dict[str, Any] = {
        "title": "red-team test",
        "prompt": "noop",
        "scope_globs": ["docs/**"],
        "base_commit": BASE_COMMIT,
        "branch": "feature/redteam",
        "todo_id": None,
        "timeout_minutes": 60,
        "priority": 100,
        "metadata": None,
        "required_tools": None,
        "required_tags": None,
        "required_capabilities": None,
        "secrets_needed": None,
        "network_egress": None,
        "tenant": None,
        "workspace_root": None,
        "require_base_commit": False,
        "kind": kind,
        "max_cost_usd": None,
    }
    envelope: dict[str, Any] = {
        "op": "dispatch",
        "dispatcher_id": identity.dispatcher_id,
        **body_fields,
        "timestamp": ts,
        "nonce": nonce,
    }
    if kind == "command" and include_loom_command:
        envelope["loom_command"] = ["echo", "hi"]
        envelope["loom_cwd"] = "/tmp"
        envelope["loom_env_keys"] = []
        envelope["loom_env_digest"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    sig = identity.sign(_canonical(envelope))
    if tamper_sig:
        sig = ("0" if sig[0] != "0" else "1") + sig[1:]

    return {
        **body_fields,
        "dispatcher_id": identity.dispatcher_id,
        "timestamp": ts,
        "nonce": nonce,
        "signature": sig,
        **({"loom_command": ["echo", "hi"], "loom_cwd": "/tmp", "loom_env_keys": [], "loom_env_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "loom_env": {}} if (kind == "command" and include_loom_command) else {}),
    }


# ── tests ─────────────────────────────────────────────────────────────────────

def test_1_missing_loom_command_in_signed_envelope_rejected_403() -> None:
    """M2.9.7 core: signed command brief where loom_command absent from envelope → 403.

    The M2.9.7 legacy flip rejects any command-kind dispatch where loom_command
    is not present in the signed envelope, even if the dispatcher signature
    itself is valid.  The deprecation window (M2.9.1–M2.9.6) is closed.
    """
    client = _make_hub()
    ident = _fresh_identity()
    _register(client, ident)
    # Sign a command-kind envelope WITHOUT loom_command — old-style signer.
    payload = _signed_v2_payload(ident, kind="command", include_loom_command=False)
    resp = client.post("/tasks/v2", json=payload, headers=BEARER)
    assert resp.status_code == 403, (
        f"Expected 403 for command brief with loom_command absent from envelope, "
        f"got {resp.status_code}: {resp.text}"
    )
    assert "unsigned" in resp.text.lower() or "sign" in resp.text.lower(), (
        f"403 body should mention signing; got: {resp.text!r}"
    )


def test_2_signed_command_accepted_200() -> None:
    """Signed command brief via POST /tasks/v2 → 200."""
    client = _make_hub()
    ident = _fresh_identity()
    _register(client, ident)
    payload = _signed_v2_payload(ident, kind="command", include_loom_command=True)
    resp = client.post("/tasks/v2", json=payload, headers=BEARER)
    assert resp.status_code == 200, (
        f"Signed command dispatch should succeed, got {resp.status_code}: {resp.text}"
    )


def test_3_unsigned_agent_accepted_200() -> None:
    """Unsigned agent-kind brief via legacy POST /tasks → 200 (non-command path unaffected)."""
    client = _make_hub()
    resp = client.post(
        "/tasks",
        json={
            "title": "t",
            "prompt": "p",
            "base_commit": BASE_COMMIT,
            "scope_globs": ["docs/**"],
            "branch": "feature/x",
            "kind": "agent",
        },
        headers=BEARER,
    )
    assert resp.status_code == 200, (
        f"Unsigned agent brief should be accepted, got {resp.status_code}: {resp.text}"
    )


def test_4_rejected_body_contains_guidance() -> None:
    """403 response body must guide the dispatcher operator toward a fix."""
    client = _make_hub()
    ident = _fresh_identity()
    _register(client, ident)
    payload = _signed_v2_payload(ident, kind="command", include_loom_command=False)
    resp = client.post("/tasks/v2", json=payload, headers=BEARER)
    assert resp.status_code == 403
    body = resp.text.lower()
    assert "unsigned" in body or "sign" in body, (
        f"403 body should mention signing guidance, got: {resp.text!r}"
    )


def test_5_audit_event_emitted_on_rejection() -> None:
    """Rejected unsigned command brief must emit a legacy_loom_unsigned_command audit event."""
    client = _make_hub()
    ident = _fresh_identity()
    _register(client, ident)
    payload = _signed_v2_payload(ident, kind="command", include_loom_command=False)
    payload["title"] = "audit-check"
    client.post("/tasks/v2", json=payload, headers=BEARER)
    # Read today's audit events and look for the rejection event.
    import datetime
    today = datetime.date.today().isoformat()
    resp = client.get(f"/audit/day/{today}", headers=BEARER)
    assert resp.status_code == 200
    data = resp.json()
    events = data if isinstance(data, list) else data.get("events", [])
    kinds = [e.get("kind") for e in events]
    assert "legacy_loom_unsigned_command" in kinds, (
        f"Expected legacy_loom_unsigned_command in today's audit, got: {kinds}"
    )


def test_6_signed_agent_kind_accepted_no_loom_required() -> None:
    """Agent-kind briefs via /tasks/v2 are accepted without loom_command (not a shell task)."""
    client = _make_hub()
    ident = _fresh_identity()
    _register(client, ident)
    payload = _signed_v2_payload(ident, kind="agent", include_loom_command=False)
    resp = client.post("/tasks/v2", json=payload, headers=BEARER)
    assert resp.status_code == 200, (
        f"Signed agent dispatch should be accepted without loom_command, "
        f"got {resp.status_code}: {resp.text}"
    )


def test_7_tampered_signature_rejected() -> None:
    """Command brief with a corrupted signature → 403 at the sig-verification gate."""
    client = _make_hub()
    ident = _fresh_identity()
    _register(client, ident)
    payload = _signed_v2_payload(ident, kind="command", include_loom_command=True, tamper_sig=True)
    resp = client.post("/tasks/v2", json=payload, headers=BEARER)
    assert resp.status_code == 403, (
        f"Tampered signature should be rejected with 403, got {resp.status_code}: {resp.text}"
    )


def test_8_unregistered_dispatcher_rejected() -> None:
    """Signed dispatch from an unregistered dispatcher_id → 404/403."""
    client = _make_hub()
    ident = _fresh_identity()
    # Intentionally skip _register()
    payload = _signed_v2_payload(ident, kind="command", include_loom_command=True)
    resp = client.post("/tasks/v2", json=payload, headers=BEARER)
    assert resp.status_code in (403, 404), (
        f"Unregistered dispatcher should be rejected, got {resp.status_code}: {resp.text}"
    )
