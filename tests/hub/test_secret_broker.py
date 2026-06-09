"""M2.5.5a: sealed secret broker tests.

Tests NEVER register runners or dispatchers in rqlite.  The cluster has
exactly two real machines; no test may add to that count.

Layers:
* Key provider unit tests (no rqlite).
* HTTP CRUD via the hub API (PUT, GET, DELETE).
* Blackboard-level put/resolve round-trip (verifies encryption works).
* Redaction via blackboard.redact_text() (no runner needed).
* Audit: dispatching a task with secrets_needed records names, not values.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forgewire_fabric.hub.secret_broker import (
    REDACTION_MARKER,
    EnvKeyProvider,
)
from forgewire_fabric.hub.server import BlackboardConfig, create_app


HUB_TOKEN = "z" * 32
BEARER = {"Authorization": f"Bearer {HUB_TOKEN}"}


def _build_client() -> tuple[TestClient, Path]:
    tmp = Path(tempfile.mkdtemp(prefix="fw-sec-"))
    cfg = BlackboardConfig(
        db_path=tmp / "blackboard.db",
        token=HUB_TOKEN,
        host="127.0.0.1",
        port=0,
        # These broker tests exercise the bearer-gated legacy dispatch path
        # only to verify audit redaction; signed dispatch is covered elsewhere.
        require_signed_dispatch=False,
    )
    return TestClient(create_app(cfg)), tmp


# ---------------------------------------------------------------- key provider unit tests


def test_env_key_provider_validates_hex_length() -> None:
    p = EnvKeyProvider(env_var="FW_TEST_KEY")
    os.environ["FW_TEST_KEY"] = "ab" * 32  # 64 hex chars = 32 bytes
    try:
        assert len(p.load()) == 32
        os.environ["FW_TEST_KEY"] = "deadbeef"
        with pytest.raises(ValueError):
            p.load()
    finally:
        os.environ.pop("FW_TEST_KEY", None)


# ---------------------------------------------------------------- HTTP CRUD


def test_http_put_creates_then_rotates() -> None:
    client, _ = _build_client()
    name = f"GITHUB_TOKEN_{uuid.uuid4().hex[:8].upper()}"
    r = client.post("/secrets", json={"name": name, "value": "ghp_one"}, headers=BEARER)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rotated"] is False
    assert body["secret"]["name"] == name
    v1 = body["secret"]["version"]

    r = client.post("/secrets", json={"name": name, "value": "ghp_two"}, headers=BEARER)
    body = r.json()
    assert body["rotated"] is True
    assert body["secret"]["version"] == v1 + 1


def test_http_put_rejects_bad_name() -> None:
    client, _ = _build_client()
    r = client.post("/secrets", json={"name": "lower.bad", "value": "x"}, headers=BEARER)
    assert r.status_code == 422


def test_http_put_requires_auth() -> None:
    client, _ = _build_client()
    r = client.post("/secrets", json={"name": "X", "value": "y"})
    assert r.status_code in (401, 403)


def test_http_list_returns_metadata_only() -> None:
    client, _ = _build_client()
    name = f"API_KEY_{uuid.uuid4().hex[:8].upper()}"
    client.post("/secrets", json={"name": name, "value": "do-not-leak"}, headers=BEARER)
    r = client.get("/secrets", headers=BEARER)
    assert r.status_code == 200
    payload = r.json()
    assert "secrets" in payload
    assert b"do-not-leak" not in json.dumps(payload).encode("utf-8")


def test_http_delete_missing_is_404() -> None:
    client, _ = _build_client()
    r = client.delete("/secrets/NEVER", headers=BEARER)
    assert r.status_code == 404


def test_http_delete_happy_path() -> None:
    client, _ = _build_client()
    name = f"DOOMED_{uuid.uuid4().hex[:8].upper()}"
    client.post("/secrets", json={"name": name, "value": "ttl-zero"}, headers=BEARER)
    r = client.delete(f"/secrets/{name}", headers=BEARER)
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    listing = client.get("/secrets", headers=BEARER).json()["secrets"]
    assert all(s["name"] != name for s in listing)


# ---------------------------------------------------------------- blackboard put/resolve/redact
#
# These tests cover the same behaviour as the old e2e runner-claim tests
# but at the blackboard level — no runner registration required.


def test_put_and_resolve_round_trip() -> None:
    """Secret stored via HTTP can be resolved by name through the blackboard."""
    client, _ = _build_client()
    bb = client.app.state.blackboard
    name = f"ROUND_TRIP_{uuid.uuid4().hex[:8].upper()}"
    secret_value = f"sk-{uuid.uuid4().hex}"

    client.post("/secrets", json={"name": name, "value": secret_value}, headers=BEARER)
    resolved = bb.resolve_secrets([name])
    assert resolved.get(name) == secret_value


def test_resolve_missing_secret_returns_empty() -> None:
    client, _ = _build_client()
    bb = client.app.state.blackboard
    resolved = bb.resolve_secrets(["DOES_NOT_EXIST_XYZ"])
    assert "DOES_NOT_EXIST_XYZ" not in resolved


def test_redact_text_replaces_secret_value() -> None:
    """redact_text() removes the plaintext secret value from a log string."""
    client, _ = _build_client()
    bb = client.app.state.blackboard
    name = f"REDACT_{uuid.uuid4().hex[:8].upper()}"
    secret_value = f"sk-{uuid.uuid4().hex}"

    client.post("/secrets", json={"name": name, "value": secret_value}, headers=BEARER)

    dirty = f"connecting with token={secret_value} done."
    clean = bb.redact_text(dirty)

    assert secret_value not in clean
    assert REDACTION_MARKER.format(name=name) in clean


def test_redact_returns_unchanged_text_when_no_secrets() -> None:
    client, _ = _build_client()
    bb = client.app.state.blackboard
    text = "no secrets here, just plain text"
    assert bb.redact_text(text) == text


# ---------------------------------------------------------------- audit: names not values


def test_secrets_names_not_values_in_dispatch_audit() -> None:
    """Dispatching a task with secrets_needed records names, not values, in audit."""
    client, _ = _build_client()
    name = f"AUDIT_SEC_{uuid.uuid4().hex[:8].upper()}"
    secret_value = f"sk-{uuid.uuid4().hex}"

    client.post("/secrets", json={"name": name, "value": secret_value}, headers=BEARER)

    task = client.post("/tasks", json={
        "title": "sec-audit",
        "prompt": "noop",
        "scope_globs": ["docs/x.md"],
        "base_commit": "a" * 40,
        "branch": "feature/sec-audit",
        "secrets_needed": [name],
    }, headers=BEARER).json()

    audit = client.get(f"/audit/tasks/{task['id']}", headers=BEARER).json()
    audit_text = json.dumps(audit)

    # The plaintext secret value must never appear in any audit payload.
    assert secret_value not in audit_text, "secret value leaked into audit"

    # The secret name (not value) appears in the dispatch event.
    dispatch_ev = next((e for e in audit["events"] if e["kind"] == "dispatch"), None)
    assert dispatch_ev is not None
    assert name in json.dumps(dispatch_ev["payload"])
