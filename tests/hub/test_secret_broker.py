"""M2.5.5a: sealed secret broker — HTTP integration tests (rqlite only).

SQLite-backed unit tests for SecretBroker internals were removed when SQLite
was retired (M2.7.3). The HTTP integration tests below cover the same surface
via the FastAPI layer against a real rqlite instance.

These tests require a live rqlite — see tests/hub/conftest.py.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forgewire_fabric.hub.secret_broker import (
    REDACTION_MARKER,
    EnvKeyProvider,
    FileKeyProvider,
    SecretBroker,
)
from forgewire_fabric.hub.server import BlackboardConfig, create_app
from forgewire_fabric.runner.identity import load_or_create
from forgewire_fabric.runner.runner_capabilities import sign_payload


HUB_TOKEN = "z" * 32
BEARER = {"Authorization": f"Bearer {HUB_TOKEN}"}


def _now_iso(offset: int = 0) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset))


def test_env_key_provider_validates_hex_length() -> None:
    import os
    p = EnvKeyProvider(env_var="FW_TEST_KEY")
    os.environ["FW_TEST_KEY"] = "ab" * 32  # 64 hex chars = 32 bytes
    try:
        assert len(p.load()) == 32
        os.environ["FW_TEST_KEY"] = "deadbeef"
        with pytest.raises(ValueError):
            p.load()
    finally:
        os.environ.pop("FW_TEST_KEY", None)

# ---------------------------------------------------------------- http


def _build_client() -> tuple[TestClient, Path]:
    tmp = Path(tempfile.mkdtemp(prefix="fw-sec-"))
    cfg = BlackboardConfig(
        db_path=tmp / "blackboard.db",
        token=HUB_TOKEN,
        host="127.0.0.1",
        port=0,
    )
    return TestClient(create_app(cfg)), tmp


def test_http_put_creates_then_rotates(tmp_path: Path) -> None:
    client, _ = _build_client()
    r = client.post(
        "/secrets",
        json={"name": "GITHUB_TOKEN", "value": "ghp_one"},
        headers=BEARER,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rotated"] is False
    assert body["secret"]["name"] == "GITHUB_TOKEN"
    assert body["secret"]["version"] == 1

    r = client.post(
        "/secrets",
        json={"name": "GITHUB_TOKEN", "value": "ghp_two"},
        headers=BEARER,
    )
    body = r.json()
    assert body["rotated"] is True
    assert body["secret"]["version"] == 2


def test_http_put_rejects_bad_name() -> None:
    client, _ = _build_client()
    # lowercase + dot — fails the pattern
    r = client.post(
        "/secrets",
        json={"name": "lower.bad", "value": "x"},
        headers=BEARER,
    )
    assert r.status_code == 422


def test_http_put_requires_auth() -> None:
    client, _ = _build_client()
    r = client.post("/secrets", json={"name": "X", "value": "y"})
    assert r.status_code in (401, 403)


def test_http_list_returns_metadata_only() -> None:
    client, _ = _build_client()
    client.post(
        "/secrets",
        json={"name": "API_KEY", "value": "do-not-leak"},
        headers=BEARER,
    )
    r = client.get("/secrets", headers=BEARER)
    assert r.status_code == 200
    payload = r.json()
    assert "secrets" in payload
    blob = json.dumps(payload).encode("utf-8")
    assert b"do-not-leak" not in blob


def test_http_delete_missing_is_404() -> None:
    client, _ = _build_client()
    r = client.delete("/secrets/NEVER", headers=BEARER)
    assert r.status_code == 404


def test_http_delete_happy_path() -> None:
    client, _ = _build_client()
    client.post(
        "/secrets",
        json={"name": "DOOMED", "value": "ttl-zero"},
        headers=BEARER,
    )
    r = client.delete("/secrets/DOOMED", headers=BEARER)
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    listing = client.get("/secrets", headers=BEARER).json()["secrets"]
    assert all(s["name"] != "DOOMED" for s in listing)


# ---------------------------------------------------------------- e2e


def _register(client: TestClient, ident) -> None:
    ts = int(time.time())
    nonce = _stdlib_secrets.token_hex(16)
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
        "runner_version": "0.11.0",
        "hostname": f"host-{ident.runner_id[:8]}",
        "os": "test-os",
        "arch": "x86_64",
        "tools": [],
        "tags": [],
        "scope_prefixes": [],
        "metadata": {},
        "capabilities": {},
        "timestamp": ts,
        "nonce": nonce,
        "signature": sig,
    }
    r = client.post("/runners/register", json=payload, headers=BEARER)
    assert r.status_code == 200, r.text


def _claim_v2(client: TestClient, ident) -> dict:
    ts = int(time.time())
    nonce = _stdlib_secrets.token_hex(16)
    body = {"op": "claim", "runner_id": ident.runner_id, "timestamp": ts, "nonce": nonce}
    sig = sign_payload(ident, body)
    payload = {
        "runner_id": ident.runner_id,
        "timestamp": ts,
        "nonce": nonce,
        "signature": sig,
        "scope_prefixes": [],
        "tools": [],
        "tags": [],
    }
    r = client.post("/tasks/claim-v2", json=payload, headers=BEARER)
    assert r.status_code == 200, r.text
    return r.json()


def test_e2e_dispatch_claim_injects_secrets_and_audits_names_only(
    tmp_path: Path,
) -> None:
    client, _ = _build_client()
    ident = load_or_create(tmp_path / "id.json")
    _register(client, ident)
    # Plant the secret.
    client.post(
        "/secrets",
        json={"name": "GITHUB_TOKEN", "value": "ghp_e2e_value"},
        headers=BEARER,
    )
    # Dispatch a task that declares secrets_needed.
    dispatch_body = {
        "title": "secret-claim",
        "prompt": "noop",
        "scope_globs": ["docs/x.md"],
        "base_commit": "a" * 40,
        "branch": "feature/secret-claim",
        "secrets_needed": ["GITHUB_TOKEN"],
    }
    task = client.post("/tasks", json=dispatch_body, headers=BEARER).json()

    claim = _claim_v2(client, ident)
    assert claim["task"] is not None
    assert claim["task"]["id"] == task["id"]
    # Secret value lands in the claim response and only there.
    assert claim["task"]["secrets"] == {"GITHUB_TOKEN": "ghp_e2e_value"}

    # Audit chain: dispatch records the names, claim records dispatched
    # names; nowhere does the value appear.
    audit = client.get(f"/audit/tasks/{task['id']}", headers=BEARER).json()
    assert audit["verified"] is True, audit["error"]
    kinds = [ev["kind"] for ev in audit["events"]]
    assert "dispatch" in kinds and "claim" in kinds
    dispatch_ev = next(ev for ev in audit["events"] if ev["kind"] == "dispatch")
    claim_ev = next(ev for ev in audit["events"] if ev["kind"] == "claim")
    assert dispatch_ev["payload"]["secrets_needed"] == ["GITHUB_TOKEN"]
    assert claim_ev["payload"]["secrets_dispatched"] == ["GITHUB_TOKEN"]
    assert b"ghp_e2e_value" not in json.dumps(audit).encode("utf-8")


def test_e2e_submit_result_redacts_secret_value(tmp_path: Path) -> None:
    client, _ = _build_client()
    ident = load_or_create(tmp_path / "id-redact.json")
    _register(client, ident)
    client.post(
        "/secrets",
        json={"name": "OPENAI_API_KEY", "value": "sk-leakvalue123"},
        headers=BEARER,
    )
    dispatch_body = {
        "title": "redact-me",
        "prompt": "noop",
        "scope_globs": ["docs/y.md"],
        "base_commit": "b" * 40,
        "branch": "feature/redact-me",
        "secrets_needed": ["OPENAI_API_KEY"],
    }
    task = client.post("/tasks", json=dispatch_body, headers=BEARER).json()
    _claim_v2(client, ident)

    # Runner submits a result whose log_tail + error contain the secret
    # value. The hub must redact both before persisting.
    result_body = {
        "worker_id": ident.runner_id,
        "status": "done",
        "log_tail": "boot ok. token=sk-leakvalue123 done.",
        "error": "trace: sk-leakvalue123 surfaced in error",
        "head_commit": "c" * 40,
        "commits": ["c" * 40],
        "files_touched": ["docs/y.md"],
    }
    r = client.post(f"/tasks/{task['id']}/result", json=result_body, headers=BEARER)
    assert r.status_code == 200, r.text
    persisted = r.json()
    log_tail = persisted["result"]["log_tail"]
    error = persisted["result"]["error"]
    assert "sk-leakvalue123" not in log_tail
    assert "sk-leakvalue123" not in error
    assert REDACTION_MARKER.format(name="OPENAI_API_KEY") in log_tail
    assert REDACTION_MARKER.format(name="OPENAI_API_KEY") in error


def test_e2e_progress_and_stream_redact_secret_value(tmp_path: Path) -> None:
    client, _ = _build_client()
    ident = load_or_create(tmp_path / "id-progress.json")
    _register(client, ident)
    client.post(
        "/secrets",
        json={"name": "DB_PASS", "value": "pa55w0rd-leak"},
        headers=BEARER,
    )
    dispatch_body = {
        "title": "redact-stream",
        "prompt": "noop",
        "scope_globs": ["docs/z.md"],
        "base_commit": "d" * 40,
        "branch": "feature/redact-stream",
        "secrets_needed": ["DB_PASS"],
    }
    task = client.post("/tasks", json=dispatch_body, headers=BEARER).json()
    _claim_v2(client, ident)

    # Progress
    pr = client.post(
        f"/tasks/{task['id']}/progress",
        json={
            "worker_id": ident.runner_id,
            "message": "step 1 used pa55w0rd-leak",
        },
        headers=BEARER,
    )
    assert pr.status_code == 200, pr.text

    # Stream single
    sr = client.post(
        f"/tasks/{task['id']}/stream",
        json={
            "worker_id": ident.runner_id,
            "channel": "stdout",
            "line": "connect with pa55w0rd-leak",
        },
        headers=BEARER,
    )
    assert sr.status_code == 200, sr.text

    # Stream bulk
    br = client.post(
        f"/tasks/{task['id']}/stream/bulk",
        json={
            "worker_id": ident.runner_id,
            "entries": [
                {"channel": "stderr", "line": "leak1 pa55w0rd-leak"},
                {"channel": "stdout", "line": "leak2 pa55w0rd-leak"},
            ],
        },
        headers=BEARER,
    )
    assert br.status_code == 200, br.text

    # Pull progress + stream back and confirm redaction.
    fetched = client.get(f"/tasks/{task['id']}", headers=BEARER).json()
    progress_blob = json.dumps(fetched.get("progress") or []).encode("utf-8")
    assert b"pa55w0rd-leak" not in progress_blob

    stream = client.get(
        f"/tasks/{task['id']}/stream", headers=BEARER
    ).json()
    stream_blob = json.dumps(stream).encode("utf-8")
    assert b"pa55w0rd-leak" not in stream_blob
    assert REDACTION_MARKER.format(name="DB_PASS").encode("utf-8") in stream_blob
