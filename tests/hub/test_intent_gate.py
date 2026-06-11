"""Tests for the M2.5.1 intent gate (POST /tasks/{task_id}/intent).

The runner calls this endpoint before performing a gated action. The hub
evaluates the intent against the policy engine and returns:
  200  — allowed
  400  — unknown intent kind
  403  — denied (structured PolicyDecision)
  428  — require_approval (returns approval_id; caller must re-POST after approval)
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from forgewire_fabric.hub.server import BlackboardConfig, create_app


HUB_TOKEN = "x" * 32
BEARER = {"Authorization": f"Bearer {HUB_TOKEN}"}


def _make_client(policy: dict) -> tuple[TestClient, int]:
    tmp = Path(tempfile.mkdtemp(prefix="fw-intent-"))
    policy_path = tmp / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    cfg = BlackboardConfig(
        db_path=tmp / "blackboard.db",
        token=HUB_TOKEN,
        host="127.0.0.1",
        port=0,
        policy_path=policy_path,
    )
    client = TestClient(create_app(cfg), raise_server_exceptions=False)
    task = client.post(
        "/tasks",
        json={
            "title": "intent-test",
            "prompt": "p",
            "base_commit": "a" * 40,
            "scope_globs": ["src/**"],
            "branch": "feature/x",
            "kind": "agent",
        },
        headers=BEARER,
    )
    assert task.status_code == 200, task.text
    return client, task.json()["id"]


# ---------------------------------------------------------------------------
# 200 — allowed by default policy (no restrictions)
# ---------------------------------------------------------------------------

def test_intent_allowed_by_default() -> None:
    client, task_id = _make_client({})
    resp = client.post(
        f"/tasks/{task_id}/intent",
        json={"worker_id": "runner-1", "kind": "fs_write", "paths": ["src/foo.py"]},
        headers=BEARER,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allowed"] is True
    assert body["kind"] == "fs_write"


# ---------------------------------------------------------------------------
# 400 — unknown intent kind
# ---------------------------------------------------------------------------

def test_intent_unknown_kind() -> None:
    client, task_id = _make_client({})
    resp = client.post(
        f"/tasks/{task_id}/intent",
        json={"worker_id": "runner-1", "kind": "not_a_real_kind"},
        headers=BEARER,
    )
    assert resp.status_code == 400
    assert "unknown intent kind" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 428 — require_approval for network_egress
# ---------------------------------------------------------------------------

def test_intent_require_approval_network_egress() -> None:
    client, task_id = _make_client({"require_approval": ["network_egress"]})
    resp = client.post(
        f"/tasks/{task_id}/intent",
        json={"worker_id": "runner-1", "kind": "network_egress", "hosts": ["api.openai.com"]},
        headers=BEARER,
    )
    assert resp.status_code == 428
    detail = resp.json()["detail"]
    assert "approval_id" in detail
    assert "envelope_hash" in detail
    assert "hint" in detail


# ---------------------------------------------------------------------------
# 428 → approve → 200 round-trip
# ---------------------------------------------------------------------------

def test_intent_approve_and_retry() -> None:
    client, task_id = _make_client({"require_approval": ["network_egress"]})
    intent_body = {"worker_id": "runner-1", "kind": "network_egress", "hosts": ["api.openai.com"]}

    # First call creates the pending approval
    resp1 = client.post(f"/tasks/{task_id}/intent", json=intent_body, headers=BEARER)
    assert resp1.status_code == 428
    approval_id = resp1.json()["detail"]["approval_id"]

    # Operator approves
    approve = client.post(
        f"/approvals/{approval_id}/approve",
        json={"approver": "operator", "reason": "ok"},
        headers=BEARER,
    )
    assert approve.status_code == 200

    # Runner re-POSTs with approval_id
    resp2 = client.post(
        f"/tasks/{task_id}/intent",
        json={**intent_body, "approval_id": approval_id},
        headers=BEARER,
    )
    assert resp2.status_code == 200
    assert resp2.json()["allowed"] is True


# ---------------------------------------------------------------------------
# 403 — denied (egress to host outside allowlist)
# ---------------------------------------------------------------------------

def test_intent_denied_egress_outside_allowlist() -> None:
    client, task_id = _make_client({"egress_allowlist": ["pypi.org", "github.com"]})
    resp = client.post(
        f"/tasks/{task_id}/intent",
        json={"worker_id": "runner-1", "kind": "network_egress", "hosts": ["evil.example.com"]},
        headers=BEARER,
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail.get("decision") == "deny"
