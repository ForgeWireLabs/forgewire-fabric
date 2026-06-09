"""Runner-kind tagging.

`apply_kind_tag` is the choke point that pins a runner's task-kind
affinity into its register/claim tags. The shell-exec runner must
advertise ``kind:command``; the Copilot-Chat MCP runner must advertise
``kind:agent``. The hub uses that tag (and only that tag) to keep the
two queues disjoint.

These tests pin:
1. The helper itself (default, env override, idempotency, validation).
2. The end-to-end consequence: a runner that registers + claims with
   ``kind:command`` only ever gets ``kind='command'`` tasks, and vice
   versa.
"""

from __future__ import annotations

import json
import secrets
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from forgewire_fabric.hub.server import BlackboardConfig, create_app
from forgewire_fabric.runner.runner_capabilities import (
    apply_kind_tag,
    sign_payload,
)

_MACHINE_IDENTITY_PATH = Path(r"C:\ProgramData\forgewire\runner_identity.json")

HUB_TOKEN = "k" * 32
BEARER = {"authorization": f"Bearer {HUB_TOKEN}"}


class _MachineIdent:
    """Duck-typed runner identity backed by the machine's fabric_identity.json."""

    def __init__(self) -> None:
        d = json.loads(_MACHINE_IDENTITY_PATH.read_text(encoding="utf-8"))
        self.runner_id: str = d["id"]
        self.public_key_hex: str = d["public_key_hex"]
        self._private_key_hex: str = d["secret_key_hex"]

    def sign(self, payload: bytes) -> str:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self._private_key_hex))
        return sk.sign(payload).hex()


# ---------------------------------------------------------------- helper unit


def test_apply_kind_tag_appends_default_when_missing() -> None:
    assert apply_kind_tag(["gpu:cuda"], default_kind="command") == [
        "gpu:cuda",
        "kind:command",
    ]


def test_apply_kind_tag_overrides_operator_supplied_kind() -> None:
    """The runner's kind is the binary, not the config: any operator-
    supplied ``kind:*`` tag in the sidecar/env must be stripped and
    replaced by the binary's hard default."""
    out = apply_kind_tag(["kind:agent", "rust"], default_kind="command")
    assert "kind:agent" not in out
    assert out == ["rust", "kind:command"]


def test_apply_kind_tag_strips_equals_form_too() -> None:
    out = apply_kind_tag(["KIND=Command", "gpu"], default_kind="agent")
    assert out == ["gpu", "kind:agent"]


def test_apply_kind_tag_rejects_invalid_default() -> None:
    with pytest.raises(ValueError):
        apply_kind_tag([], default_kind="banana")


def test_apply_kind_tag_idempotent() -> None:
    once = apply_kind_tag(["x"], default_kind="command")
    twice = apply_kind_tag(once, default_kind="command")
    assert once == twice


# ---------------------------------------------------------------- e2e routing


def _build_client() -> TestClient:
    tmp = Path(tempfile.mkdtemp(prefix="fw-runnerkind-"))
    cfg = BlackboardConfig(
        db_path=tmp / "blackboard.db",
        token=HUB_TOKEN,
        host="127.0.0.1",
        port=0,
    )
    return TestClient(create_app(cfg))


def _claim_v2(client: TestClient, ident, *, tags: list[str]) -> tuple[int, dict]:
    ts = int(time.time())
    nonce = secrets.token_hex(16)
    signed = {"op": "claim", "runner_id": ident.runner_id, "timestamp": ts, "nonce": nonce}
    sig = sign_payload(ident, signed)
    payload = {
        "runner_id": ident.runner_id,
        "timestamp": ts,
        "nonce": nonce,
        "signature": sig,
        "scope_prefixes": [],
        "tools": [],
        "tags": tags,
    }
    r = client.post("/tasks/claim-v2", json=payload, headers=BEARER)
    return r.status_code, r.json()


def _dispatch(client: TestClient, *, title: str, kind: str) -> dict:
    body = {
        "title": title,
        "prompt": "noop",
        "scope_globs": ["docs/x.md"],
        "base_commit": "a" * 40,
        "branch": f"feature/{title}",
        "kind": kind,
    }
    r = client.post("/tasks", json=body, headers=BEARER)
    assert r.status_code == 200, r.text
    return r.json()


def test_command_runner_only_claims_command_tasks() -> None:
    """A runner tagged ``kind:command`` must not be handed an agent task,
    and must successfully claim its own. Uses the machine's real runner
    identity — no ghost runner registration."""
    client = _build_client()
    ident = _MachineIdent()
    _clean_task_state(ident.runner_id)
    cmd_tags = apply_kind_tag([], default_kind="command")

    # Only an agent task is queued -> command-tagged claim must miss.
    agent_task = _dispatch(client, title="for-agent", kind="agent")
    status, body = _claim_v2(client, ident, tags=cmd_tags)
    assert status == 200
    assert body.get("task") is None, body

    # Now add a command task -> the command runner picks it up.
    cmd_task = _dispatch(client, title="for-cmd", kind="command")
    status, body = _claim_v2(client, ident, tags=cmd_tags)
    assert status == 200
    assert body.get("task") is not None, body
    assert int(body["task"]["id"]) == int(cmd_task["id"])
    assert body["task"]["kind"] == "command"

    # The agent task is still queued for an agent runner.
    r = client.get(f"/tasks/{agent_task['id']}", headers=BEARER)
    assert r.status_code == 200
    assert r.json()["status"] == "queued"


def _clean_task_state(runner_id: str) -> None:
    """Cancel all queued tasks and any active tasks held by runner_id.

    Mirrors the hub conftest _enforce_cluster_invariant for tests outside tests/hub/.
    """
    import urllib.request as _ur
    import json as _json
    url = "http://127.0.0.1:4001/db/execute"
    stmts = [
        ["UPDATE tasks SET status='cancelled', cancel_requested=1 WHERE status='queued'"],
        [f"UPDATE tasks SET status='cancelled', cancel_requested=1 "
         f"WHERE worker_id='{runner_id}' AND status IN ('claimed','running')"],
    ]
    data = _json.dumps(stmts).encode()
    req = _ur.Request(url, data=data, method="POST",
                      headers={"Content-Type": "application/json"})
    _ur.urlopen(req, timeout=5).read()


def test_agent_runner_only_claims_agent_tasks() -> None:
    """A runner tagged ``kind:agent`` must not claim command tasks.
    Uses the machine's real runner identity — no ghost runner registration."""
    client = _build_client()
    ident = _MachineIdent()
    ag_tags = apply_kind_tag([], default_kind="agent")

    # Cancel stale queued/active tasks so the test starts from a clean state.
    _clean_task_state(ident.runner_id)

    # Only a command task queued -> agent-tagged claim must miss.
    cmd_task = _dispatch(client, title="cmd-only", kind="command")
    status, body = _claim_v2(client, ident, tags=ag_tags)
    assert status == 200
    assert body.get("task") is None, body

    # Now add an agent task -> the agent runner picks it up.
    ag_task = _dispatch(client, title="ag-only", kind="agent")
    status, body = _claim_v2(client, ident, tags=ag_tags)
    assert status == 200
    assert body.get("task") is not None, body
    assert int(body["task"]["id"]) == int(ag_task["id"])
    assert body["task"]["kind"] == "agent"

    # Command task untouched.
    r = client.get(f"/tasks/{cmd_task['id']}", headers=BEARER)
    assert r.json()["status"] == "queued"
