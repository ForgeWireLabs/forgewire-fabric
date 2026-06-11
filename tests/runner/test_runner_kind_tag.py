"""Runner-kind routing via first-class ``kinds`` column.

M2.8.3 removed ``apply_kind_tag`` and the ``kind:*`` tag system. Runner kind
is now a hard ``kinds: ["agent"|"command"]`` field on the registration body,
stored in the ``runners.kinds`` column and enforced at the claim route level
(``/tasks/claim-fabric`` for agent tasks, ``/tasks/claim-loom`` for command
tasks).

These tests pin the end-to-end consequence: a runner that registers as
``kinds:["command"]`` must only be routed Loom (command) tasks, and a runner
registered as ``kinds:["agent"]`` must only be routed Fabric (agent) tasks.
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
from forgewire_fabric.runner.runner_capabilities import sign_payload

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


def _clean_task_state(runner_id: str) -> None:
    """Cancel all queued tasks and any active tasks held by runner_id via rqlite."""
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


def _build_client() -> TestClient:
    tmp = Path(tempfile.mkdtemp(prefix="fw-runnerkind-"))
    cfg = BlackboardConfig(
        db_path=tmp / "blackboard.db",
        token=HUB_TOKEN,
        host="127.0.0.1",
        port=0,
    )
    return TestClient(create_app(cfg))


def _register(client: TestClient, ident: _MachineIdent, *, kinds: list[str]) -> None:
    ts = int(time.time())
    nonce = secrets.token_hex(16)
    signed = {
        "op": "register",
        "runner_id": ident.runner_id,
        "public_key": ident.public_key_hex,
        "protocol_version": 3,
        "timestamp": ts,
        "nonce": nonce,
    }
    sig = sign_payload(ident, signed)
    payload = {
        "runner_id": ident.runner_id,
        "public_key": ident.public_key_hex,
        "protocol_version": 3,
        "runner_version": "0.4.1",
        "hostname": "test-host",
        "os": "windows",
        "arch": "x86_64",
        "tools": [],
        "tags": [],
        "scope_prefixes": [],
        "tenant": None,
        "workspace_root": None,
        "max_concurrent": 1,
        "capabilities": {},
        "metadata": {},
        "kinds": kinds,
        "agent_type": None,
        "mcp_manifest": None,
        "timestamp": ts,
        "nonce": nonce,
        "signature": sig,
    }
    r = client.post("/runners/register", json=payload, headers=BEARER)
    assert r.status_code == 200, r.text


def _claim(client: TestClient, ident: _MachineIdent, *, queue: str) -> tuple[int, dict]:
    """Claim via the kind-specific endpoint.

    M2.8.9 removed the unified ``/tasks/claim-v2`` alias; a runner posts to the
    endpoint matching its registered kind — ``queue="loom"`` (command) or
    ``queue="fabric"`` (agent). The hub enforces that the runner's stored
    ``kinds`` column (M2.8.3) includes the queue's kind.
    """
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
        "tags": [],
    }
    r = client.post(f"/tasks/claim-{queue}", json=payload, headers=BEARER)
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
    """A runner registered with ``kinds:["command"]`` must not be handed an
    agent task and must successfully claim its own command task.

    Uses ``/tasks/claim-loom``; routing is driven by the stored ``kinds``
    column (M2.8.3), not tags.
    """
    client = _build_client()
    ident = _MachineIdent()
    _register(client, ident, kinds=["command"])
    _clean_task_state(ident.runner_id)

    # Only an agent task is queued -> command runner must miss.
    _dispatch(client, title="for-agent", kind="agent")
    status, body = _claim(client, ident, queue="loom")
    assert status == 200
    assert body.get("task") is None, body

    # Now add a command task -> the command runner picks it up.
    cmd_task = _dispatch(client, title="for-cmd", kind="command")
    status, body = _claim(client, ident, queue="loom")
    assert status == 200
    assert body.get("task") is not None, body
    assert int(body["task"]["id"]) == int(cmd_task["id"])
    assert body["task"]["kind"] == "command"


def test_agent_runner_only_claims_agent_tasks() -> None:
    """A runner registered with ``kinds:["agent"]`` must not claim command tasks."""
    client = _build_client()
    ident = _MachineIdent()
    _register(client, ident, kinds=["agent"])
    _clean_task_state(ident.runner_id)

    # Only a command task queued -> agent runner must miss.
    cmd_task = _dispatch(client, title="cmd-only", kind="command")
    status, body = _claim(client, ident, queue="fabric")
    assert status == 200
    assert body.get("task") is None, body

    # Now add an agent task -> the agent runner picks it up.
    ag_task = _dispatch(client, title="ag-only", kind="agent")
    status, body = _claim(client, ident, queue="fabric")
    assert status == 200
    assert body.get("task") is not None, body
    assert int(body["task"]["id"]) == int(ag_task["id"])
    assert body["task"]["kind"] == "agent"

    # Command task untouched.
    r = client.get(f"/tasks/{cmd_task['id']}", headers=BEARER)
    assert r.json()["status"] == "queued"
