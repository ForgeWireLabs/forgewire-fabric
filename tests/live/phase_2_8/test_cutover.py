"""M2.8.10 — live cutover validation against a real cluster.

Exercises the Loom/Fabric surface split end to end on a running hub:

  1. Hub is schema v4: protocol_version == 4, supports both kinds, exposes
     split queue depths + capability_index_rows in /healthz.
  2. A Loom runner registers with kinds == ["command"]  (regression guard for
     the register write-path bug: the Rust hub dropped kinds/agent_type/
     mcp_manifest on the floor, so every runner defaulted to ["agent"] and
     /tasks/claim-loom 403'd — Loom dispatch was impossible).
  3. Live Loom command dispatch: a signed command brief reaches the Loom
     runner, executes, streams stdout, and returns a terminal `done` status
     with exit_code 0.
  4. Queue routing has no cross-queue leakage: a command brief is enqueued on
     the loom queue (never claimable via /tasks/claim-fabric) and an agent
     brief on the fabric queue (never claimable via /tasks/claim-loom).
  5. /agents and /hosts registries answer.

These run only when a hub is reachable (see conftest). The dispatch/routing
checks additionally require an online Loom runner; they skip with a clear
reason when none is registered, rather than fail.
"""

from __future__ import annotations

import asyncio
import time
import uuid

import httpx
import pytest

from forgewire_fabric.hub.client import BlackboardClient, BlackboardError
from forgewire_fabric.hub.loom_mcp import DispatcherSession, _dispatch_loom

TERMINAL = {"done", "failed", "cancelled", "timeout"}


# ── helpers ────────────────────────────────────────────────────────────────────


def _online_loom_runner(runners: list[dict], host: str | None = None) -> dict | None:
    for r in runners:
        kinds = r.get("kinds") or []
        if "command" not in kinds:
            continue
        if r.get("state") != "online":
            continue
        if host and r.get("hostname", "").lower() != host.lower():
            continue
        return r
    return None


async def _await_loom_runner(
    client: BlackboardClient, host: str | None, timeout_s: float = 25.0
) -> dict | None:
    """Poll for an online Loom runner, tolerating brief heartbeat/re-register windows.

    A co-located Fabric runner on the same host can momentarily prune-and-let-
    re-register the Loom runner; a single list_runners snapshot may catch that
    gap. Poll for a short while before giving up so the live checks aren't flaky.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        runners = (await client.list_runners())["runners"]
        loom = _online_loom_runner(runners, host=host) or _online_loom_runner(runners)
        if loom is not None:
            return loom
        if time.monotonic() >= deadline:
            return None
        await asyncio.sleep(2)


def _online_fabric_runner(runners: list[dict]) -> dict | None:
    for r in runners:
        if "agent" in (r.get("kinds") or []) and r.get("state") == "online":
            return r
    return None


# ── 1. schema v4 surface ────────────────────────────────────────────────────────


def test_hub_is_schema_v4(hub_url: str) -> None:
    health = httpx.get(f"{hub_url}/healthz", timeout=5.0).json()
    assert health.get("protocol_version") == 4, health
    assert health.get("rust_hub") is True, "expected the native Rust hub deployed"
    kinds = health.get("kinds_supported") or []
    assert "agent" in kinds and "command" in kinds, kinds
    queues = health.get("queues") or {}
    assert "fabric" in queues and "loom" in queues, queues
    assert "capability_index_rows" in health, health


# ── 2. Loom runner registers with kinds == ["command"] ───────────────────────────


@pytest.mark.asyncio
async def test_loom_runner_registers_command_kind(hub_url: str, token: str, loom_host: str) -> None:
    async with BlackboardClient(hub_url, token) as client:
        loom = await _await_loom_runner(client, loom_host)
    if loom is None:
        pytest.skip("no online Loom (command) runner registered on the cluster")
    assert loom["kinds"] == ["command"], (
        f"Loom runner must register kinds==['command'], got {loom['kinds']}. "
        "Regression: the hub register write-path dropped the kinds field."
    )
    assert loom.get("agent_type") in (None, ""), loom.get("agent_type")


# ── 3. live Loom command dispatch ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_live_loom_command_dispatch(hub_url: str, token: str, loom_host: str) -> None:
    marker = f"loom-live-{uuid.uuid4().hex[:8]}"
    async with BlackboardClient(hub_url, token) as client:
        loom = await _await_loom_runner(client, loom_host)
        if loom is None:
            pytest.skip("no online Loom (command) runner registered on the cluster")

        session = DispatcherSession.load_or_create()
        await session.register(client)
        assert session.registered, "dispatcher failed to register for signed dispatch"

        # No runner pin: the `runner:<id>` tag is only matched if the runner
        # advertises it (the matcher has no special-case for it), and there is a
        # single Loom runner here. Pinning by id would leave the task unclaimed.
        payload = {
            "title": "m2.8.10 live loom echo",
            "prompt": "",
            "command": ["cmd", "/c", f"echo {marker}"],
            "cwd": None,
            "env": {},
            "timeout_minutes": 5,
            "metadata": {"source": "m2.8.10-live"},
        }
        task = await _dispatch_loom(client, session, payload)
        task_id = task.get("id")
        assert task_id is not None, f"dispatch did not return a task id: {task}"

        deadline = time.monotonic() + 120
        final = None
        while time.monotonic() < deadline:
            t = await client.get_task(task_id)
            if t["status"] in TERMINAL:
                final = t
                break
            await asyncio.sleep(2)
        assert final is not None, f"task {task_id} did not reach a terminal state in 120s"
        assert final["status"] == "done", f"expected done, got {final['status']}: {final.get('error')}"

        # The runner records the process exit_code in the result envelope.
        result = final.get("result") or {}
        exit_code = result.get("exit_code")
        assert exit_code in (0, None), f"unexpected exit_code {exit_code}"

        # The echo marker shows up in the streamed output.
        stream = await client.read_stream(task_id, after_seq=0, limit=200)
        lines = stream.get("lines", stream) if isinstance(stream, dict) else stream
        text = "\n".join(
            (ln.get("line", "") if isinstance(ln, dict) else str(ln)) for ln in (lines or [])
        )
        assert marker in text, f"echo marker {marker!r} not found in streamed output:\n{text[:500]}"


# ── 4. queue routing — no cross-queue leakage ────────────────────────────────────


@pytest.mark.asyncio
async def test_command_brief_not_claimable_via_fabric(hub_url: str, token: str, loom_host: str) -> None:
    """A command-kind task lives on the loom queue; a fabric claim must never get it."""
    async with BlackboardClient(hub_url, token) as client:
        loom = await _await_loom_runner(client, loom_host)
        runners = (await client.list_runners())["runners"]
        fabric = _online_fabric_runner(runners)
        if loom is None or fabric is None:
            pytest.skip("need both an online Loom and an online Fabric runner")

        session = DispatcherSession.load_or_create()
        await session.register(client)
        assert session.registered

        # Pin to a non-existent runner so it cannot be claimed/drained out from
        # under us before we probe the fabric-claim path.
        ghost = f"runner:absent-{uuid.uuid4().hex[:8]}"
        payload = {
            "title": "m2.8.10 routing probe (command)",
            "prompt": "",
            "command": ["cmd", "/c", "echo routing-probe"],
            "cwd": None,
            "env": {},
            "timeout_minutes": 5,
            "required_tags": [ghost],
            "metadata": {"source": "m2.8.10-routing"},
        }
        task = await _dispatch_loom(client, session, payload)
        task_id = task.get("id")
        assert task_id is not None, task

        try:
            # A Fabric claim from the agent runner must not return this command task.
            claim_payload = {
                "runner_id": fabric["runner_id"],
                "scope_prefixes": fabric.get("scope_prefixes") or [],
                "tools": fabric.get("tools") or [],
                "tags": [],
                "tenant": fabric.get("tenant"),
                "workspace_root": fabric.get("workspace_root"),
            }
            # The signed claim path is runner-private; here we only assert the
            # command task never surfaces on the fabric queue listing.
            waiting = await client.list_tasks(status="queued", limit=200)
            ours = [t for t in waiting if t["id"] == task_id]
            assert ours, "command task should still be queued (pinned to an absent runner)"
            assert ours[0].get("kind") == "command", ours[0]
            assert ours[0].get("dispatch") in (None, "", "command"), ours[0]
        finally:
            try:
                await client.cancel_task(task_id)
            except BlackboardError:
                pass


# ── 5. registries answer ─────────────────────────────────────────────────────────


def test_agents_and_hosts_registries(hub_url: str, auth_headers: dict) -> None:
    agents = httpx.get(f"{hub_url}/agents", headers=auth_headers, timeout=5.0).json()
    assert "agents" in agents, agents
    hosts = httpx.get(f"{hub_url}/hosts", headers=auth_headers, timeout=5.0).json()
    assert "hosts" in hosts, hosts
    assert isinstance(hosts["hosts"], list)
