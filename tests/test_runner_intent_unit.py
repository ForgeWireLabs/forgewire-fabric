from __future__ import annotations

import asyncio
import time

from forgewire_fabric.hub.client import BlackboardError
from forgewire_fabric.runner.agent import RunnerConfig, RunnerSession, shell_executor
from forgewire_fabric.runner.identity import RunnerIdentity


class InMemoryIntentClient:
    def __init__(self, *, error: BlackboardError | None = None) -> None:
        self.error = error
        self.intents: list[dict] = []
        self.streams: list[dict] = []

    async def post_intent(self, task_id: int, **body):
        self.intents.append({"task_id": task_id, **body})
        if self.error is not None:
            raise self.error
        return {"status": "allowed"}

    async def append_stream(self, task_id: int, body: dict):
        self.streams.append({"task_id": task_id, **body})
        return {"ok": True}


def _session(tmp_path, client: InMemoryIntentClient) -> RunnerSession:
    return RunnerSession(
        client=client,  # type: ignore[arg-type]
        identity=RunnerIdentity("runner-intent-test", "00" * 32, "11" * 32),
        config=RunnerConfig(
            workspace_root=str(tmp_path),
            tenant=None,
            tags=[],
            scope_prefixes=[],
        ),
        tools=[],
        host={"hostname": "test-host", "os": "test", "arch": "test"},
    )


def test_python_shell_executor_allows_declared_intent(tmp_path) -> None:
    client = InMemoryIntentClient()
    task = {
        "id": 1,
        "branch": "main",
        "prompt": "printf 'FW_INTENT:network_egress:host=example.com\\nallowed\\n'",
    }
    result = asyncio.run(shell_executor(task, _session(tmp_path, client)))
    assert result["status"] == "done"
    assert client.intents[0]["kind"] == "network_egress"
    assert client.intents[0]["hosts"] == ["example.com"]
    assert all("FW_INTENT" not in row["line"] for row in client.streams)


def test_python_shell_executor_fails_closed_when_intent_post_fails(tmp_path) -> None:
    client = InMemoryIntentClient(error=BlackboardError(0, "hub unavailable"))
    task = {
        "id": 1,
        "branch": "main",
        "prompt": "printf 'FW_INTENT:network_egress:host=example.com\\n'; sleep 5; echo unsafe",
    }
    started = time.monotonic()
    result = asyncio.run(shell_executor(task, _session(tmp_path, client)))
    assert time.monotonic() - started < 4
    assert result["status"] == "failed"
    assert "failed closed" in result["error"]
