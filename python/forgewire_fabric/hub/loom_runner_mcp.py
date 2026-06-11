"""MCP server (Loom runner side) — command-kind claim path via /tasks/claim-loom.

The Loom runner is a dumb shell executor.  No LLM.  No MCP introspection.
It registers as ``kinds: ["command"]``, ``agent_type: null``, empty manifest.

Tools surfaced to the dispatching agent:

* ``claim_next_command``   -- claim from /tasks/claim-loom
* ``start_process``        -- spawn the claimed command as a subprocess
* ``report_output``        -- append a stdout/stderr line (alias for report_stream)
* ``report_exit``          -- terminal report with exit_code and log_tail
* ``kill_process``         -- terminate a tracked process
* ``list_processes``       -- enumerate tracked in-flight processes
* ``runner_identity``      -- identity + host snapshot

Env knobs:
  FORGEWIRE_HUB_URL              -- hub base URL (optional; falls back to mDNS)
  FORGEWIRE_HUB_TOKEN_FILE       -- bearer token file
  FORGEWIRE_RUNNER_IDENTITY      -- identity JSON path
  FORGEWIRE_RUNNER_TAGS          -- comma-separated extra routing tags
  FORGEWIRE_RUNNER_SCOPE_PREFIXES -- comma-separated path prefix allowlist
  FORGEWIRE_RUNNER_TENANT        -- tenant id
  FORGEWIRE_RUNNER_MAX_CONCURRENT -- concurrency cap (default 2)
  FORGEWIRE_RUNNER_VERSION       -- override version string

.. TEST-ONLY REFERENCE — not a deployed daemon ..
The canonical deployed Loom runner is the Rust ``forgewire-loom-runner`` binary
(``crates/loom-runner``).  This Python module is a parity-reference and test
harness.  It must NOT be shipped as the primary runner; a drift-guard test
(``tests/test_loom_runner_parity.py``) asserts this banner is present.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time as _time
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server

from forgewire_fabric.hub.client import (
    BlackboardClient,
    BlackboardError,
    load_client_from_env,
)
from forgewire_fabric.hub.mcp_common import ToolRegistry
from forgewire_fabric.runner.identity import RunnerIdentity, load_or_create
from forgewire_fabric.runner.runner_capabilities import (
    describe_host,
    detect_tools,
    fresh_nonce,
    now_ts,
    sample_resources,
    sign_payload,
)


LOGGER = logging.getLogger("forgewire_fabric.loom_runner_mcp")

PROTOCOL_VERSION = 4
HEARTBEAT_INTERVAL_SECONDS = 20
DEFAULT_VERSION = "0.17.0"  # Python package line (forgewire_fabric.__version__)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [s.strip() for s in value.split(",") if s.strip()]


class ProcessHandle:
    """In-memory state for one running subprocess."""

    def __init__(self, task_id: int, proc: asyncio.subprocess.Process) -> None:
        self.task_id = task_id
        self.proc = proc
        self.started_at = _time.time()


class LoomSession:
    """Runner state shared between MCP tools and the heartbeat loop."""

    def __init__(
        self,
        client: BlackboardClient,
        identity: RunnerIdentity,
        *,
        tenant: str | None,
        tags: list[str],
        scope_prefixes: list[str],
        max_concurrent: int,
        runner_version: str,
    ) -> None:
        self.client = client
        self.identity = identity
        self.tenant = tenant
        self.tags = tags
        self.scope_prefixes = scope_prefixes
        self.max_concurrent = max_concurrent
        self.runner_version = runner_version
        self.tools = detect_tools()
        self.host = describe_host()
        self.last_resources: dict[str, Any] = {}
        self.last_heartbeat_ok: bool = False
        self.last_register_response: dict[str, Any] | None = None
        self._processes: dict[int, ProcessHandle] = {}  # task_id -> handle

    @property
    def runner_id(self) -> str:
        return self.identity.runner_id

    def _signed_envelope(self, op: str) -> tuple[int, str, str]:
        ts = now_ts()
        nonce = fresh_nonce()
        signed = {
            "op": op,
            "runner_id": self.runner_id,
            "timestamp": ts,
            "nonce": nonce,
        }
        return ts, nonce, sign_payload(self.identity, signed)

    def claim_payload(self) -> dict[str, Any]:
        resources = sample_resources()
        self.last_resources = resources
        ts, nonce, signature = self._signed_envelope("claim")
        return {
            "runner_id": self.runner_id,
            "timestamp": ts,
            "nonce": nonce,
            "signature": signature,
            "scope_prefixes": self.scope_prefixes,
            "tools": self.tools,
            "tags": self.tags,
            "tenant": self.tenant,
            "workspace_root": None,
            "last_known_commit": None,
            **resources,
        }

    def heartbeat_payload(self) -> dict[str, Any]:
        resources = sample_resources()
        self.last_resources = resources
        ts, nonce, signature = self._signed_envelope("heartbeat")
        return {
            "runner_id": self.runner_id,
            "timestamp": ts,
            "nonce": nonce,
            "signature": signature,
            "last_known_commit": None,
            **resources,
        }

    def drain_payload(self) -> dict[str, Any]:
        ts, nonce, signature = self._signed_envelope("drain")
        return {"runner_id": self.runner_id, "timestamp": ts, "nonce": nonce, "signature": signature}

    def register_payload(self) -> dict[str, Any]:
        ts = now_ts()
        nonce = fresh_nonce()
        signed = {
            "op": "register",
            "runner_id": self.runner_id,
            "public_key": self.identity.public_key_hex,
            "protocol_version": PROTOCOL_VERSION,
            "timestamp": ts,
            "nonce": nonce,
        }
        signature = sign_payload(self.identity, signed)
        body = {
            "runner_id": self.runner_id,
            "public_key": self.identity.public_key_hex,
            "protocol_version": PROTOCOL_VERSION,
            "runner_version": self.runner_version,
            "tools": self.tools,
            "tags": self.tags,
            "scope_prefixes": self.scope_prefixes,
            "tenant": self.tenant,
            "workspace_root": None,
            "max_concurrent": self.max_concurrent,
            "metadata": {},
            "kinds": ["command"],
            "agent_type": None,
            "mcp_manifest": None,
            "timestamp": ts,
            "nonce": nonce,
            "signature": signature,
        }
        body.update(self.host)
        return body


def _build_session(client: BlackboardClient) -> LoomSession:
    identity = load_or_create()
    tags = _parse_csv(
        os.environ.get("FORGEWIRE_RUNNER_TAGS")
        or os.environ.get("PHRENFORGE_RUNNER_TAGS")
    )
    scope_prefixes = _parse_csv(
        os.environ.get("FORGEWIRE_RUNNER_SCOPE_PREFIXES")
        or os.environ.get("PHRENFORGE_RUNNER_SCOPE_PREFIXES")
    )
    tenant = (
        os.environ.get("FORGEWIRE_RUNNER_TENANT")
        or os.environ.get("PHRENFORGE_RUNNER_TENANT")
        or None
    )
    max_concurrent = int(
        os.environ.get("FORGEWIRE_RUNNER_MAX_CONCURRENT")
        or os.environ.get("PHRENFORGE_RUNNER_MAX_CONCURRENT", "2")
    )
    runner_version = (
        os.environ.get("FORGEWIRE_RUNNER_VERSION")
        or os.environ.get("PHRENFORGE_RUNNER_VERSION", DEFAULT_VERSION)
    )
    return LoomSession(
        client,
        identity,
        tenant=tenant,
        tags=tags,
        scope_prefixes=scope_prefixes,
        max_concurrent=max_concurrent,
        runner_version=runner_version,
    )


async def _register_with_retries(session: LoomSession) -> dict[str, Any]:
    delay = 1.0
    while True:
        try:
            response = await session.client.register_runner(session.register_payload())
            session.last_register_response = response
            LOGGER.info(
                "loom runner registered with hub as runner_id=%s (host=%s, tools=%s)",
                session.runner_id,
                session.host["hostname"],
                ",".join(session.tools) or "<none>",
            )
            return response
        except BlackboardError as exc:
            LOGGER.warning("loom registration failed: %s; retrying in %.1fs", exc, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)


async def _heartbeat_loop(session: LoomSession) -> None:
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
        if session.last_register_response is None:
            continue
        try:
            await session.client.heartbeat(session.runner_id, session.heartbeat_payload())
            session.last_heartbeat_ok = True
        except BlackboardError as exc:
            session.last_heartbeat_ok = False
            LOGGER.warning("loom heartbeat failed: %s", exc)
            if exc.status_code == 404:
                LOGGER.info("hub forgot loom runner; re-registering")
                await _register_with_retries(session)


STDIN_POLL_INTERVAL_SECONDS = 2


async def _stdin_drain_loop(session: LoomSession) -> None:
    """Poll GET /tasks/{id}/input and write signed stdin batches to subprocess pipes."""
    cursors: dict[int, int] = {}

    while True:
        await asyncio.sleep(STDIN_POLL_INTERVAL_SECONDS)
        for task_id, handle in list(session._processes.items()):
            if handle.proc.returncode is not None:
                continue
            after_seq = cursors.get(task_id, 0)
            try:
                result = await session.client.get_task_input(task_id, after_seq=after_seq)
            except BlackboardError:
                continue
            entries = result.get("entries") or []
            for entry in entries:
                seq = entry.get("seq") or 0
                if seq > after_seq:
                    after_seq = seq
                lines: list[str] = entry.get("lines") or []
                if lines and handle.proc.stdin is not None:
                    try:
                        for line in lines:
                            handle.proc.stdin.write((line + "\n").encode())
                        await handle.proc.stdin.drain()
                    except (BrokenPipeError, ConnectionResetError):
                        break
            cursors[task_id] = after_seq


def _register_tools(registry: ToolRegistry, session: LoomSession) -> None:
    client = session.client

    async def claim_next_command(_args: dict[str, Any]) -> dict[str, Any]:
        return await client.claim_task_loom(session.claim_payload())

    registry.register(
        name="claim_next_command",
        description=(
            "Claim the next queued command-kind task from /tasks/claim-loom. "
            "Returns ``{task: <record|null>, info: {...}}``. The task record "
            "carries ``command`` (argv array), ``cwd``, ``env``, and "
            "``timeout_seconds`` fields."
        ),
        input_schema={"type": "object", "properties": {}},
        handler=claim_next_command,
    )

    async def start_process(args: dict[str, Any]) -> dict[str, Any]:
        task_id = int(args["task_id"])
        command: list[str] = args["command"]
        cwd: str = args.get("cwd") or os.getcwd()
        env_overrides: dict[str, str] = args.get("env") or {}
        timeout_seconds: int = int(args.get("timeout_seconds") or 0)

        # M2.9.3 (F3): build env from explicit allowlist + brief overrides only.
        # Never inherit the service environment — it carries FORGEWIRE_HUB_TOKEN
        # and other secret-bearing variables that commands must not see.
        _ALLOWLIST = (
            "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "SYSTEMDRIVE",
            "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
            "COMPUTERNAME", "USERNAME",
        )
        env = {k: v for k, v in os.environ.items() if k in _ALLOWLIST}
        env.update(env_overrides)

        if len(session._processes) >= session.max_concurrent:
            return {"error": "max_concurrent reached", "running": len(session._processes)}

        # M2.9.2 (F2) parity: call the intent gate before spawning — fail closed on
        # deny or hub unreachability, matching agent.py _post_intent_fail_closed.
        try:
            await client.post_intent(
                task_id,
                worker_id=session.runner_id,
                kind="shell_exec",
                command=" ".join(command) if command else None,
            )
        except BlackboardError as exc:
            LOGGER.warning(
                "loom intent gate denied task_id=%d: %s", task_id, exc
            )
            return {"error": "intent_denied", "detail": str(exc)}

        proc = await asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        handle = ProcessHandle(task_id, proc)
        session._processes[task_id] = handle

        if len(command) > 0:
            LOGGER.info("loom started task_id=%d: %s", task_id, " ".join(command))

        # Kick off background pump tasks.
        async def _pump(pipe: asyncio.StreamReader | None, channel: str) -> None:
            if pipe is None:
                return
            while True:
                line_bytes = await pipe.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode(errors="replace").rstrip("\n")
                try:
                    await client.append_stream(
                        task_id, {"worker_id": session.runner_id, "channel": channel, "line": line}
                    )
                except BlackboardError as exc:
                    LOGGER.warning("loom stream append failed: %s", exc)

        asyncio.create_task(_pump(proc.stdout, "stdout"))
        asyncio.create_task(_pump(proc.stderr, "stderr"))

        # M2.9.5 (F7): single finish path with optional timeout wrapper.
        # Timeout sentinel -124 matches the Rust loom-runner's SIGXCPU-like constant.
        async def _auto_finish(timeout_secs: int = 0) -> None:
            rc: int
            if timeout_secs > 0:
                try:
                    rc = await asyncio.wait_for(proc.wait(), timeout=float(timeout_secs))
                except asyncio.TimeoutError:
                    LOGGER.warning("loom task_id=%d timed out after %ds", task_id, timeout_secs)
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    await proc.wait()
                    session._processes.pop(task_id, None)
                    try:
                        await client.submit_result(
                            task_id,
                            {
                                "worker_id": session.runner_id,
                                "status": "timed_out",
                                "exit_code": -124,
                                "error": f"timed out after {timeout_secs}s",
                            },
                        )
                    except BlackboardError:
                        pass
                    return
            else:
                rc = await proc.wait()
            session._processes.pop(task_id, None)
            try:
                await client.submit_result(
                    task_id,
                    {
                        "worker_id": session.runner_id,
                        "status": "done" if rc == 0 else "failed",
                        "exit_code": rc,
                        "error": None if rc == 0 else f"exit code {rc}",
                    },
                )
            except BlackboardError as exc:
                LOGGER.warning("loom auto-finish submit failed: %s", exc)

        asyncio.create_task(_auto_finish(timeout_seconds))

        return {"task_id": task_id, "pid": proc.pid, "status": "running"}

    registry.register(
        name="start_process",
        description=(
            "Spawn the claimed command as a tracked subprocess. Streams "
            "stdout/stderr to the hub automatically. On exit, submits a "
            "terminal result with ``exit_code``. Returns "
            "``{task_id, pid, status: 'running'}``."
        ),
        input_schema={
            "type": "object",
            "required": ["task_id", "command"],
            "properties": {
                "task_id": {"type": "integer"},
                "command": {"type": "array", "items": {"type": "string"}},
                "cwd": {"type": "string"},
                "env": {"type": "object", "additionalProperties": {"type": "string"}},
                "timeout_seconds": {"type": "integer", "default": 0},
            },
        },
        handler=start_process,
    )

    async def report_output(args: dict[str, Any]) -> dict[str, Any]:
        task_id = int(args["task_id"])
        return await client.append_stream(
            task_id,
            {
                "worker_id": session.runner_id,
                "channel": args.get("channel", "stdout"),
                "line": args["line"],
            },
        )

    registry.register(
        name="report_output",
        description=(
            "Append a single stdout/stderr/info line for a running task. "
            "Use this when you are driving the subprocess manually rather "
            "than through start_process's auto-pump."
        ),
        input_schema={
            "type": "object",
            "required": ["task_id", "line"],
            "properties": {
                "task_id": {"type": "integer"},
                "channel": {"type": "string", "enum": ["stdout", "stderr", "info"], "default": "stdout"},
                "line": {"type": "string"},
            },
        },
        handler=report_output,
    )

    async def report_exit(args: dict[str, Any]) -> dict[str, Any]:
        task_id = int(args["task_id"])
        exit_code = int(args["exit_code"])
        log_tail: str | None = args.get("log_tail")
        session._processes.pop(task_id, None)
        status = "done" if exit_code == 0 else "failed"
        return await client.submit_result(
            task_id,
            {
                "worker_id": session.runner_id,
                "status": status,
                "exit_code": exit_code,
                "log_tail": log_tail,
                "error": None if exit_code == 0 else f"exit code {exit_code}",
            },
        )

    registry.register(
        name="report_exit",
        description=(
            "Submit a terminal result for a command task with the process "
            "``exit_code``. Automatically sets status to ``done`` (rc=0) or "
            "``failed`` (rc!=0). Removes the process from the tracked set."
        ),
        input_schema={
            "type": "object",
            "required": ["task_id", "exit_code"],
            "properties": {
                "task_id": {"type": "integer"},
                "exit_code": {"type": "integer"},
                "log_tail": {"type": ["string", "null"]},
            },
        },
        handler=report_exit,
    )

    async def kill_process(args: dict[str, Any]) -> dict[str, Any]:
        task_id = int(args["task_id"])
        handle = session._processes.pop(task_id, None)
        if handle is None:
            return {"task_id": task_id, "status": "not_found"}
        try:
            handle.proc.kill()
            await handle.proc.wait()
        except ProcessLookupError:
            pass
        return {"task_id": task_id, "status": "killed"}

    registry.register(
        name="kill_process",
        description="Terminate a tracked process by task_id. Sends SIGKILL (Windows: TerminateProcess).",
        input_schema={
            "type": "object",
            "required": ["task_id"],
            "properties": {"task_id": {"type": "integer"}},
        },
        handler=kill_process,
    )

    async def list_processes(_args: dict[str, Any]) -> dict[str, Any]:
        entries = []
        for tid, h in session._processes.items():
            rc = h.proc.returncode
            entries.append({
                "task_id": tid,
                "pid": h.proc.pid,
                "running": rc is None,
                "exit_code": rc,
                "elapsed_seconds": int(_time.time() - h.started_at),
            })
        return {"processes": entries, "count": len(entries)}

    registry.register(
        name="list_processes",
        description="List all subprocess handles currently tracked by this Loom runner.",
        input_schema={"type": "object", "properties": {}},
        handler=list_processes,
    )

    async def runner_identity_tool(_args: dict[str, Any]) -> dict[str, Any]:
        return {
            "runner_id": session.runner_id,
            "hostname": session.host["hostname"],
            "os": session.host["os"],
            "arch": session.host["arch"],
            "tools": session.tools,
            "tags": session.tags,
            "scope_prefixes": session.scope_prefixes,
            "tenant": session.tenant,
            "runner_version": session.runner_version,
            "protocol_version": PROTOCOL_VERSION,
            "max_concurrent": session.max_concurrent,
            "kinds": ["command"],
            "agent_type": None,
            "registered": session.last_register_response is not None,
            "last_register_response": session.last_register_response,
            "last_resources": session.last_resources,
            "last_heartbeat_ok": session.last_heartbeat_ok,
            "active_processes": len(session._processes),
        }

    registry.register(
        name="runner_identity",
        description=(
            "Return this Loom runner's identity, advertised capabilities, "
            "and current process count."
        ),
        input_schema={"type": "object", "properties": {}},
        handler=runner_identity_tool,
    )


async def _run() -> None:
    logging.basicConfig(level=logging.INFO)
    client = load_client_from_env()
    session = _build_session(client)
    LOGGER.info(
        "forgewire-loom-runner MCP starting as runner_id=%s host=%s",
        session.runner_id,
        session.host["hostname"],
    )
    registration_task = asyncio.create_task(_register_with_retries(session))
    heartbeat_task = asyncio.create_task(_heartbeat_loop(session))
    stdin_poll_task = asyncio.create_task(_stdin_drain_loop(session))
    server = Server("forgewire-loom-runner")
    registry = ToolRegistry()
    _register_tools(registry, session)
    registry.bind(server)
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
    except BlackboardError as exc:
        LOGGER.error("blackboard error: %s", exc)
        raise
    finally:
        registration_task.cancel()
        heartbeat_task.cancel()
        stdin_poll_task.cancel()
        await asyncio.gather(registration_task, heartbeat_task, stdin_poll_task, return_exceptions=True)
        await client.aclose()


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
