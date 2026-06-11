"""MCP server (dispatcher side) — Loom surface for command-kind task dispatch.

Replaces the shell-execution half of ``dispatcher_mcp.py``.  The Loom surface
drives *dumb shell executor* runners (``kinds: ["command"]``); no LLM, no MCP
manifest.  For agent dispatch use ``forgewire-fabric`` (fabric_mcp.py).

Server name advertised to MCP clients: ``forgewire-loom``

Tools:
  list_hosts        -- Loom runner registry with host info and load
  run_command       -- convenience: dispatch + await_result on the Loom queue
  start_process     -- dispatch a command task without blocking (returns task_id)
  read_output       -- pull stdout/stderr lines since seq N
  send_input        -- post signed stdin lines to a running process
  kill_process      -- cancel / kill a running command task
  list_processes    -- list active command tasks (running / queued)
  await_result      -- block until terminal state
  discover_hub      -- mDNS + UDP beacon hub discovery

Env knobs:
  FORGEWIRE_HUB_URL          -- hub base URL (optional; falls back to mDNS)
  FORGEWIRE_HUB_TOKEN_FILE   -- path to bearer token file
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import platform
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
    canonical_payload,
    fresh_nonce,
    now_ts,
    sign_payload,
)

LOGGER = logging.getLogger("forgewire_fabric.loom_mcp")

TERMINAL_STATES = {"done", "failed", "cancelled", "timed_out"}


def _loom_env_digest(env: dict[str, str]) -> str:
    """SHA-256 of the canonical JSON of the env map (values bound, keys auditable).

    Uses the shared ``canonical_payload`` encoder (sorted keys, compact
    separators, ``ensure_ascii=True``) so the digest bytes are identical to the
    Rust runner's ``compute_env_digest`` via ``fabric_protocol::canonicalize``.
    The previous ``ensure_ascii=False`` + hand-escaped Rust counterpart diverged
    on any control char (newline/tab), rejecting legitimately signed briefs.
    """
    return hashlib.sha256(canonical_payload(dict(env))).hexdigest()


class DispatcherSession:
    """Dispatcher identity for signed ``POST /tasks/v2`` (shared with fabric_mcp).

    Loads (or generates) an ed25519 keypair from the standard dispatcher
    identity file and registers with the hub once on startup.  Provides
    :meth:`build_signed_payload` for constructing the full signed dispatch
    body accepted by ``POST /tasks/v2``.

    Falls back to unsigned dispatch on registration failure so the server
    still works against Python hubs that have ``require_signed_dispatch=false``.
    """

    _DEFAULT_PATH_WIN = r"C:\ProgramData\forgewire\dispatcher_identity.json"
    _DEFAULT_PATH_POSIX = "/var/lib/forgewire/dispatcher_identity.json"

    def __init__(self, identity: RunnerIdentity) -> None:
        self._identity = identity
        self.dispatcher_id: str = identity.runner_id
        self.registered: bool = False

    @classmethod
    def load_or_create(cls) -> "DispatcherSession":
        path_env = os.environ.get("FORGEWIRE_DISPATCHER_IDENTITY")
        if path_env:
            from pathlib import Path
            path = Path(path_env)
        elif platform.system() == "Windows":
            from pathlib import Path
            path = Path(cls._DEFAULT_PATH_WIN)
        else:
            from pathlib import Path
            path = Path(cls._DEFAULT_PATH_POSIX)
        identity = load_or_create(path)
        return cls(identity)

    async def register(self, client: BlackboardClient) -> None:
        ts = now_ts()
        nonce = fresh_nonce()
        envelope = {
            "op": "register-dispatcher",
            "dispatcher_id": self.dispatcher_id,
            "public_key": self._identity.public_key_hex,
            "timestamp": ts,
            "nonce": nonce,
        }
        sig = sign_payload(self._identity, envelope)
        try:
            await client.register_dispatcher({
                **envelope,
                "signature": sig,
                "label": f"loom-mcp@{platform.node()}",
                "hostname": platform.node(),
                "metadata": {"source": "loom_mcp"},
            })
            self.registered = True
            LOGGER.info("loom dispatcher registered: %s", self.dispatcher_id)
        except BlackboardError as exc:
            LOGGER.warning(
                "loom dispatcher registration failed (%s); unsigned dispatch will be used on Python hubs",
                exc,
            )

    def build_signed_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return ``payload`` augmented with dispatcher_id, timestamp, nonce, signature."""
        ts = now_ts()
        nonce = fresh_nonce()
        envelope: dict[str, Any] = {
            "op": "dispatch",
            "dispatcher_id": self.dispatcher_id,
            "title": payload.get("title") or "",
            "prompt": payload.get("prompt") or "",
            "scope_globs": payload.get("scope_globs") or [],
            "base_commit": payload.get("base_commit") or ("0" * 40),
            "branch": payload.get("branch") or "",
            "todo_id": payload.get("todo_id"),
            "timeout_minutes": payload.get("timeout_minutes") or 60,
            "priority": payload.get("priority") or 100,
            "metadata": payload.get("metadata") or {},
            "required_tools": payload.get("required_tools"),
            "required_tags": payload.get("required_tags"),
            "required_capabilities": payload.get("required_capabilities"),
            "secrets_needed": payload.get("secrets_needed"),
            "network_egress": payload.get("network_egress"),
            "tenant": payload.get("tenant"),
            "workspace_root": payload.get("workspace_root"),
            "require_base_commit": payload.get("require_base_commit") or False,
            "kind": "command",
            "max_cost_usd": payload.get("max_cost_usd"),
            "timestamp": ts,
            "nonce": nonce,
        }
        # M2.9.1 (F1): extend the signed envelope with the executable payload so
        # the dispatcher signature covers what the runner will actually execute.
        command: list[str] = payload.get("command") or []
        cwd: str = payload.get("cwd") or ""
        env_map: dict[str, str] = payload.get("env") or {}
        if command:
            envelope["loom_command"] = command
            envelope["loom_cwd"] = cwd
            envelope["loom_env_keys"] = sorted(env_map.keys())
            envelope["loom_env_digest"] = _loom_env_digest(env_map)
        sig = sign_payload(self._identity, envelope)
        return {
            **payload,
            "dispatcher_id": self.dispatcher_id,
            "timestamp": ts,
            "nonce": nonce,
            "signature": sig,
            # Surface digest so the hub can re-verify and the runner can cross-check.
            **({"loom_env_digest": envelope["loom_env_digest"]} if command else {}),
        }


async def _dispatch_loom(
    client: BlackboardClient,
    session: "DispatcherSession | None",
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Send a Loom (command-kind) dispatch with the signed POST /tasks/v2 path."""
    payload = {**payload, "kind": "command"}
    if session is not None and session.registered:
        return await client.dispatch_task_signed(session.build_signed_payload(payload))
    return await client.dispatch_task(payload)


# ── tool registration ──────────────────────────────────────────────────────────


def _register_tools(
    registry: ToolRegistry,
    client: BlackboardClient,
    session: "DispatcherSession | None" = None,
) -> None:

    # ── list_hosts ─────────────────────────────────────────────────────────────

    async def list_hosts(_args: dict[str, Any]) -> dict[str, Any]:
        return await client.list_hosts()

    registry.register(
        name="list_hosts",
        description=(
            "Return all Loom runners (runners with 'command' in kinds) with "
            "their hostname, OS, state, available tools, and load. "
            "Use this to discover which host machines are online and pick a "
            "target runner_id for pinned command dispatch."
        ),
        input_schema={"type": "object", "properties": {}},
        handler=list_hosts,
    )

    # ── start_process ──────────────────────────────────────────────────────────

    async def start_process(args: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a command task and return immediately (non-blocking)."""
        command: list[str] = args["command"]
        title = args.get("title") or " ".join(command[:3])
        payload: dict[str, Any] = {
            "title": title,
            "prompt": "",
            "command": command,
            "cwd": args.get("cwd"),
            "env": args.get("env") or {},
            "timeout_minutes": args.get("timeout_minutes") or 60,
            "priority": args.get("priority"),
            "required_tags": args.get("required_tags") or [],
            "tenant": args.get("tenant"),
            "metadata": args.get("metadata") or {},
        }
        if args.get("runner_id"):
            payload["required_tags"] = [
                *payload["required_tags"],
                f"runner:{args['runner_id']}",
            ]
        return await _dispatch_loom(client, session, payload)

    registry.register(
        name="start_process",
        description=(
            "Dispatch a command task to a Loom host runner without waiting for "
            "it to finish. Returns the queued task record (including task_id). "
            "Use read_output + await_result to follow output and get the exit "
            "code. Use run_command instead if you want to block until done."
        ),
        input_schema={
            "type": "object",
            "required": ["command"],
            "properties": {
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Argv array, e.g. ['pytest', '-q', 'tests/'].",
                },
                "cwd": {"type": ["string", "null"], "description": "Working directory on the remote host."},
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Extra environment variables to overlay on the runner's env.",
                },
                "title": {"type": ["string", "null"]},
                "timeout_minutes": {"type": "integer", "minimum": 1, "maximum": 720},
                "priority": {"type": ["integer", "null"]},
                "runner_id": {
                    "type": ["string", "null"],
                    "description": "Pin to a specific Loom runner (use list_hosts to find runner_id).",
                },
                "required_tags": {"type": "array", "items": {"type": "string"}},
                "tenant": {"type": ["string", "null"]},
                "metadata": {"type": "object"},
            },
        },
        handler=start_process,
    )

    # ── run_command ────────────────────────────────────────────────────────────

    async def run_command(args: dict[str, Any]) -> dict[str, Any]:
        """Dispatch + await_result convenience wrapper."""
        task_result = await start_process(args)
        task_id = task_result.get("id")
        if task_id is None:
            return {"error": "dispatch failed", "detail": task_result}

        timeout_seconds = int(args.get("timeout_seconds", 1800))
        poll_seconds = float(args.get("poll_seconds", 2.0))
        deadline = asyncio.get_event_loop().time() + timeout_seconds

        while True:
            task = await client.get_task(task_id)
            if task["status"] in TERMINAL_STATES:
                # Attach tail of stdout/stderr for convenience.
                try:
                    stream = await client.read_stream(task_id, after_seq=0, limit=500)
                    task["output_lines"] = stream
                except BlackboardError:
                    pass
                return task
            if asyncio.get_event_loop().time() >= deadline:
                return {
                    "task": task,
                    "timed_out_waiting": True,
                    "elapsed_seconds": timeout_seconds,
                }
            await asyncio.sleep(poll_seconds)

    registry.register(
        name="run_command",
        description=(
            "Dispatch a command to a Loom host and block until it completes "
            "(or the timeout elapses). Returns the final task record with an "
            "``output_lines`` list containing stdout/stderr. This is the "
            "primary tool for one-shot shell commands (e.g. run pytest, git, "
            "make). For long-running processes where you want to stream output "
            "incrementally, use start_process + read_output + await_result."
        ),
        input_schema={
            "type": "object",
            "required": ["command"],
            "properties": {
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Argv array, e.g. ['pytest', '-q', 'tests/'].",
                },
                "cwd": {"type": ["string", "null"]},
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
                "title": {"type": ["string", "null"]},
                "timeout_minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 720,
                    "description": "Task queue timeout passed to the runner.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "default": 1800,
                    "description": "Client-side await timeout before returning timed_out_waiting.",
                },
                "poll_seconds": {"type": "number", "default": 2.0},
                "runner_id": {"type": ["string", "null"]},
                "required_tags": {"type": "array", "items": {"type": "string"}},
                "tenant": {"type": ["string", "null"]},
                "metadata": {"type": "object"},
            },
        },
        handler=run_command,
    )

    # ── read_output ────────────────────────────────────────────────────────────

    async def read_output(args: dict[str, Any]) -> dict[str, Any]:
        lines = await client.read_stream(
            int(args["task_id"]),
            after_seq=int(args.get("after_seq", 0)),
            limit=int(args.get("limit", 500)),
        )
        return {"lines": lines}

    registry.register(
        name="read_output",
        description=(
            "Read stdout/stderr lines emitted by the Loom runner for a task, "
            "since after_seq (0 = from beginning). Returns ``{lines: [...]}`` "
            "where each entry has ``seq``, ``channel`` (stdout/stderr/info), "
            "and ``line`` fields. Call repeatedly with the last seen seq to "
            "follow a running process incrementally."
        ),
        input_schema={
            "type": "object",
            "required": ["task_id"],
            "properties": {
                "task_id": {"type": "integer"},
                "after_seq": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 500},
            },
        },
        handler=read_output,
    )

    # ── send_input ─────────────────────────────────────────────────────────────
    # M2.9.4 (F4): signed POST /tasks/{id}/input replaces the note-transport
    # path. The dispatcher signs each batch so the hub can verify it before
    # queuing, and the runner trusts only hub-verified entries.

    _send_input_seq: list[int] = [0]  # mutable counter via single-element list

    async def send_input(args: dict[str, Any]) -> dict[str, Any]:
        task_id = int(args["task_id"])
        lines: list[str] = args["lines"]
        if session is None or not session.registered:
            return {"error": "dispatcher not registered; cannot send signed stdin"}
        ts = now_ts()
        nonce = fresh_nonce()
        _send_input_seq[0] += 1
        seq = _send_input_seq[0]
        envelope: dict[str, Any] = {
            "op": "task-input",
            "task_id": task_id,
            "dispatcher_id": session.dispatcher_id,
            "lines": lines,
            "seq": seq,
            "timestamp": ts,
            "nonce": nonce,
        }
        sig = sign_payload(session._identity, envelope)
        return await client.post_task_input(task_id, {
            "dispatcher_id": session.dispatcher_id,
            "lines": lines,
            "seq": seq,
            "timestamp": ts,
            "nonce": nonce,
            "signature": sig,
        })

    registry.register(
        name="send_input",
        description=(
            "Post signed stdin lines to a running Loom process. Lines are "
            "delivered via the signed POST /tasks/{id}/input route and written "
            "to the process stdin pipe by the runner. Use for interactive "
            "commands that read from stdin (e.g. confirmations, REPL prompts)."
        ),
        input_schema={
            "type": "object",
            "required": ["task_id", "lines"],
            "properties": {
                "task_id": {"type": "integer"},
                "lines": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lines to write to the process stdin (without trailing newline).",
                },
            },
        },
        handler=send_input,
    )

    # ── kill_process ───────────────────────────────────────────────────────────

    registry.register(
        name="kill_process",
        description=(
            "Request cancellation of a running Loom command task. Queued tasks "
            "terminate immediately; running tasks have a cancel_requested flag "
            "set which the runner honours by killing the subprocess."
        ),
        input_schema={
            "type": "object",
            "required": ["task_id"],
            "properties": {"task_id": {"type": "integer"}},
        },
        handler=lambda args: client.cancel_task(int(args["task_id"])),
    )

    # ── list_processes ─────────────────────────────────────────────────────────

    async def list_processes(args: dict[str, Any]) -> dict[str, Any]:
        status = args.get("status") or "running"
        result = await client.list_tasks(status=status, limit=int(args.get("limit", 100)))
        tasks = result if isinstance(result, list) else result.get("tasks", [])
        loom_tasks = [t for t in tasks if t.get("kind") == "command"]
        return {"tasks": loom_tasks, "count": len(loom_tasks)}

    registry.register(
        name="list_processes",
        description=(
            "List command-kind tasks, optionally filtered by status "
            "(default: 'running'). Returns only Loom (kind='command') tasks. "
            "Use list_hosts to see which runner each task is executing on."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["queued", "claimed", "running", "done", "failed", "cancelled", "timed_out"],
                    "default": "running",
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
            },
        },
        handler=list_processes,
    )

    # ── await_result ───────────────────────────────────────────────────────────

    async def await_result(args: dict[str, Any]) -> dict[str, Any]:
        task_id = int(args["task_id"])
        timeout_seconds = int(args.get("timeout_seconds", 1800))
        poll_seconds = float(args.get("poll_seconds", 2.0))
        deadline = asyncio.get_event_loop().time() + timeout_seconds
        while True:
            task = await client.get_task(task_id)
            if task["status"] in TERMINAL_STATES:
                return task
            if asyncio.get_event_loop().time() >= deadline:
                return {
                    "task": task,
                    "timed_out_waiting": True,
                    "elapsed_seconds": timeout_seconds,
                }
            await asyncio.sleep(poll_seconds)

    registry.register(
        name="await_result",
        description=(
            "Block (server-side) until a Loom task reaches a terminal state "
            "or the timeout elapses. Returns the final task record including "
            "exit_code. Use read_output while waiting to stream output."
        ),
        input_schema={
            "type": "object",
            "required": ["task_id"],
            "properties": {
                "task_id": {"type": "integer"},
                "timeout_seconds": {"type": "integer", "default": 1800},
                "poll_seconds": {"type": "number", "default": 2.0},
            },
        },
        handler=await_result,
    )

    # ── discover_hub ───────────────────────────────────────────────────────────

    async def discover_hub(args: dict[str, Any]) -> dict[str, Any]:
        from forgewire_fabric.hub.discovery import discover_hubs_beacon, discover_hubs

        timeout = float(args.get("timeout_seconds", 3.0))
        beacon_hits = discover_hubs_beacon(timeout=min(timeout * 0.4, 1.5))
        mdns_hits = discover_hubs(timeout=max(timeout * 0.6, 2.0))
        seen: set[str] = set()
        hubs: list[dict[str, Any]] = []
        for h in beacon_hits + mdns_hits:
            key = f"{h['host']}:{h['port']}"
            if key not in seen:
                seen.add(key)
                hubs.append(h)
        return {"hubs": hubs}

    registry.register(
        name="discover_hub",
        description=(
            "Scan the local LAN for ForgeWire hubs via UDP beacon (Rust hub) "
            "and mDNS (Python hub). Returns a list of {host, port, "
            "protocol_version, token_hash, name} dicts."
        ),
        input_schema={
            "type": "object",
            "properties": {"timeout_seconds": {"type": "number", "default": 3.0}},
        },
        handler=discover_hub,
    )

    # ── get_task / list_tasks (observability passthrough) ─────────────────────

    registry.register(
        name="get_task",
        description="Fetch the current state of a Loom task by id.",
        input_schema={
            "type": "object",
            "required": ["task_id"],
            "properties": {"task_id": {"type": "integer"}},
        },
        handler=lambda args: client.get_task(int(args["task_id"])),
    )


# ── server entrypoint ──────────────────────────────────────────────────────────


async def _run() -> None:
    logging.basicConfig(level=logging.INFO)
    client = load_client_from_env()
    session = DispatcherSession.load_or_create()
    await session.register(client)
    server = Server("forgewire-loom")
    registry = ToolRegistry()
    _register_tools(registry, client, session)
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
        await client.aclose()


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
