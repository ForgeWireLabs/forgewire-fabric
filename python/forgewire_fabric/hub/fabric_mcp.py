"""MCP server (dispatcher side) — Fabric surface for agent-kind task dispatch.

Replaces ``dispatcher_mcp.py`` for agent tasks.  The existing
``dispatcher_mcp`` module is a deprecated shim that re-exports from here
(will be removed in M2.8.9).

Server name advertised to MCP clients: ``forgewire-fabric``

Tools:
  list_agents       -- Fabric runner registry with mcp_manifest and state
  dispatch_skill    -- capability-routed: invoke a named prompt on an agent
  dispatch_tool     -- capability-routed: call a named tool on an agent
  dispatch_prompt   -- freeform fallback (existing Phase 2.5 behaviour)
  await_result      -- block until terminal state
  read_stream       -- pull stdout/stderr lines since seq N
  stream_progress   -- pull progress beats since seq N
  post_note         -- dispatcher -> runner back-channel
  read_notes        -- read runner -> dispatcher notes
  cancel_task       -- cancel in-flight task
  drain_agent       -- dispatcher-initiated runner drain (renamed drain_runner)
  discover_hub      -- mDNS + UDP beacon hub discovery

Env knobs:
  FORGEWIRE_HUB_URL          -- hub base URL (optional; falls back to mDNS)
  FORGEWIRE_HUB_TOKEN_FILE   -- path to bearer token file
"""

from __future__ import annotations

import asyncio
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
from forgewire_fabric.runner.runner_capabilities import fresh_nonce, now_ts, sign_payload

LOGGER = logging.getLogger("forgewire_fabric.fabric_mcp")

TERMINAL_STATES = {"done", "failed", "cancelled", "timed_out"}


class DispatcherSession:
    """Dispatcher identity for signed ``POST /tasks/v2`` (protocol v3 Rust hub).

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
                "label": f"fabric-mcp@{platform.node()}",
                "hostname": platform.node(),
                "metadata": {"source": "fabric_mcp"},
            })
            self.registered = True
            LOGGER.info("dispatcher registered: %s", self.dispatcher_id)
        except BlackboardError as exc:
            LOGGER.warning("dispatcher registration failed (%s); unsigned dispatch will be used on Python hubs", exc)

    def build_signed_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return a fully-formed signed ``POST /tasks/v2`` body for an agent brief.

        The returned body carries the same canonical brief fields the signature
        covers (``scope_globs``/``base_commit``/``branch`` and the rest) so the
        body validates against the hub's required-field schema and matches the
        signature exactly. The capability-routed dispatchers nest these under
        ``context``; we lift them to the top level here. The agent-routing
        fields (``dispatch``/``skill``/``tool``/``args``/``input``/``target``)
        are out-of-band body fields the hub reads but does not require in the
        signed set — they pass through unchanged.
        """
        ts = now_ts()
        nonce = fresh_nonce()
        context = payload.get("context") or {}
        scope_globs = payload.get("scope_globs")
        if scope_globs is None:
            scope_globs = context.get("scope_globs") or []
        base_commit = payload.get("base_commit") or context.get("base_commit") or ("0" * 40)
        branch = payload.get("branch") or context.get("branch") or ""
        brief: dict[str, Any] = {
            "title": payload.get("title") or "",
            "prompt": payload.get("prompt") or "",
            "scope_globs": scope_globs,
            "base_commit": base_commit,
            "branch": branch,
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
            "kind": payload.get("kind") or "agent",
            "max_cost_usd": payload.get("max_cost_usd"),
        }
        envelope: dict[str, Any] = {
            "op": "dispatch",
            "dispatcher_id": self.dispatcher_id,
            **brief,
            "timestamp": ts,
            "nonce": nonce,
        }
        sig = sign_payload(self._identity, envelope)
        # Agent-routing body fields (out-of-band; hub reads, signature does not cover).
        routing = {
            k: payload[k]
            for k in ("dispatch", "skill", "tool", "args", "input", "target")
            if k in payload
        }
        return {
            **brief,
            **routing,
            "dispatcher_id": self.dispatcher_id,
            "timestamp": ts,
            "nonce": nonce,
            "signature": sig,
        }


async def _dispatch(
    client: BlackboardClient,
    session: "DispatcherSession | None",
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Send a dispatch, using signed POST /tasks/v2 when a session is present."""
    if session is not None and session.registered:
        return await client.dispatch_task_signed(session.build_signed_payload(payload))
    # Fallback: unsigned (Python hub with require_signed_dispatch=false).
    return await client.dispatch_task(payload)

# ── helpers ────────────────────────────────────────────────────────────────────


def _no_capability_error(kind: str, name: str) -> dict[str, Any]:
    return {
        "error": "no_runner_advertises_capability",
        "capability_kind": kind,
        "capability_name": name,
        "hint": (
            f"No online agent runner has '{name}' in its mcp_manifest. "
            "Run list_agents to see available capabilities, or use "
            "dispatch_prompt for freeform routing."
        ),
    }


async def _validate_capability(
    client: BlackboardClient, kind: str, name: str
) -> dict[str, Any] | None:
    """Return None if at least one online runner advertises the capability, else an error dict."""
    try:
        result = await client.query_capability(kind, name)
        runners = result.get("runners") or []
        online = [r for r in runners if r.get("state") == "online"]
        if online:
            return None
        return _no_capability_error(kind, name)
    except BlackboardError as exc:
        if exc.status_code == 404:
            return _no_capability_error(kind, name)
        raise


# ── tool registration ──────────────────────────────────────────────────────────


def _register_tools(
    registry: ToolRegistry,
    client: BlackboardClient,
    session: "DispatcherSession | None" = None,
) -> None:

    # ── list_agents ────────────────────────────────────────────────────────────

    async def list_agents(_args: dict[str, Any]) -> dict[str, Any]:
        return await client.list_agents()

    registry.register(
        name="list_agents",
        description=(
            "Return all Fabric runners (runners with 'agent' in kinds) with "
            "their agent_type, hostname, state, full mcp_manifest, and load. "
            "Use this to discover which agents are online, what skills/tools/"
            "resources they advertise, and to pick a target runner_id for "
            "pinned dispatch."
        ),
        input_schema={"type": "object", "properties": {}},
        handler=list_agents,
    )

    # ── dispatch_skill ─────────────────────────────────────────────────────────

    async def dispatch_skill(args: dict[str, Any]) -> dict[str, Any]:
        skill = str(args["skill"])
        # Validate capability before submit.
        cap_error = await _validate_capability(client, "prompt", skill)
        if cap_error:
            return cap_error

        context = args.get("context") or {}
        target = args.get("target") or {}
        payload: dict[str, Any] = {
            "kind": "agent",
            "dispatch": "skill",
            "skill": skill,
            "args": args.get("args") or {},
            "title": args.get("title") or f"skill: {skill}",
            "context": {
                "repo": context.get("repo"),
                "base_commit": context.get("base_commit"),
                "branch": context.get("branch"),
                "scope_globs": context.get("scope_globs") or [],
            },
            "target": {
                "agent_type": target.get("agent_type"),
                "runner_id": target.get("runner_id"),
                "required_tools": target.get("required_tools") or [],
                "required_resources": target.get("required_resources") or [],
                "tenant": target.get("tenant"),
            },
            "metadata": args.get("metadata") or {},
        }
        return await _dispatch(client, session, payload)

    registry.register(
        name="dispatch_skill",
        description=(
            "Capability-routed dispatch: invoke a named prompt (skill) "
            "advertised in an agent's mcp_manifest.servers[*].prompts[*]. "
            "Validates that at least one online agent has the skill before "
            "queuing; returns no_runner_advertises_capability otherwise. "
            "Use list_agents to browse available skills."
        ),
        input_schema={
            "type": "object",
            "required": ["skill"],
            "properties": {
                "skill": {
                    "type": "string",
                    "description": "Prompt name as advertised in the agent manifest (e.g. 'code-review').",
                },
                "args": {
                    "type": "object",
                    "description": "Arguments passed to the prompt per its argument schema.",
                    "additionalProperties": True,
                },
                "title": {"type": "string"},
                "context": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": ["string", "null"]},
                        "base_commit": {"type": ["string", "null"]},
                        "branch": {"type": ["string", "null"]},
                        "scope_globs": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "target": {
                    "type": "object",
                    "properties": {
                        "agent_type": {"type": ["string", "null"]},
                        "runner_id": {"type": ["string", "null"]},
                        "required_tools": {"type": "array", "items": {"type": "string"}},
                        "required_resources": {"type": "array", "items": {"type": "string"}},
                        "tenant": {"type": ["string", "null"]},
                    },
                },
                "metadata": {"type": "object"},
            },
        },
        handler=dispatch_skill,
    )

    # ── dispatch_tool ──────────────────────────────────────────────────────────

    async def dispatch_tool(args: dict[str, Any]) -> dict[str, Any]:
        tool = str(args["tool"])
        cap_error = await _validate_capability(client, "tool", tool)
        if cap_error:
            return cap_error

        context = args.get("context") or {}
        target = args.get("target") or {}
        payload: dict[str, Any] = {
            "kind": "agent",
            "dispatch": "tool",
            "tool": tool,
            "input": args.get("input") or {},
            "title": args.get("title") or f"tool: {tool}",
            "context": {
                "repo": context.get("repo"),
                "base_commit": context.get("base_commit"),
                "branch": context.get("branch"),
                "scope_globs": context.get("scope_globs") or [],
            },
            "target": {
                "agent_type": target.get("agent_type"),
                "runner_id": target.get("runner_id"),
                "required_tools": target.get("required_tools") or [],
                "required_resources": target.get("required_resources") or [],
                "tenant": target.get("tenant"),
            },
            "metadata": args.get("metadata") or {},
        }
        return await _dispatch(client, session, payload)

    registry.register(
        name="dispatch_tool",
        description=(
            "Capability-routed dispatch: call a specific MCP tool advertised "
            "in an agent's mcp_manifest.servers[*].tools[*]. Validates "
            "capability before queuing. Use list_agents to browse available tools."
        ),
        input_schema={
            "type": "object",
            "required": ["tool"],
            "properties": {
                "tool": {
                    "type": "string",
                    "description": "Tool name as advertised in the agent manifest (e.g. 'git__commit').",
                },
                "input": {
                    "type": "object",
                    "description": "Input arguments for the tool per its input_schema.",
                    "additionalProperties": True,
                },
                "title": {"type": "string"},
                "context": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": ["string", "null"]},
                        "base_commit": {"type": ["string", "null"]},
                        "branch": {"type": ["string", "null"]},
                        "scope_globs": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "target": {
                    "type": "object",
                    "properties": {
                        "agent_type": {"type": ["string", "null"]},
                        "runner_id": {"type": ["string", "null"]},
                        "required_tools": {"type": "array", "items": {"type": "string"}},
                        "required_resources": {"type": "array", "items": {"type": "string"}},
                        "tenant": {"type": ["string", "null"]},
                    },
                },
                "metadata": {"type": "object"},
            },
        },
        handler=dispatch_tool,
    )

    # ── dispatch_prompt ────────────────────────────────────────────────────────

    async def dispatch_prompt(args: dict[str, Any]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": "agent",
            "dispatch": "prompt",
            "title": args.get("title") or "Freeform agent task",
            "prompt": str(args["prompt"]),
            "scope_globs": args.get("scope_globs") or [],
            "base_commit": args.get("base_commit"),
            "branch": args.get("branch"),
            "todo_id": args.get("todo_id"),
            "timeout_minutes": args.get("timeout_minutes"),
            "priority": args.get("priority"),
            "required_tools": args.get("required_tools") or [],
            "required_tags": args.get("required_tags") or [],
            "tenant": args.get("tenant"),
            "workspace_root": args.get("workspace_root"),
            "require_base_commit": args.get("require_base_commit", False),
            "metadata": args.get("metadata") or {},
        }
        return await _dispatch(client, session, payload)

    registry.register(
        name="dispatch_prompt",
        description=(
            "Freeform agent task dispatch — the existing Phase 2.5 behaviour, "
            "now explicit. Routes to any eligible agent runner without "
            "capability filtering. Use dispatch_skill or dispatch_tool when "
            "the target capability is known for deterministic routing."
        ),
        input_schema={
            "type": "object",
            "required": ["prompt"],
            "properties": {
                "title": {"type": "string"},
                "prompt": {"type": "string"},
                "scope_globs": {"type": "array", "items": {"type": "string"}},
                "base_commit": {"type": ["string", "null"]},
                "branch": {"type": ["string", "null"]},
                "todo_id": {"type": ["string", "null"]},
                "timeout_minutes": {"type": "integer", "minimum": 1, "maximum": 720},
                "priority": {"type": "integer"},
                "required_tools": {"type": "array", "items": {"type": "string"}},
                "required_tags": {"type": "array", "items": {"type": "string"}},
                "tenant": {"type": ["string", "null"]},
                "workspace_root": {"type": ["string", "null"]},
                "require_base_commit": {"type": "boolean"},
                "metadata": {"type": "object"},
            },
        },
        handler=dispatch_prompt,
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
            "Block (server-side) until a task reaches a terminal state or the "
            "timeout elapses. Returns the final task record."
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

    # ── read_stream ────────────────────────────────────────────────────────────

    async def read_stream(args: dict[str, Any]) -> dict[str, Any]:
        lines = await client.read_stream(
            int(args["task_id"]),
            after_seq=int(args.get("after_seq", 0)),
            limit=int(args.get("limit", 500)),
        )
        return {"lines": lines}

    registry.register(
        name="read_stream",
        description=(
            "Read structured stdout/stderr/info lines emitted by the agent "
            "runner for a task, since after_seq. Use to follow long-running "
            "skill or build output without re-pulling progress beats."
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
        handler=read_stream,
    )

    # ── stream_progress ────────────────────────────────────────────────────────

    async def stream_progress(args: dict[str, Any]) -> dict[str, Any]:
        task_id = int(args["task_id"])
        after_seq = int(args.get("after_seq", 0))
        task = await client.get_task(task_id)
        events: list[dict[str, Any]] = []
        try:
            async for event_name, raw in client.stream_events(task_id):
                if event_name == "progress":
                    import json as _json
                    payload = _json.loads(raw)
                    if payload.get("seq", 0) > after_seq:
                        events.append(payload)
                if event_name == "task":
                    break
        except Exception as exc:
            LOGGER.warning("stream_progress fallthrough: %s", exc)
        return {"task": task, "progress": events}

    registry.register(
        name="stream_progress",
        description=(
            "Poll any new progress beats (and current task state) for a task. "
            "Returns immediately after one event-stream pass."
        ),
        input_schema={
            "type": "object",
            "required": ["task_id"],
            "properties": {
                "task_id": {"type": "integer"},
                "after_seq": {"type": "integer", "default": 0},
            },
        },
        handler=stream_progress,
    )

    # ── post_note ──────────────────────────────────────────────────────────────

    registry.register(
        name="post_note",
        description="Post a free-form note onto a task (dispatcher -> runner channel).",
        input_schema={
            "type": "object",
            "required": ["task_id", "body"],
            "properties": {
                "task_id": {"type": "integer"},
                "author": {"type": "string", "default": "dispatcher"},
                "body": {"type": "string"},
            },
        },
        handler=lambda args: client.post_note(
            int(args["task_id"]),
            {"author": args.get("author", "dispatcher"), "body": args["body"]},
        ),
    )

    # ── read_notes ─────────────────────────────────────────────────────────────

    registry.register(
        name="read_notes",
        description="Read notes for a task posted after the given id (default 0).",
        input_schema={
            "type": "object",
            "required": ["task_id"],
            "properties": {
                "task_id": {"type": "integer"},
                "after_id": {"type": "integer", "default": 0},
            },
        },
        handler=lambda args: client.read_notes(
            int(args["task_id"]), after_id=int(args.get("after_id", 0))
        ),
    )

    # ── cancel_task ────────────────────────────────────────────────────────────

    registry.register(
        name="cancel_task",
        description=(
            "Request cancellation of a task. Queued tasks terminate immediately; "
            "running tasks set a cancel_requested flag the runner should honour."
        ),
        input_schema={
            "type": "object",
            "required": ["task_id"],
            "properties": {"task_id": {"type": "integer"}},
        },
        handler=lambda args: client.cancel_task(int(args["task_id"])),
    )

    # ── drain_agent ────────────────────────────────────────────────────────────

    async def drain_agent(args: dict[str, Any]) -> dict[str, Any]:
        return await client.drain_runner_by_dispatcher(str(args["runner_id"]))

    registry.register(
        name="drain_agent",
        description=(
            "Dispatcher-initiated agent runner drain. The hub stops handing out "
            "new tasks to the runner; in-flight tasks complete normally. "
            "(Renamed from drain_runner to make the Fabric boundary explicit. "
            "drain_runner is kept as a deprecated alias in dispatcher_mcp shim.)"
        ),
        input_schema={
            "type": "object",
            "required": ["runner_id"],
            "properties": {"runner_id": {"type": "string"}},
        },
        handler=drain_agent,
    )

    # ── drain_runner (deprecated alias for drain_agent) ────────────────────────

    async def drain_runner_compat(args: dict[str, Any]) -> dict[str, Any]:
        LOGGER.warning(
            "drain_runner is deprecated; use drain_agent instead. "
            "This tool alias will be removed in M2.8.9."
        )
        return await drain_agent(args)

    registry.register(
        name="drain_runner",
        description=(
            "[DEPRECATED — use drain_agent] Dispatcher-initiated runner drain. "
            "Kept for one release cycle; will be removed in M2.8.9."
        ),
        input_schema={
            "type": "object",
            "required": ["runner_id"],
            "properties": {"runner_id": {"type": "string"}},
        },
        handler=drain_runner_compat,
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
        description="Fetch the current state of a task by id.",
        input_schema={
            "type": "object",
            "required": ["task_id"],
            "properties": {"task_id": {"type": "integer"}},
        },
        handler=lambda args: client.get_task(int(args["task_id"])),
    )

    registry.register(
        name="list_tasks",
        description="List tasks, optionally filtered by status.",
        input_schema={
            "type": "object",
            "properties": {
                "status": {
                    "type": ["string", "null"],
                    "enum": [None, "queued", "claimed", "running", "done", "failed", "cancelled", "timed_out"],
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            },
        },
        handler=lambda args: client.list_tasks(
            status=args.get("status"), limit=int(args.get("limit", 100))
        ),
    )


# ── server entrypoint ──────────────────────────────────────────────────────────


async def _run() -> None:
    logging.basicConfig(level=logging.INFO)
    client = load_client_from_env()
    # Load (or generate) a dispatcher identity and register with the hub so
    # dispatch goes through signed POST /tasks/v2 (required by the Rust hub).
    session = DispatcherSession.load_or_create()
    await session.register(client)
    server = Server("forgewire-fabric")
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
