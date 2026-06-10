"""MCP manifest introspection for Fabric runners.

Builds the ``mcp_manifest`` blob sent to the hub on registration and on
heartbeats when the connected-server topology changes. Loom (command-kind)
runners never import this module — the lazy import is deliberate.

The manifest format matches the wire spec from
``todos/114-forgewire-fabric/phase-2.8-loom-fabric-surface-split.md``:

.. code-block:: json

    {
      "schema_version": 1,
      "servers": [
        {
          "server_id": "...",
          "tools":     [{"name": "...", "description": "...", "input_schema": {...}}],
          "resources": [{"uri":  "...", "name": "...",        "mime_type": "..."}],
          "prompts":   [{"name": "...", "description": "...", "arguments": [...]}]
        }
      ]
    }
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

LOGGER = logging.getLogger("forgewire_fabric.runner.mcp_introspection")

MANIFEST_SCHEMA_VERSION = 1


def build_mcp_manifest(registry: Any = None) -> dict[str, Any] | None:
    """Build the ``mcp_manifest`` blob from the local MCP server registry.

    Performs a lazy import of ``MCPServerRegistry`` so Loom runners that
    never call this function never pay the import cost.

    Args:
        registry: An ``MCPServerRegistry`` instance (or duck-typed equivalent).
                  When ``None`` the function attempts to locate the running
                  ForgeWire app's registry via
                  ``core.services.integrations.mcp.MCPServerRegistry``.
                  Returns ``None`` (with a warning) if the import fails or the
                  registry has no connected servers.

    Returns:
        A manifest dict ready to JSON-serialise into the registration body, or
        ``None`` when introspection is unavailable.
    """
    reg = registry
    if reg is None:
        try:
            from core.services.integrations.mcp.registry import MCPServerRegistry  # noqa: F401
        except ImportError as exc:
            LOGGER.debug("MCPServerRegistry not available (%s); skipping manifest build", exc)
            return None

    try:
        connected = reg.list_connected_servers() if reg is not None else []
    except Exception as exc:
        LOGGER.warning("list_connected_servers() failed: %s", exc)
        return None

    if not connected:
        return None

    servers: list[dict[str, Any]] = []
    for info in connected:
        server_entry: dict[str, Any] = {"server_id": info.server_id}

        tools = []
        for t in (info.tools or []):
            entry: dict[str, Any] = {"name": t.name, "description": t.description or ""}
            if t.input_schema:
                entry["input_schema"] = t.input_schema
            tools.append(entry)
        if tools:
            server_entry["tools"] = tools

        resources = []
        for r in (info.resources or []):
            resources.append({
                "uri": r.uri,
                "name": r.name or "",
                "mime_type": getattr(r, "mime_type", ""),
            })
        if resources:
            server_entry["resources"] = resources

        prompts = []
        for p in (info.prompts or []):
            args = []
            for a in (p.arguments or []):
                args.append({
                    "name": a.name,
                    "description": a.description or "",
                    "required": bool(getattr(a, "required", False)),
                })
            prompt_entry: dict[str, Any] = {
                "name": p.name,
                "description": p.description or "",
            }
            if args:
                prompt_entry["arguments"] = args
            prompts.append(prompt_entry)
        if prompts:
            server_entry["prompts"] = prompts

        servers.append(server_entry)

    return {"schema_version": MANIFEST_SCHEMA_VERSION, "servers": servers}


def manifest_hash(manifest: dict[str, Any] | None) -> str:
    """Return a stable hex digest of ``manifest`` for change detection.

    Comparing digests on each heartbeat is cheaper than a deep structural
    comparison. An empty string is returned when ``manifest`` is ``None``.
    """
    if manifest is None:
        return ""
    serialised = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(serialised).hexdigest()
