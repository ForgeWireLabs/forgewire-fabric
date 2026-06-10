"""Deprecated shim — use ``forgewire_fabric.hub.fabric_mcp`` instead.

This module is kept for one minor cycle so existing MCP configs that reference
``forgewire_fabric.hub.dispatcher_mcp`` continue to work.  It emits a one-shot
deprecation warning at import time, re-exports everything from
``fabric_mcp``, and registers two compatibility aliases:

* ``dispatch_task``  → thin wrapper that calls ``dispatch_prompt`` (legacy shape)
* ``drain_runner``   → alias for ``drain_agent`` (renamed in M2.8.6)

Will be removed in M2.8.9.
"""

from __future__ import annotations

import asyncio
import logging
import warnings

warnings.warn(
    "forgewire_fabric.hub.dispatcher_mcp is deprecated; "
    "use forgewire_fabric.hub.fabric_mcp instead. "
    "This shim will be removed in M2.8.9.",
    DeprecationWarning,
    stacklevel=2,
)

logging.getLogger("forgewire_fabric.dispatcher_mcp").warning(
    "dispatcher_mcp is a deprecated shim; please update your MCP config to use "
    "fabric_mcp. This shim will be removed in M2.8.9."
)

from forgewire_fabric.hub.fabric_mcp import (  # noqa: F401, E402
    _register_tools,
    _run,
    main,
    TERMINAL_STATES,
)
from forgewire_fabric.hub.client import (  # noqa: F401, E402
    BlackboardClient,
    BlackboardError,
    load_client_from_env,
)
from forgewire_fabric.hub.mcp_common import ToolRegistry  # noqa: F401

from mcp.server import Server  # noqa: F401
from mcp.server.stdio import stdio_server  # noqa: F401

LOGGER = logging.getLogger("forgewire_fabric.dispatcher_mcp")

__all__ = [
    "_register_tools",
    "_run",
    "main",
    "TERMINAL_STATES",
]

if __name__ == "__main__":
    main()
