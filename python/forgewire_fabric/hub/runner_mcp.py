"""Deprecated shim — use ``forgewire_fabric.hub.fabric_runner_mcp`` instead.

This module is kept for one minor cycle so existing MCP configs that reference
``forgewire_fabric.hub.runner_mcp`` continue to work.  It emits a one-shot
deprecation warning at import time and re-exports everything from the canonical
``fabric_runner_mcp`` module.

Will be removed in M2.8.9.
"""

from __future__ import annotations

import logging
import warnings

warnings.warn(
    "forgewire_fabric.hub.runner_mcp is deprecated; "
    "use forgewire_fabric.hub.fabric_runner_mcp instead. "
    "This shim will be removed in M2.8.9.",
    DeprecationWarning,
    stacklevel=2,
)

logging.getLogger("forgewire_fabric.runner_mcp").warning(
    "runner_mcp is a deprecated shim; please update your MCP config to use "
    "fabric_runner_mcp. This shim will be removed in M2.8.9."
)

from forgewire_fabric.hub.fabric_runner_mcp import (  # noqa: F401, E402
    RunnerSession,
    _build_session,
    _heartbeat_loop,
    _register_tools,
    _register_with_retries,
    _run,
    main,
    self_update_workspace,
    PROTOCOL_VERSION,
    HEARTBEAT_INTERVAL_SECONDS,
    DEFAULT_VERSION,
    SELF_UPDATE_MIN_INTERVAL_SECONDS,
)

__all__ = [
    "RunnerSession",
    "_build_session",
    "_heartbeat_loop",
    "_register_tools",
    "_register_with_retries",
    "_run",
    "main",
    "self_update_workspace",
    "PROTOCOL_VERSION",
    "HEARTBEAT_INTERVAL_SECONDS",
    "DEFAULT_VERSION",
    "SELF_UPDATE_MIN_INTERVAL_SECONDS",
]

if __name__ == "__main__":
    main()
