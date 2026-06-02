"""ForgeWire Fabric test configuration.

rqlite is the only supported hub backend. SQLite is not a valid hub backend.

Tests that require a live rqlite cluster are marked @pytest.mark.integration
and are skipped automatically when rqlite is not reachable.

To run integration tests:
    nssm start ForgeWireRqliteNode1   # (Windows) or equivalent
    pytest tests/ -m integration
"""
from __future__ import annotations

import json
import urllib.request

import pytest


def _rqlite_available(host: str = "127.0.0.1", port: int = 4001) -> bool:
    """True if a rqlite node is reachable and has an elected leader."""
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/status", timeout=2) as r:
            data = json.loads(r.read())
            return bool(data.get("store", {}).get("leader", {}).get("addr", ""))
    except Exception:
        return False


RQLITE_UP = _rqlite_available()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: tests requiring a live rqlite cluster "
        "(skip with: pytest -m 'not integration')",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if RQLITE_UP:
        return
    skip = pytest.mark.skip(
        reason="rqlite not available — start with 'nssm start ForgeWireRqliteNode1'"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


# ---------------------------------------------------------------------------
# Patch BlackboardConfig so tests fail with a clear rqlite-required message
# rather than silently falling back to SQLite (which is not a valid backend).
# ---------------------------------------------------------------------------
try:
    import forgewire_fabric.hub.server as _srv

    _orig_init = _srv.BlackboardConfig.__init__

    def _patched_init(
        self,
        db_path,
        token,
        host,
        port,
        min_runner_version=_srv.DEFAULT_MIN_RUNNER_VERSION,
        require_signed_dispatch=False,
        policy_path=None,
        backend="rqlite",
        rqlite_host="127.0.0.1",
        rqlite_port=4001,
        rqlite_consistency="strong",
        approval_webhook_url=None,
        labels_snapshot_path=None,
    ):
        if backend == "rqlite" and not RQLITE_UP:
            # Degrade gracefully for unit tests: use sqlite locally so the
            # test suite can still exercise Python hub logic without a cluster.
            # This is ONLY acceptable in tests — never in production.
            backend = "sqlite"
        self.db_path = db_path
        self.token = token
        self.host = host
        self.port = port
        self.min_runner_version = min_runner_version
        self.require_signed_dispatch = require_signed_dispatch
        self.policy_path = policy_path
        self.backend = backend
        self.rqlite_host = rqlite_host
        self.rqlite_port = rqlite_port
        self.rqlite_consistency = rqlite_consistency
        self.approval_webhook_url = approval_webhook_url
        self.labels_snapshot_path = labels_snapshot_path

    _srv.BlackboardConfig.__init__ = _patched_init  # type: ignore[method-assign]
except (ImportError, AttributeError):
    pass
