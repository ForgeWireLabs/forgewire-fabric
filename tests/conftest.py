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


# SQLite backend was retired in M2.7.3. rqlite is the only valid backend.
# Hub tests that use create_app() run against rqlite; if rqlite is unavailable
# the test suite still passes for unit tests that use in-memory mocks.
