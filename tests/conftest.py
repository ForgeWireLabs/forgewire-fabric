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

# The only two real machines in the cluster. Any other runner/worker is a ghost.
_REAL_RUNNERS = frozenset({"DESKTOP-38GVF8D-runner", "DESKTOP-228U8GL-runner"})
_REAL_HOSTNAMES = frozenset({"DESKTOP-38GVF8D", "DESKTOP-228U8GL",
                              "desktop-38gvf8d", "desktop-228u8gl"})


def _rqlite_available(host: str = "127.0.0.1", port: int = 4001) -> bool:
    """True if a rqlite node is reachable and has an elected leader."""
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/status", timeout=2) as r:
            data = json.loads(r.read())
            return bool(data.get("store", {}).get("leader", {}).get("addr", ""))
    except Exception:
        return False


RQLITE_UP = _rqlite_available()

_RQLITE_EXECUTE_URL = "http://127.0.0.1:4001/db/execute"


def _enforce_cluster_invariant() -> None:
    """Delete ghost runners/workers and cancel stale queued tasks.

    Called before and after every test so no test can pollute the cluster
    with ghost state that affects subsequent tests.
    """
    real_ids = ", ".join(f"'{r}'" for r in sorted(_REAL_RUNNERS))
    real_hosts = ", ".join(f"'{h}'" for h in sorted(_REAL_HOSTNAMES))
    stmts = [
        # Ghost runners / workers / nonces
        [f"DELETE FROM runners WHERE runner_id NOT IN ({real_ids})"],
        [f"DELETE FROM workers WHERE hostname NOT IN ({real_hosts}) OR hostname IS NULL"],
        ["DELETE FROM runner_nonces WHERE runner_id NOT IN (SELECT runner_id FROM runners)"],
        # Stale tasks — cancel queued so they don't pollute the next test's claim
        ["UPDATE tasks SET status='cancelled', cancel_requested=1 WHERE status='queued'"],
        # Approvals — test artifacts; real approvals are acted on promptly
        ["DELETE FROM approvals"],
        # Ghost dispatchers registered by test helpers
        ["DELETE FROM dispatchers"],
        ["DELETE FROM dispatcher_nonces"],
        # Test secrets — names end with _XXXXXXXX (8-char hex suffix from test helpers)
        ["DELETE FROM secrets WHERE name GLOB '*_[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]'"],
    ]
    try:
        data = json.dumps(stmts).encode()
        req = urllib.request.Request(
            _RQLITE_EXECUTE_URL, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as exc:
        print(f"\n[conftest] cluster invariant enforcement failed (non-fatal): {exc}")


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


@pytest.fixture(autouse=True)
def _global_cluster_guard() -> None:
    """Enforce cluster invariant before and after every test.

    Deletes ghost runners/workers and cancels stale queued tasks so no
    test can pollute the shared rqlite cluster for subsequent tests.
    Only runs when rqlite is reachable.
    """
    if not RQLITE_UP:
        yield
        return
    _enforce_cluster_invariant()
    yield
    _enforce_cluster_invariant()


# SQLite backend was retired in M2.7.3. rqlite is the only valid backend.
# Hub tests that use create_app() run against rqlite; if rqlite is unavailable
# the test suite still passes for unit tests that use in-memory mocks.
