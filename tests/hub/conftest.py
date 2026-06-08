"""Hub test configuration.

rqlite is the only supported hub backend (SQLite retired M2.7.3).
rqlite is a required ForgeWire Fabric dependency — tests do not skip when it
is unavailable, they fail hard. If rqlite is not running, this fixture starts
the NSSM service and waits up to 30 s. If it still isn't up, the session
aborts with a clear message.

Start rqlite manually if the service is not installed:
    Windows:  nssm start ForgeWireRqliteNode1
    Linux:    systemctl start forgewire-rqlite
    Manual:   rqlited -node-id n1 -http-addr 127.0.0.1:4001 -raft-addr 127.0.0.1:4002 ~/rqlite/n1

HARD INVARIANT: only the two real machines (DESKTOP-38GVF8D and DESKTOP-228U8GL)
may ever appear in the runners or dispatchers tables.  The cleanup fixture below
enforces this after every test.  Tests must NEVER call POST /runners/register or
POST /dispatchers/register.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request

import pytest

# The two real cluster machines. Any other runner or dispatcher is a ghost.
_REAL_RUNNERS = {"DESKTOP-38GVF8D-runner", "DESKTOP-228U8GL-runner"}
_REAL_HOSTNAMES = {"DESKTOP-38GVF8D", "DESKTOP-228U8GL",
                   "desktop-38gvf8d", "desktop-228u8gl"}


def _reachable(host: str = "127.0.0.1", port: int = 4001) -> bool:
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/status", timeout=2) as r:
            data = json.loads(r.read())
            return isinstance(data, dict)
    except Exception:
        return False


def _start_rqlite_service() -> None:
    if sys.platform.startswith("win"):
        for svc in ("ForgeWireRqlite", "ForgeWireRqliteNode1", "ForgeWireRqliteNode2"):
            try:
                r = subprocess.run(["nssm", "start", svc], capture_output=True, timeout=10)
                if r.returncode == 0:
                    return
            except Exception:
                continue
    elif sys.platform.startswith("linux"):
        subprocess.run(["systemctl", "start", "forgewire-rqlite"],
                       capture_output=True, timeout=10)
    elif sys.platform == "darwin":
        subprocess.run(["launchctl", "start", "com.forgewire.rqlite"],
                       capture_output=True, timeout=10)


def pytest_sessionstart(session: pytest.Session) -> None:
    """Ensure rqlite is running and the cluster is clean before any hub test."""
    if _reachable():
        _enforce_cluster_invariant()
        return
    print("\nrqlite not reachable — attempting to start service...")
    _start_rqlite_service()
    for i in range(1, 31):
        time.sleep(1)
        if _reachable():
            print(f"rqlite ready after {i}s")
            _enforce_cluster_invariant()
            return
    pytest.exit(
        "\n\nFATAL: rqlite not available on 127.0.0.1:4001 after 30s.\n"
        "rqlite is a required ForgeWire Fabric dependency.\n"
        "  Windows: nssm start ForgeWireRqliteNode1\n"
        "  Linux:   systemctl start forgewire-rqlite\n"
        "  Install: scripts/install/install-fabric.ps1\n",
        returncode=1,
    )


@pytest.fixture(autouse=True)
def _cluster_guard():
    """Enforce cluster invariant before AND after every test.

    Before: cancel queued tasks so competitive claims don't pick up stale work.
    After: remove any ghost runners/dispatchers/workers the test created.
    """
    _enforce_cluster_invariant()
    yield
    _enforce_cluster_invariant()


def _enforce_cluster_invariant(host: str = "127.0.0.1", port: int = 4001) -> None:
    """Delete ghost runners/dispatchers and cancel stale queued tasks.

    Safe to call repeatedly — all statements are idempotent.
    """
    statements = [
        # Cancel tasks that tests left in queued state.
        ["UPDATE tasks SET status = 'cancelled', cancel_requested = 1 "
         "WHERE status = 'queued'"],
        # Delete any runner that isn't one of the two real machines.
        ["DELETE FROM runners WHERE runner_id NOT IN "
         "('DESKTOP-38GVF8D-runner', 'DESKTOP-228U8GL-runner')"],
        # Delete all dispatchers — no test should register one; real dispatchers
        # re-register themselves on next heartbeat.
        ["DELETE FROM dispatchers"],
        # Delete workers added by test legacy-claim calls.
        ["DELETE FROM workers WHERE hostname NOT IN "
         "('DESKTOP-38GVF8D', 'DESKTOP-228U8GL') "
         "OR hostname IS NULL"],
        # Remove nonces that belong to deleted runners.
        ["DELETE FROM runner_nonces WHERE runner_id NOT IN "
         "(SELECT runner_id FROM runners)"],
    ]
    try:
        with urllib.request.urlopen(
            f"http://{host}:{port}/db/execute",
            data=json.dumps(statements).encode("utf-8"),
            timeout=5,
        ) as r:
            r.read()
    except Exception as exc:
        print(f"\n[conftest] cluster invariant enforcement failed (non-fatal): {exc}")
