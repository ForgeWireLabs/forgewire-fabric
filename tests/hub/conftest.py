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
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request

import pytest


def _reachable(host: str = "127.0.0.1", port: int = 4001) -> bool:
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/status", timeout=2) as r:
            data = json.loads(r.read())
            # Accept any response — leader may still be electing on fresh start
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
    """Ensure rqlite is running before any hub tests execute."""
    if _reachable():
        _drain_stale_test_tasks()
        return
    print("\nrqlite not reachable — attempting to start service...")
    _start_rqlite_service()
    for i in range(1, 31):
        time.sleep(1)
        if _reachable():
            print(f"rqlite ready after {i}s")
            _drain_stale_test_tasks()
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
def _clean_task_queue():
    """Cancel all queued tasks before each test so inter-test contamination
    cannot cause competitive claims to pick up the wrong task."""
    _drain_stale_test_tasks()
    yield


def _drain_stale_test_tasks(host: str = "127.0.0.1", port: int = 4001) -> None:
    """Cancel all queued tasks left behind by previous test runs.

    Tests dispatch tasks into the shared rqlite cluster.  If they exit before
    submitting a result (assertion failure, KeyboardInterrupt, crash) those
    tasks remain in 'queued' state and pollute competitive-claim tests in
    subsequent runs.  Mark them all cancelled before each session so the
    queue is clean.
    """
    try:
        with urllib.request.urlopen(
            f"http://{host}:{port}/db/execute",
            data=json.dumps(
                [["UPDATE tasks SET status = 'cancelled', cancel_requested = 1 "
                  "WHERE status = 'queued'"]]
            ).encode("utf-8"),
            timeout=5,
        ) as r:
            r.read()
    except Exception as exc:
        print(f"\n[conftest] stale-task drain failed (non-fatal): {exc}")
