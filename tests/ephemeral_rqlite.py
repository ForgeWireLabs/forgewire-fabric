"""Provision a throwaway single-node rqlite for tests that write account state.

Why this exists
---------------

The rest of this suite runs against the **live shared** rqlite on
``127.0.0.1:4001`` and mutates it: ``tests/conftest.py``'s autouse guard deletes
every approval and dispatcher and cancels every queued task before and after
each test. That arrangement cannot carry 114C, in two directions.

It would erase 114C's own evidence. The live two-machine runbook dispatches
signed work and approves it from the other client, then proves the audit joins
human account, client, task, runner, and completion. ``DELETE FROM approvals``
runs before and after every test in any later session.

And it would leave ghost credentials. 114C adds ``human_accounts``,
``human_credentials``, ``human_memberships``, ``human_sessions``,
``human_refresh_uses``, ``human_recovery_codes``, and
``human_auth_challenges``; the guard cleans none of them, so test-created
accounts, sessions, passkeys, and recovery codes would accumulate in the real
cluster as durable security state. AC-114C-4 forbids ghost hosts and runners;
ghost credentials are worse. Wiping ``human_*`` per test is not an escape
either -- it would delete the account under test between its setup and its
assertion.

So: anything that writes account state uses one of these instead. The live
cluster is touched by exactly one milestone, 114C.8's runbook.

See ``work/active/114-forgewire-fabric/114C-evidence-plan.md`` (Rule 2).

Usage
-----

::

    from forgewire_fabric.hub import _rqlite_db as rdb

    def test_something(ephemeral_rqlite):
        conn = rdb.connect(ephemeral_rqlite.host, ephemeral_rqlite.port)

The node is standalone: it is never given ``-join``, so it cannot enter the
real Raft cluster.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

#: The live cluster. An ephemeral node must never bind or address these.
LIVE_HTTP_PORT = 4001
LIVE_RAFT_PORT = 4002

#: Default location of the rqlited binary on this fleet.
DEFAULT_RQLITED = Path(r"C:\rqlite\rqlited.exe")

_LEADER_TIMEOUT_S = 30.0


class EphemeralRqliteUnavailable(RuntimeError):
    """Raised when a throwaway node could not be provisioned."""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def rqlited_path() -> Path | None:
    """Locate rqlited, or None if it is not installed."""
    if DEFAULT_RQLITED.exists():
        return DEFAULT_RQLITED
    found = shutil.which("rqlited")
    return Path(found) if found else None


@dataclass(frozen=True)
class EphemeralRqlite:
    """A live, throwaway, single-node rqlite. Isolated from the real cluster."""

    host: str
    port: int
    raft_port: int
    data_dir: Path

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def execute(self, *statements: str) -> dict:
        """Run write statements against this node."""
        return self._post("/db/execute", [[s] for s in statements])

    def query(self, sql: str) -> dict:
        """Run a read query against this node."""
        return self._post("/db/query", [[sql]])

    def table_names(self) -> set[str]:
        rows = self.query(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )["results"][0].get("values") or []
        return {r[0] for r in rows}

    def _post(self, path: str, payload: list) -> dict:
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())


class _EphemeralNode:
    """Spawns rqlited and tears it down. Use `provision()` rather than this."""

    def __init__(self, binary: Path) -> None:
        self._binary = binary
        self._proc: subprocess.Popen | None = None
        self._dir: Path | None = None

    def start(self) -> EphemeralRqlite:
        http_port, raft_port = _free_port(), _free_port()

        # A belt-and-braces guard. Binding these would mean colliding with the
        # real cluster, and the whole point of this module is that it cannot.
        for port in (http_port, raft_port):
            if port in (LIVE_HTTP_PORT, LIVE_RAFT_PORT):
                raise EphemeralRqliteUnavailable(
                    f"refusing to bind live cluster port {port}"
                )

        self._dir = Path(tempfile.mkdtemp(prefix="fabric-ephemeral-rqlite-"))
        self._proc = subprocess.Popen(
            [
                str(self._binary),
                "-node-id", f"ephemeral-{http_port}",
                "-http-addr", f"127.0.0.1:{http_port}",
                "-raft-addr", f"127.0.0.1:{raft_port}",
                # Deliberately no -join: a standalone node cannot enter the
                # real Raft cluster even by accident.
                str(self._dir),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        node = EphemeralRqlite("127.0.0.1", http_port, raft_port, self._dir)
        self._await_leader(node)
        return node

    def _await_leader(self, node: EphemeralRqlite) -> None:
        deadline = time.monotonic() + _LEADER_TIMEOUT_S
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                self.stop()
                raise EphemeralRqliteUnavailable(
                    f"rqlited exited with code {self._proc.returncode}"
                )
            try:
                with urllib.request.urlopen(f"{node.base_url}/status", timeout=1) as r:
                    status = json.loads(r.read().decode())
                if status.get("store", {}).get("leader", {}).get("addr"):
                    return
            except (urllib.error.URLError, OSError, ValueError):
                pass
            time.sleep(0.25)
        self.stop()
        raise EphemeralRqliteUnavailable(
            f"no leader elected within {_LEADER_TIMEOUT_S:.0f}s"
        )

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=10)
            self._proc = None
        if self._dir is not None:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None
