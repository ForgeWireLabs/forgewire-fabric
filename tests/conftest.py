"""ForgeWire Fabric test configuration.

rqlite is the only supported hub backend. SQLite is not a valid hub backend.

Tests that require a live rqlite cluster are marked @pytest.mark.integration
and are skipped automatically when rqlite is not reachable.

To run integration tests:
    nssm start ForgeWireRqliteNode1   # (Windows) or equivalent
    pytest tests/ -m integration

**This suite runs against the real, shared rqlite cluster and mutates it.**

``_global_cluster_guard`` below is autouse: before and after *every* test it
deletes every approval and dispatcher, cancels every queued task, and removes
any runner/worker/host_role that is not one of the two real machines. That is
coherent for one session -- it stops tests polluting each other -- and unsound
for two, because a second session's guard fires while the first session's test
is mid-flight and deletes the rows it is using.

Two consequences worth knowing before you run this:

1. **Only one session at a time.** A concurrent run is not slow, it is wrong:
   it produces failures that look like flaky tests and do not reproduce. The
   session lock below fails fast instead of letting that happen.
2. **Running this suite is destructive to live cluster state.** On a machine
   where the cluster is doing real work, a routine ``pytest`` cancels queued
   tasks and drops approvals and dispatchers. Real dispatchers re-register on
   their next heartbeat; queued work does not come back.
"""
from __future__ import annotations

import atexit
import json
import os
import urllib.request
from pathlib import Path

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


LIVE_CLUSTER_ENV = "FORGEWIRE_TEST_ALLOW_LIVE_CLUSTER"
LIVE_CLUSTER_ALLOWED = os.environ.get(LIVE_CLUSTER_ENV) == "1"
RQLITE_UP = LIVE_CLUSTER_ALLOWED and _rqlite_available()

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
        # Stale tasks — cancel queued AND tasks held by ghost workers so they
        # don't pollute the next test's claim or inflate active-task counts.
        ["UPDATE tasks SET status='cancelled', cancel_requested=1 WHERE status='queued'"],
        [f"UPDATE tasks SET status='cancelled', cancel_requested=1 "
         f"WHERE status IN ('claimed','running') "
         f"AND (worker_id IS NULL OR worker_id NOT IN ({real_ids}))"],
        # Approvals — test artifacts; real approvals are acted on promptly
        ["DELETE FROM approvals"],
        # Ghost dispatchers registered by test helpers
        ["DELETE FROM dispatchers"],
        ["DELETE FROM dispatcher_nonces"],
        # Host-role facts are denormalized from registrations and therefore
        # survive the direct dispatcher cleanup above. Keep facts for the two
        # physical machines, but remove test-only hosts and the explicit
        # agent-runner marker used by host summary tests.
        [f"DELETE FROM host_roles WHERE hostname NOT IN ({real_hosts})"],
        [
            "DELETE FROM host_roles "
            "WHERE role='agent_runner' AND metadata LIKE '%\"mcp_server\": \"test\"%'"
        ],
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


_SESSION_LOCK = Path(__file__).resolve().parent / ".fabric-suite.lock"
_LOCK_HANDLE = None


def _try_lock(fh) -> bool:
    """Take an exclusive, non-blocking lock on *fh*. False if already held.

    An OS-held lock rather than a pid file, deliberately. The kernel drops it
    when the holder exits for any reason, so a killed run cannot leave a stale
    lock that wedges everyone, and no liveness probe is needed.

    That matters here: the obvious probe, os.kill(pid, 0), is a liveness check
    on POSIX but not on Windows, where CPython routes any signal other than
    CTRL_C_EVENT/CTRL_BREAK_EVENT to TerminateProcess -- it would kill the very
    session it was meant to detect.
    """
    try:
        if os.name == "nt":
            import msvcrt

            # msvcrt.locking locks N bytes from the CURRENT position, so both
            # sessions must agree on which byte. Seek to 0 explicitly: opening
            # "a+" positions at end-of-file, which would have each session lock
            # a different byte and defeat the whole guard.
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _claim_session_lock() -> None:
    """Refuse to start if another fabric test session is already running.

    The autouse cluster guard mutates the shared live rqlite before and after
    every test, so two concurrent sessions delete each other's rows mid-test.
    The result is not a slow run; it is failures that look flaky and never
    reproduce -- see evidence run 20260717-114-fabric-suite-concurrency-hazard,
    where a concurrent session cancelled a queued task out from under
    test_legacy_claim_skips_capability_gated_tasks.

    Set FABRIC_ALLOW_CONCURRENT_TESTS=1 to override -- only meaningful if the
    other session cannot reach the same rqlite.
    """
    global _LOCK_HANDLE
    if os.environ.get("FABRIC_ALLOW_CONCURRENT_TESTS") == "1":
        return

    # Deliberately not a `with` block: the lock must stay held for the whole
    # pytest session, not close at the end of this function. Released by the
    # OS when the process exits (see the docstring above).
    fh = open(_SESSION_LOCK, "a+")  # noqa: SIM115
    if not _try_lock(fh):
        fh.close()
        # pytest.exit, not UsageError: raising from pytest_configure surfaces as
        # an INTERNALERROR traceback, which is the same kind of confusing output
        # this guard exists to prevent. Matches tests/hub/conftest.py.
        pytest.exit(
            "\n\nAnother ForgeWire Fabric test session is already running.\n"
            "\n"
            "This suite mutates the shared live rqlite cluster before and after every\n"
            "test (it deletes approvals and dispatchers and cancels queued tasks), so a\n"
            "second session deletes rows the first one is mid-way through using. The\n"
            "result is failures that look flaky and do not reproduce.\n"
            "\n"
            "Wait for the other session to finish. The lock is held by the OS and is\n"
            "released automatically when it exits, so there is nothing to clean up.\n"
            f"  {_SESSION_LOCK}\n",
            returncode=pytest.ExitCode.USAGE_ERROR,
        )
    # Nothing is written to the file. The OS lock on byte 0 is the whole signal,
    # and writing would mean truncating a byte the lock covers.
    _LOCK_HANDLE = fh  # held open for the session; released on exit
    atexit.register(_release_session_lock)


def _release_session_lock() -> None:
    global _LOCK_HANDLE
    if _LOCK_HANDLE is None:
        return
    try:
        if os.name == "nt":
            import msvcrt

            _LOCK_HANDLE.seek(0)
            msvcrt.locking(_LOCK_HANDLE.fileno(), msvcrt.LK_UNLCK, 1)
    except OSError:
        pass
    try:
        _LOCK_HANDLE.close()
    finally:
        _LOCK_HANDLE = None
        _SESSION_LOCK.unlink(missing_ok=True)


@pytest.fixture
def ephemeral_rqlite():
    """A throwaway single-node rqlite, isolated from the live cluster.

    Any test that writes account state (human_accounts, human_credentials,
    human_memberships, human_sessions, human_refresh_uses,
    human_recovery_codes, human_auth_challenges) must use this rather than the
    shared cluster on 127.0.0.1:4001. Writing that state to the live cluster
    would leave ghost credentials that nothing cleans up -- the autouse guard
    above does not touch those tables -- and the guard would in turn erase the
    approvals the 114C live runbook exists to prove.

    See work/active/114-forgewire-fabric/114C-evidence-plan.md, Rule 2.
    """
    from tests.ephemeral_rqlite import (EphemeralRqliteUnavailable, _EphemeralNode,
                                        rqlited_path)

    binary = rqlited_path()
    if binary is None:
        pytest.skip("rqlited not installed; cannot provision an ephemeral node")

    node = _EphemeralNode(binary)
    try:
        instance = node.start()
    except EphemeralRqliteUnavailable as exc:
        pytest.skip(f"ephemeral rqlite unavailable: {exc}")
    try:
        yield instance
    finally:
        node.stop()


def _requires_live_cluster(item: pytest.Item) -> bool:
    """Return whether a test may read or mutate shared cluster state."""
    nodeid = item.nodeid.replace("\\", "/")

    live_prefixes = (
        "tests/hub/",
        "tests/live/",
        "tests/test_hub_rqlite_e2e.py",
        "tests/test_rqlite_db_adapter.py",
        "tests/test_forgewire_streams_parity.py::test_hub_",
    )
    if nodeid.startswith(live_prefixes):
        return True

    return nodeid in {
        "tests/test_ephemeral_rqlite_harness.py::"
        "test_ephemeral_writes_are_invisible_to_the_live_cluster",
        "tests/test_ephemeral_rqlite_harness.py::"
        "test_a_session_leaves_live_human_tables_untouched",
    }


def pytest_sessionstart(session: pytest.Session) -> None:
    if LIVE_CLUSTER_ALLOWED:
        _claim_session_lock()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: tests requiring external integration dependencies",
    )
    config.addinivalue_line(
        "markers",
        "live_cluster: tests that may read or mutate shared rqlite state",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    live_disabled = pytest.mark.skip(
        reason=f"live cluster access requires {LIVE_CLUSTER_ENV}=1"
    )
    unavailable = pytest.mark.skip(reason="required rqlite cluster is unavailable")

    for item in items:
        if _requires_live_cluster(item):
            item.add_marker(pytest.mark.live_cluster)
            item.add_marker(pytest.mark.integration)

        if "live_cluster" in item.keywords:
            if not LIVE_CLUSTER_ALLOWED:
                item.add_marker(live_disabled)
            elif not RQLITE_UP:
                item.add_marker(unavailable)
        elif "integration" in item.keywords and not RQLITE_UP:
            item.add_marker(unavailable)


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
