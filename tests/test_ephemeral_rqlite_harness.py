"""114C.0 gate: prove account state can be written without touching the cluster.

The 114C evidence plan (Rule 2) forbids account tests from using the live
shared rqlite, for two reasons found during the 114B audit:

* the autouse guard in ``tests/conftest.py`` deletes every approval before and
  after each test, which would erase the evidence the 114C live runbook exists
  to produce; and
* the guard cleans none of 114C's seven ``human_*`` tables, so test-created
  accounts, sessions, passkeys, and recovery codes would accumulate in the real
  cluster as durable security state -- ghost credentials, which are worse than
  the ghost runners AC-114C-4 already forbids.

The plan therefore gates all 114C account code behind this file: no account
code merges until an ephemeral instance is provable. These tests are that
proof, not a description of it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

import pytest

from tests.ephemeral_rqlite import (LIVE_HTTP_PORT, LIVE_RAFT_PORT,
                                    rqlited_path)

# The seven tables 114C introduces. Named here so this test fails loudly if a
# future change starts writing them to the live cluster.
HUMAN_TABLES = (
    "human_accounts",
    "human_credentials",
    "human_memberships",
    "human_sessions",
    "human_refresh_uses",
    "human_recovery_codes",
    "human_auth_challenges",
    # Eighth human_* table (114C.3): the exactly-once first-administrator
    # bootstrap gate. Added here in the same commit that introduced it, per
    # 114C-name-lock.md's binding rule -- otherwise this guard would stop
    # covering it silently.
    "human_bootstrap_state",
    # Ninth human_* table (114C.3, 114c-3-negative-auth): login-attempt
    # records backing the rolling-window throttle. Same rule, same commit.
    "human_login_attempts",
    # Tenth identity table (114D D.1): the realm's founding-identity singleton.
    # Not a `human_*` table (realm-scoped, not account-scoped), but it is
    # durable identity state created by the same `init_human_accounts_schema`
    # call, so it belongs under the same "must not leak to the live cluster"
    # guard. Added here in the commit that introduced it, per the name-lock rule.
    "realm_identity",
)


def _live_tables() -> set[str] | None:
    """Read-only peek at the live cluster. None if it is not reachable."""
    q = urllib.parse.quote("SELECT name FROM sqlite_master WHERE type='table'")
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{LIVE_HTTP_PORT}/db/query?q={q}", timeout=3
        ) as r:
            body = json.loads(r.read().decode())
    except (urllib.error.URLError, OSError, ValueError):
        return None
    rows = body.get("results", [{}])[0].get("values") or []
    return {row[0] for row in rows}


# ---------------------------------------------------------------------------
# The instance works
# ---------------------------------------------------------------------------


def test_rqlited_is_installed() -> None:
    """The harness needs a real rqlited; the plan forbids faking the store."""
    assert rqlited_path() is not None, (
        "rqlited not found. The 114C plan requires real rqlite rather than a "
        "mocked account repository."
    )


def test_ephemeral_instance_elects_a_leader(ephemeral_rqlite) -> None:
    with urllib.request.urlopen(f"{ephemeral_rqlite.base_url}/status", timeout=5) as r:
        status = json.loads(r.read().decode())
    assert status["store"]["leader"]["addr"], "ephemeral node has no leader"


def test_ephemeral_instance_accepts_writes_and_reads(ephemeral_rqlite) -> None:
    ephemeral_rqlite.execute(
        "CREATE TABLE probe_accounts (id INTEGER PRIMARY KEY, username TEXT)",
        "INSERT INTO probe_accounts (username) VALUES ('operator')",
    )
    result = ephemeral_rqlite.query("SELECT username FROM probe_accounts")
    assert result["results"][0]["values"] == [["operator"]]


def test_standard_http_client_can_connect_to_the_ephemeral_node(ephemeral_rqlite) -> None:
    """The harness speaks rqlite's real HTTP wire contract."""
    import httpx

    response = httpx.post(
        f"{ephemeral_rqlite.base_url}/db/execute?transaction",
        json=[["CREATE TABLE via_client (id INTEGER)"]],
        timeout=10.0,
    )
    response.raise_for_status()
    assert "via_client" in ephemeral_rqlite.table_names()


# ---------------------------------------------------------------------------
# It is isolated — the claim the gate actually rests on
# ---------------------------------------------------------------------------


def test_ephemeral_node_never_binds_live_cluster_ports(ephemeral_rqlite) -> None:
    assert ephemeral_rqlite.port != LIVE_HTTP_PORT
    assert ephemeral_rqlite.raft_port != LIVE_RAFT_PORT


def test_ephemeral_writes_are_invisible_to_the_live_cluster(ephemeral_rqlite) -> None:
    """The load-bearing claim: writing here does not reach the real cluster."""
    before = _live_tables()
    if before is None:
        pytest.skip("live cluster not reachable; isolation cannot be demonstrated")

    marker = f"ephemeral_isolation_probe_{ephemeral_rqlite.port}"
    ephemeral_rqlite.execute(f"CREATE TABLE {marker} (id INTEGER)")
    assert marker in ephemeral_rqlite.table_names(), "write did not land locally"

    after = _live_tables()
    assert after is not None, "live cluster became unreachable mid-test"
    assert marker not in after, (
        f"{marker} reached the LIVE cluster — the ephemeral node is not isolated"
    )
    assert after == before, (
        f"the live cluster's tables changed during an ephemeral-only test: "
        f"added={after - before} removed={before - after}"
    )


def test_a_session_leaves_live_human_tables_untouched() -> None:
    """The specific promise 114C.0 owes: this suite does not create account
    state in the real cluster.

    Today it holds trivially -- the tables do not exist yet. It is written now
    so that it starts failing the moment 114C account code writes them to the
    wrong database, which is exactly when it matters and far too late to notice
    by reading.
    """
    live = _live_tables()
    if live is None:
        pytest.skip("live cluster not reachable")
    present = sorted(t for t in HUMAN_TABLES if t in live)
    assert not present, (
        f"account tables exist on the LIVE cluster: {present}. 114C account "
        f"state belongs on an ephemeral instance (evidence plan, Rule 2); "
        f"these are ghost credentials."
    )


def test_two_ephemeral_instances_do_not_share_state(ephemeral_rqlite) -> None:
    """Each provisioning is its own database, so tests cannot leak into
    each other the way they do on the shared cluster."""
    from tests.ephemeral_rqlite import _EphemeralNode, rqlited_path

    ephemeral_rqlite.execute("CREATE TABLE only_in_first (id INTEGER)")

    second_node = _EphemeralNode(rqlited_path())
    second = second_node.start()
    try:
        assert second.port != ephemeral_rqlite.port
        assert "only_in_first" not in second.table_names()
    finally:
        second_node.stop()


def test_teardown_removes_the_data_directory() -> None:
    from tests.ephemeral_rqlite import _EphemeralNode, rqlited_path

    node = _EphemeralNode(rqlited_path())
    instance = node.start()
    data_dir = instance.data_dir
    assert data_dir.exists()
    node.stop()
    assert not data_dir.exists(), "ephemeral data directory outlived the test"
