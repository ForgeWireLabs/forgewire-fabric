"""Host role summaries for the primary Hosts pane.

Tests NEVER register runners or dispatchers in rqlite.  The cluster has
exactly two real machines (DESKTOP-38GVF8D and DESKTOP-228U8GL); no test
may add to that count.

What is tested here:
* Auth guards on /hosts/roles, /runners deregister, /dispatchers deregister.
* The active hub always appears in /hosts.
* host_roles written via POST /hosts/roles are reflected in /hosts and
  are cleaned up after the test (host_roles rows do not represent machines).
* The /hosts endpoint returns well-formed host entries for the real cluster.
"""

from __future__ import annotations

import socket
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from forgewire_fabric.hub.server import BlackboardConfig, create_app


HUB_TOKEN = "test-hub-token-aaaaaaaaaaaaaaaaa"


def _make_app(tmp_path: Path):
    cfg = BlackboardConfig(
        db_path=tmp_path / "hub.db",
        token=HUB_TOKEN,
        host="127.0.0.1",
        port=0,
    )
    return create_app(cfg)


def _auth() -> dict[str, str]:
    return {"authorization": f"Bearer {HUB_TOKEN}"}


# ---------------------------------------------------------------- auth guards


def test_host_role_report_requires_auth() -> None:
    app = _make_app(Path(tempfile.mkdtemp()))
    with TestClient(app) as client:
        r = client.post(
            "/hosts/roles",
            json={"hostname": "any-host", "role": "agent_runner", "enabled": True},
        )
        assert r.status_code == 401


def test_deregister_endpoints_require_auth() -> None:
    app = _make_app(Path(tempfile.mkdtemp()))
    with TestClient(app) as client:
        assert client.delete("/runners/some-id").status_code == 401
        assert client.delete("/dispatchers/some-id").status_code == 401


def test_deregister_nonexistent_runner_is_404() -> None:
    app = _make_app(Path(tempfile.mkdtemp()))
    with TestClient(app) as client:
        r = client.delete("/runners/does-not-exist-runner-id", headers=_auth())
        assert r.status_code == 404


def test_deregister_nonexistent_dispatcher_is_404() -> None:
    app = _make_app(Path(tempfile.mkdtemp()))
    with TestClient(app) as client:
        r = client.delete("/dispatchers/does-not-exist-dispatcher-id", headers=_auth())
        assert r.status_code == 404


# ---------------------------------------------------------------- real cluster reads


def test_active_hub_appears_in_hosts() -> None:
    """The machine running the hub always appears in /hosts as hub_head active."""
    app = _make_app(Path(tempfile.mkdtemp()))
    with TestClient(app) as client:
        r = client.get("/hosts", headers=_auth())
        assert r.status_code == 200
        hosts = {h["hostname"]: h for h in r.json()["hosts"]}
        local = hosts.get(socket.gethostname())
        assert local is not None, f"{socket.gethostname()} missing from /hosts"
        assert local["roles"]["hub_head"]["status"] == "active"
        assert local["roles"]["control"]["status"] == "master"


def test_hosts_endpoint_returns_valid_structure() -> None:
    """/hosts returns a list where each entry has the required fields."""
    app = _make_app(Path(tempfile.mkdtemp()))
    with TestClient(app) as client:
        r = client.get("/hosts", headers=_auth())
        assert r.status_code == 200
        body = r.json()
        assert "hosts" in body
        for host in body["hosts"]:
            assert "hostname" in host
            assert "roles" in host
            assert isinstance(host["roles"], dict)


def test_host_roles_written_and_visible(tmp_path: Path) -> None:
    """POST /hosts/roles creates a role fact visible in /hosts.

    Uses the local machine hostname (the active hub) so no new machine
    is introduced.  Uses a valid role name from the enum.
    """
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        hostname = socket.gethostname()
        r = client.post(
            "/hosts/roles",
            json={
                "hostname": hostname,
                "role": "agent_runner",
                "enabled": True,
                "status": "registered",
                "metadata": {"mcp_server": "test"},
            },
            headers=_auth(),
        )
        assert r.status_code == 200

        r = client.get("/hosts", headers=_auth())
        hosts = {h["hostname"]: h for h in r.json()["hosts"]}
        assert hostname in hosts
        assert "agent_runner" in hosts[hostname]["roles"]
