from __future__ import annotations

import json
from pathlib import Path

from forgewire_fabric import cli as cli_mod


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_mcp_runner_uses_configured_hub_url(tmp_path, monkeypatch) -> None:
    appdata = tmp_path / "AppData" / "Roaming"
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setattr(cli_mod.sys, "platform", "win32")

    cli_mod._write_vscode_user_mcp(
        hub_url="http://192.0.2.10:8765",
        install_runner=True,
        workspace_root="C:\\Projects\\forgewire",
    )

    mcp_path = appdata / "Code" / "User" / "mcp.json"
    payload = json.loads(mcp_path.read_text(encoding="utf-8"))
    servers = payload["servers"]
    # M2.8.9: the dispatcher surface is two servers (loom + fabric); the agent
    # runner is forgewire-fabric-runner. The legacy single-server names are gone.
    assert servers["forgewire-loom"]["args"] == ["-m", "forgewire_fabric.hub.loom_mcp"]
    assert servers["forgewire-loom"]["env"]["FORGEWIRE_HUB_URL"] == "http://192.0.2.10:8765"
    assert servers["forgewire-fabric"]["args"] == ["-m", "forgewire_fabric.hub.fabric_mcp"]
    assert servers["forgewire-fabric"]["env"]["FORGEWIRE_HUB_URL"] == "http://192.0.2.10:8765"
    assert servers["forgewire-fabric-runner"]["args"] == ["-m", "forgewire_fabric.hub.fabric_runner_mcp"]
    assert servers["forgewire-fabric-runner"]["env"]["FORGEWIRE_HUB_URL"] == "http://192.0.2.10:8765"
    assert "forgewire-dispatcher" not in servers
    assert "forgewire-runner" not in servers


def test_runner_mcp_registration_is_backgrounded() -> None:
    # M2.8.4: the canonical runner-MCP implementation lives in
    # fabric_runner_mcp.py.  Check registration is backgrounded.
    body = (REPO_ROOT / "python" / "forgewire_fabric" / "hub" / "fabric_runner_mcp.py").read_text(encoding="utf-8")
    assert "registration_task = asyncio.create_task(_register_with_retries(session))" in body
    assert "await _register_with_retries(session)\n    heartbeat_task" not in body


def test_legacy_mcp_shims_removed() -> None:
    # M2.8.9: the dispatcher_mcp.py / runner_mcp.py deprecation shims are gone;
    # the repackaged modules (fabric_mcp / loom_mcp / fabric_runner_mcp /
    # loom_runner_mcp) are the only path.
    hub = REPO_ROOT / "python" / "forgewire_fabric" / "hub"
    assert not (hub / "dispatcher_mcp.py").exists()
    assert not (hub / "runner_mcp.py").exists()
    for canonical in ("fabric_mcp.py", "loom_mcp.py", "fabric_runner_mcp.py", "loom_runner_mcp.py"):
        assert (hub / canonical).exists(), f"missing canonical module {canonical}"


def test_dispatchers_view_collapsed_into_hosts() -> None:
    package = json.loads((REPO_ROOT / "vscode" / "package.json").read_text(encoding="utf-8"))
    activity_containers = package["contributes"]["viewsContainers"]["activitybar"]
    container_ids = {container["id"] for container in activity_containers}
    assert "forgewire" in container_ids
    assert "forgewireFabric" not in container_ids

    view_ids = {view["id"] for view in package["contributes"]["views"]["forgewire"]}
    assert "forgewire.dispatchers" not in view_ids
    assert "forgewire.hosts" in view_ids

    extension = (REPO_ROOT / "vscode" / "src" / "extension.ts").read_text(encoding="utf-8")
    assert 'registerTreeDataProvider("forgewire.dispatchers"' not in extension
    assert 'registerTreeDataProvider("forgewireFabric.dispatchers"' not in extension

    providers = (REPO_ROOT / "vscode" / "src" / "treeProviders.ts").read_text(encoding="utf-8")
    assert 'kind: "dispatcher"' in providers
    assert "hosts:dispatcher:" in providers
