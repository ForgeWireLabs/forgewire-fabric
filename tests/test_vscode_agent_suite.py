from __future__ import annotations

import ast
import json
from pathlib import Path


FABRIC_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = FABRIC_ROOT.parent
VSCODE_ROOT = FABRIC_ROOT / "vscode"
CONFIG_ROOT = FABRIC_ROOT / "install" / "mcp-configs" / "vscode"


def _frontmatter_tools(path: Path) -> list[str]:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("tools: "):
            tools = ast.literal_eval(line.removeprefix("tools: "))
            assert isinstance(tools, list)
            return tools
    raise AssertionError(f"missing tools frontmatter: {path}")


def test_agent_suite_manifest_has_four_distinct_roles_and_two_server_topology() -> None:
    manifest = json.loads((CONFIG_ROOT / "agent-suite.manifest.json").read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 1
    assert manifest["mcp_topology"] == {
        "dispatcher": ["forgewire-fabric", "forgewire-loom"],
        "runner": ["forgewire-fabric-runner"],
    }
    roles = {role["id"]: role for role in manifest["roles"]}
    assert set(roles) == {"dispatcher", "runner", "approver", "observer"}
    assert roles["dispatcher"]["servers"] == ["forgewire-fabric", "forgewire-loom"]
    assert roles["runner"]["servers"] == ["forgewire-fabric-runner"]
    assert "read-only" in roles["approver"]["authority"]
    assert "read-only" in roles["observer"]["authority"]
    assert manifest["install"]["conflict_policy"] == "preserve-unless-operator-confirms-replace"


def test_packaged_chatmodes_match_workspace_reference_and_enforce_role_boundaries() -> None:
    expected = {
        "dispatcher": "forgewire-dispatcher.chatmode.md",
        "runner": "forgewire-runner.chatmode.md",
        "approver": "forgewire-approver.chatmode.md",
        "observer": "forgewire-observer.chatmode.md",
    }
    tools_by_role: dict[str, set[str]] = {}
    for role, filename in expected.items():
        packaged = VSCODE_ROOT / "chatmodes" / filename
        workspace = REPO_ROOT / ".github" / "chatmodes" / filename
        assert packaged.read_bytes() == workspace.read_bytes()
        tools_by_role[role] = set(_frontmatter_tools(packaged))

    assert "forgewire-fabric/dispatch_prompt" in tools_by_role["dispatcher"]
    assert "forgewire-loom/run_command" in tools_by_role["dispatcher"]
    assert "forgewire-fabric-runner/claim_next_task" in tools_by_role["runner"]

    mutation_fragments = (
        "/dispatch_",
        "/cancel_task",
        "/drain_",
        "/start_process",
        "/run_command",
        "/send_input",
        "/kill_process",
    )
    for role in ("approver", "observer"):
        assert not any(fragment in tool for tool in tools_by_role[role] for fragment in mutation_fragments)

    all_tools = set().union(*tools_by_role.values())
    assert not any(tool == "forgewire-dispatcher" or tool.startswith("forgewire-dispatcher/") for tool in all_tools)
    assert not any(tool == "forgewire-runner" or tool.startswith("forgewire-runner/") for tool in all_tools)


def test_seven_packaged_skills_are_bounded_prompt_templates() -> None:
    manifest = json.loads((CONFIG_ROOT / "agent-suite.manifest.json").read_text(encoding="utf-8"))
    expected = set(manifest["skills"])
    files = {path.stem.removesuffix(".prompt"): path for path in (VSCODE_ROOT / "skills").glob("*.prompt.md")}

    assert set(files) == expected
    for name, path in files.items():
        body = path.read_text(encoding="utf-8")
        assert "mode: agent" in body
        assert "tools: [" in body
        assert "forgewire-dispatcher/" not in body
        assert "forgewire-runner/" not in body
        assert "FORGEWIRE_HUB_TOKEN=" not in body
        assert "Authorization: Bearer" not in body
        assert name in expected


def test_agent_suite_installer_and_vsix_package_guard_are_wired() -> None:
    package = json.loads((VSCODE_ROOT / "package.json").read_text(encoding="utf-8"))
    commands = {command["command"] for command in package["contributes"]["commands"]}
    assert "forgewire.installAgentSuite" in commands

    extension = (VSCODE_ROOT / "src" / "extension.ts").read_text(encoding="utf-8")
    assert '"forgewire.installAgentSuite": () => installAgentSuite(ctx)' in extension
    assert '"Install missing only"' in extension
    assert '"Replace ForgeWire files"' in extension
    assert 'path.join(selected.uri.fsPath, ".github", "chatmodes", name)' in extension
    assert 'path.join(selected.uri.fsPath, ".github", "prompts", name)' in extension

    package_guard = (VSCODE_ROOT / "scripts" / "verify-package-list.mjs").read_text(encoding="utf-8")
    for path in (*sorted((VSCODE_ROOT / "chatmodes").glob("*.md")), *sorted((VSCODE_ROOT / "skills").glob("*.md"))):
        relative = path.relative_to(VSCODE_ROOT).as_posix()
        assert f'"{relative}"' in package_guard

    shared_commands = (FABRIC_ROOT / "packages" / "fabric-client-core" / "src" / "commands.ts").read_text(encoding="utf-8")
    assert 'vscodeOnly("forgewire.installAgentSuite"' in shared_commands
    assert "No desktop equivalent: this installs VS Code chatmodes" in shared_commands


def test_reference_mcp_configs_keep_dispatcher_and_runner_surfaces_separate() -> None:
    dispatcher = json.loads((CONFIG_ROOT / "mcp.json").read_text(encoding="utf-8"))
    runner = json.loads((CONFIG_ROOT / "mcp.runner.json").read_text(encoding="utf-8"))

    assert set(dispatcher["servers"]) == {"forgewire-fabric", "forgewire-loom"}
    assert set(runner["servers"]) == {"forgewire-fabric-runner"}
    assert all("FORGEWIRE_HUB_TOKEN" not in server.get("env", {}) for server in dispatcher["servers"].values())
    assert "FORGEWIRE_HUB_TOKEN" not in runner["servers"]["forgewire-fabric-runner"]["env"]
