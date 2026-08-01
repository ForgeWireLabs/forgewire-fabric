"""Architecture guards for the platform-neutral Fabric client core."""

from __future__ import annotations

import json
import re
from pathlib import Path


FABRIC = Path(__file__).resolve().parents[1]
CORE = FABRIC / "packages" / "fabric-client-core"


def _package(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_workspace_and_core_package_contract() -> None:
    root = _package(FABRIC / "package.json")
    package = _package(CORE / "package.json")
    assert root["name"] == "@forgewire/fabric-clients-workspace"
    assert root["private"] is True
    assert root["workspaces"] == ["packages/*", "vscode", "desktop"]
    assert root["engines"] == {"node": "^20.19.0 || >=22.12.0"}
    assert package["name"] == "@forgewire/fabric-client-core"
    assert package["version"] == "0.2.0"
    assert package["type"] == "module"
    assert package["sideEffects"] is False
    assert package["dependencies"] == {}


def test_core_has_no_platform_imports_or_globals() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in (CORE / "src").glob("*.ts") if not path.name.endswith(".test.ts"))
    forbidden_imports = ("vscode", "@tauri", "react", "node:", "fs", "path", "process")
    import_specifiers = re.findall(
        r'^\s*(?:import|export)\s+(?:type\s+)?(?:[^\n;]*?\s+from\s+)?["\']([^"\']+)["\']',
        source,
        flags=re.MULTILINE,
    )
    for forbidden in forbidden_imports:
        assert all(forbidden not in specifier for specifier in import_specifiers)
    for forbidden_global in ("window", "document", "localStorage", "sessionStorage", "globalThis"):
        assert not re.search(rf"\b{forbidden_global}\b", source)
    assert not re.search(r"\bfetch\s*\(", source)
    tsconfig = _package(CORE / "tsconfig.json")
    assert tsconfig["compilerOptions"]["lib"] == ["ES2022"]


def test_canonical_identifier_counts() -> None:
    source = (CORE / "src" / "constants.ts").read_text(encoding="utf-8")
    command_ids = re.findall(r'"(forgewire\.[^"]+)"', source.split("COMMAND_IDS", 1)[1].split("] as const", 1)[0])
    view_ids = re.findall(r'"(forgewire\.[^"]+)"', source.split("VIEW_IDS", 1)[1].split("] as const", 1)[0])
    manifest = _package(FABRIC / "vscode" / "package.json")
    contributed = manifest["contributes"]
    manifest_commands = [item["command"] for item in contributed["commands"]]
    manifest_views = [item["id"] for item in contributed["views"]["forgewire"]]
    assert command_ids == manifest_commands
    assert view_ids == manifest_views
    assert len(command_ids) == len(set(command_ids)) == 58
    assert len(view_ids) == len(set(view_ids)) == 10
    route_block = source.split("DESKTOP_ROUTES", 1)[1].split("] as const", 1)[0]
    assert len(re.findall(r'"/[^\"]+"', route_block)) == 16


def test_consumers_use_exact_core_version_when_migrated() -> None:
    """114B.2 and 114B.3 add consumers; once present they must be exact."""
    for consumer in (FABRIC / "vscode" / "package.json", FABRIC / "desktop" / "package.json"):
        dependencies = _package(consumer).get("dependencies", {})
        version = dependencies.get("@forgewire/fabric-client-core")
        if version is not None:
            assert version == "0.2.0"


def test_114b_shared_parity_modules_are_explicit_and_complete() -> None:
    constants = (CORE / "src" / "constants.ts").read_text(encoding="utf-8")
    commands = (CORE / "src" / "commands.ts").read_text(encoding="utf-8")
    fixtures = (CORE / "src" / "fixtures.ts").read_text(encoding="utf-8")
    index = (CORE / "src" / "index.ts").read_text(encoding="utf-8")

    command_ids = re.findall(
        r'"(forgewire\.[^"]+)"',
        constants.split("COMMAND_IDS", 1)[1].split("] as const", 1)[0],
    )
    descriptor_block = commands.split("COMMAND_DESCRIPTORS", 1)[1].split("] as const", 1)[0]
    descriptor_ids = re.findall(r'(?:both|vscodeOnly)\("(forgewire\.[^"]+)"', descriptor_block)
    assert descriptor_ids == command_ids
    assert 'readonly identity: DispatcherIdentityState' in commands
    assert 'readonly platforms: readonly ClientPlatform[]' in commands
    assert 'requiresDispatcherIdentity' in commands

    fixture_block = fixtures.split("REFERENCE_DOMAIN_FIXTURES", 1)[1]
    for view_id in re.findall(
        r'"(forgewire\.[^"]+)"',
        constants.split("VIEW_IDS", 1)[1].split("] as const", 1)[0],
    ):
        assert f'"{view_id}":' in fixture_block
    assert "secretValue" not in fixture_block
    assert "REFERENCE_FABRIC_FIXTURE.secrets!" in fixture_block

    # navigation.ts/candidates.ts were removed in 114C.7 Slice 6c (AC-114B-5):
    # both were built and unit-tested but never imported by either client, and
    # adopting them turned out to require a real design change (navigation.ts)
    # or was unachievable for Desktop's Rust-side candidate election
    # (candidates.ts) -- see 114B-parity-ledger.json's discover_and_select_candidate
    # / select_show_task reconciliation notes. Not re-tracked here.
    for module in ("commands", "resilience", "fixtures"):
        assert f'export * from "./{module}.js"' in index


def test_114b_resilience_policy_stays_platform_neutral() -> None:
    # 114C.7 Slice 6d (AC-114B-5): the task-stream-lifecycle family
    # (appendTaskStream/TaskStreamBudget/TaskStreamBuffer/TaskStreamLifecycle/
    # shouldContinueTaskStream) was removed rather than adopted -- neither
    # client's actual stream representation fit its string-only buffer model,
    # and the practical value was low next to the refresh-scheduler adoption's
    # real correctness win (see 114B-parity-ledger.json's poll_task_stream
    # reconciliation note). The refresh-scheduler family below is now adopted
    # by both clients (extension.ts's tickRefresh, main.tsx's periodic effect).
    resilience = (CORE / "src" / "resilience.ts").read_text(encoding="utf-8")
    assert "maximumBackoffMs" in resilience and "backgroundMs" in resilience
    assert "isRefreshDue" in resilience and "beginRefresh" in resilience and "completeRefresh" in resilience
    assert 'next === "offline"' in resilience
    assert 'next === "connected"' in resilience
