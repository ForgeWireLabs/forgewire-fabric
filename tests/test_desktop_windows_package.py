from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = REPO_ROOT / "desktop" / "package" / "windows"
DESKTOP_PACKAGE = REPO_ROOT / "desktop" / "package.json"


def _read(name: str) -> str:
    return (PACKAGE_DIR / name).read_text(encoding="utf-8")


def test_desktop_package_contains_installer_uninstaller_and_builder() -> None:
    for name in (
        "install-forgewire-fabric-desktop.ps1",
        "uninstall-forgewire-fabric-desktop.ps1",
        "package-forgewire-fabric-desktop.ps1",
        "test-forgewire-fabric-desktop.ps1",
    ):
        assert (PACKAGE_DIR / name).exists(), f"missing desktop package script: {name}"


def test_desktop_installer_is_user_scope_and_registers_uninstaller() -> None:
    body = _read("install-forgewire-fabric-desktop.ps1")
    for needle in (
        "Programs\\ForgeWire Fabric",
        "ForgeWire Fabric.exe",
        "ForgeWire Fabric.lnk",
        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ForgeWire Fabric Desktop",
        "QuietUninstallString",
        "uninstall-forgewire-fabric-desktop.ps1",
    ):
        assert needle in body
    assert "ProgramData\\forgewire" not in body, "desktop installer must not write Fabric service secrets"
    assert "hub.token" not in body, "desktop installer must not create or store hub tokens"
    version = json.loads(DESKTOP_PACKAGE.read_text(encoding="utf-8"))["version"]
    assert f'-Name "DisplayVersion" -Value "{version}"' in body


def test_desktop_uninstaller_leaves_fabric_services_and_secrets_intact() -> None:
    body = _read("uninstall-forgewire-fabric-desktop.ps1")
    for needle in (
        "Fabric services and secrets were left intact",
        "does not remove Fabric hub",
        "dispatcher identities",
        "Programs\\ForgeWire Fabric",
    ):
        assert needle in body
    for forbidden in ("C:\\ProgramData\\forgewire", "C:\\rqlite", "hub.token"):
        assert forbidden not in body


def test_desktop_package_builder_emits_complete_zip_payload() -> None:
    body = _read("package-forgewire-fabric-desktop.ps1")
    for needle in (
        "npm run tauri -- build --no-bundle",
        "ForgeWire-Fabric-Desktop-Windows-x64.zip",
        "ForgeWire Fabric.exe",
        "install-forgewire-fabric-desktop.ps1",
        "uninstall-forgewire-fabric-desktop.ps1",
        "test-forgewire-fabric-desktop.ps1",
        "Compress-Archive",
    ):
        assert needle in body


def test_desktop_package_validator_uses_real_topology_without_leaking_token() -> None:
    body = _read("test-forgewire-fabric-desktop.ps1")
    for needle in (
        "DESKTOP-228U8GL",
        "DESKTOP-38GVF8D",
        "desktop_dispatcher_identity.json",
        "Start-Process",
        "WindowStyle Hidden",
        "Live host inventory mismatch",
    ):
        assert needle in body
    assert "ConvertTo-Json -Depth 5" in body
    assert "Token =" not in body
