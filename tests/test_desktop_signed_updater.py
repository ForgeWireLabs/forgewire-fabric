from __future__ import annotations

import json
from pathlib import Path


FABRIC_ROOT = Path(__file__).resolve().parents[1]
DESKTOP = FABRIC_ROOT / "desktop"


def test_updater_config_is_https_signed_artifact_lane() -> None:
    config = json.loads((DESKTOP / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))

    assert config["bundle"]["createUpdaterArtifacts"] is True
    endpoints = config["plugins"]["updater"]["endpoints"]
    assert endpoints
    assert all(endpoint.startswith("https://") for endpoint in endpoints)


def test_renderer_has_no_raw_updater_plugin_authority() -> None:
    capability = json.loads(
        (DESKTOP / "src-tauri" / "capabilities" / "default.json").read_text(encoding="utf-8")
    )
    permissions = capability["permissions"]

    assert not any(permission.startswith("updater:") for permission in permissions)


def test_native_update_commands_fail_closed_and_verify_before_install() -> None:
    source = (DESKTOP / "src-tauri" / "src" / "main.rs").read_text(encoding="utf-8")

    assert 'option_env!("FORGEWIRE_UPDATER_PUBLIC_KEY")' in source
    assert "if !updater_is_configured()" in source
    assert ".download_and_install(" in source
    assert "install_verified_desktop_update" in source
    assert "check_for_desktop_update" in source


def test_release_runbook_keeps_service_state_during_rollback() -> None:
    runbook = (DESKTOP / "package" / "release" / "README.md").read_text(encoding="utf-8")

    assert "uninstall only ForgeWire Fabric Desktop" in runbook
    assert "Do not remove Fabric Hub, Runner, rqlite" in runbook
    assert "never checks or installs updates silently" in runbook
