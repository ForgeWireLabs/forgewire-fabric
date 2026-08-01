from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DESKTOP_ROOT = REPO_ROOT / "desktop"
RELEASE_SCRIPT = DESKTOP_ROOT / "package" / "release" / "desktop-release.mjs"


def _run_lane(
    tmp_path: Path,
    *,
    platform: str,
    tools: dict[str, object],
    environment: dict[str, object],
    operation: str = "plan",
    mode: str = "development",
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    tool_manifest = tmp_path / "tools.json"
    environment_manifest = tmp_path / "environment.json"
    evidence_path = tmp_path / "evidence.json"
    tool_manifest.write_text(json.dumps(tools), encoding="utf-8")
    environment_manifest.write_text(json.dumps(environment), encoding="utf-8")
    completed = subprocess.run(
        [
            "node",
            os.fspath(RELEASE_SCRIPT),
            operation,
            "--platform",
            platform,
            "--mode",
            mode,
            "--arch",
            "test-arch",
            "--tool-manifest",
            os.fspath(tool_manifest),
            "--environment-manifest",
            os.fspath(environment_manifest),
            "--evidence",
            os.fspath(evidence_path),
            "--dry-run",
        ],
        cwd=DESKTOP_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed, json.loads(evidence_path.read_text(encoding="utf-8"))


BASE_TOOLS = {
    "node": "v22.0.0-test",
    "npm": "10.0.0-test",
    "cargo": "cargo 1.90.0-test",
    "rustc": "rustc 1.90.0-test",
}

UPDATER_ENV = {
    "TAURI_SIGNING_PRIVATE_KEY": True,
    "TAURI_SIGNING_PRIVATE_KEY_PASSWORD": True,
    "FORGEWIRE_UPDATER_PUBLIC_KEY": True,
}


def test_release_lane_selects_windows_native_and_existing_zip_targets(tmp_path: Path) -> None:
    result, evidence = _run_lane(
        tmp_path,
        platform="windows",
        tools={**BASE_TOOLS, "pwsh": "7.5.0", "signtool": "10.0-test"},
        environment={},
    )

    assert result.returncode == 0
    assert evidence["evidenceKind"] == "manifest-plan"
    assert evidence["platformSource"] == "override"
    assert evidence["status"] == "ready"
    assert [target["name"] for target in evidence["targets"] if target["selected"]] == ["nsis", "msi", "zip"]
    commands = {command["id"]: command for command in evidence["commands"]}
    assert commands["tauri-native-bundles"]["args"][-1] == "nsis,msi"
    assert commands["windows-portable-zip"]["args"][-1] == "-SkipBuild"


@pytest.mark.parametrize(
    ("platform", "tools", "expected"),
    [
        (
            "macos",
            {**BASE_TOOLS, "hdiutil": "test", "xcrun": "test", "codesign": "test", "security": "test"},
            ["app", "dmg"],
        ),
        (
            "linux",
            {**BASE_TOOLS, "pkg-config": "test", "cc": "test", "dpkg-deb": "test"},
            ["appimage", "deb"],
        ),
    ],
)
def test_release_lane_selects_only_platform_supported_targets(
    tmp_path: Path,
    platform: str,
    tools: dict[str, object],
    expected: list[str],
) -> None:
    result, evidence = _run_lane(tmp_path, platform=platform, tools=tools, environment={})

    assert result.returncode == 0
    assert [target["name"] for target in evidence["targets"] if target["selected"]] == expected
    assert evidence["commands"][0]["args"][-1] == ",".join(expected)


def test_release_preflight_fails_closed_and_records_missing_metadata_without_values(tmp_path: Path) -> None:
    secret_value = "must-never-appear-in-evidence"
    result, evidence = _run_lane(
        tmp_path,
        platform="windows",
        tools={**BASE_TOOLS, "pwsh": "7.5.0", "signtool": "10.0-test"},
        environment={"TAURI_SIGNING_PRIVATE_KEY": {"present": True, "value": secret_value}},
        operation="preflight",
        mode="release",
    )

    assert result.returncode == 2
    assert evidence["status"] == "blocked"
    assert "required release metadata is absent: FORGEWIRE_UPDATER_PUBLIC_KEY" in evidence["blockedReasons"]
    assert secret_value not in json.dumps(evidence)
    assert set(evidence["signing"]["environment"]["TAURI_SIGNING_PRIVATE_KEY"]) == {"present"}


@pytest.mark.parametrize(
    ("platform", "tools", "environment"),
    [
        (
            "windows",
            {**BASE_TOOLS, "pwsh": "7.5.0", "signtool": "10.0-test"},
            {
                **UPDATER_ENV,
                "FORGEWIRE_WINDOWS_CERT_THUMBPRINT": True,
                "FORGEWIRE_WINDOWS_TIMESTAMP_URL": True,
            },
        ),
        (
            "macos",
            {**BASE_TOOLS, "hdiutil": "test", "xcrun": "test", "codesign": "test", "security": "test"},
            {
                **UPDATER_ENV,
                "APPLE_CERTIFICATE": True,
                "APPLE_CERTIFICATE_PASSWORD": True,
                "APPLE_SIGNING_IDENTITY": True,
                "APPLE_ID": True,
                "APPLE_PASSWORD": True,
                "APPLE_TEAM_ID": True,
            },
        ),
    ],
)
def test_release_preflight_accepts_complete_platform_readiness(
    tmp_path: Path,
    platform: str,
    tools: dict[str, object],
    environment: dict[str, object],
) -> None:
    result, evidence = _run_lane(
        tmp_path,
        platform=platform,
        tools=tools,
        environment=environment,
        operation="preflight",
        mode="release",
    )

    assert result.returncode == 0
    assert evidence["status"] == "ready"
    assert evidence["signing"]["ready"] is True
    assert all(command["status"] == "planned" for command in evidence["commands"])


def test_linux_release_preflight_fails_closed_on_unresolved_glib_advisory(tmp_path: Path) -> None:
    result, evidence = _run_lane(
        tmp_path,
        platform="linux",
        tools={**BASE_TOOLS, "pkg-config": "test", "cc": "test", "dpkg-deb": "test", "rpmbuild": "test"},
        environment=UPDATER_ENV,
        operation="preflight",
        mode="release",
    )

    assert result.returncode == 2
    assert evidence["status"] == "blocked"
    assert evidence["security"]["ready"] is False
    assert evidence["security"]["advisories"] == [
        {
            "id": "GHSA-wrw7-89jp-8q8g",
            "package": "glib",
            "detectedVersion": "0.18.5",
            "patchedVersion": ">=0.20.0",
            "status": "upstream-blocked",
        }
    ]
    assert any("GHSA-wrw7-89jp-8q8g" in reason for reason in evidence["blockedReasons"])


def test_release_preflight_reports_missing_platform_tool_version(tmp_path: Path) -> None:
    result, evidence = _run_lane(
        tmp_path,
        platform="linux",
        tools={**BASE_TOOLS, "cc": "test", "dpkg-deb": "test"},
        environment=UPDATER_ENV,
        operation="preflight",
        mode="release",
    )

    assert result.returncode == 2
    assert evidence["tools"]["pkg-config"] == {"found": False, "version": None, "source": "manifest"}
    assert "required tool not found: pkg-config" in evidence["blockedReasons"]


def test_release_signing_readiness_includes_platform_signing_tools(tmp_path: Path) -> None:
    result, evidence = _run_lane(
        tmp_path,
        platform="windows",
        tools={**BASE_TOOLS, "pwsh": "7.5.0"},
        environment={
            **UPDATER_ENV,
            "FORGEWIRE_WINDOWS_CERT_THUMBPRINT": True,
            "FORGEWIRE_WINDOWS_TIMESTAMP_URL": True,
        },
        operation="preflight",
        mode="release",
    )

    assert result.returncode == 2
    assert evidence["signing"]["requiredTools"] == ["signtool"]
    assert evidence["signing"]["toolsReady"] is False
    assert evidence["signing"]["ready"] is False
    assert "required release signing tool not found: signtool" in evidence["blockedReasons"]


def test_release_build_dry_run_preserves_planned_commands_without_execution(tmp_path: Path) -> None:
    result, evidence = _run_lane(
        tmp_path,
        platform="windows",
        tools={**BASE_TOOLS, "pwsh": "7.5.0", "signtool": "10.0-test"},
        environment={
            **UPDATER_ENV,
            "FORGEWIRE_WINDOWS_CERT_THUMBPRINT": True,
            "FORGEWIRE_WINDOWS_TIMESTAMP_URL": True,
        },
        operation="build",
        mode="release",
    )

    assert result.returncode == 0
    assert evidence["operation"] == "build"
    assert evidence["dryRun"] is True
    assert evidence["status"] == "ready"
    assert [command["status"] for command in evidence["commands"]] == ["planned", "planned"]


def test_desktop_package_wires_release_lane_commands() -> None:
    package = json.loads((DESKTOP_ROOT / "package.json").read_text(encoding="utf-8"))

    assert package["scripts"]["release:plan"].endswith("desktop-release.mjs plan")
    assert package["scripts"]["release:preflight"].endswith("preflight --mode release")
    assert package["scripts"]["release:build"].endswith("build --mode release")
