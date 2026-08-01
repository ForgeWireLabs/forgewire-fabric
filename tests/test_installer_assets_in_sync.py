"""Drift guard for installer assets.

The repository keeps two copies of the same PowerShell installer scripts:

* ``scripts/install/*.ps1`` — what humans / CI scripts edit.
* ``python/forgewire_fabric/_installer_assets/*.ps1`` — what gets bundled
  into the wheel and shipped to operators via ``forgewire_fabric.cli hub install``
  and ``forgewire_fabric.cli runner install``.

If these two trees drift, deployments via the published package silently
ship stale installer logic. That has bitten us at least once already
(rqlite flags landed in ``scripts/install/`` but never made it into the
bundled asset). This test fails loudly when the two diverge so future
PRs cannot land an out-of-band fix.

Source of truth is ``scripts/install/``. To update bundled copies::

    pwsh -File scripts/dev/sync_installer_assets.ps1
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

from click.testing import CliRunner
import pytest

from forgewire_fabric.cli import cli

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = REPO_ROOT / "scripts" / "install"
BUNDLED_DIR = REPO_ROOT / "python" / "forgewire_fabric" / "_installer_assets"

# Mirrored files. Anything in scripts/install/ that ends in .ps1 *and* is
# legitimately bundle-only (none today) would be excluded here. Today every
# script in scripts/install/*.ps1 is mirrored.
MIRRORED = (
    "install-fabric.ps1",
    "install-operator-overlay.ps1",
    "replay-operator-overlays.ps1",
    "update-fabric.ps1",
    "nssm-install-hub.ps1",
    "nssm-install-runner.ps1",
    "install-hub-watchdog.ps1",
    "install-runner-watchdog.ps1",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("name", MIRRORED)
def test_installer_asset_in_sync(name: str) -> None:
    src = SOURCE_DIR / name
    dst = BUNDLED_DIR / name
    assert src.exists(), f"missing source asset: {src}"
    assert dst.exists(), (
        f"missing bundled asset: {dst}. Run "
        f"`pwsh -File scripts/dev/sync_installer_assets.ps1`."
    )
    assert _sha256(src) == _sha256(dst), (
        f"installer asset drift: {name}\n"
        f"  source:  {src}\n"
        f"  bundled: {dst}\n"
        f"Run `pwsh -File scripts/dev/sync_installer_assets.ps1` to sync."
    )


def test_runner_installer_exposes_hub_ssh_failover_params() -> None:
    """OOTB cross-host hub failover: the runner installer MUST accept and
    forward the SSH-target parameters so a single ``forgewire-fabric setup``
    or ``runner install`` invocation wires every fabric node with a hub
    watchdog. If any of these are dropped, peers stop being able to
    restart a wedged hub.
    """
    body = (SOURCE_DIR / "nssm-install-runner.ps1").read_text(encoding="utf-8")
    for needle in (
        "$HubSshHost",
        "$HubSshUser",
        "$HubSshKeyFile",
        "$HubServiceName",
        "$HubHealthzUrl",
        "NoHubWatchdog",
        "hub-restart.ed25519",
        "install-hub-watchdog.ps1",
        "ssh-keyscan",
    ):
        assert needle in body, (
            f"nssm-install-runner.ps1 missing required token '{needle}'. "
            "Cross-host hub watchdog cannot be wired OOTB without it."
        )


def test_operator_overlays_survive_managed_data_removal_and_replay() -> None:
    """Operator services and identities must not live under the uninstall tree."""
    installer = (SOURCE_DIR / "install-operator-overlay.ps1").read_text(encoding="utf-8")
    replay = (SOURCE_DIR / "replay-operator-overlays.ps1").read_text(encoding="utf-8")
    node_installer = (SOURCE_DIR / "install-fabric.ps1").read_text(encoding="utf-8")
    for needle in (
        "C:\\ProgramData\\forgewire-operator",
        "cached_source",
        "migrate_files",
        "system-admin",
        "AppEnvironmentExtra",
    ):
        assert needle in installer
    assert "install-operator-overlay.ps1" in replay
    assert "replay-operator-overlays.ps1" in node_installer
    assert "-StartServices" in node_installer


def test_deployment_clone_sync_preserves_dirty_work_without_hard_reset() -> None:
    body = (REPO_ROOT / "scripts" / "install" / "sync-deployment-clone.ps1").read_text(
        encoding="utf-8"
    )
    for needle in ("operator/$hostName/$stamp", "git bundle create", "git merge --ff-only"):
        assert needle in body
    assert "reset --hard" not in body


def test_privileged_binary_update_waits_before_overlay_replay() -> None:
    body = (SOURCE_DIR / "update-fabric.ps1").read_text(encoding="utf-8")
    assert "-Verb RunAs -Wait -PassThru" in body
    assert "exit $process.ExitCode" in body


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows NSSM overlay contract")
def test_operator_overlay_cli_reaches_real_manifest_validator(tmp_path: Path) -> None:
    manifest = tmp_path / "overlay.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "test-overlay",
                "services": [
                    {
                        "name": "ForgeWireTestOverlay",
                        "executable": r"C:\ProgramData\forgewire\bin\test.exe",
                        "working_directory": r"C:\Projects",
                        "startup": "manual",
                        "environment": {
                            "FORGEWIRE_HUB_TOKEN_FILE": r"C:\ProgramData\forgewire\hub.token"
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        cli,
        ["operator-overlays", "apply", str(manifest), "--validate-only"],
    )
    assert result.exit_code == 0, result.output


def test_hub_watchdog_supports_remote_ssh_restart() -> None:
    """The hub watchdog MUST be able to restart the hub on a peer host via
    SSH. Anything less and the failover wiring in nssm-install-runner.ps1
    would silently degrade to log-noise."""
    body = (SOURCE_DIR / "install-hub-watchdog.ps1").read_text(encoding="utf-8")
    for needle in (
        "$SshHost",
        "$SshUser",
        "$SshKeyFile",
        "$RemoteServiceName",
        "$KnownHostsFile",
        "ssh.exe",
        "BatchMode=yes",
    ):
        assert needle in body, (
            f"install-hub-watchdog.ps1 missing required token '{needle}'."
        )


def test_hub_installer_defaults_rqlite_consistency_to_strong() -> None:
    """The NSSM hub installer MUST default ``-RqliteConsistency`` to
    ``"strong"``. ``"weak"`` skips the Raft read-index, so a SELECT can
    return state older than the last committed write across a leader
    flip. This violates audit-chain integrity (``prev_hash`` reads
    must be linearizable) and is binding under the thesis. Every other
    defaulting layer in the tree (``Connection.__init__``,
    ``BlackboardConfig``, the CLI ``--rqlite-consistency`` flag, and the
    ``FORGEWIRE_HUB_RQLITE_CONSISTENCY`` env var) already defaults to
    ``strong``; the installer was the lone outlier.
    """
    needle = (
        '[ValidateSet("none","weak","strong","linearizable")]'
        '[string]$RqliteConsistency = "strong"'
    )
    for asset in (
        SOURCE_DIR / "nssm-install-hub.ps1",
        BUNDLED_DIR / "nssm-install-hub.ps1",
    ):
        body = asset.read_text(encoding="utf-8")
        assert needle in body, (
            f"{asset}: -RqliteConsistency default must be 'strong' for "
            "audit-chain integrity. Do not weaken without a measured "
            "latency justification."
        )



def test_watchdogs_use_system_reachable_pwsh_host() -> None:
    """Both watchdog scheduled tasks MUST resolve a SYSTEM-reachable
    PowerShell host at install time. Using bare 'pwsh.exe' picks up the
    Microsoft Store install under WindowsApps/, which is not executable
    by the SYSTEM scheduled task account (ERROR_FILE_NOT_FOUND), silently
    breaking the watchdog."""
    for name in ("install-hub-watchdog.ps1", "install-runner-watchdog.ps1"):
        body = (SOURCE_DIR / name).read_text(encoding="utf-8")
        assert "WindowsPowerShell\\v1.0\\powershell.exe" in body, (
            f"{name}: missing built-in WindowsPowerShell 5.1 fallback for SYSTEM."
        )
        assert "ProgramFiles\\PowerShell\\7\\pwsh.exe" in body, (
            f"{name}: missing preferred pwsh 7 path."
        )
        assert "-Execute \"pwsh.exe\"" not in body, (
            f"{name}: still using bare 'pwsh.exe' which SYSTEM cannot launch "
            "when pwsh comes from the Microsoft Store."
        )



def test_native_and_python_runner_identity_paths_are_exported() -> None:
    """Windows service installers must support both runner runtimes."""
    installer = (SOURCE_DIR / "nssm-install-runner.ps1").read_text(encoding="utf-8")
    migration = (
        REPO_ROOT / "scripts" / "install" / "switch-to-rust-services.ps1"
    ).read_text(encoding="utf-8")

    for name, body in (("installer", installer), ("migration", migration)):
        assert "FORGEWIRE_RUNNER_IDENTITY=$IdentityFile" in body, (
            f"{name}: native Rust runners require FORGEWIRE_RUNNER_IDENTITY"
        )
        assert "FORGEWIRE_RUNNER_IDENTITY_PATH=$IdentityFile" in body, (
            f"{name}: Python runners require FORGEWIRE_RUNNER_IDENTITY_PATH"
        )
