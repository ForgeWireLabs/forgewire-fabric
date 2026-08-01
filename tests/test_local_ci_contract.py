"""Contracts for deterministic and explicitly authorized local CI."""

from __future__ import annotations

import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_CI = REPO_ROOT / "scripts" / "ci" / "local-ci.ps1"
ROOT_CONFTEST = REPO_ROOT / "tests" / "conftest.py"
HUB_CONFTEST = REPO_ROOT / "tests" / "hub" / "conftest.py"
PYPROJECT = REPO_ROOT / "pyproject.toml"


def test_pytest_registers_local_ci_markers() -> None:
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    markers = config["tool"]["pytest"]["ini_options"]["markers"]

    assert any(marker.startswith("integration:") for marker in markers)
    assert any(marker.startswith("live_cluster:") for marker in markers)


def test_root_conftest_requires_explicit_live_cluster_opt_in() -> None:
    body = ROOT_CONFTEST.read_text(encoding="utf-8")

    assert 'LIVE_CLUSTER_ENV = "FORGEWIRE_TEST_ALLOW_LIVE_CLUSTER"' in body
    assert 'os.environ.get(LIVE_CLUSTER_ENV) == "1"' in body
    assert "RQLITE_UP = LIVE_CLUSTER_ALLOWED and _rqlite_available()" in body
    assert "if LIVE_CLUSTER_ALLOWED:" in body
    assert "if not LIVE_CLUSTER_ALLOWED:" in body
    assert "item.add_marker(pytest.mark.live_cluster)" in body


def test_hub_conftest_cannot_start_or_clean_cluster_without_opt_in() -> None:
    body = HUB_CONFTEST.read_text(encoding="utf-8")

    assert 'LIVE_CLUSTER_ENV = "FORGEWIRE_TEST_ALLOW_LIVE_CLUSTER"' in body
    assert body.count("if not LIVE_CLUSTER_ALLOWED:") >= 2
    assert "_start_rqlite_service()" in body
    assert "_enforce_cluster_invariant()" in body


def test_local_ci_has_fast_full_and_live_modes() -> None:
    body = LOCAL_CI.read_text(encoding="utf-8")

    assert '[ValidateSet("Fast", "Full", "Live")]' in body
    assert "[switch]$AllowLiveCluster" in body
    assert '"FORGEWIRE_TEST_ALLOW_LIVE_CLUSTER"' in body
    assert '"not live_cluster"' in body
    assert '"live_cluster"' in body
    assert '"test",' in body
    assert '"--workspace"' in body


def test_local_ci_does_not_hide_tests_by_node_id() -> None:
    body = LOCAL_CI.read_text(encoding="utf-8")

    assert "--deselect" not in body
    assert "test_audit_for_day_returns_today" not in body
    assert "test_a_session_leaves_live_human_tables_untouched" not in body


def test_local_ci_fast_mode_checks_repository_contracts() -> None:
    body = LOCAL_CI.read_text(encoding="utf-8")

    assert "Test-PowerShellSyntax" in body
    assert '"compileall"' in body
    assert '"fmt"' in body
    assert '"--check"' in body
    assert "tests/test_installer_assets_in_sync.py" in body
    assert "tests/test_versioning_doc_matches_sources.py" in body
    assert "tests/test_local_ci_contract.py" in body


def test_local_ci_documentation_covers_modes_and_safety_boundary() -> None:
    body = (REPO_ROOT / "scripts" / "ci" / "README.md").read_text(
        encoding="utf-8"
    )

    assert "## Fast mode" in body
    assert "## Full mode" in body
    assert "## Live mode" in body
    assert "-AllowLiveCluster" in body
    assert "FORGEWIRE_TEST_ALLOW_LIVE_CLUSTER=1" in body
    assert "Full mode is the normal local merge gate." in body
