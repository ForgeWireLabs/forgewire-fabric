from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType


FABRIC_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = FABRIC_ROOT / "scripts" / "dr" / "third_voter_readiness.py"
FIXTURES = FABRIC_ROOT / "tests" / "fixtures" / "rqlite"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("third_voter_readiness", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _contract(module: ModuleType) -> dict[str, object]:
    contract = module.inspect_installer_contract(FABRIC_ROOT)
    assert contract["verified_from_shipped_scripts"] is True
    return contract


def test_fixture_cases_enforce_stable_exit_contract() -> None:
    module = _load_script()
    cases = json.loads((FIXTURES / "third_voter_readiness_cases.json").read_text(encoding="utf-8"))

    for name, case in cases.items():
        report = module.analyze_nodes(case["nodes"], source="fixture", installer_contract=_contract(module))
        assert report["exit_code"] == case["expected_exit"], name
        assert report["source"] == "fixture"
        assert report["schema_version"] == 1


def test_multiple_rqlite_processes_on_one_hostname_are_not_three_host_proof() -> None:
    module = _load_script()
    case = json.loads((FIXTURES / "third_voter_readiness_cases.json").read_text(encoding="utf-8"))["duplicate_processes"]

    report = module.analyze_nodes(case["nodes"], source="fixture", installer_contract=_contract(module))

    assert report["counts"]["voter_nodes"] == 3
    assert report["counts"]["reachable_voter_physical_hosts"] == 2
    assert report["duplicate_process_hosts"] == ["HOST-A"]
    assert "duplicate_processes_on_one_physical_host_do_not_count" in report["reasons"]
    assert report["status"] == "hardware_blocked"


def test_ip_only_advertisement_cannot_claim_physical_host_identity() -> None:
    module = _load_script()
    nodes = {
        f"node-{index}": {
            "id": f"node-{index}",
            "api_addr": f"http://192.0.2.{index}:4001",
            "addr": f"192.0.2.{index}:4002",
            "voter": True,
            "reachable": True,
            "leader": index == 1,
        }
        for index in range(1, 4)
    }

    report = module.analyze_nodes(nodes, source="fixture", installer_contract=_contract(module))

    assert report["exit_code"] == 2
    assert report["counts"]["verified_physical_hosts"] == 0
    assert report["unverified_physical_identity_nodes"] == ["node-1", "node-2", "node-3"]
    assert "ip_only_or_unverifiable_physical_host_identity" in report["reasons"]


def test_installer_contract_confirms_voter_join_without_executing_or_exposing_token() -> None:
    module = _load_script()
    contract = _contract(module)
    command = str(contract["operator_command"])

    assert contract["executed"] is False
    assert "-RqliteJoinAddr <EXISTING_VOTER_HOST>:4002" in command
    assert "-Token (Get-Content <SECURE_HUB_TOKEN_FILE_ON_THIRD_HOST> -Raw)" in command
    assert "Bearer " not in command
    assert "Joining as a voter" not in command


def test_fixture_cli_output_is_stable_json_and_returns_hardware_blocked() -> None:
    command = [sys.executable, str(SCRIPT), "--nodes-file", str(FIXTURES / "current_two_nodes.json")]

    first = subprocess.run(command, check=False, capture_output=True, text=True)
    second = subprocess.run(command, check=False, capture_output=True, text=True)

    assert first.returncode == second.returncode == 2
    assert first.stdout == second.stdout
    report = json.loads(first.stdout)
    assert report["status"] == "hardware_blocked"
    assert report["counts"]["reported_nodes"] == 2
    assert report["counts"]["reachable_voter_physical_hosts"] == 1
    assert first.stderr == second.stderr == ""


def test_url_credentials_are_rejected_without_echoing_them() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--rqlite-url", "http://credential-user-731:do-not-print@127.0.0.1:4001"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "credential-user-731" not in result.stdout
    assert "do-not-print" not in result.stdout
    assert json.loads(result.stdout)["source"] == "invalid-rqlite-url"
