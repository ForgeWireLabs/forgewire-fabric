from __future__ import annotations

from pathlib import Path
import json

from forgewire_fabric.parity_variance import compute_variance_stats, evaluate_variance_gate, persist_variance_report


def test_compute_variance_stats_and_gate_pass() -> None:
    stats = compute_variance_stats([0.01, 0.011, 0.009, 0.01], [3, 3, 3, 3])
    ok, reasons = evaluate_variance_gate(scenario="match_middle", backend="sqlite", stats=stats)
    assert ok is True
    assert reasons == []


def test_gate_fails_with_remediation_hints() -> None:
    stats = compute_variance_stats([0.001, 0.1, 0.001, 0.2], [1, 2, 1, 2])
    ok, reasons = evaluate_variance_gate(scenario="match_middle", backend="sqlite", stats=stats)
    assert ok is False
    assert any("Remediation:" in reason for reason in reasons)


def test_persist_variance_report(tmp_path: Path) -> None:
    out = tmp_path / "variance.json"
    persist_variance_report(out, {"reports": [{"gate": {"ok": True}}]})
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["reports"][0]["gate"]["ok"] is True
