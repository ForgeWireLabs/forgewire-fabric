from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import math
from statistics import mean, pstdev


@dataclass(frozen=True)
class VarianceBound:
    max_latency_cv: float
    max_selection_flip_rate: float


@dataclass(frozen=True)
class ScenarioPolicy:
    scenario: str
    backend: str
    bound: VarianceBound


DEFAULT_VARIANCE_POLICY: dict[tuple[str, str], VarianceBound] = {
    ("match_middle", "rqlite"): VarianceBound(0.45, 0.00),
    ("full_scan_no_match", "rqlite"): VarianceBound(0.50, 0.00),
}


def _cv(values: list[float]) -> float:
    if not values:
        return 0.0
    mu = mean(values)
    if mu == 0:
        return 0.0
    return pstdev(values) / mu


def compute_variance_stats(latency_samples: list[float], picks: list[int | None]) -> dict[str, float]:
    """Compute latency and output-stability proxies across repeated seed runs."""
    if len(latency_samples) != len(picks):
        raise ValueError("latency_samples and picks must have equal length")
    if not latency_samples:
        raise ValueError("at least one run is required")

    baseline = picks[0]
    flips = sum(1 for p in picks[1:] if p != baseline)
    flip_rate = flips / max(1, len(picks) - 1)

    return {
        "runs": float(len(latency_samples)),
        "latency_mean_s": mean(latency_samples),
        "latency_std_s": pstdev(latency_samples) if len(latency_samples) > 1 else 0.0,
        "latency_cv": _cv(latency_samples),
        "selection_flip_rate": flip_rate,
    }


def evaluate_variance_gate(
    *,
    scenario: str,
    backend: str,
    stats: dict[str, float],
    policy: dict[tuple[str, str], VarianceBound] | None = None,
) -> tuple[bool, list[str]]:
    bounds = (policy or DEFAULT_VARIANCE_POLICY).get((scenario, backend))
    if bounds is None:
        return False, [
            f"No variance policy configured for scenario={scenario!r}, backend={backend!r}.",
            "Remediation: define a bound for this scenario/backend pair before running the gate.",
        ]

    reasons: list[str] = []
    if stats["latency_cv"] > bounds.max_latency_cv:
        reasons.append(
            f"latency_cv {stats['latency_cv']:.3f} exceeded max {bounds.max_latency_cv:.3f}. "
            "Remediation: increase run count, isolate host contention, and compare backend IO saturation."
        )
    if stats["selection_flip_rate"] > bounds.max_selection_flip_rate:
        reasons.append(
            f"selection_flip_rate {stats['selection_flip_rate']:.3f} exceeded max {bounds.max_selection_flip_rate:.3f}. "
            "Remediation: inspect parity fields and deterministic ordering in candidate evaluation."
        )

    return (len(reasons) == 0), reasons


def persist_variance_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
