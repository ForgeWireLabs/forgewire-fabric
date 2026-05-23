"""Microbench: forgewire_runtime.pick_task (Rust) vs Python reference.

Run from the repo root with the venv active:

    python scripts/remote/bench_claim_router.py

Locked numbers are recorded in ``forgewire-runtime/PERFORMANCE.md``.
"""

from __future__ import annotations

import argparse
import random
import time
from pathlib import Path
from statistics import median

from forgewire_fabric.parity_variance import compute_variance_stats, evaluate_variance_gate, persist_variance_report

from forgewire_fabric.hub._router import _py_pick_task

try:
    import forgewire_runtime as _rust
    HAS_RUST = bool(getattr(_rust, "HAS_RUST", False)) and hasattr(_rust, "pick_task")
except ImportError:
    _rust = None
    HAS_RUST = False


SCOPES = [
    "modules/jobs/**", "modules/orchestration/**", "core/services/**",
    "docs/research/**", "docs/operations/**", "tests/remote/**",
    "shell/http/**", "shell/cli/**", "**/*.md", "scripts/**",
]
PREFIXES = ["modules/", "core/", "docs/", "tests/", "shell/", "scripts/",
            "modules/jobs/", "docs/research/"]
TOOLS = ["git", "pytest", "rg", "rust", "mypy", "ruff"]
TAGS = ["persona:forge", "persona:researcher", "tier:1", "tier:2"]


def _make_corpus(n_tasks: int, seed: int = 42) -> tuple[list, dict]:
    rng = random.Random(seed)
    tasks = []
    for _ in range(n_tasks):
        tasks.append(
            {
                "scope_globs": rng.sample(SCOPES, rng.randint(1, 3)),
                "required_tools": rng.sample(TOOLS, rng.randint(0, 2)),
                "required_tags": rng.sample(TAGS, rng.randint(0, 2)),
                "tenant": rng.choice([None, "alpha", "beta"]),
                "workspace_root": None,
                "require_base_commit": False,
                "base_commit": "",
            }
        )
    runner = {
        "scope_prefixes": ["modules/", "docs/", "tests/"],
        "tools": TOOLS,
        "tags": TAGS,
        "tenant": "alpha",
        "workspace_root": None,
        "last_known_commit": None,
    }
    return tasks, runner


def _bench(label: str, fn, iterations: int) -> float:
    fn()
    samples: list[float] = []
    for _ in range(5):
        t0 = time.perf_counter()
        for _ in range(iterations):
            fn()
        samples.append((time.perf_counter() - t0) / iterations)
    m = median(samples)
    print(f"  {label:<24s} {m * 1e6:9.2f} µs/op  ({iterations:,} iters x 5 runs)")
    return m


def _run_seeded_repeats(*, scenario: str, backend: str, n_tasks: int, seeds: list[int], use_rust: bool) -> dict:
    latencies: list[float] = []
    picks: list[int | None] = []
    for seed in seeds:
        tasks, runner = _make_corpus(n_tasks, seed=seed)
        if scenario == "full_scan_no_match":
            runner = dict(runner, tenant="zzz_unknown")
            for t in tasks:
                t["tenant"] = "alpha"
        t0 = time.perf_counter()
        pick_idx, _ = (_rust.pick_task(tasks, runner) if use_rust else _py_pick_task(tasks, runner))
        latencies.append(time.perf_counter() - t0)
        picks.append(pick_idx)

    stats = compute_variance_stats(latencies, picks)
    ok, reasons = evaluate_variance_gate(scenario=scenario, backend=backend, stats=stats)
    return {
        "scenario": scenario,
        "backend": backend,
        "seeds": seeds,
        "parity_fields": ["scope_globs", "required_tools", "required_tags", "tenant", "workspace_root", "require_base_commit", "base_commit"],
        "stats": stats,
        "gate": {"ok": ok, "reasons": reasons},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed-start", type=int, default=100)
    parser.add_argument("--seed-count", type=int, default=12)
    parser.add_argument("--report", type=Path, default=Path("artifacts/claim-router-variance.json"))
    args = parser.parse_args()

    print(f"forgewire_runtime HAS_RUST = {HAS_RUST}\n")
    print("=== Match in middle (typical case) ===")
    for n in (5, 25, 50):
        tasks, runner = _make_corpus(n)
        print(f"\nN_tasks = {n}")
        py_t = _bench("python", lambda: _py_pick_task(tasks, runner), 20_000)
        if HAS_RUST:
            rust_t = _bench("rust ", lambda: _rust.pick_task(tasks, runner), 20_000)
            print(f"  speedup            = {py_t / rust_t:6.2f}x")

    print("\n=== Worst case: full scan, no match (tenant mismatch on every task) ===")
    for n in (5, 25, 50):
        tasks, runner = _make_corpus(n)
        # Force every candidate to be filtered — runner tenant doesn't match any.
        runner_no = dict(runner, tenant="zzz_unknown")
        # And every task pins a tenant.
        for t in tasks:
            t["tenant"] = "alpha"
        print(f"\nN_tasks = {n}")
        py_t = _bench("python", lambda: _py_pick_task(tasks, runner_no), 20_000)
        if HAS_RUST:
            rust_t = _bench("rust ", lambda: _rust.pick_task(tasks, runner_no), 20_000)
            print(f"  speedup            = {py_t / rust_t:6.2f}x")

    seeds = [args.seed_start + i for i in range(args.seed_count)]
    reports = []
    reports.append(_run_seeded_repeats(scenario="match_middle", backend="sqlite", n_tasks=25, seeds=seeds, use_rust=False))
    reports.append(_run_seeded_repeats(scenario="full_scan_no_match", backend="sqlite", n_tasks=25, seeds=seeds, use_rust=False))
    if HAS_RUST:
        reports.append(_run_seeded_repeats(scenario="match_middle", backend="rqlite", n_tasks=25, seeds=seeds, use_rust=True))
        reports.append(_run_seeded_repeats(scenario="full_scan_no_match", backend="rqlite", n_tasks=25, seeds=seeds, use_rust=True))

    for r in reports:
        print(f"variance {r['scenario']}/{r['backend']}: cv={r['stats']['latency_cv']:.4f}, flip={r['stats']['selection_flip_rate']:.4f}, gate={r['gate']['ok']}")
        for reason in r["gate"]["reasons"]:
            print(f"  - {reason}")

    persist_variance_report(args.report, {"reports": reports})
    if not all(r["gate"]["ok"] for r in reports):
        raise SystemExit("variance gate failed; see remediation hints above")


if __name__ == "__main__":
    main()
