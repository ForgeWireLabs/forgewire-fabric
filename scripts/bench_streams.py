"""Benchmark ``POST /tasks/{id}/stream`` and ``/stream/bulk`` against rqlite.

Measures lines-per-second for both the single-line and bulk append paths,
with optional comparison between the Rust counter and pure-Python fallback.

Usage:
    # Standard run (500 warm-up + 5 000 timed lines):
    python scripts/bench_streams.py

    # Force pure-Python counter:
    FORGEWIRE_FORCE_PYTHON=1 python scripts/bench_streams.py

    # Larger run:
    python scripts/bench_streams.py --lines 20000 --bulk-size 200

Requirements:
    A live rqlite cluster must be reachable on 127.0.0.1:4001 (or set
    FORGEWIRE_HUB_RQLITE_HOST / FORGEWIRE_HUB_RQLITE_PORT).
    The hub itself is started in-process via TestClient so no separate hub
    process is needed.
"""

from __future__ import annotations

import argparse
import os
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from forgewire_fabric.hub._streams import HAS_RUST
from forgewire_fabric.hub.server import BlackboardConfig, create_app

_TOKEN = "bench-token-" + "x" * 20
_BEARER = {"Authorization": f"Bearer {_TOKEN}"}
_BASE_TASK = {
    "title": "bench-streams",
    "prompt": "echo bench",
    "scope_globs": ["src/**"],
    "base_commit": "a" * 40,
    "branch": "main",
}


def _make_app() -> TestClient:
    tmp = Path(tempfile.mkdtemp(prefix="fw-bench-"))
    rqlite_host = os.environ.get("FORGEWIRE_HUB_RQLITE_HOST", "127.0.0.1")
    rqlite_port = int(os.environ.get("FORGEWIRE_HUB_RQLITE_PORT", "4001"))
    cfg = BlackboardConfig(
        db_path=tmp / "hub.db",
        token=_TOKEN,
        host="127.0.0.1",
        port=0,
        rqlite_host=rqlite_host,
        rqlite_port=int(rqlite_port),
        labels_snapshot_path=tmp / "labels.json",
    )
    return TestClient(create_app(cfg))


def _setup_task(client: TestClient) -> int:
    """Dispatch, claim, and start a task. Returns task_id."""
    task = client.post("/tasks", json=_BASE_TASK, headers=_BEARER).json()
    task_id = task["id"]
    client.post(
        "/tasks/claim",
        json={"worker_id": "bench-w", "hostname": "bench-host"},
        headers=_BEARER,
    )
    client.post(f"/tasks/{task_id}/start", headers=_BEARER)
    return task_id


def bench_single(client: TestClient, task_id: int, n_lines: int) -> float:
    """POST one line at a time. Returns elapsed seconds."""
    start = time.perf_counter()
    for i in range(n_lines):
        client.post(
            f"/tasks/{task_id}/stream",
            json={"worker_id": "bench-w", "channel": "stdout", "line": f"line {i}"},
            headers=_BEARER,
        )
    return time.perf_counter() - start


def bench_bulk(
    client: TestClient, task_id: int, n_lines: int, bulk_size: int
) -> float:
    """POST in bulk batches of bulk_size. Returns elapsed seconds."""
    start = time.perf_counter()
    sent = 0
    while sent < n_lines:
        batch_n = min(bulk_size, n_lines - sent)
        entries = [{"channel": "stdout", "line": f"bulk-{sent + i}"} for i in range(batch_n)]
        client.post(
            f"/tasks/{task_id}/stream/bulk",
            json={"worker_id": "bench-w", "entries": entries},
            headers=_BEARER,
        )
        sent += batch_n
    return time.perf_counter() - start


def _counter_label() -> str:
    if HAS_RUST and not os.environ.get("FORGEWIRE_FORCE_PYTHON"):
        return "rust"
    return "python"


def run(n_lines: int = 5_000, warmup: int = 500, bulk_size: int = 100) -> None:
    label = _counter_label()
    rqlite_host = os.environ.get("FORGEWIRE_HUB_RQLITE_HOST", "127.0.0.1")
    rqlite_port = os.environ.get("FORGEWIRE_HUB_RQLITE_PORT", "4001")

    print(f"ForgeWire stream bench  counter={label}  rqlite={rqlite_host}:{rqlite_port}")
    print(f"  warm-up={warmup}  timed={n_lines}  bulk-size={bulk_size}")
    print()

    client = _make_app()

    # ── Single-line path ───────────────────────────────────────────────────
    task_single = _setup_task(client)
    print(f"  Warming up single ({warmup} lines)…", end=" ", flush=True)
    bench_single(client, task_single, warmup)
    print("done")

    print(f"  Benchmarking single ({n_lines} lines)…", end=" ", flush=True)
    elapsed_single = bench_single(client, task_single, n_lines)
    rate_single = n_lines / elapsed_single
    print(f"done  {elapsed_single:.3f}s  {rate_single:,.0f} lines/sec")

    # ── Bulk path ──────────────────────────────────────────────────────────
    task_bulk = _setup_task(client)
    print(f"  Warming up bulk ({warmup} lines, batch={bulk_size})…", end=" ", flush=True)
    bench_bulk(client, task_bulk, warmup, bulk_size)
    print("done")

    print(f"  Benchmarking bulk ({n_lines} lines, batch={bulk_size})…", end=" ", flush=True)
    elapsed_bulk = bench_bulk(client, task_bulk, n_lines, bulk_size)
    rate_bulk = n_lines / elapsed_bulk
    print(f"done  {elapsed_bulk:.3f}s  {rate_bulk:,.0f} lines/sec")

    print()
    speedup = rate_bulk / rate_single if rate_single else 0
    print(f"  Bulk vs single: {speedup:.1f}× faster  ({rate_bulk:,.0f} vs {rate_single:,.0f} lines/sec)")
    print()
    print("Summary:")
    print(f"  [{label}] single  {rate_single:>10,.0f} lines/sec")
    print(f"  [{label}] bulk    {rate_bulk:>10,.0f} lines/sec  (batch={bulk_size})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark hub stream append paths")
    parser.add_argument("--lines", type=int, default=5_000, help="Lines to time")
    parser.add_argument("--warmup", type=int, default=500, help="Warm-up lines")
    parser.add_argument("--bulk-size", type=int, default=100, help="Bulk batch size")
    args = parser.parse_args()
    run(n_lines=args.lines, warmup=args.warmup, bulk_size=args.bulk_size)
