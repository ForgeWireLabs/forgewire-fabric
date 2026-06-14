"""Parity + correctness tests for the ForgeWire stream-seq counter.

Two layers of coverage:

1. **Counter unit tests** (parametrised over Python and Rust impls) — pure
   in-process, no I/O. Verify monotonicity, priming, idempotence, concurrency.
   These pass without rqlite.

2. **Hub HTTP integration tests** — dispatch → claim → start → stream via the
   real FastAPI hub against a live rqlite instance. Verify that the hub emits
   dense, monotonic sequence numbers, that bulk appends are contiguous, that
   invalid channels are rejected, and that seq survives a hub restart (the
   new hub re-primes from the rqlite MAX(seq)).

   These tests require rqlite — see tests/hub/conftest.py.
"""

from __future__ import annotations

import importlib
import tempfile
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forgewire_fabric.hub import _streams as streams_module
from forgewire_fabric.hub._streams import _PyStreamCounter
from forgewire_fabric.hub.server import BlackboardConfig, create_app

try:
    import forgewire_runtime as _rust  # type: ignore[import-not-found]

    _RUST_AVAILABLE = bool(getattr(_rust, "HAS_RUST", False)) and hasattr(
        _rust, "StreamCounter"
    )
except ImportError:
    _RUST_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers shared by the HTTP integration tests
# ---------------------------------------------------------------------------

HUB_TOKEN = "stream-test-" + "x" * 20
BEARER = {"Authorization": f"Bearer {HUB_TOKEN}"}
_BASE_TASK = {
    "title": "stream-seq-test",
    "prompt": "echo test",
    "scope_globs": ["src/**"],
    "base_commit": "a" * 40,
    "branch": "main",
    # M2.8.9: kind is hard-required (missing kind -> 400); the legacy
    # /tasks/claim path used below serves kind='agent' tasks only.
    "kind": "agent",
}


def _rqlite_port() -> int:
    import os
    return int(os.environ.get("FORGEWIRE_HUB_RQLITE_PORT", "4001"))


def _make_client() -> TestClient:
    tmp = Path(tempfile.mkdtemp(prefix="fw-stream-"))
    cfg = BlackboardConfig(
        db_path=tmp / "hub.db",
        token=HUB_TOKEN,
        host="127.0.0.1",
        port=0,
        rqlite_port=_rqlite_port(),
        labels_snapshot_path=tmp / "labels.json",
    )
    return TestClient(create_app(cfg), raise_server_exceptions=False)


def _setup_running_task(client: TestClient) -> int:
    """Dispatch, claim, and start a task. Returns the claimed task_id."""
    dispatched = client.post("/tasks", json=_BASE_TASK, headers=BEARER)
    assert dispatched.status_code == 200, f"dispatch failed: {dispatched.status_code} {dispatched.text}"
    claim = client.post(
        "/tasks/claim",
        json={"worker_id": "bench-worker", "hostname": "bench-host"},
        headers=BEARER,
    ).json()
    assert claim["task"] is not None, f"claim failed: {claim}"
    task_id = claim["task"]["id"]
    client.post(f"/tasks/{task_id}/start", headers=BEARER)
    return task_id


# ---------------------------------------------------------------------------
# Counter unit tests (no rqlite needed)
# ---------------------------------------------------------------------------

def _both_counters() -> list[tuple[str, object]]:
    out: list[tuple[str, object]] = [("python", _PyStreamCounter())]
    if _RUST_AVAILABLE:
        out.append(("rust", _rust.StreamCounter()))
    return out


@pytest.mark.parametrize("name,counter", _both_counters())
def test_next_seq_requires_prime(name: str, counter: object) -> None:
    with pytest.raises(LookupError):
        counter.next_seq(1)  # type: ignore[attr-defined]


@pytest.mark.parametrize("name,counter", _both_counters())
def test_basic_increment(name: str, counter: object) -> None:
    counter.prime(1, 0)  # type: ignore[attr-defined]
    assert counter.next_seq(1) == 1  # type: ignore[attr-defined]
    assert counter.next_seq(1) == 2  # type: ignore[attr-defined]
    assert counter.next_seq(1) == 3  # type: ignore[attr-defined]


@pytest.mark.parametrize("name,counter", _both_counters())
def test_prime_resumes_after_existing_rows(name: str, counter: object) -> None:
    counter.prime(42, 17)  # type: ignore[attr-defined]
    assert counter.next_seq(42) == 18  # type: ignore[attr-defined]


@pytest.mark.parametrize("name,counter", _both_counters())
def test_prime_idempotent_no_regression(name: str, counter: object) -> None:
    counter.prime(7, 100)  # type: ignore[attr-defined]
    counter.next_seq(7)  # type: ignore[attr-defined]
    counter.prime(7, 50)  # stale prime  # type: ignore[attr-defined]
    assert counter.next_seq(7) == 102  # type: ignore[attr-defined]


@pytest.mark.parametrize("name,counter", _both_counters())
def test_distinct_tasks_independent(name: str, counter: object) -> None:
    counter.prime(1, 0)  # type: ignore[attr-defined]
    counter.prime(2, 0)  # type: ignore[attr-defined]
    assert counter.next_seq(1) == 1  # type: ignore[attr-defined]
    assert counter.next_seq(2) == 1  # type: ignore[attr-defined]
    assert counter.next_seq(1) == 2  # type: ignore[attr-defined]


@pytest.mark.parametrize("name,counter", _both_counters())
def test_forget_resets(name: str, counter: object) -> None:
    counter.prime(1, 5)  # type: ignore[attr-defined]
    assert counter.next_seq(1) == 6  # type: ignore[attr-defined]
    counter.forget(1)  # type: ignore[attr-defined]
    with pytest.raises(LookupError):
        counter.next_seq(1)  # type: ignore[attr-defined]


@pytest.mark.parametrize("name,counter", _both_counters())
def test_concurrent_increments_unique_and_dense(name: str, counter: object) -> None:
    counter.prime(1, 0)  # type: ignore[attr-defined]
    n_threads = 8
    per_thread = 500
    out: list[int] = []
    out_lock = threading.Lock()

    def worker() -> None:
        local = [counter.next_seq(1) for _ in range(per_thread)]  # type: ignore[attr-defined]
        with out_lock:
            out.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    out.sort()
    total = n_threads * per_thread
    assert out[0] == 1
    assert out[-1] == total
    assert out == list(range(1, total + 1))


def test_facade_force_python(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operators can pin the Python path with FORGEWIRE_FORCE_PYTHON=1."""
    monkeypatch.setenv("FORGEWIRE_FORCE_PYTHON", "1")
    reloaded = importlib.reload(streams_module)
    try:
        assert reloaded.HAS_RUST is False
        c = reloaded.make_counter()
        c.prime(1, 0)
        assert c.next_seq(1) == 1
    finally:
        monkeypatch.delenv("FORGEWIRE_FORCE_PYTHON", raising=False)
        importlib.reload(streams_module)


# ---------------------------------------------------------------------------
# Hub HTTP integration tests (require rqlite)
# ---------------------------------------------------------------------------

def test_hub_append_stream_emits_dense_monotonic_seqs() -> None:
    """POST /tasks/{id}/stream returns strictly-increasing seq numbers."""
    client = _make_client()
    task_id = _setup_running_task(client)

    seqs: list[int] = []
    for i in range(50):
        r = client.post(
            f"/tasks/{task_id}/stream",
            json={"worker_id": "bench-worker", "channel": "stdout", "line": f"line {i}"},
            headers=BEARER,
        )
        assert r.status_code == 200, r.text
        seqs.append(r.json()["seq"])

    assert seqs == list(range(1, 51)), f"seqs not dense: {seqs[:10]}…"


def test_hub_seq_continues_after_hub_restart() -> None:
    """A new hub instance re-primes from rqlite MAX(seq) — kill -9 safe."""
    tmp = Path(tempfile.mkdtemp(prefix="fw-restart-"))
    cfg = BlackboardConfig(
        db_path=tmp / "hub.db",
        token=HUB_TOKEN,
        host="127.0.0.1",
        port=0,
        rqlite_port=_rqlite_port(),
        labels_snapshot_path=tmp / "labels.json",
    )

    # Hub instance 1 — dispatch, claim, start, append 5 lines.
    client1 = TestClient(create_app(cfg), raise_server_exceptions=False)
    task_id = _setup_running_task(client1)
    for i in range(5):
        r = client1.post(
            f"/tasks/{task_id}/stream",
            json={"worker_id": "bench-worker", "channel": "stdout", "line": str(i)},
            headers=BEARER,
        )
        assert r.status_code == 200
    # Confirm last seq is 5.
    assert r.json()["seq"] == 5

    # Hub instance 2 — fresh app, same rqlite.
    client2 = TestClient(create_app(cfg), raise_server_exceptions=False)
    r2 = client2.post(
        f"/tasks/{task_id}/stream",
        json={"worker_id": "bench-worker", "channel": "stdout", "line": "post-restart"},
        headers=BEARER,
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["seq"] == 6, f"expected 6 after restart, got {r2.json()['seq']}"


def test_hub_stream_bulk_dense_seqs_and_readback() -> None:
    """POST /tasks/{id}/stream/bulk: dense seqs, contiguous with follow-up single."""
    client = _make_client()
    task_id = _setup_running_task(client)

    entries = [{"channel": "stdout", "line": f"bulk-{i}"} for i in range(100)]
    r = client.post(
        f"/tasks/{task_id}/stream/bulk",
        json={"worker_id": "bench-worker", "entries": entries},
        headers=BEARER,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 100
    assert body["first_seq"] == 1
    assert body["last_seq"] == 100

    # Subsequent single-line append picks up at 101.
    follow = client.post(
        f"/tasks/{task_id}/stream",
        json={"worker_id": "bench-worker", "channel": "info", "line": "after"},
        headers=BEARER,
    )
    assert follow.status_code == 200, follow.text
    assert follow.json()["seq"] == 101

    # All 101 rows are persisted in the correct order.
    readback = client.get(
        f"/tasks/{task_id}/stream",
        headers=BEARER,
        params={"limit": 200},
    )
    assert readback.status_code == 200
    lines = readback.json()["lines"]
    assert len(lines) == 101
    assert [ln["seq"] for ln in lines] == list(range(1, 102))
    assert lines[-1]["channel"] == "info"
    assert lines[-1]["line"] == "after"


def test_hub_stream_bulk_rejects_bad_channel() -> None:
    """Bulk append with an invalid channel name returns 400."""
    client = _make_client()
    task_id = _setup_running_task(client)

    r = client.post(
        f"/tasks/{task_id}/stream/bulk",
        json={
            "worker_id": "bench-worker",
            "entries": [
                {"channel": "stdout", "line": "ok"},
                {"channel": "bogus_invalid", "line": "no"},
            ],
        },
        headers=BEARER,
    )
    assert r.status_code in (400, 422), r.text  # 422 = Pydantic schema validation

    # Nothing was written — stream is still empty.
    readback = client.get(f"/tasks/{task_id}/stream", headers=BEARER)
    assert readback.json()["lines"] == []


def test_hub_stream_bulk_empty_is_noop() -> None:
    """Empty bulk append returns count=0 and writes nothing."""
    client = _make_client()
    task_id = _setup_running_task(client)

    r = client.post(
        f"/tasks/{task_id}/stream/bulk",
        json={"worker_id": "bench-worker", "entries": []},
        headers=BEARER,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 0
    assert body.get("first_seq") is None
    assert body.get("last_seq") is None

    # Stream still empty.
    readback = client.get(f"/tasks/{task_id}/stream", headers=BEARER)
    assert readback.json()["lines"] == []
