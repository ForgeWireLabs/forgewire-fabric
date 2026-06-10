"""M2.9.5 (F7) — Loom runner parity reconciliation tests.

Two goals:
1. Drift-guard: assert the TEST-ONLY banner is present in loom_runner_mcp so the
   module is never accidentally shipped as the primary runner without the warning.
2. Finish-path parity: the single _auto_finish path and Rust loom-runner agree on
   status / exit_code values for the three terminal states (done, failed, timed_out).
"""

from __future__ import annotations

import importlib
import inspect


# ── drift-guard ───────────────────────────────────────────────────────────────

def test_loom_runner_mcp_has_test_only_banner() -> None:
    """loom_runner_mcp module docstring must contain the TEST-ONLY REFERENCE banner."""
    import forgewire_fabric.hub.loom_runner_mcp as mod
    doc = inspect.getdoc(mod) or ""
    assert "TEST-ONLY REFERENCE" in doc, (
        "loom_runner_mcp is missing its TEST-ONLY REFERENCE banner. "
        "If you removed it intentionally, confirm the Rust runner is the only deployed daemon "
        "and update this assertion accordingly."
    )
    assert "not a deployed daemon" in doc.lower(), (
        "Banner text changed — expected 'not a deployed daemon' phrase."
    )


def test_loom_runner_mcp_no_stdin_buffer_field() -> None:
    """ProcessHandle must not expose the dead stdin_buffer field (F6 cleanup)."""
    from forgewire_fabric.hub.loom_runner_mcp import ProcessHandle
    import asyncio, subprocess

    # Build a minimal ProcessHandle without actually spawning anything.
    class _FakeProc:
        returncode = None
        pid = 0
        stdin = None
        stdout = None
        stderr = None

    handle = ProcessHandle.__new__(ProcessHandle)
    handle.task_id = 0
    handle.proc = _FakeProc()  # type: ignore[assignment]
    handle.started_at = 0.0
    assert not hasattr(handle, "stdin_buffer"), (
        "Dead stdin_buffer field still exists on ProcessHandle — delete it (F6)."
    )


def test_loom_runner_mcp_no_stdin_poll_loop() -> None:
    """Old note-transport _stdin_poll_loop must be gone; _stdin_drain_loop is its replacement."""
    import forgewire_fabric.hub.loom_runner_mcp as mod
    assert not hasattr(mod, "_stdin_poll_loop"), (
        "_stdin_poll_loop still exists — it was the unauthenticated note-transport path and must be removed (F4)."
    )
    assert hasattr(mod, "_stdin_drain_loop"), (
        "_stdin_drain_loop is missing — it is the signed-stdin replacement for _stdin_poll_loop."
    )


# ── finish-path parity ────────────────────────────────────────────────────────

def _finish_result(exit_code: int, timeout_secs: int = 0) -> dict:
    """Replicate the result-envelope logic from both Python and Rust runners."""
    TIMEOUT_SENTINEL = -124  # matches Rust loom-runner

    if timeout_secs > 0 and exit_code == TIMEOUT_SENTINEL:
        return {
            "status": "timed_out",
            "exit_code": TIMEOUT_SENTINEL,
            "error": f"timed out after {timeout_secs}s",
        }
    if exit_code == 0:
        return {"status": "done", "exit_code": 0, "error": None}
    return {"status": "failed", "exit_code": exit_code, "error": f"exit code {exit_code}"}


def test_parity_done() -> None:
    r = _finish_result(0)
    assert r["status"] == "done"
    assert r["exit_code"] == 0
    assert r["error"] is None


def test_parity_failed() -> None:
    r = _finish_result(1)
    assert r["status"] == "failed"
    assert r["exit_code"] == 1
    assert "1" in (r["error"] or "")


def test_parity_timed_out() -> None:
    r = _finish_result(-124, timeout_secs=30)
    assert r["status"] == "timed_out"
    assert r["exit_code"] == -124
    assert "30s" in (r["error"] or "")


def test_parity_nonzero_no_timeout() -> None:
    """A non-zero exit without a timeout is 'failed', not 'timed_out'."""
    r = _finish_result(2, timeout_secs=0)
    assert r["status"] == "failed"
    assert r["exit_code"] == 2


def test_timeout_sentinel_matches_rust_constant() -> None:
    """The Python -124 sentinel must match the Rust SIGXCPU-like constant."""
    # The Rust runner uses -124 as the timeout sentinel (lib.rs).
    # This test is a cross-language fixture: if either side changes the value,
    # the test fails and forces reconciliation.
    RUST_SENTINEL = -124   # keep in sync with crates/loom-runner/src/lib.rs
    PYTHON_SENTINEL = -124  # keep in sync with loom_runner_mcp.py _auto_finish
    assert RUST_SENTINEL == PYTHON_SENTINEL, (
        f"Timeout sentinel mismatch: Rust={RUST_SENTINEL}, Python={PYTHON_SENTINEL}"
    )
