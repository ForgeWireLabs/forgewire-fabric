"""Tests for M2.5.2 cost ledger — schema, recording, routes, weekly budget."""

from __future__ import annotations

import tempfile
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from forgewire_fabric.hub.server import BlackboardConfig, create_app
from forgewire_fabric.policy.budget import (
    BudgetEnforcer,
    BudgetPolicy,
    CostLedger,
    CostRecord,
    TaskBudget,
    _to_week,
)


HUB_TOKEN = "x" * 32
BEARER = {"Authorization": f"Bearer {HUB_TOKEN}"}
BASE_TASK = {
    "title": "cost-test",
    "prompt": "echo hello",
    "base_commit": "a" * 40,
    "scope_globs": ["src/**"],
    "branch": "feature/cost",
    "kind": "agent",
}


def _make_client(policy: dict | None = None) -> TestClient:
    tmp = Path(tempfile.mkdtemp(prefix="fw-cost-"))
    cfg_kwargs: dict = {"db_path": tmp / "hub.db", "token": HUB_TOKEN, "host": "127.0.0.1", "port": 0}
    if policy:
        p = tmp / "policy.yaml"
        p.write_text(yaml.safe_dump(policy), encoding="utf-8")
        cfg_kwargs["policy_path"] = p
    return TestClient(create_app(BlackboardConfig(**cfg_kwargs)), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Unit tests — CostLedger + BudgetEnforcer
# ---------------------------------------------------------------------------

def test_cost_ledger_weekly_tracking() -> None:
    ledger = CostLedger()
    import time
    ts = time.time()
    week = _to_week(ts)
    ledger.record(CostRecord(task_id="t1", dispatch_id="d1", model="m1",
                             cost_usd=1.50, recorded_at=ts))
    ledger.record(CostRecord(task_id="t2", dispatch_id="d2", model="m1",
                             cost_usd=0.50, recorded_at=ts))
    assert abs(ledger.weekly_total_cost(week) - 2.00) < 1e-6


def test_weekly_budget_deny() -> None:
    ledger = CostLedger()
    import time
    ts = time.time()
    ledger.record(CostRecord(task_id="old", dispatch_id="d", model="m",
                             cost_usd=9.00, recorded_at=ts))
    enforcer = BudgetEnforcer(ledger=ledger, policy=BudgetPolicy(weekly_budget_usd=10.0))
    decision = enforcer.evaluate_dispatch(
        task_id="new", estimated_cost_usd=2.0
    )
    assert decision.denied
    assert any("weekly" in v.rule for v in decision.violations)


def test_weekly_budget_allow_under_cap() -> None:
    ledger = CostLedger()
    enforcer = BudgetEnforcer(ledger=ledger, policy=BudgetPolicy(weekly_budget_usd=10.0))
    decision = enforcer.evaluate_dispatch(task_id="t", estimated_cost_usd=3.0)
    assert decision.allowed


def test_max_cost_usd_per_task() -> None:
    ledger = CostLedger()
    import time
    ledger.record(CostRecord(task_id="t1", dispatch_id="d", model="m",
                             cost_usd=0.40, recorded_at=time.time()))
    enforcer = BudgetEnforcer(ledger=ledger, policy=BudgetPolicy())
    decision = enforcer.evaluate_dispatch(
        task_id="t1",
        estimated_cost_usd=0.20,
        task_budget=TaskBudget(max_cost_usd=0.50),
    )
    assert decision.denied
    assert any("max_cost_usd" in v.rule for v in decision.violations)


# ---------------------------------------------------------------------------
# Integration tests — hub routes
# ---------------------------------------------------------------------------

def test_cost_summary_returns_shape() -> None:
    # On a shared cluster the cost_ledger already has rows from prior runs.
    # Assert the response shape only, not exact totals.
    client = _make_client()
    resp = client.get("/cost/summary", headers=BEARER)
    assert resp.status_code == 200
    body = resp.json()
    assert "total_cost_usd" in body
    assert "record_count" in body
    assert body["total_cost_usd"] >= 0.0
    assert body["record_count"] >= 0


def test_cost_records_returns_list() -> None:
    # On a shared cluster cost_ledger already has rows from prior runs.
    # Assert the response shape, not an exact count.
    client = _make_client()
    resp = client.get("/cost/records", headers=BEARER)
    assert resp.status_code == 200
    body = resp.json()
    assert "count" in body
    assert "records" in body
    assert isinstance(body["records"], list)
    assert body["count"] == len(body["records"])


def test_cost_budget_no_caps() -> None:
    client = _make_client()
    resp = client.get("/cost/budget", headers=BEARER)
    assert resp.status_code == 200
    body = resp.json()
    assert "daily_spend_usd" in body
    assert "weekly_spend_usd" in body
    assert "daily_budget_usd" not in body


def test_cost_recorded_at_submit_result() -> None:
    client = _make_client()
    # Capture baseline before this test's dispatch (shared cluster has prior records).
    baseline = client.get("/cost/summary", headers=BEARER).json()
    baseline_count = baseline["record_count"]
    baseline_total = baseline["total_cost_usd"]

    client.post("/tasks", json=BASE_TASK, headers=BEARER)
    claim = client.post(
        "/tasks/claim",
        json={"worker_id": "r1", "hostname": "h"},
        headers=BEARER,
    ).json()
    task_id = claim["task"]["id"]
    client.post(f"/tasks/{task_id}/start", headers=BEARER)
    resp = client.post(
        f"/tasks/{task_id}/result",
        json={
            "worker_id": "r1",
            "status": "done",
            "model_id": "claude-3",
            "prompt_tokens": 100,
            "completion_tokens": 200,
            "cost_usd": 0.0042,
            "wall_seconds": 12.5,
        },
        headers=BEARER,
    )
    assert resp.status_code == 200

    summary = client.get("/cost/summary", headers=BEARER).json()
    assert summary["record_count"] == baseline_count + 1
    assert abs(summary["total_cost_usd"] - baseline_total - 0.0042) < 1e-6
    assert summary["total_tokens"] >= 300
    assert "claude-3" in summary["by_model"]


def test_dispatch_denied_over_daily_budget() -> None:
    """Direct BudgetEnforcer test for daily cap — no hub round-trip needed."""
    ledger = CostLedger()
    import time
    ledger.record(CostRecord(task_id="t0", dispatch_id="d", model="m",
                             cost_usd=9.50, recorded_at=time.time()))
    enforcer = BudgetEnforcer(ledger=ledger, policy=BudgetPolicy(daily_budget_usd=10.0))
    decision = enforcer.evaluate_dispatch(task_id="t1", estimated_cost_usd=1.0)
    assert decision.denied
    assert any("daily" in v.rule for v in decision.violations)


def test_dispatch_max_cost_usd_via_hub() -> None:
    """max_cost_usd on the brief denies when task has already spent that much."""
    client = _make_client()
    # Dispatch + complete a task so its cost is recorded in the in-memory ledger
    client.post("/tasks", json=BASE_TASK, headers=BEARER)
    claim = client.post(
        "/tasks/claim",
        json={"worker_id": "r1", "hostname": "h"},
        headers=BEARER,
    ).json()
    task_id = str(claim["task"]["id"])
    client.post(f"/tasks/{task_id}/start", headers=BEARER)
    client.post(
        f"/tasks/{task_id}/result",
        json={"worker_id": "r1", "status": "done", "cost_usd": 0.60},
        headers=BEARER,
    )
    # Re-dispatch the same todo_id with max_cost_usd=0.50 — should be denied
    # because ledger already shows 0.60 for that task_id
    resp = client.post(
        "/tasks",
        json={**BASE_TASK, "todo_id": task_id, "max_cost_usd": 0.50},
        headers=BEARER,
    )
    assert resp.status_code == 403
    assert "budget" in str(resp.json()).lower() or "cost" in str(resp.json()).lower()
