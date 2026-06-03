"""Cost ledger query routes (M2.5.2).

GET /cost/summary[?since_days=7]          — aggregated spend by model + day
GET /cost/records[?since_days=30&limit=N] — raw cost_ledger rows newest-first
GET /cost/budget                          — current daily/weekly totals vs caps
"""

from __future__ import annotations

from datetime import datetime, timedelta, UTC
from typing import Any

from fastapi import APIRouter, Depends, Request

from ._deps import get_context, require_auth

router = APIRouter()


def _since_iso(days: int) -> str:
    dt = datetime.now(tz=UTC) - timedelta(days=days)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


@router.get("/cost/summary", dependencies=[Depends(require_auth)])
def cost_summary(request: Request, since_days: int = 7) -> dict[str, Any]:
    ctx = get_context(request)
    since = _since_iso(since_days) if since_days > 0 else None
    summary = ctx.blackboard.cost_summary(since_iso=since)
    summary["since_days"] = since_days
    return summary


@router.get("/cost/records", dependencies=[Depends(require_auth)])
def cost_records(
    request: Request, since_days: int = 30, limit: int = 500
) -> dict[str, Any]:
    ctx = get_context(request)
    since = _since_iso(since_days) if since_days > 0 else None
    rows = ctx.blackboard.query_cost(since_iso=since, limit=limit)
    return {"records": rows, "count": len(rows), "since_days": since_days}


@router.get("/cost/budget", dependencies=[Depends(require_auth)])
def cost_budget(request: Request) -> dict[str, Any]:
    """Return current period spend vs configured caps."""
    ctx = get_context(request)
    gate = ctx.gate
    ledger = gate.budget_enforcer.ledger
    policy = gate.budget_enforcer.policy

    from forgewire_fabric.policy.budget import _today, _this_week  # type: ignore[attr-defined]

    today = _today()
    week = _this_week()
    daily_spend = ledger.daily_total_cost(today)
    weekly_spend = ledger.weekly_total_cost(week)

    result: dict[str, Any] = {
        "today": today,
        "week": week,
        "daily_spend_usd": round(daily_spend, 6),
        "weekly_spend_usd": round(weekly_spend, 6),
    }
    if policy.daily_budget_usd is not None:
        result["daily_budget_usd"] = policy.daily_budget_usd
        result["daily_remaining_usd"] = round(
            max(0.0, policy.daily_budget_usd - daily_spend), 6
        )
        result["daily_pct"] = round(daily_spend / policy.daily_budget_usd * 100, 1)
    if policy.weekly_budget_usd is not None:
        result["weekly_budget_usd"] = policy.weekly_budget_usd
        result["weekly_remaining_usd"] = round(
            max(0.0, policy.weekly_budget_usd - weekly_spend), 6
        )
        result["weekly_pct"] = round(weekly_spend / policy.weekly_budget_usd * 100, 1)
        threshold = policy.weekly_alert_threshold
        result["weekly_alert"] = (weekly_spend / policy.weekly_budget_usd) >= threshold
    return result
