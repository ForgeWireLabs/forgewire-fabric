"""M2.5.2 cost ledger CLI commands.

  forgewire-fabric cost summary [--since 7d] [--by model|day]
  forgewire-fabric cost export   [--since 30d] [--format json|csv]
  forgewire-fabric cost burndown [--week]
  forgewire-fabric cost budget
"""

from __future__ import annotations

import csv
import io
import json

import click

from . import cli
from ._helpers import _async, _client


@cli.group(help="Cost ledger reporting (M2.5.2).")
def cost() -> None:
    pass


@cost.command("summary", help="Aggregated spend for the last N days.")
@click.option("--since", default="7d", show_default=True, help="Look-back window, e.g. 7d, 30d.")
@click.option(
    "--by",
    type=click.Choice(["model", "day", "both"]),
    default="both",
    show_default=True,
)
def cost_summary(since: str, by: str) -> None:
    days = _parse_days(since)

    async def _go() -> None:
        async with _client() as c:
            data = await c.cost_summary(since_days=days)
        click.echo(f"Period:       last {days}d")
        click.echo(f"Total cost:   ${data['total_cost_usd']:.4f}")
        click.echo(f"Total tokens: {data['total_tokens']:,}")
        click.echo(f"Wall time:    {data['total_wall_seconds']:.0f}s")
        click.echo(f"Records:      {data['record_count']}")
        if by in ("model", "both") and data.get("by_model"):
            click.echo("\nBy model:")
            for model, agg in sorted(data["by_model"].items(), key=lambda x: -x[1]["cost_usd"]):
                click.echo(f"  {model or '(unknown)':40s}  ${agg['cost_usd']:.4f}  {agg['tokens']:>10,} tok")
        if by in ("day", "both") and data.get("by_day"):
            click.echo("\nBy day:")
            for day, agg in sorted(data["by_day"].items()):
                click.echo(f"  {day}  ${agg['cost_usd']:.4f}  {agg['tokens']:>10,} tok")

    _async(_go())


@cost.command("export", help="Export raw cost records.")
@click.option("--since", default="30d", show_default=True)
@click.option("--limit", default=10_000, show_default=True)
@click.option(
    "--format", "fmt",
    type=click.Choice(["json", "csv"]),
    default="json",
    show_default=True,
)
def cost_export(since: str, limit: int, fmt: str) -> None:
    days = _parse_days(since)

    async def _go() -> None:
        async with _client() as c:
            data = await c.cost_records(since_days=days, limit=limit)
        records = data.get("records", [])
        if fmt == "json":
            click.echo(json.dumps(records, indent=2))
        else:
            if not records:
                click.echo("task_id,model_id,prompt_tokens,completion_tokens,cost_usd,wall_seconds,created_at")
                return
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=list(records[0].keys()), extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)
            click.echo(buf.getvalue(), nl=False)

    _async(_go())


@cost.command("burndown", help="Weekly spend trend (last 8 weeks).")
@click.option("--weeks", default=8, show_default=True)
def cost_burndown(weeks: int) -> None:
    days = weeks * 7

    async def _go() -> None:
        async with _client() as c:
            data = await c.cost_summary(since_days=days)
        by_day: dict[str, float] = {
            d: v["cost_usd"] for d, v in (data.get("by_day") or {}).items()
        }
        if not by_day:
            click.echo("No cost records in the requested period.")
            return

        # Group days into ISO weeks for display.
        from datetime import datetime, UTC
        from collections import defaultdict
        weeks_map: dict[str, float] = defaultdict(float)
        for day_str, usd in by_day.items():
            try:
                dt = datetime.strptime(day_str, "%Y-%m-%d").replace(tzinfo=UTC)
                iso = dt.isocalendar()
                wk = f"{iso.year}-W{iso.week:02d}"
            except ValueError:
                wk = "unknown"
            weeks_map[wk] += usd

        max_usd = max(weeks_map.values()) or 1.0
        bar_width = 40
        click.echo(f"Weekly burndown (last {weeks} weeks):\n")
        for wk in sorted(weeks_map):
            usd = weeks_map[wk]
            bar = "█" * int(usd / max_usd * bar_width)
            click.echo(f"  {wk}  {bar:<{bar_width}}  ${usd:.4f}")

    _async(_go())


@cost.command("budget", help="Current period spend vs configured caps.")
def cost_budget_cmd() -> None:
    async def _go() -> None:
        async with _client() as c:
            data = await c.cost_budget()
        click.echo(f"Today ({data['today']}):")
        click.echo(f"  Spent:     ${data['daily_spend_usd']:.4f}")
        if "daily_budget_usd" in data:
            pct = data.get("daily_pct", 0)
            rem = data.get("daily_remaining_usd", 0)
            click.echo(f"  Budget:    ${data['daily_budget_usd']:.4f}  ({pct:.1f}% used, ${rem:.4f} remaining)")

        click.echo(f"\nThis week ({data['week']}):")
        click.echo(f"  Spent:     ${data['weekly_spend_usd']:.4f}")
        if "weekly_budget_usd" in data:
            pct = data.get("weekly_pct", 0)
            rem = data.get("weekly_remaining_usd", 0)
            alert = " ⚠ ALERT" if data.get("weekly_alert") else ""
            click.echo(f"  Budget:    ${data['weekly_budget_usd']:.4f}  ({pct:.1f}% used, ${rem:.4f} remaining){alert}")

    _async(_go())


def _parse_days(s: str) -> int:
    """Parse '7d', '30d', or bare int string → int days."""
    s = s.strip().lower()
    if s.endswith("d"):
        return int(s[:-1])
    if s.endswith("w"):
        return int(s[:-1]) * 7
    return int(s)
