"""Hub runtime configuration models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class BlackboardConfig:
    db_path: Path
    token: str
    host: str
    port: int
    min_runner_version: str = "0.4.0"
    require_signed_dispatch: bool = False
    scoped_tokens: dict[str, set[str]] | None = None
    policy_path: Path | None = None
    backend: str = "rqlite"
    rqlite_host: str = "127.0.0.1"
    rqlite_port: int = 4001
    rqlite_consistency: str = "strong"
    approval_webhook_url: str | None = None
    approval_ntfy_url: str | None = None
    approval_slack_url: str | None = None
    labels_snapshot_path: Path | None = None
