"""Shared fixtures for the Phase 2.8 live cutover suite.

These tests run against a **real, running** ForgeWire cluster (Rust hub +
rqlite + at least one Loom runner). They are skipped automatically when no hub
is reachable, so the default `pytest` run on a dev box is unaffected.

Point the suite at a cluster with:

  FORGEWIRE_LIVE_HUB_URL    (default http://127.0.0.1:8765)
  FORGEWIRE_HUB_TOKEN_FILE  (default C:\\ProgramData\\forgewire\\hub.token)
  FORGEWIRE_LIVE_LOOM_HOST  hostname of the node whose Loom runner should run
                            the command-dispatch checks (default: local host)

A Loom runner must be online for the dispatch/routing checks; if none is
registered the relevant tests skip with a clear reason rather than fail.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

import httpx
import pytest


def _hub_url() -> str:
    return os.environ.get("FORGEWIRE_LIVE_HUB_URL", "http://127.0.0.1:8765").rstrip("/")


def _token() -> str:
    tf = os.environ.get("FORGEWIRE_HUB_TOKEN_FILE")
    candidates = [tf] if tf else []
    if platform.system() == "Windows":
        candidates.append(r"C:\ProgramData\forgewire\hub.token")
    else:
        candidates.append("/var/lib/forgewire/hub.token")
    for c in candidates:
        if c and Path(c).exists():
            try:
                return Path(c).read_text(encoding="utf-8").strip()
            except OSError:
                continue
    return os.environ.get("FORGEWIRE_HUB_TOKEN", "")


def _hub_reachable() -> bool:
    try:
        r = httpx.get(f"{_hub_url()}/healthz", timeout=3.0)
        return r.status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(
    not _hub_reachable(),
    reason=f"live hub {_hub_url()} not reachable",
)


@pytest.fixture(scope="session")
def hub_url() -> str:
    return _hub_url()


@pytest.fixture(scope="session")
def token() -> str:
    t = _token()
    if not t:
        pytest.skip("no hub token available for live cluster")
    return t


@pytest.fixture(scope="session")
def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def loom_host() -> str:
    return os.environ.get("FORGEWIRE_LIVE_LOOM_HOST", platform.node())
