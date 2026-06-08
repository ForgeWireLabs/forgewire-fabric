"""M2.5.4: capability matcher + smart routing.

Two layers:

* ``test_matcher_*``  — pure unit tests for the parser/evaluator.
* ``test_route_*``    — unit tests for pick_task routing logic using plain
  dicts; no runner registration, no rqlite writes.
* ``test_legacy_*``   — HTTP tests for the legacy /tasks/claim skip behaviour.

Tests NEVER register runners in rqlite.  The cluster has exactly two real
machines; tests must not add to that count.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from forgewire_fabric.hub._router import pick_task
from forgewire_fabric.hub.capability_matcher import match
from forgewire_fabric.hub.server import BlackboardConfig, create_app


HUB_TOKEN = "x" * 32
BEARER = {"Authorization": f"Bearer {HUB_TOKEN}"}


# ---------------------------------------------------------------- matcher unit tests


def test_matcher_presence_predicate() -> None:
    ok, missing = match(["toolchains.rust"], {"toolchains": {"rust": True, "node": True}})
    assert ok and missing == []
    ok, missing = match(["toolchains.go"], {"toolchains": {"rust": True}})
    assert not ok and any("go" in m for m in missing)


def test_matcher_list_membership_shorthand() -> None:
    caps = {"toolchains": ["rust", "node"]}
    ok, _ = match(["toolchains.rust"], caps)
    assert ok
    ok, missing = match(["toolchains.go"], caps)
    assert not ok and "go" in " ".join(missing)


def test_matcher_version_comparisons() -> None:
    caps = {"python": "3.13.1", "ram_gb": 64, "cpu": {"cores": 16}}
    ok, _ = match(["python ~= 3.12", "ram_gb >= 32", "cpu.cores >= 8"], caps)
    assert ok
    ok, missing = match(["python ~= 3.14"], caps)
    assert not ok
    ok, missing = match(["ram_gb >= 128"], caps)
    assert not ok and "ram_gb" in missing[0]


def test_matcher_compatible_release_rejects_major_jump() -> None:
    ok, _ = match(["python ~= 3.12"], {"python": "4.0.0"})
    assert not ok


def test_matcher_equality_and_string() -> None:
    caps = {"os": "windows-11", "region": "homelab"}
    ok, _ = match(['os == "windows-11"', "region == homelab"], caps)
    assert ok
    ok, _ = match(['os == "linux"'], caps)
    assert not ok


def test_matcher_substring_subkey_on_gpu_label() -> None:
    caps = {"gpu": "nvidia:cuda:12.4"}
    ok, _ = match(["gpu.cuda >= 12"], caps)
    assert ok
    ok, _ = match(["gpu.cuda >= 13"], caps)
    assert not ok


def test_matcher_empty_required_passes_anything() -> None:
    ok, missing = match([], {"anything": "goes"})
    assert ok and missing == []


# ---------------------------------------------------------------- routing unit tests
#
# pick_task() takes plain Python dicts — no rqlite, no runner registration.
# These tests verify that the router selects the correct candidate from a
# list of task dicts given a runner dict.


def _task(task_id: int, required_capabilities: list[str] | None = None) -> dict:
    return {
        "id": task_id,
        "scope_globs": ["src/**"],
        "required_tools": [],
        "required_tags": [],
        "required_capabilities": required_capabilities or [],
        "tenant": None,
        "workspace_root": None,
        "require_base_commit": False,
        "base_commit": "a" * 40,
    }


def _runner(capabilities: dict | None = None) -> dict:
    return {
        "scope_prefixes": [],
        "tools": [],
        "tags": [],
        "tenant": None,
        "workspace_root": None,
        "last_known_commit": None,
        "capabilities": capabilities or {},
    }


def test_route_task_without_caps_picked_by_any_runner() -> None:
    """Task with no required_capabilities is picked by any runner."""
    tasks = [_task(1, required_capabilities=[])]
    idx, _ = pick_task(tasks, _runner({}))
    assert idx == 0


def test_route_tags_filter_tasks() -> None:
    """Task requiring a tag is skipped by a runner that lacks it."""
    gated = {**_task(1), "required_tags": ["gpu"]}
    plain = _task(2, required_capabilities=[])
    runner_no_tag = _runner({})
    runner_no_tag["tags"] = []
    # Runner without 'gpu' tag skips gated, picks plain.
    idx, _ = pick_task([gated, plain], runner_no_tag)
    assert idx == 1

    runner_with_tag = {**runner_no_tag, "tags": ["gpu"]}
    idx2, _ = pick_task([gated], runner_with_tag)
    assert idx2 == 0


def test_route_capability_match_capable() -> None:
    """Capability matching: capable runner satisfies requirements."""
    ok, missing = match(["toolchains.rust", "ram_gb >= 32"],
                        {"toolchains": {"rust": True}, "ram_gb": 64})
    assert ok
    assert missing == []


def test_route_capability_match_weak() -> None:
    """Capability matching: weak runner reports missing capabilities."""
    ok, missing = match(["toolchains.rust", "ram_gb >= 32"],
                        {"toolchains": {"node": True}, "ram_gb": 8})
    assert not ok
    assert any("rust" in m or "ram_gb" in m for m in missing)


def test_route_capability_match_no_requirements() -> None:
    """Empty requirements always match any runner."""
    ok, missing = match([], {})
    assert ok
    assert missing == []


def test_route_empty_task_list() -> None:
    idx, seen = pick_task([], _runner())
    assert idx is None
    assert seen == 0


# ---------------------------------------------------------------- legacy claim HTTP tests
#
# These tests dispatch tasks and claim via POST /tasks/claim (worker_id string,
# no runner registration). They verify hub-side filtering logic only.


def _build_client() -> TestClient:
    tmp = Path(tempfile.mkdtemp(prefix="fw-cap-"))
    cfg = BlackboardConfig(
        db_path=tmp / "blackboard.db", token=HUB_TOKEN, host="127.0.0.1", port=0,
    )
    return TestClient(create_app(cfg))


def test_legacy_claim_skips_capability_gated_tasks() -> None:
    """Legacy /tasks/claim must not pick up tasks with required_capabilities."""
    client = _build_client()
    # Dispatch a capability-gated task.
    client.post("/tasks", json={
        "title": "cap-task", "prompt": "noop", "scope_globs": ["docs/x.md"],
        "base_commit": "a" * 40, "branch": "feature/cap",
        "required_capabilities": ["toolchains.rust"],
    }, headers=BEARER)

    # Dispatch a plain task with higher priority so legacy claim picks it first
    # if it skips the gated one.
    plain = client.post("/tasks", json={
        "title": "plain", "prompt": "noop", "scope_globs": ["docs/y.md"],
        "base_commit": "b" * 40, "branch": "feature/plain", "priority": 9999,
    }, headers=BEARER).json()

    r = client.post("/tasks/claim",
                    json={"worker_id": "test-legacy-1", "hostname": "test-host"},
                    headers=BEARER)
    assert r.status_code == 200
    claimed = r.json()["task"]
    assert claimed is not None
    assert claimed["id"] == plain["id"]
