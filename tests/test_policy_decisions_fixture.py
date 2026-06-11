"""M2.9.0 cross-language fixture: policy dispatch-gate decisions (cross-scope cases).

Verifies that the Python FabricPolicyEngine produces the expected outcome for
every 'cross' case in `tests/fixtures/phase_2_9/policy_decisions.json`. Cases
marked 'rust_only' exercise predicates not in the Python engine (blocked_branches,
cwd scope-escape, etc.) and are tested by the Rust suite only.

The matching Rust test (`cargo test -p fabric-policy policy_decisions_fixture`)
covers all 17 cases.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forgewire_fabric.policy.engine import (
    DispatchRequest,
    FabricPolicy,
    FabricPolicyEngine,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "phase_2_9" / "policy_decisions.json"


def _load_cross_cases() -> list[dict]:
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return [c for c in data["cases"] if c.get("scope") == "cross"]


@pytest.mark.parametrize(
    "case", _load_cross_cases(), ids=[c["name"] for c in _load_cross_cases()]
)
def test_policy_decision_matches_fixture(case: dict) -> None:
    policy = FabricPolicy.from_mapping(case["policy"])
    engine = FabricPolicyEngine(policy)

    req_data = case["request"]
    request = DispatchRequest(
        task_id="fixture-test",
        scope_globs=req_data.get("scope_globs") or [],
        target_branch=req_data.get("target_branch"),
    )
    decision = engine.evaluate_dispatch(request)

    expected = case["expected_decision"]
    reason_substr = case.get("expected_reason_contains", "")

    if expected == "allow":
        assert decision.allowed, (
            f"[{case['name']}] expected allow, got {decision.decision.value}: {decision.reason}"
        )
    elif expected == "deny":
        assert decision.denied, (
            f"[{case['name']}] expected deny, got {decision.decision.value}: {decision.reason}"
        )
    elif expected == "needs_approval":
        assert decision.needs_approval, (
            f"[{case['name']}] expected needs_approval, got {decision.decision.value}: {decision.reason}"
        )
    else:
        pytest.fail(f"Unknown expected_decision: {expected!r}")

    if reason_substr:
        searchable = (decision.reason + " " + " ".join(
            v.message for v in decision.violations
        )).lower()
        assert reason_substr.lower() in searchable, (
            f"[{case['name']}] expected reason to contain {reason_substr!r}, "
            f"got reason={decision.reason!r} violations={[v.message for v in decision.violations]}"
        )
