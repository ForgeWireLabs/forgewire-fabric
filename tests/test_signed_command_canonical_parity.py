"""M2.9.0 cross-language fixture: signed Loom command canonical parity.

Verifies that `canonical_payload` (Python) produces the exact bytes recorded in
`tests/fixtures/phase_2_9/signed_command_canonical.json` for every case. The
matching Rust test (`cargo test -p fabric-protocol canonical_fixture`) checks the
same fixture independently so any divergence is caught on either side.

The agent-kind case is the additive-only proof: loom fields are absent for agent
briefs, so the canonical is byte-identical to the pre-M2.9 shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forgewire_fabric.hub.loom_mcp import canonical_payload

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "phase_2_9" / "signed_command_canonical.json"


def _load_cases() -> list[dict]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", _load_cases(), ids=[c["name"] for c in _load_cases()])
def test_canonical_matches_fixture(case: dict) -> None:
    envelope = case["envelope"]
    expected = case["expected_canonical"].encode("utf-8")
    actual = canonical_payload(envelope)
    assert actual == expected, (
        f"[{case['name']}] canonical mismatch.\n"
        f"  expected: {expected!r}\n"
        f"  actual:   {actual!r}"
    )
