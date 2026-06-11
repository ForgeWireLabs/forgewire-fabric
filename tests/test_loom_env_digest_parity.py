"""M2.9.0 (F1) — cross-language Loom env-digest parity.

The Python signer (``loom_mcp._loom_env_digest``) and the Rust runner
(``loom-runner::compute_env_digest``) must produce byte-identical digests for the
same env map, or the runner refuses legitimately signed briefs with an "env
digest mismatch". This test consumes the same fixture as the Rust unit test in
``crates/loom-runner/src/lib.rs`` (``tests/fixtures/phase_2_9/env_digest.json``):
each case carries the exact canonical UTF-8 bytes, both sides hash those bytes
and assert the digest function reproduces them.

Regression guard: M2.9.1 shipped a hand-rolled Rust escaper that only escaped
backslash + double-quote, so newline / tab / non-ASCII values diverged from the
Python ``json.dumps`` canonical form. The newline/tab/unicode cases below are
exactly that bug.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from forgewire_fabric.hub.loom_mcp import _loom_env_digest
from forgewire_fabric.runner.runner_capabilities import canonical_payload

_FIXTURE = Path(__file__).parent / "fixtures" / "phase_2_9" / "env_digest.json"


def _cases() -> list[dict]:
    doc = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    cases = doc["cases"]
    assert cases, "fixture must have cases"
    return cases


def test_env_digest_matches_canonical_fixture() -> None:
    for case in _cases():
        name = case["name"]
        env = case["env"]
        expected_canonical = case["expected_canonical"]

        # canonical_payload must reproduce the fixture's canonical bytes exactly
        # (this is the byte-parity the Rust side must also match).
        assert canonical_payload(dict(env)).decode("utf-8") == expected_canonical, (
            f"case {name}: canonical_payload diverged from fixture"
        )

        expected_digest = hashlib.sha256(expected_canonical.encode("utf-8")).hexdigest()
        assert _loom_env_digest(env) == expected_digest, (
            f"case {name}: _loom_env_digest mismatch (canonical={expected_canonical!r})"
        )
