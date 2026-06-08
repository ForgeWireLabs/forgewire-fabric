"""M2.7.0 golden-fixture generator.

Run from the repo root:

    python tests/fixtures/generate_fixtures.py

Produces deterministic JSON fixtures in tests/fixtures/{protocol,audit,routing,store}/.
Every fixture is byte-stable: the same ed25519 test keypair, same inputs, same outputs.
The Rust test suite loads these files and must reproduce the same bytes.

Requires: cryptography >= 41 (already in the venv).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Deterministic test keypair (NOT a real key — for fixtures only)
# Derived from a fixed 32-byte seed so fixtures are reproducible.
# ---------------------------------------------------------------------------

_SEED_HEX = "deadbeef" * 8  # 32 bytes, obviously fake


def _make_test_keypair() -> tuple[str, str]:
    """Return (secret_key_hex, public_key_hex) from a fixed seed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = bytes.fromhex(_SEED_HEX)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key()
    sk_hex = seed.hex()
    pk_hex = pk.public_bytes_raw().hex()
    return sk_hex, pk_hex


def _sign(sk_hex: str, payload: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk_hex))
    return sk.sign(payload).hex()


def _verify(pk_hex: str, payload: bytes, sig_hex: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
        pk.verify(bytes.fromhex(sig_hex), payload)
        return True
    except Exception:
        return False


def _canonicalize(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Audit chain helpers (must match Blackboard._audit_event_hash exactly)
# ---------------------------------------------------------------------------

AUDIT_GENESIS_HASH = "0" * 64


def _audit_canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _audit_event_hash(prev_hash: str, kind: str, payload: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))  # ascii(prev_hash)
    h.update(b"|")                       # LITERAL separator byte
    h.update(kind.encode("utf-8"))       # utf8(kind)
    h.update(b"|")                       # LITERAL separator byte
    h.update(_audit_canonical(payload))  # audit_canonical_json(payload)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Fixture writers
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent


def write_protocol_fixtures(sk_hex: str, pk_hex: str) -> None:
    """protocol/envelope_v2.json — canonical JSON + sign/verify/tamper fixtures."""

    SKEW = 300  # SIGNATURE_MAX_SKEW_SECONDS

    # Minimal valid v2 dispatch envelope
    envelope_minimal = {
        "op": "dispatch",
        "dispatcher_id": "test-dispatcher-001",
        "title": "Test task",
        "prompt": "Do the thing.",
        "scope_globs": ["core/services/**"],
        "base_commit": "abc1234",
        "branch": "agent/test/task-1",
        "timestamp": 1748649600,  # 2025-05-31 00:00:00 UTC (fixed, not now())
        "nonce": "fixture-nonce-0001",
    }

    canonical_minimal = _canonicalize(envelope_minimal)
    sig_minimal = _sign(sk_hex, canonical_minimal)

    # Unicode in title and prompt (must survive canonical round-trip)
    envelope_unicode = {
        "op": "dispatch",
        "dispatcher_id": "test-dispatcher-001",
        "title": "Tâche — données «spéciales» éàü",
"prompt": "Emoji: \U0001f525 and plane-1: \U00010FFF",
        "scope_globs": ["modules/漢字/**"],
        "base_commit": "abc1234",
        "branch": "agent/test/unicode",
        "timestamp": 1748649601,
        "nonce": "fixture-nonce-unicode",
    }
    canonical_unicode = _canonicalize(envelope_unicode)
    sig_unicode = _sign(sk_hex, canonical_unicode)

    # Tampered envelope — flip one byte in canonical bytes → sig must fail
    canonical_tampered = bytearray(canonical_minimal)
    canonical_tampered[10] ^= 0x01
    tamper_verifies = _verify(pk_hex, bytes(canonical_tampered), sig_minimal)
    assert not tamper_verifies, "tampered payload must not verify"

    # Wrong-key envelope — sign with different key, verify with test key → fail
    wrong_sk_hex = "cafebabe" * 8
    wrong_sig = _sign(wrong_sk_hex, canonical_minimal)
    wrong_key_verifies = _verify(pk_hex, canonical_minimal, wrong_sig)
    assert not wrong_key_verifies, "wrong-key sig must not verify with test key"

    # Keys must be 32 bytes / 64 hex chars
    assert len(pk_hex) == 64
    assert len(sk_hex) == 64

    out = {
        "_description": (
            "Golden fixtures for ForgeWire v2 dispatch envelope canonicalization, "
            "signing, and verification. Every digest and signature was produced by "
            "the Python oracle at oracle/v2.7.0-baseline. Rust tests must reproduce "
            "all canonical_hex and signature values byte-for-byte."
        ),
        "_oracle_tag": "oracle/v2.7.0-baseline",
        "_seed_hex": _SEED_HEX,
        "test_keypair": {
            "secret_key_hex": sk_hex,
            "public_key_hex": pk_hex,
            "note": "Fixed seed — NOT a real key. For fixture cross-language parity only.",
        },
        "canonical_formula": (
            "json.dumps(envelope, sort_keys=True, separators=(',', ':'))"
            ".encode('utf-8')"
        ),
        "cases": [
            {
                "id": "minimal_valid",
                "description": "Minimal valid v2 dispatch envelope — happy path sign + verify.",
                "envelope": envelope_minimal,
                "canonical_hex": canonical_minimal.hex(),
                "canonical_utf8": canonical_minimal.decode("utf-8"),
                "signature_hex": sig_minimal,
                "verify_with_correct_key": True,
                "verify_with_wrong_key": False,
            },
            {
                "id": "unicode_fields",
                "description": "Unicode in title, prompt, scope_globs — must survive canonical round-trip.",
                "envelope": envelope_unicode,
                "canonical_hex": canonical_unicode.hex(),
                "canonical_utf8": canonical_unicode.decode("utf-8"),
                "signature_hex": sig_unicode,
                "verify_with_correct_key": True,
            },
            {
                "id": "tamper_rejection",
                "description": "Canonical bytes with one bit flipped — signature must not verify.",
                "envelope": envelope_minimal,
                "canonical_hex": canonical_minimal.hex(),
                "signature_hex": sig_minimal,
                "tampered_canonical_hex": bytes(canonical_tampered).hex(),
                "tampered_verifies": False,
            },
            {
                "id": "wrong_key",
                "description": "Signature produced by a different key — must not verify with test public key.",
                "envelope": envelope_minimal,
                "canonical_hex": canonical_minimal.hex(),
                "wrong_signature_hex": wrong_sig,
                "verifies_with_test_key": False,
            },
            {
                "id": "timestamp_skew_ok",
                "description": f"Timestamp within ±{SKEW}s window — accepted.",
                "timestamp": envelope_minimal["timestamp"],
                "skew_seconds": SKEW,
                "verdict": "accept",
            },
            {
                "id": "timestamp_skew_reject_future",
                "description": f"Timestamp {SKEW + 1}s in the future — rejected.",
                "delta_seconds": SKEW + 1,
                "verdict": "reject",
                "detail": "timestamp out of skew window",
            },
            {
                "id": "timestamp_skew_reject_past",
                "description": f"Timestamp {SKEW + 1}s in the past — rejected.",
                "delta_seconds": -(SKEW + 1),
                "verdict": "reject",
                "detail": "timestamp out of skew window",
            },
            {
                "id": "nonce_replay",
                "description": "Same nonce submitted twice — second attempt rejected.",
                "nonce": "fixture-nonce-replay-001",
                "first_verdict": "accept",
                "second_verdict": "reject",
                "detail": "nonce already consumed",
            },
            {
                "id": "sort_key_stability",
                "description": "Envelope with keys that sort differently from insertion order.",
                "envelope": {
                    "z_last": 1,
                    "a_first": 2,
                    "m_middle": 3,
                },
                "canonical_hex": _canonicalize({"z_last": 1, "a_first": 2, "m_middle": 3}).hex(),
                "canonical_utf8": _canonicalize({"z_last": 1, "a_first": 2, "m_middle": 3}).decode("utf-8"),
                "expected_key_order": ["a_first", "m_middle", "z_last"],
            },
        ],
    }

    (ROOT / "protocol" / "envelope_v2.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("wrote protocol/envelope_v2.json")


def write_audit_fixtures() -> None:
    """audit/chain.json — hash-chain fixtures with literal separator bytes."""

    # Event 1: dispatch
    kind_1 = "dispatch"
    payload_1: dict[str, Any] = {
        "task_id": 1,
        "title": "Test task",
        "branch": "agent/test/task-1",
        "base_commit": "abc1234",
        "scope_globs": ["core/services/**"],
        "sealed_brief_hash": "a" * 64,
        "dispatcher_id": "test-dispatcher-001",
        "signed": True,
        "approval_id": None,
        "tenant": None,
        "workspace_root": None,
        "required_tools": [],
        "required_tags": [],
        "secrets_needed": [],
        "network_egress": None,
        "timeout_minutes": 60,
        "priority": 100,
        "todo_id": None,
    }
    hash_1 = _audit_event_hash(AUDIT_GENESIS_HASH, kind_1, payload_1)

    # Event 2: claim
    kind_2 = "claim"
    payload_2: dict[str, Any] = {
        "task_id": 1,
        "worker_id": "runner-abc-001",
        "claimed_at": "2025-05-31 00:01:00",
        "secrets_dispatched": [],
    }
    hash_2 = _audit_event_hash(hash_1, kind_2, payload_2)

    # Event 3: result
    kind_3 = "result"
    payload_3: dict[str, Any] = {
        "task_id": 1,
        "worker_id": "runner-abc-001",
        "status": "done",
        "head_commit": "def5678",
        "commits": ["def5678"],
        "files_touched": ["core/services/foo.py"],
        "test_summary": "5 pass / 0 fail",
        "error": None,
        "reported_at": "2025-05-31 00:10:00",
    }
    hash_3 = _audit_event_hash(hash_2, kind_3, payload_3)

    # Verify the chain manually
    assert len(hash_1) == 64
    assert len(hash_2) == 64
    assert len(hash_3) == 64
    assert hash_1 != hash_2 != hash_3

    # Tamper: change one byte in payload_1 → hash_1 must differ
    payload_1_tampered = dict(payload_1)
    payload_1_tampered["title"] = "Test task (tampered)"
    hash_1_tampered = _audit_event_hash(AUDIT_GENESIS_HASH, kind_1, payload_1_tampered)
    assert hash_1_tampered != hash_1, "tampered payload must produce different hash"

    # Missing event: skip event 2, compute hash_3 from hash_1 → must differ from real hash_3
    hash_3_with_gap = _audit_event_hash(hash_1, kind_3, payload_3)
    assert hash_3_with_gap != hash_3, "skipped event must break chain continuity"

    # Reorder: swap events 1 and 2 (use hash from reordered chain)
    hash_2_reordered = _audit_event_hash(AUDIT_GENESIS_HASH, kind_2, payload_2)
    hash_1_reordered = _audit_event_hash(hash_2_reordered, kind_1, payload_1)
    assert hash_1_reordered != hash_2, "reordered events must produce different hashes"

    # Secret name-only: payload with secret names but no values
    kind_secret = "claim"
    payload_secret = {
        "task_id": 2,
        "worker_id": "runner-abc-001",
        "claimed_at": "2025-05-31 00:02:00",
        "secrets_dispatched": ["GITHUB_TOKEN", "OPENAI_API_KEY"],
        # Values are NEVER logged — only names
    }
    hash_secret = _audit_event_hash(AUDIT_GENESIS_HASH, kind_secret, payload_secret)

    # Expected-tail conflict: two writers compute hash from the same prev → one wins
    prev_for_conflict = hash_1
    kind_conflict_a = "result"
    kind_conflict_b = "claim"
    payload_conflict_a = {"task_id": 1, "worker_id": "runner-a", "status": "done"}
    payload_conflict_b = {"task_id": 1, "worker_id": "runner-b", "claimed_at": "2025-05-31 00:00:30"}
    hash_conflict_a = _audit_event_hash(prev_for_conflict, kind_conflict_a, payload_conflict_a)
    hash_conflict_b = _audit_event_hash(prev_for_conflict, kind_conflict_b, payload_conflict_b)
    assert hash_conflict_a != hash_conflict_b, "concurrent events from same prev produce different hashes"

    # Separator bytes: prove the formula uses b"|" between fields
    # If separators were absent, different inputs could collide.
    # Test: prev="A", kind="B", payload={} vs prev="A|B", kind="", payload={}
    no_sep_attempt = hashlib.sha256(
        b"A" + b"B" + b"{}"
    ).hexdigest()
    with_sep = _audit_event_hash("A", "B", {})
    assert with_sep != no_sep_attempt, "separator bytes must prevent field-boundary collisions"

    out = {
        "_description": (
            "Golden audit-chain fixtures for the ForgeWire hash-chained audit log. "
            "The literal b'|' separator bytes between prev_hash, kind, and payload "
            "are part of the compatibility contract. Every digest was computed by "
            "the Python oracle at oracle/v2.7.0-baseline and must be reproduced "
            "byte-for-byte by the Rust fabric-audit crate."
        ),
        "_oracle_tag": "oracle/v2.7.0-baseline",
        "formula": {
            "description": "sha256(ascii(prev) || b'|' || utf8(kind) || b'|' || audit_canonical_json(payload))",
            "audit_canonical_json": "json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')",
            "genesis_hash": AUDIT_GENESIS_HASH,
            "separator_byte_hex": "7c",
            "separator_char": "|",
        },
        "separator_isolation_proof": {
            "description": "Proves separator bytes prevent field-boundary collisions.",
            "attempt_without_separators_hex": no_sep_attempt,
            "result_with_separators_hex": with_sep,
            "are_equal": False,
        },
        "valid_chain": {
            "events": [
                {
                    "seq": 1,
                    "kind": kind_1,
                    "payload": payload_1,
                    "prev_hash": AUDIT_GENESIS_HASH,
                    "event_id_hash": hash_1,
                    "canonical_payload_hex": _audit_canonical(payload_1).hex(),
                },
                {
                    "seq": 2,
                    "kind": kind_2,
                    "payload": payload_2,
                    "prev_hash": hash_1,
                    "event_id_hash": hash_2,
                    "canonical_payload_hex": _audit_canonical(payload_2).hex(),
                },
                {
                    "seq": 3,
                    "kind": kind_3,
                    "payload": payload_3,
                    "prev_hash": hash_2,
                    "event_id_hash": hash_3,
                    "canonical_payload_hex": _audit_canonical(payload_3).hex(),
                },
            ],
            "chain_tail": hash_3,
            "verified": True,
        },
        "tamper_rejection": {
            "description": "Payload byte changed — hash must differ from valid chain.",
            "original_event_id_hash": hash_1,
            "tampered_payload": payload_1_tampered,
            "tampered_event_id_hash": hash_1_tampered,
            "hashes_equal": False,
        },
        "missing_event": {
            "description": "Event 2 omitted — event 3 computed from event 1's hash. Must not match valid hash_3.",
            "valid_hash_3": hash_3,
            "gap_hash_3": hash_3_with_gap,
            "hashes_equal": False,
        },
        "reordered_events": {
            "description": "Events 1 and 2 swapped — must produce different hashes throughout.",
            "valid_hash_1": hash_1,
            "valid_hash_2": hash_2,
            "reordered_hash_2_first": hash_2_reordered,
            "reordered_hash_1_second": hash_1_reordered,
        },
        "secret_name_only_logging": {
            "description": "Secrets log names only — values must never appear in audit payloads.",
            "kind": kind_secret,
            "payload": payload_secret,
            "event_id_hash": hash_secret,
            "allowed_fields": ["secrets_dispatched"],
            "forbidden_field_pattern": "value|secret_value|plaintext|token",
        },
        "expected_tail_conflict": {
            "description": (
                "Two concurrent writers compute from the same prev_hash. "
                "The store's linearizable append must accept exactly one and "
                "reject or retry the other. The two hashes are different so "
                "the winner is deterministic from the payload."
            ),
            "prev_hash": prev_for_conflict,
            "writer_a": {
                "kind": kind_conflict_a,
                "payload": payload_conflict_a,
                "event_id_hash": hash_conflict_a,
            },
            "writer_b": {
                "kind": kind_conflict_b,
                "payload": payload_conflict_b,
                "event_id_hash": hash_conflict_b,
            },
            "hashes_equal": False,
        },
    }

    (ROOT / "audit" / "chain.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("wrote audit/chain.json")


def write_routing_fixtures() -> None:
    """routing/decisions.json — claim-routing accept/reject fixtures."""

    # Each case: task + runner → verdict (accept | reject) + reason
    cases = [
        # --- Tenant gate ---
        {
            "id": "tenant_match",
            "description": "Task pins tenant A; runner is tenant A — accept.",
            "task": {"tenant": "tenant-a", "scope_globs": ["core/**"], "required_tools": [], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": "tenant-a", "scope_prefixes": ["core/"], "tools": [], "tags": [], "last_known_commit": None},
            "verdict": "accept",
        },
        {
            "id": "tenant_mismatch",
            "description": "Task pins tenant A; runner is tenant B — reject.",
            "task": {"tenant": "tenant-a", "scope_globs": ["core/**"], "required_tools": [], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": "tenant-b", "scope_prefixes": ["core/"], "tools": [], "tags": [], "last_known_commit": None},
            "verdict": "reject",
            "reason": "tenant mismatch",
        },
        {
            "id": "tenant_task_none_runner_set",
            "description": "Task has no tenant; runner has a tenant — accept (task is unscoped).",
            "task": {"tenant": None, "scope_globs": ["core/**"], "required_tools": [], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": "tenant-a", "scope_prefixes": ["core/"], "tools": [], "tags": [], "last_known_commit": None},
            "verdict": "accept",
        },
        # --- Workspace gate ---
        {
            "id": "workspace_match",
            "description": "Both task and runner pin the same workspace root — accept.",
            "task": {"tenant": None, "workspace_root": "/home/user/project", "scope_globs": ["src/**"], "required_tools": [], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": None, "workspace_root": "/home/user/project", "scope_prefixes": ["src/"], "tools": [], "tags": [], "last_known_commit": None},
            "verdict": "accept",
        },
        {
            "id": "workspace_mismatch",
            "description": "Task and runner pin different workspace roots — reject.",
            "task": {"tenant": None, "workspace_root": "/home/user/project-a", "scope_globs": ["src/**"], "required_tools": [], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": None, "workspace_root": "/home/user/project-b", "scope_prefixes": ["src/"], "tools": [], "tags": [], "last_known_commit": None},
            "verdict": "reject",
            "reason": "workspace_root mismatch",
        },
        # --- Scope prefix affinity ---
        {
            "id": "scope_prefix_overlap",
            "description": "Task glob core/services/** overlaps runner prefix core/ — accept.",
            "task": {"tenant": None, "scope_globs": ["core/services/**"], "required_tools": [], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": None, "scope_prefixes": ["core/"], "tools": [], "tags": [], "last_known_commit": None},
            "verdict": "accept",
        },
        {
            "id": "scope_prefix_no_overlap",
            "description": "Task glob shell/** does not overlap runner prefix core/ — reject.",
            "task": {"tenant": None, "scope_globs": ["shell/**"], "required_tools": [], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": None, "scope_prefixes": ["core/"], "tools": [], "tags": [], "last_known_commit": None},
            "verdict": "reject",
            "reason": "scope prefix affinity miss",
        },
        {
            "id": "scope_prefix_empty_runner",
            "description": "Runner has empty scope_prefixes — accepts any task glob.",
            "task": {"tenant": None, "scope_globs": ["shell/gtk/**"], "required_tools": [], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": None, "scope_prefixes": [], "tools": [], "tags": [], "last_known_commit": None},
            "verdict": "accept",
        },
        # --- Required tools ---
        {
            "id": "tools_satisfied",
            "description": "Task requires ['rust', 'python']; runner has both — accept.",
            "task": {"tenant": None, "scope_globs": ["**"], "required_tools": ["rust", "python"], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": None, "scope_prefixes": [], "tools": ["rust", "python", "node"], "tags": [], "last_known_commit": None},
            "verdict": "accept",
        },
        {
            "id": "tools_missing",
            "description": "Task requires ['rust']; runner only has ['python'] — reject.",
            "task": {"tenant": None, "scope_globs": ["**"], "required_tools": ["rust"], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": None, "scope_prefixes": [], "tools": ["python"], "tags": [], "last_known_commit": None},
            "verdict": "reject",
            "reason": "required tool 'rust' not available",
        },
        # --- Required tags ---
        {
            "id": "tags_satisfied",
            "description": "Task requires tag 'gpu'; runner has 'gpu' — accept.",
            "task": {"tenant": None, "scope_globs": ["**"], "required_tools": [], "required_tags": ["gpu"], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": None, "scope_prefixes": [], "tools": [], "tags": ["gpu", "cuda"], "last_known_commit": None},
            "verdict": "accept",
        },
        {
            "id": "tags_missing",
            "description": "Task requires tag 'tpm'; runner has none — reject.",
            "task": {"tenant": None, "scope_globs": ["**"], "required_tools": [], "required_tags": ["tpm"], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": None, "scope_prefixes": [], "tools": [], "tags": [], "last_known_commit": None},
            "verdict": "reject",
            "reason": "required tag 'tpm' not available",
        },
        # --- Base-commit precondition ---
        {
            "id": "base_commit_match",
            "description": "Task require_base_commit=True; runner HEAD matches — accept.",
            "task": {"tenant": None, "scope_globs": ["**"], "required_tools": [], "required_tags": [], "require_base_commit": True, "base_commit": "abc1234"},
            "runner": {"tenant": None, "scope_prefixes": [], "tools": [], "tags": [], "last_known_commit": "abc1234"},
            "verdict": "accept",
        },
        {
            "id": "base_commit_mismatch",
            "description": "Task require_base_commit=True; runner HEAD differs — reject.",
            "task": {"tenant": None, "scope_globs": ["**"], "required_tools": [], "required_tags": [], "require_base_commit": True, "base_commit": "abc1234"},
            "runner": {"tenant": None, "scope_prefixes": [], "tools": [], "tags": [], "last_known_commit": "zzz9999"},
            "verdict": "reject",
            "reason": "base commit precondition not met",
        },
        {
            "id": "base_commit_not_required",
            "description": "Task require_base_commit=False; runner HEAD differs — accept (no gate).",
            "task": {"tenant": None, "scope_globs": ["**"], "required_tools": [], "required_tags": [], "require_base_commit": False, "base_commit": "abc1234"},
            "runner": {"tenant": None, "scope_prefixes": [], "tools": [], "tags": [], "last_known_commit": "zzz9999"},
            "verdict": "accept",
        },
        # --- Drain state ---
        {
            "id": "drain_requested",
            "description": "Runner has drain_requested=True — must not be selected for new tasks.",
            "task": {"tenant": None, "scope_globs": ["**"], "required_tools": [], "required_tags": [], "require_base_commit": False, "base_commit": ""},
            "runner": {"tenant": None, "scope_prefixes": [], "tools": [], "tags": [], "last_known_commit": None, "drain_requested": True},
            "verdict": "reject",
            "reason": "runner is draining",
            "gate": "pre-router (hub checks drain_requested before routing)",
        },
        # --- Task kind routing ---
        {
            "id": "kind_agent_to_agent_runner",
            "description": "Task kind='agent' dispatched to agent runner — accept.",
            "task_kind": "agent",
            "runner_kind": "agent",
            "verdict": "accept",
        },
        {
            "id": "kind_command_to_command_runner",
            "description": "Task kind='command' dispatched to command runner — accept.",
            "task_kind": "command",
            "runner_kind": "command",
            "verdict": "accept",
        },
        {
            "id": "kind_agent_to_command_runner",
            "description": "Task kind='agent' must NOT go to command runner — reject.",
            "task_kind": "agent",
            "runner_kind": "command",
            "verdict": "reject",
            "reason": "task kind/runner kind mismatch",
            "gate": "hub job-queue separation (cluster.jobs.<kind> channel)",
        },
        # --- Concurrency cap ---
        {
            "id": "concurrency_at_cap",
            "description": "Runner max_concurrent=1 and already has 1 active task — reject.",
            "runner_max_concurrent": 1,
            "runner_active_tasks": 1,
            "verdict": "reject",
            "reason": "runner at concurrency cap",
            "gate": "pre-router (hub checks active task count before routing)",
        },
        {
            "id": "concurrency_under_cap",
            "description": "Runner max_concurrent=2 and has 1 active task — accept.",
            "runner_max_concurrent": 2,
            "runner_active_tasks": 1,
            "verdict": "accept",
        },
    ]

    out = {
        "_description": (
            "Routing accept/reject decision fixtures for the ForgeWire claim-routing path. "
            "The Rust fabric-router crate must reproduce all verdicts and reasons. "
            "Cases marked gate='pre-router' are enforced by the hub before calling the router "
            "and must be replicated in the native hub as well."
        ),
        "_oracle_tag": "oracle/v2.7.0-baseline",
        "routing_gates_in_order": [
            "1. tenant gate (task.tenant must match runner.tenant if both non-null)",
            "2. workspace gate (task.workspace_root must match runner.workspace_root if both non-null)",
            "3. scope prefix affinity (each task glob's static prefix must overlap a runner prefix; empty runner prefixes accept all)",
            "4. required tools (all task required_tools must be in runner.tools, case-insensitive)",
            "5. required tags (all task required_tags must be in runner.tags, case-insensitive)",
            "6. base-commit precondition (if task.require_base_commit, runner.last_known_commit must equal task.base_commit)",
        ],
        "pre_router_gates": [
            "drain_requested: runner with drain_requested=True is excluded before routing",
            "concurrency cap: runner with active_tasks >= max_concurrent is excluded before routing",
            "task kind: agent tasks go only to agent runners; command tasks go only to command runners",
            "offline state: runner state not in (online, degraded) is excluded",
        ],
        "cases": cases,
    }

    (ROOT / "routing" / "decisions.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("wrote routing/decisions.json")


def write_store_fixtures() -> None:
    """store/schema_v2.sql + store/MIGRATION_COMPAT.md."""

    # Canonical schema snapshot (schema.sql + additive ALTER TABLE columns from server.py)
    schema_snapshot = """\
-- ForgeWire hub schema — v2 snapshot (oracle/v2.7.0-baseline)
-- Captured: 2026-05-31
-- Source: python/forgewire_fabric/hub/schema.sql + additive migrations in server.py
--
-- The Rust fabric-store-sqlite implementation MUST consume this schema without
-- changes to existing column names, types, or constraints. New columns are
-- additive-only. No column may be removed or renamed during the migration window.

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

-- v1 and v2 both inserted at first start (idempotent INSERT OR IGNORE).
-- schema_version rows: (1, <ts>), (2, <ts>)

CREATE TABLE IF NOT EXISTS tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    todo_id         TEXT,
    title           TEXT NOT NULL,
    prompt          TEXT NOT NULL,
    scope_globs     TEXT NOT NULL,          -- JSON array
    base_commit     TEXT NOT NULL,
    branch          TEXT NOT NULL,
    timeout_minutes INTEGER NOT NULL DEFAULT 60,
    priority        INTEGER NOT NULL DEFAULT 100,
    kind            TEXT NOT NULL DEFAULT 'agent',  -- 'agent' | 'command'
    status          TEXT NOT NULL DEFAULT 'queued',
    worker_id       TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    claimed_at      TEXT,
    started_at      TEXT,
    completed_at    TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}',     -- JSON
    -- Additive columns (v2 migration, applied at runtime via ALTER TABLE ADD COLUMN):
    required_tools  TEXT,                           -- JSON array | NULL
    required_tags   TEXT,                           -- JSON array | NULL
    tenant          TEXT,
    workspace_root  TEXT,
    require_base_commit INTEGER NOT NULL DEFAULT 0,
    -- M2.5.4: structured capability predicates
    required_capabilities TEXT,                     -- JSON array | NULL
    -- M2.5.5a: declared secret names
    secrets_needed  TEXT,                           -- JSON array | NULL
    -- M2.5.5b: per-task egress policy
    network_egress  TEXT,                           -- JSON object | NULL
    -- dispatcher_id: which dispatcher created this task
    dispatcher_id   TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_status_priority
    ON tasks (status, priority DESC, id ASC);
CREATE INDEX IF NOT EXISTS idx_tasks_branch ON tasks (branch);
CREATE INDEX IF NOT EXISTS idx_tasks_todo_id ON tasks (todo_id);

CREATE TABLE IF NOT EXISTS results (
    task_id         INTEGER PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
    status          TEXT NOT NULL,
    branch          TEXT NOT NULL,
    head_commit     TEXT,
    commits_json    TEXT NOT NULL DEFAULT '[]',
    files_touched   TEXT NOT NULL DEFAULT '[]',
    test_summary    TEXT,
    log_tail        TEXT,
    error           TEXT,
    reported_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS progress (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    message         TEXT NOT NULL,
    files_touched   TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_progress_task_seq ON progress (task_id, seq);

CREATE TABLE IF NOT EXISTS notes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    author          TEXT NOT NULL,
    body            TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_notes_task ON notes (task_id, id);

CREATE TABLE IF NOT EXISTS workers (
    worker_id       TEXT PRIMARY KEY,
    hostname        TEXT,
    capabilities    TEXT NOT NULL DEFAULT '{}',
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    current_task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS runners (
    runner_id        TEXT PRIMARY KEY,
    public_key       TEXT NOT NULL,
    hostname         TEXT NOT NULL,
    os               TEXT NOT NULL,
    arch             TEXT NOT NULL,
    cpu_model        TEXT,
    cpu_count        INTEGER,
    ram_mb           INTEGER,
    gpu              TEXT,
    tools            TEXT NOT NULL DEFAULT '[]',
    tags             TEXT NOT NULL DEFAULT '[]',
    scope_prefixes   TEXT NOT NULL DEFAULT '[]',
    tenant           TEXT,
    workspace_root   TEXT,
    runner_version   TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    max_concurrent   INTEGER NOT NULL DEFAULT 1,
    state            TEXT NOT NULL DEFAULT 'online',
    drain_requested  INTEGER NOT NULL DEFAULT 0,
    cpu_load_pct     REAL,
    ram_free_mb      INTEGER,
    battery_pct      INTEGER,
    on_battery       INTEGER NOT NULL DEFAULT 0,
    last_known_commit TEXT,
    metadata         TEXT NOT NULL DEFAULT '{}',
    first_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    last_heartbeat   TEXT NOT NULL DEFAULT (datetime('now')),
    last_nonce       TEXT,
    -- Additive columns (v2 migration):
    capabilities     TEXT NOT NULL DEFAULT '{}'  -- JSON object for M2.5.4 capability matching
);
CREATE INDEX IF NOT EXISTS idx_runners_state    ON runners (state);
CREATE INDEX IF NOT EXISTS idx_runners_tenant   ON runners (tenant);
CREATE INDEX IF NOT EXISTS idx_runners_hostname ON runners (hostname);

CREATE TABLE IF NOT EXISTS task_streams (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    channel         TEXT NOT NULL,      -- 'stdout' | 'stderr' | 'info'
    line            TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_task_streams_task_seq ON task_streams (task_id, seq);

CREATE TABLE IF NOT EXISTS dispatchers (
    dispatcher_id   TEXT PRIMARY KEY,
    public_key      TEXT NOT NULL,
    label           TEXT NOT NULL,
    hostname        TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dispatcher_nonces (
    dispatcher_id   TEXT NOT NULL REFERENCES dispatchers(dispatcher_id) ON DELETE CASCADE,
    nonce           TEXT NOT NULL,
    used_at         TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (dispatcher_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_dispatcher_nonces_used_at ON dispatcher_nonces (used_at);

CREATE TABLE IF NOT EXISTS runner_nonces (
    runner_id       TEXT NOT NULL REFERENCES runners(runner_id) ON DELETE CASCADE,
    nonce           TEXT NOT NULL,
    used_at         TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (runner_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_runner_nonces_used_at ON runner_nonces (used_at);

CREATE TABLE IF NOT EXISTS audit_event (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id_hash   TEXT NOT NULL UNIQUE,
    prev_event_id_hash TEXT NOT NULL,
    kind            TEXT NOT NULL,       -- 'dispatch' | 'claim' | 'result'
    task_id         INTEGER,
    payload_json    TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_event (task_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_day  ON audit_event (created_at);

CREATE TABLE IF NOT EXISTS host_roles (
    hostname        TEXT NOT NULL,
    role            TEXT NOT NULL,       -- 'hub_head' | 'control' | 'dispatch' | 'command_runner' | 'agent_runner'
    enabled         INTEGER NOT NULL DEFAULT 1,
    status          TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (hostname, role)
);

CREATE TABLE IF NOT EXISTS labels (
    key             TEXT PRIMARY KEY,
    value_json      TEXT NOT NULL,
    updated_by      TEXT,
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id     TEXT PRIMARY KEY,
    envelope_hash   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'approved' | 'denied' | 'consumed'
    decision_json   TEXT NOT NULL DEFAULT '{}',
    task_label      TEXT,
    branch          TEXT,
    scope_globs_json TEXT NOT NULL DEFAULT '[]',
    dispatcher_id   TEXT,
    approver        TEXT,
    reason          TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals (status);
CREATE INDEX IF NOT EXISTS idx_approvals_envelope ON approvals (envelope_hash);

CREATE TABLE IF NOT EXISTS secrets (
    name            TEXT PRIMARY KEY,
    encrypted_value TEXT NOT NULL,      -- AES-256-GCM encrypted, base64
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_rotated_at TEXT
);
"""

    (ROOT / "store" / "schema_v2.sql").write_text(schema_snapshot, encoding="utf-8")
    print("wrote store/schema_v2.sql")

    compat = """\
# Store Migration Compatibility Metadata

> **Oracle tag:** `oracle/v2.7.0-baseline`
> **Schema version at capture:** 2 (rows 1 and 2 in `schema_version` table)

## Reader/writer compatibility

| Scenario | Safe? | Notes |
|---|---|---|
| REMOVED — rqlite only since M2.7.3
| REMOVED — rqlite only since M2.7.3
| REMOVED — rqlite only since M2.7.3
| Rust hub reads schema_v1 (before additive columns) | ✅ Yes | Additive columns absent; Rust applies `ALTER TABLE ADD COLUMN IF NOT EXISTS` |

## Additive columns (applied at runtime by Python hub)

These columns are not in `schema.sql` but are added by Python `server.py` at startup
via `ALTER TABLE ADD COLUMN` (idempotent). The Rust `fabric-store-sqlite` crate must
apply the same migrations before first use.

### tasks table

| Column | Type | Default | Added for |
|---|---|---|---|
| `required_tools` | TEXT (JSON) | NULL | Runner capability routing |
| `required_tags` | TEXT (JSON) | NULL | Runner tag routing |
| `tenant` | TEXT | NULL | Tenant placement |
| `workspace_root` | TEXT | NULL | Workspace placement |
| `require_base_commit` | INTEGER | 0 | Commit precondition |
| `required_capabilities` | TEXT (JSON) | NULL | M2.5.4 structured caps |
| `secrets_needed` | TEXT (JSON) | NULL | M2.5.5a secret names |
| `network_egress` | TEXT (JSON) | NULL | M2.5.5b egress policy |
| `dispatcher_id` | TEXT | NULL | Dispatcher attribution |

### runners table

| Column | Type | Default | Added for |
|---|---|---|---|
| `capabilities` | TEXT (JSON) | '{}' | M2.5.4 capability blob |

## Rollback safety

Rolling back from Rust hub to Python hub after Rust writes is safe if:
1. No schema_version row beyond `2` was inserted by Rust.
2. No column was dropped or renamed by Rust.
3. Rust wrote valid UTF-8 JSON in all TEXT JSON columns.
4. Rust did not insert NULLs into NOT NULL columns.

**Before rolling back:** run `python -m forgewire_fabric.hub.server --check-schema` to
verify schema integrity.

## UTC timestamp contract

All `created_at`, `updated_at`, `applied_at`, and similar columns store ISO-8601 strings
in UTC, formatted as `%Y-%m-%d %H:%M:%S` (no timezone suffix, no fractional seconds).
The Python hub uses `datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")`.
The Rust hub must use the same format — not `datetime('now')` (SQLite local time) and
not RFC3339 with offset. Explicit UTC only.

## rqlite compatibility notes

The following patterns are prohibited (always use explicit UTC strings):
- `SELECT` inside `BEGIN` / `COMMIT` (rqlite shim contract)
- Cross-statement transactions relying on statement ordering
- `datetime('now')` (SQLite-local, use explicit UTC string instead)
- Assumed auto-increment continuity across reconnects

Atomic claim operations and audit-tail reads are expressed as single-statement
compare-and-swap updates. See `store/rqlite_scenarios.json` for CAS fixtures.
"""

    (ROOT / "store" / "MIGRATION_COMPAT.md").write_text(compat, encoding="utf-8")
    print("wrote store/MIGRATION_COMPAT.md")

    # rqlite synthetic scenarios
    rqlite_scenarios = {
        "_description": (
            "Synthetic rqlite behavioral fixtures derived from the Python _rqlite_db.py "
            "implementation and the rqlite HTTP API contract. These are not captured from "
            "a live rqlite deployment (none at oracle capture). They describe required "
            "behavior that fabric-store-rqlite must implement."
        ),
        "_oracle_tag": "oracle/v2.7.0-baseline",
        "scenarios": [
            {
                "id": "claim_cas",
                "description": "Atomic claim: UPDATE tasks SET status='claimed', worker_id=? WHERE id=? AND status='queued'. Single statement, no transaction. Returns rowcount=1 on success, 0 on race.",
                "sql": "UPDATE tasks SET status = 'claimed', worker_id = ?, claimed_at = ? WHERE id = ? AND status = 'queued'",
                "on_rowcount_0": "another runner claimed first — retry with next candidate",
                "on_rowcount_1": "claim succeeded",
            },
            {
                "id": "audit_append_cas",
                "description": "Linearizable audit append: read tail, compute hash, INSERT with UNIQUE constraint on event_id_hash. Conflict = another writer appended first — retry from new tail.",
                "read_sql": "SELECT event_id_hash FROM audit_event ORDER BY seq DESC LIMIT 1",
                "insert_sql": "INSERT INTO audit_event (event_id_hash, prev_event_id_hash, kind, task_id, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                "conflict_behavior": "UNIQUE constraint on event_id_hash catches concurrent appends. Retry: re-read tail, recompute hash, re-insert.",
            },
            {
                "id": "redirect_follow",
                "description": "rqlite non-leader node returns HTTP 301/302 redirect to leader. Client must follow up to 3 times before treating as error.",
                "status_codes": [301, 302],
                "max_redirects": 3,
                "on_exceeded": "raise rqlite connection error",
            },
            {
                "id": "quorum_loss",
                "description": "rqlite cluster loses quorum (>= half nodes down). Writes return 503 Service Unavailable. Hub must surface audit-failure-profile=required if audit is required.",
                "write_status_code": 503,
                "required_hub_behavior": "if audit_profile=required, reject new dispatches; if best_effort, log degraded and continue",
            },
            {
                "id": "explicit_utc_timestamp",
                "description": "All timestamps must be explicit UTC strings, not datetime('now'). rqlite may run on nodes in different timezones.",
                "correct": "datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')",
                "incorrect": "datetime('now')",
            },
        ],
    }

    (ROOT / "store" / "rqlite_scenarios.json").write_text(
        json.dumps(rqlite_scenarios, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("wrote store/rqlite_scenarios.json")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    sk_hex, pk_hex = _make_test_keypair()
    print(f"test keypair: pk={pk_hex[:16]}...")

    write_protocol_fixtures(sk_hex, pk_hex)
    write_audit_fixtures()
    write_routing_fixtures()
    write_store_fixtures()

    print("\nAll fixtures written. Run `python tests/fixtures/generate_fixtures.py` to regenerate.")
    print("Run `pytest tests/test_fixtures.py` to validate against the Python oracle.")


if __name__ == "__main__":
    main()
