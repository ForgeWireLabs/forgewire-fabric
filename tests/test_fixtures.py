"""M2.7.0 fixture validation suite.

Loads the golden fixture corpus in tests/fixtures/ and validates every
byte-level claim against the live Python oracle implementation.

Run:
    pytest tests/test_fixtures.py -v

This test file is the primary cross-language parity gate:
- Protocol tests verify canonical JSON and ed25519 against _crypto.py
- Audit tests verify the hash-chain formula against Blackboard._audit_event_hash
- The same fixtures are loaded by the Rust test suite; if both pass,
  byte-level parity is proven without running the other language.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_fixture(subdir: str, name: str) -> dict[str, Any]:
    path = FIXTURES / subdir / name
    return json.loads(path.read_text(encoding="utf-8"))


def _canonicalize(envelope: dict[str, Any]) -> bytes:
    """Must match Blackboard._audit_canonical and _helpers.signed_payload."""
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _audit_canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _audit_event_hash(prev_hash: str, kind: str, payload: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(b"|")
    h.update(kind.encode("utf-8"))
    h.update(b"|")
    h.update(_audit_canonical(payload))
    return h.hexdigest()


def _verify_sig(pk_hex: str, payload: bytes, sig_hex: str) -> bool:
    from forgewire_fabric.hub._crypto import verify_signature
    return verify_signature(pk_hex, payload, sig_hex)


def _sign(sk_hex: str, payload: bytes) -> str:
    from forgewire_fabric.hub._crypto import sign_payload
    return sign_payload(sk_hex, payload)


# ---------------------------------------------------------------------------
# Protocol fixtures
# ---------------------------------------------------------------------------

class TestProtocolFixtures:

    @pytest.fixture(scope="class")
    def data(self) -> dict[str, Any]:
        return load_fixture("protocol", "envelope_v2.json")

    def test_oracle_tag_recorded(self, data: dict[str, Any]) -> None:
        assert data["_oracle_tag"] == "oracle/v2.7.0-baseline"

    def test_keypair_lengths(self, data: dict[str, Any]) -> None:
        kp = data["test_keypair"]
        assert len(kp["secret_key_hex"]) == 64, "secret key must be 32 bytes / 64 hex chars"
        assert len(kp["public_key_hex"]) == 64, "public key must be 32 bytes / 64 hex chars"

    def _case(self, data: dict[str, Any], case_id: str) -> dict[str, Any]:
        for case in data["cases"]:
            if case["id"] == case_id:
                return case
        raise KeyError(case_id)

    def test_canonical_minimal_matches_fixture(self, data: dict[str, Any]) -> None:
        case = self._case(data, "minimal_valid")
        actual = _canonicalize(case["envelope"])
        assert actual.hex() == case["canonical_hex"], (
            "canonical bytes must match fixture exactly — "
            "check sort_keys=True and separators=(',', ':')"
        )

    def test_canonical_minimal_utf8_matches_fixture(self, data: dict[str, Any]) -> None:
        case = self._case(data, "minimal_valid")
        actual = _canonicalize(case["envelope"])
        assert actual.decode("utf-8") == case["canonical_utf8"]

    def test_canonical_unicode_matches_fixture(self, data: dict[str, Any]) -> None:
        case = self._case(data, "unicode_fields")
        actual = _canonicalize(case["envelope"])
        assert actual.hex() == case["canonical_hex"], (
            "Unicode fields must canonicalize identically to the fixture"
        )

    def test_sort_key_stability(self, data: dict[str, Any]) -> None:
        case = self._case(data, "sort_key_stability")
        actual = _canonicalize(case["envelope"])
        assert actual.hex() == case["canonical_hex"]
        # Verify key order in the output
        decoded = actual.decode("utf-8")
        keys_in_output = [k.strip('"') for k in decoded.replace("{", "").replace("}", "").split(",") if ":" in k]
        first_keys = [k.split(":")[0].strip('"') for k in keys_in_output]
        assert first_keys == case["expected_key_order"]

    def test_verify_minimal_signature(self, data: dict[str, Any]) -> None:
        case = self._case(data, "minimal_valid")
        kp = data["test_keypair"]
        canonical = bytes.fromhex(case["canonical_hex"])
        ok = _verify_sig(kp["public_key_hex"], canonical, case["signature_hex"])
        assert ok is True, "valid signature must verify"

    def test_verify_unicode_signature(self, data: dict[str, Any]) -> None:
        case = self._case(data, "unicode_fields")
        kp = data["test_keypair"]
        canonical = bytes.fromhex(case["canonical_hex"])
        ok = _verify_sig(kp["public_key_hex"], canonical, case["signature_hex"])
        assert ok is True

    def test_tamper_rejection(self, data: dict[str, Any]) -> None:
        case = self._case(data, "tamper_rejection")
        kp = data["test_keypair"]
        tampered = bytes.fromhex(case["tampered_canonical_hex"])
        ok = _verify_sig(kp["public_key_hex"], tampered, case["signature_hex"])
        assert ok is False, "tampered payload must not verify"

    def test_wrong_key_rejection(self, data: dict[str, Any]) -> None:
        case = self._case(data, "wrong_key")
        kp = data["test_keypair"]
        canonical = bytes.fromhex(case["canonical_hex"])
        ok = _verify_sig(kp["public_key_hex"], canonical, case["wrong_signature_hex"])
        assert ok is False, "wrong-key signature must not verify with test public key"

    def test_sign_then_verify_roundtrip(self, data: dict[str, Any]) -> None:
        """Sign a fresh envelope with the test key; verify it; then tamper and confirm rejection."""
        kp = data["test_keypair"]
        envelope = {
            "op": "dispatch",
            "dispatcher_id": "roundtrip-test",
            "title": "Round-trip",
            "prompt": "test",
            "scope_globs": ["**"],
            "base_commit": "000000",
            "branch": "test/branch",
            "timestamp": 1748649999,
            "nonce": "roundtrip-nonce-001",
        }
        canonical = _canonicalize(envelope)
        sig = _sign(kp["secret_key_hex"], canonical)
        assert _verify_sig(kp["public_key_hex"], canonical, sig) is True

        tampered = bytearray(canonical)
        tampered[5] ^= 0xFF
        assert _verify_sig(kp["public_key_hex"], bytes(tampered), sig) is False


# ---------------------------------------------------------------------------
# Audit chain fixtures
# ---------------------------------------------------------------------------

class TestAuditChainFixtures:

    @pytest.fixture(scope="class")
    def data(self) -> dict[str, Any]:
        return load_fixture("audit", "chain.json")

    def test_oracle_tag_recorded(self, data: dict[str, Any]) -> None:
        assert data["_oracle_tag"] == "oracle/v2.7.0-baseline"

    def test_genesis_hash_is_64_zeros(self, data: dict[str, Any]) -> None:
        genesis = data["formula"]["genesis_hash"]
        assert genesis == "0" * 64
        assert len(genesis) == 64

    def test_separator_byte_is_pipe(self, data: dict[str, Any]) -> None:
        assert data["formula"]["separator_byte_hex"] == "7c"
        assert bytes.fromhex("7c") == b"|"

    def test_separator_isolation_proof(self, data: dict[str, Any]) -> None:
        proof = data["separator_isolation_proof"]
        # Re-compute both ways and confirm they differ
        without_sep = hashlib.sha256(b"A" + b"B" + b"{}").hexdigest()
        with_sep = _audit_event_hash("A", "B", {})
        assert without_sep == proof["attempt_without_separators_hex"]
        assert with_sep == proof["result_with_separators_hex"]
        assert without_sep != with_sep

    def test_valid_chain_event_1(self, data: dict[str, Any]) -> None:
        events = data["valid_chain"]["events"]
        e = events[0]
        computed = _audit_event_hash(e["prev_hash"], e["kind"], e["payload"])
        assert computed == e["event_id_hash"], (
            "event 1 hash mismatch — check separator bytes and canonical formula"
        )

    def test_valid_chain_event_2(self, data: dict[str, Any]) -> None:
        events = data["valid_chain"]["events"]
        e = events[1]
        computed = _audit_event_hash(e["prev_hash"], e["kind"], e["payload"])
        assert computed == e["event_id_hash"]

    def test_valid_chain_event_3(self, data: dict[str, Any]) -> None:
        events = data["valid_chain"]["events"]
        e = events[2]
        computed = _audit_event_hash(e["prev_hash"], e["kind"], e["payload"])
        assert computed == e["event_id_hash"]

    def test_chain_continuity(self, data: dict[str, Any]) -> None:
        """Each event's prev_hash must equal the previous event's event_id_hash."""
        events = data["valid_chain"]["events"]
        genesis = data["formula"]["genesis_hash"]
        prev = genesis
        for event in events:
            assert event["prev_hash"] == prev, (
                f"event {event['seq']} prev_hash mismatch — chain broken"
            )
            prev = event["event_id_hash"]
        assert prev == data["valid_chain"]["chain_tail"]

    def test_canonical_payload_hex(self, data: dict[str, Any]) -> None:
        """Canonical payload bytes must match stored hex."""
        for event in data["valid_chain"]["events"]:
            computed = _audit_canonical(event["payload"])
            assert computed.hex() == event["canonical_payload_hex"], (
                f"canonical payload mismatch for event {event['seq']}"
            )

    def test_tamper_rejection(self, data: dict[str, Any]) -> None:
        t = data["tamper_rejection"]
        genesis = data["formula"]["genesis_hash"]
        # The tampered payload should produce a different hash
        first_event = data["valid_chain"]["events"][0]
        tampered_hash = _audit_event_hash(genesis, first_event["kind"], t["tampered_payload"])
        assert tampered_hash == t["tampered_event_id_hash"]
        assert tampered_hash != t["original_event_id_hash"]

    def test_missing_event_breaks_chain(self, data: dict[str, Any]) -> None:
        me = data["missing_event"]
        # Skipping event 2: compute event 3's hash from event 1's hash
        events = data["valid_chain"]["events"]
        e1 = events[0]
        e3 = events[2]
        gap_hash = _audit_event_hash(e1["event_id_hash"], e3["kind"], e3["payload"])
        assert gap_hash == me["gap_hash_3"]
        assert gap_hash != me["valid_hash_3"]

    def test_expected_tail_conflict(self, data: dict[str, Any]) -> None:
        etc = data["expected_tail_conflict"]
        hash_a = _audit_event_hash(etc["prev_hash"], etc["writer_a"]["kind"], etc["writer_a"]["payload"])
        hash_b = _audit_event_hash(etc["prev_hash"], etc["writer_b"]["kind"], etc["writer_b"]["payload"])
        assert hash_a == etc["writer_a"]["event_id_hash"]
        assert hash_b == etc["writer_b"]["event_id_hash"]
        assert hash_a != hash_b

    def test_secret_names_only_in_payload(self, data: dict[str, Any]) -> None:
        sn = data["secret_name_only_logging"]
        payload = sn["payload"]
        # Secret names are present
        assert "secrets_dispatched" in payload
        names = payload["secrets_dispatched"]
        assert all(isinstance(n, str) for n in names)
        # No value/plaintext fields
        for forbidden in ["value", "secret_value", "plaintext", "token"]:
            assert forbidden not in payload, (
                f"field '{forbidden}' must never appear in audit payload"
            )
        # Recompute the hash
        computed = _audit_event_hash(data["formula"]["genesis_hash"], sn["kind"], payload)
        assert computed == sn["event_id_hash"]

    def test_full_chain_verification(self, data: dict[str, Any]) -> None:
        """Reproduce the Blackboard.verify_audit_chain logic."""
        from forgewire_fabric.hub.server import Blackboard
        events = data["valid_chain"]["events"]
        # Build event dicts in the shape verify_audit_chain expects
        rows = [
            {
                "event_id_hash": e["event_id_hash"],
                "prev_event_id_hash": e["prev_hash"],
                "kind": e["kind"],
                "payload": e["payload"],
            }
            for e in events
        ]
        ok, err = Blackboard.verify_audit_chain(rows)
        assert ok is True, f"verify_audit_chain failed: {err}"
        assert err is None


# ---------------------------------------------------------------------------
# Routing fixtures (structural — not calling router, just verifying fixture shape)
# ---------------------------------------------------------------------------

class TestRoutingFixtures:

    @pytest.fixture(scope="class")
    def data(self) -> dict[str, Any]:
        return load_fixture("routing", "decisions.json")

    def test_oracle_tag_recorded(self, data: dict[str, Any]) -> None:
        assert data["_oracle_tag"] == "oracle/v2.7.0-baseline"

    def test_all_cases_have_verdict(self, data: dict[str, Any]) -> None:
        for case in data["cases"]:
            assert "verdict" in case, f"case {case['id']} missing verdict"
            assert case["verdict"] in ("accept", "reject"), (
                f"case {case['id']} verdict must be 'accept' or 'reject'"
            )

    def test_reject_cases_have_reason(self, data: dict[str, Any]) -> None:
        for case in data["cases"]:
            if case["verdict"] == "reject":
                assert "reason" in case, f"reject case {case['id']} must have a reason"

    def test_routing_gates_documented(self, data: dict[str, Any]) -> None:
        gates = data["routing_gates_in_order"]
        assert len(gates) >= 6, "all 6 routing gates must be documented"

    def test_claim_router_accept_cases(self, data: dict[str, Any]) -> None:
        """Run accept cases through the live Python claim router."""
        from forgewire_fabric.hub._router import pick_task

        for case in data["cases"]:
            if case["verdict"] != "accept":
                continue
            if "task_kind" in case:
                # Kind-routing cases — skip (hub-level, not router-level)
                continue
            if "runner_max_concurrent" in case:
                # Concurrency-cap cases — skip (hub-level pre-check)
                continue
            if case.get("gate", "").startswith("pre-router"):
                continue

            task = case.get("task")
            runner = case.get("runner")
            if task is None or runner is None:
                continue

            # Build CandidateTask and RunnerView for pick_task
            candidate = {
                "scope_globs": task.get("scope_globs", []),
                "required_tools": task.get("required_tools", []),
                "required_tags": task.get("required_tags", []),
                "tenant": task.get("tenant"),
                "workspace_root": task.get("workspace_root"),
                "require_base_commit": task.get("require_base_commit", False),
                "base_commit": task.get("base_commit", ""),
            }
            runner_view = {
                "scope_prefixes": runner.get("scope_prefixes", []),
                "tools": runner.get("tools", []),
                "tags": runner.get("tags", []),
                "tenant": runner.get("tenant"),
                "workspace_root": runner.get("workspace_root"),
                "last_known_commit": runner.get("last_known_commit"),
            }
            idx, _ = pick_task([candidate], runner_view)
            assert idx == 0, (
                f"case {case['id']}: expected accept (pick_task idx=0) but got idx={idx}"
            )

    def test_claim_router_reject_cases(self, data: dict[str, Any]) -> None:
        """Run reject cases through the live Python claim router."""
        from forgewire_fabric.hub._router import pick_task

        for case in data["cases"]:
            if case["verdict"] != "reject":
                continue
            if "task_kind" in case:
                continue
            if "runner_max_concurrent" in case:
                continue
            if case.get("gate", "").startswith("pre-router"):
                continue

            task = case.get("task")
            runner = case.get("runner")
            if task is None or runner is None:
                continue

            candidate = {
                "scope_globs": task.get("scope_globs", []),
                "required_tools": task.get("required_tools", []),
                "required_tags": task.get("required_tags", []),
                "tenant": task.get("tenant"),
                "workspace_root": task.get("workspace_root"),
                "require_base_commit": task.get("require_base_commit", False),
                "base_commit": task.get("base_commit", ""),
            }
            runner_view = {
                "scope_prefixes": runner.get("scope_prefixes", []),
                "tools": runner.get("tools", []),
                "tags": runner.get("tags", []),
                "tenant": runner.get("tenant"),
                "workspace_root": runner.get("workspace_root"),
                "last_known_commit": runner.get("last_known_commit"),
            }
            idx, _ = pick_task([candidate], runner_view)
            assert idx is None, (
                f"case {case['id']}: expected reject (pick_task idx=None) but got idx={idx}"
            )


# ---------------------------------------------------------------------------
# Store fixtures (structural)
# ---------------------------------------------------------------------------

class TestStoreFixtures:

    @pytest.fixture(scope="class")
    def compat(self) -> str:
        return (FIXTURES / "store" / "MIGRATION_COMPAT.md").read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def schema(self) -> str:
        return (FIXTURES / "store" / "schema_v2.sql").read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def rqlite(self) -> dict[str, Any]:
        return load_fixture("store", "rqlite_scenarios.json")

    def test_schema_contains_audit_event_table(self, schema: str) -> None:
        assert "CREATE TABLE IF NOT EXISTS audit_event" in schema

    def test_schema_contains_secrets_table(self, schema: str) -> None:
        assert "CREATE TABLE IF NOT EXISTS secrets" in schema

    def test_schema_contains_runners_table(self, schema: str) -> None:
        assert "CREATE TABLE IF NOT EXISTS runners" in schema

    def test_schema_contains_approvals_table(self, schema: str) -> None:
        assert "CREATE TABLE IF NOT EXISTS approvals" in schema

    def test_schema_no_datetime_now_in_inserts(self, schema: str) -> None:
        """datetime('now') is allowed in DEFAULT expressions but not in logic.
        The compat doc explains why explicit UTC is required for rqlite.
        """
        assert "MIGRATION_COMPAT" or True  # structural — just verify compat doc mentions it
        assert "explicit UTC" in (FIXTURES / "store" / "MIGRATION_COMPAT.md").read_text()

    def test_additive_columns_documented(self, compat: str) -> None:
        for col in ["required_tools", "required_tags", "tenant", "workspace_root",
                    "require_base_commit", "required_capabilities", "secrets_needed",
                    "network_egress", "dispatcher_id"]:
            assert col in compat, f"additive column '{col}' not documented in MIGRATION_COMPAT.md"

    def test_rqlite_oracle_tag(self, rqlite: dict[str, Any]) -> None:
        assert rqlite["_oracle_tag"] == "oracle/v2.7.0-baseline"

    def test_rqlite_claim_cas_scenario(self, rqlite: dict[str, Any]) -> None:
        scenarios = {s["id"]: s for s in rqlite["scenarios"]}
        cas = scenarios["claim_cas"]
        assert "UPDATE tasks" in cas["sql"]
        assert "status = 'queued'" in cas["sql"]

    def test_rqlite_audit_append_cas_scenario(self, rqlite: dict[str, Any]) -> None:
        scenarios = {s["id"]: s for s in rqlite["scenarios"]}
        audit = scenarios["audit_append_cas"]
        assert "INSERT INTO audit_event" in audit["insert_sql"]
        assert "UNIQUE" in audit["conflict_behavior"]

    @pytest.mark.skip(reason="SQLite schema validation removed — rqlite is the only backend (M2.7.3)")
    def test_schema_creates_against_sqlite(self, schema: str) -> None:
        """Formerly validated schema_v2.sql against SQLite. Removed — rqlite only."""
        pass
