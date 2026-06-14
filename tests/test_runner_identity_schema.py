"""Regression tests for cross-runtime runner-identity schema interop.

The native Rust runner (``crates/fabric-runner``) is the authoritative writer
of ``runner_identity.json`` and emits the ``id`` / ``public_key_hex`` /
``secret_key_hex`` form with a host-derived id (e.g. ``HOST-runner``). The
Python MCP sidecar reads the same file. Before this fix the sidecar required
the ``runner_id`` / ``public_key`` / ``private_key`` form *and* a UUID id, so
it rejected every identity the Rust runner produced -- the runner MCP servers
crashed on startup with "identity file missing required fields".

These tests pin that the validator accepts both schemas while still rejecting
a tampered keypair.
"""
from __future__ import annotations

import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from forgewire_fabric.runner import identity as I


def _keypair() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    skh = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    pkh = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return pkh, skh


def test_accepts_rust_schema_with_host_derived_id() -> None:
    pkh, skh = _keypair()
    rec = I._validate_identity_record(
        {"id": "DESKTOP-228U8GL-runner", "public_key_hex": pkh, "secret_key_hex": skh}
    )
    assert rec["runner_id"] == "DESKTOP-228U8GL-runner"
    assert rec["public_key"] == pkh
    assert rec["private_key"] == skh


def test_accepts_python_native_schema_with_uuid() -> None:
    pkh, skh = _keypair()
    rid = str(uuid.uuid4())
    rec = I._validate_identity_record(
        {"runner_id": rid, "public_key": pkh, "private_key": skh}
    )
    assert rec["runner_id"] == rid
    assert rec["public_key"] == pkh
    assert rec["private_key"] == skh


def test_rejects_mismatched_keypair() -> None:
    pkh, _ = _keypair()
    with pytest.raises(ValueError, match="does not match"):
        I._validate_identity_record(
            {"id": "x-runner", "public_key_hex": pkh, "secret_key_hex": "00" * 32}
        )


def test_rejects_missing_fields() -> None:
    with pytest.raises(ValueError, match="missing required fields"):
        I._validate_identity_record({"id": "x-runner"})
