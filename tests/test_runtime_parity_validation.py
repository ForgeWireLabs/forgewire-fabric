from __future__ import annotations

import importlib
import sys
import types

import pytest


@pytest.mark.parametrize(
    ("module_name", "component", "missing_attr"),
    [
        ("forgewire_fabric.hub._router", "hub.claim_router", "pick_task"),
        ("forgewire_fabric.hub._streams", "hub.stream_counter", "StreamCounter"),
        ("forgewire_fabric.hub._crypto", "hub.crypto", "sign_envelope"),
    ],
)
def test_strict_parity_raises_misconfigured_when_required_mapping_missing(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    component: str,
    missing_attr: str,
) -> None:
    fake_runtime = types.ModuleType("forgewire_runtime")
    fake_runtime.HAS_RUST = True

    # Populate all known attrs except the one under test.
    attrs = {
        "pick_task": lambda tasks, runner: (None, 0),
        "StreamCounter": object,
        "canonicalize": lambda envelope: b"{}",
        "verify_signature": lambda public_key_hex, payload, signature_hex: True,
        "sign_payload": lambda secret_key_hex, payload: "",
        "verify_envelope": lambda public_key_hex, envelope, signature_hex: True,
        "sign_envelope": lambda secret_key_hex, envelope: "",
    }
    attrs.pop(missing_attr, None)
    for name, value in attrs.items():
        setattr(fake_runtime, name, value)

    monkeypatch.setenv("FORGEWIRE_RUNTIME_PARITY_STRICT", "1")
    monkeypatch.delenv("FORGEWIRE_FORCE_PYTHON", raising=False)
    monkeypatch.setitem(sys.modules, "forgewire_runtime", fake_runtime)
    sys.modules.pop(module_name, None)

    with pytest.raises(RuntimeError) as exc:
        importlib.import_module(module_name)

    msg = str(exc.value)
    assert "MISCONFIGURED" in msg
    assert component in msg
    assert missing_attr in msg
