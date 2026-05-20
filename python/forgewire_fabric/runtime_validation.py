"""Runtime parity startup validation helpers.

When parity strict mode is enabled, missing Rust runtime symbols are treated as
hard misconfiguration errors instead of silently degrading to Python fallbacks.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

_PARITY_ENV = "FORGEWIRE_RUNTIME_PARITY_STRICT"


@dataclass(frozen=True, slots=True)
class RuntimeMisconfiguredError(RuntimeError):
    """Raised when strict parity mode detects missing required runtime mapping."""

    component: str
    details: str

    def __str__(self) -> str:
        return f"MISCONFIGURED: {self.component}: {self.details}"


def parity_strict_enabled() -> bool:
    return os.environ.get(_PARITY_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def validate_runtime_mapping(
    *,
    component: str,
    has_rust_flag: bool,
    missing_symbols: list[str],
    force_python: bool,
) -> None:
    """Fail closed in strict parity mode when required symbols are missing."""

    if not parity_strict_enabled() or force_python:
        return
    if not has_rust_flag:
        raise RuntimeMisconfiguredError(
            component=component,
            details=(
                "forgewire_runtime.HAS_RUST is false or unavailable while strict parity "
                "is enabled; install/repair the Rust runtime wheel or unset "
                f"{_PARITY_ENV}."
            ),
        )
    if missing_symbols:
        missing = ", ".join(sorted(missing_symbols))
        raise RuntimeMisconfiguredError(
            component=component,
            details=(
                f"required runtime symbol mapping missing: {missing}. "
                "Reinstall matching forgewire_runtime build, verify exported PyO3 "
                "symbols, or disable strict parity mode explicitly."
            ),
        )
