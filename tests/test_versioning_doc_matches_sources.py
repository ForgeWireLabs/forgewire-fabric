"""VERSIONING.md must tell the truth about the four version lines.

The document's own premise is that each artifact is "internally consistent
(source == built == installed == what the running process reports)". Nothing
enforced that, so it drifted: the Rust line read 0.9.0 while the workspace was
at 0.10.0, and the VSIX line read 0.6.1 while package.json was at 0.7.0. A
hand-maintained "Current" column is a clock that resets and then drifts again.

These tests make the rule machine-checkable, so a version bump that forgets the
document fails here instead of misleading the next reader. They also pin the
pyproject/__init__ lockstep that requirements.txt calls out by name, and the
agreement of the duplicated PROTOCOL_VERSION literals.

Bumping a version is expected to touch this document. That is the point.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSIONING = ROOT / "VERSIONING.md"


def _doc_current(row_prefix: str) -> str:
    """Return the 'Current' cell for the table row starting with *row_prefix*."""
    for line in VERSIONING.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"| **{row_prefix}"):
            cells = [c.strip() for c in line.split("|")]
            return cells[-2].strip("`")
    raise AssertionError(f"no VERSIONING.md row for {row_prefix!r}")


def _toml_version(path: Path) -> str:
    m = re.search(r'^version = "([^"]+)"', path.read_text(encoding="utf-8"), re.M)
    assert m, f"no version in {path}"
    return m.group(1)


# ---------------------------------------------------------------------------
# The four version lines
# ---------------------------------------------------------------------------


def test_rust_daemon_version_matches_doc() -> None:
    assert _toml_version(ROOT / "crates" / "fabric-hub" / "Cargo.toml") == _doc_current("Rust hub")


def test_python_package_version_matches_doc() -> None:
    assert _toml_version(ROOT / "pyproject.toml") == _doc_current("Python package")


def test_vsix_version_matches_doc() -> None:
    pkg = json.loads((ROOT / "vscode" / "package.json").read_text(encoding="utf-8"))
    assert pkg["version"] == _doc_current("VS Code extension")


def test_protocol_version_matches_doc() -> None:
    versions = _protocol_version_literals()
    assert versions, "no PROTOCOL_VERSION literal found"
    assert str(next(iter(versions.values()))) == _doc_current("Wire protocol")


# ---------------------------------------------------------------------------
# Internal consistency the document promises
# ---------------------------------------------------------------------------


def test_pyproject_and_dunder_version_are_equal() -> None:
    """requirements.txt asks for these two to be kept in lockstep by hand.
    Nothing checked it until now."""
    init = (ROOT / "python" / "forgewire_fabric" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__ = "([^"]+)"', init, re.M)
    assert m, "no __version__ in forgewire_fabric/__init__.py"
    assert m.group(1) == _toml_version(ROOT / "pyproject.toml")


def _protocol_version_literals() -> dict[str, int]:
    """Every PROTOCOL_VERSION definition, by file.

    The constant is duplicated across Rust and Python rather than sourced from
    one place, so the literals can silently disagree.
    """
    found: dict[str, int] = {}
    patterns = (
        (ROOT / "python", "*.py", re.compile(r"^PROTOCOL_VERSION\s*=\s*(\d+)", re.M)),
        (ROOT / "crates", "*.rs", re.compile(r"const PROTOCOL_VERSION:\s*\w+\s*=\s*(\d+)", re.M)),
    )
    for base, glob, pattern in patterns:
        for path in base.rglob(glob):
            if "__pycache__" in path.parts or "target" in path.parts:
                continue
            for m in pattern.finditer(path.read_text(encoding="utf-8", errors="replace")):
                # posix form: these keys are compared against "crates/..." prefixes,
                # and a Windows relative_to() yields backslashes.
                found[path.relative_to(ROOT).as_posix()] = int(m.group(1))
    return found


def test_all_protocol_version_literals_agree() -> None:
    versions = _protocol_version_literals()
    assert versions, "no PROTOCOL_VERSION literal found"
    distinct = set(versions.values())
    assert len(distinct) == 1, f"PROTOCOL_VERSION disagrees across sources: {versions}"


def test_protocol_version_is_defined_where_the_doc_says() -> None:
    """The document named the crate that holds the constant; it must be right,
    or the next person bumps the wrong file."""
    rust_files = [f for f in _protocol_version_literals() if f.startswith("crates/")]
    assert rust_files, "no Rust PROTOCOL_VERSION found"
    row = next(
        line for line in VERSIONING.read_text(encoding="utf-8").splitlines()
        if line.startswith("| **Wire protocol")
    )
    named = re.findall(r"Rust `([^`]+)`", row)
    assert named, "VERSIONING.md does not name the Rust crate for PROTOCOL_VERSION"
    crate = named[0]
    assert any(f.startswith(f"crates/{crate}/") for f in rust_files), (
        f"VERSIONING.md says PROTOCOL_VERSION lives in Rust {crate!r}, "
        f"but it is defined in {rust_files}"
    )
