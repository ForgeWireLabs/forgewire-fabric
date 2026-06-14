"""ADDR-3 / R1 drift guard: no hard-coded routable IPs in install assets or
generated config.

The DHCP-proof-addressing requirement R1 (``todos/114-forgewire-fabric/
dhcp-proof-addressing.md``) is binding: *no IPv4/IPv6 literal anywhere may
refer to a peer.* The cluster has lived on five subnets; every pinned address
broke. This test enforces R1 going forward by scanning install scripts and
committed config for **real routable** IPv4 literals, while allowing:

* the **self-bind / broadcast allowlist** (127.0.0.1, 0.0.0.0,
  255.255.255.255, ::1, ::) — these never refer to a peer;
* public **DNS** sentinels used for the no-traffic LAN-IP probe
  (8.8.8.8, 1.1.1.1);
* **RFC 5737 documentation** ranges (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24) — these are *intentional* placeholders in ``.EXAMPLE`` /
  help / comment text and must stay (replacing them with a fake real IP would
  be worse);
* **comment / documentation lines** (``#``, ``.EXAMPLE``, ``Example:``,
  ``.PARAMETER`` prose) — guidance, not executed config.

A failure means a routable IP literal landed in actual code or config. Fix by
using a hostname (resolved via the ADDR-2 managed hosts block) or a
runtime-derived value, never a baked-in address.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Scanned trees. config/ is gitignored at runtime but the *generator* output is
# what we care about; we scan any committed config sample plus the live file if
# present (so a regenerated cluster.yaml with IPs is caught locally too).
SCAN_DIRS = [
    REPO_ROOT / "scripts" / "install",
    REPO_ROOT / "python" / "forgewire_fabric" / "_installer_assets",
]
SCAN_GLOBS = ("*.ps1", "*.sh", "*.yaml", "*.yml")

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Never refer to a peer — always allowed.
ALLOWED_EXACT = {
    "127.0.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "8.8.8.8",  # no-traffic LAN-IP probe sentinel
    "1.1.1.1",  # default DNS in set-static-ip helpers
    "169.254.0.0",  # link-local references in filters
}


def _in_rfc5737(ip: str) -> bool:
    """RFC 5737 documentation ranges — intentional example placeholders."""
    return (
        ip.startswith("192.0.2.")
        or ip.startswith("198.51.100.")
        or ip.startswith("203.0.113.")
    )


def _is_doc_line(line: str) -> bool:
    s = line.strip()
    if not s:
        return True
    # PowerShell / shell / yaml comment.
    if s.startswith("#"):
        return True
    # Comment-based help / doc prose markers.
    lowered = s.lower()
    for marker in (".example", ".parameter", ".synopsis", ".description", "example:", "e.g.", "default:"):
        if marker in lowered:
            return True
    return False


def _iter_files():
    for d in SCAN_DIRS:
        if not d.exists():
            continue
        for pat in SCAN_GLOBS:
            yield from d.glob(pat)
    # Live generated cluster.yaml, if present (local dev / a real install).
    live = REPO_ROOT / "config" / "cluster.yaml"
    if live.exists():
        yield live


def test_no_hardcoded_routable_ips_in_install_assets():
    offenders: list[str] = []
    for path in _iter_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _is_doc_line(line):
                continue
            for ip in IPV4_RE.findall(line):
                octets = ip.split(".")
                if any(int(o) > 255 for o in octets):
                    continue  # not a real dotted-quad (e.g. a version string)
                if ip in ALLOWED_EXACT or _in_rfc5737(ip):
                    continue
                rel = path.relative_to(REPO_ROOT)
                offenders.append(f"{rel}:{lineno}: {ip}  ::  {line.strip()}")

    assert not offenders, (
        "R1 violation — hard-coded routable IP literal(s) found. Use a hostname "
        "(resolved via the ADDR-2 managed hosts block) or a runtime-derived "
        "value instead:\n  " + "\n  ".join(offenders)
    )
