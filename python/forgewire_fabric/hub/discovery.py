"""Hub advertisement and auto-discovery.

Two discovery paths are supported and tried in order:

1. **UDP beacon** (Rust hub) — broadcasts ``FWBEACON`` queries on port 48765.
   The hub replies with its port and ``token_hash`` from the source IP.
   Zero dependencies beyond stdlib ``socket``.

2. **mDNS / Zeroconf** (Python hub) — advertises ``_forgewire-hub._tcp.local.``.
   Requires the ``zeroconf`` package (required since forgewire-fabric 0.14.0).

Both paths return the same dict shape: ``{host, port, protocol_version,
token_hash, name}``.  ``discover_hub_url()`` tries beacon first (fast, < 1 s),
then mDNS as a fallback.

TXT / beacon fields:

* ``proto``      -- ``hub_protocol_version`` (e.g. ``3``)
* ``token_hash`` -- ``sha256(token)[:16]`` hex.  Clients with the token can
                    confirm cluster membership by comparing hashes.
* ``path``       -- always ``/`` (reserved for future REST prefixes).
"""

from __future__ import annotations

import hashlib
import json
import logging
import socket
import time as _time
from dataclasses import dataclass
from typing import Any

LOGGER = logging.getLogger("forgewire_fabric.discovery")

SERVICE_TYPE = "_forgewire-hub._tcp.local."
BEACON_MAGIC = "FWBEACON"
BEACON_VERSION = 1
BEACON_PORT = 48765


def discover_hubs_beacon(
    timeout: float = 1.5,
    want_token_hash: str = "",
) -> list[dict[str, Any]]:
    """Discover ForgeWire hubs via the Rust UDP beacon protocol.

    Broadcasts a query on port 48765; collects replies for *timeout* seconds.
    The hub URL is derived from the **source address** of each reply so it is
    always correct regardless of DHCP or subnet changes.

    Args:
        timeout:          How long to listen for replies (seconds).
        want_token_hash:  If non-empty, only return hubs whose ``token_hash``
                          matches (same cluster).  Obtain via
                          ``hashlib.sha256(token.encode()).hexdigest()[:16]``.
    """
    query = json.dumps(
        {"magic": BEACON_MAGIC, "v": BEACON_VERSION, "role": "query"}
    ).encode()
    found: dict[str, dict[str, Any]] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.1)
        sock.bind(("", 0))
        sock.sendto(query, ("255.255.255.255", BEACON_PORT))
        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                b = json.loads(data.decode("utf-8"))
            except Exception:
                continue
            if (
                b.get("magic") != BEACON_MAGIC
                or b.get("v") != BEACON_VERSION
                or b.get("role") != "hub"
                or not b.get("port")
            ):
                continue
            if want_token_hash and b.get("token_hash") and b["token_hash"] != want_token_hash:
                continue
            url = f"http://{src_ip}:{b['port']}"
            if url not in found:
                found[url] = {
                    "host": src_ip,
                    "port": int(b["port"]),
                    "protocol_version": int(b.get("proto", 0)),
                    "token_hash": b.get("token_hash", ""),
                    "name": b.get("name", ""),
                    "addresses": [src_ip],
                }
        sock.close()
    except OSError as exc:
        LOGGER.debug("beacon discovery failed: %s", exc)
    return list(found.values())


def _token_hash(token: str) -> str:
    """sha256(token)[:16] hex — mirrors the Rust beacon token_hash()."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


@dataclass(slots=True)
class HubAdvertisement:
    """Handle returned by :func:`advertise_hub`. Call ``close`` on shutdown."""

    _zeroconf: Any
    _info: Any

    def close(self) -> None:
        try:
            self._zeroconf.unregister_service(self._info)
        except Exception as exc:  # pragma: no cover - shutdown best-effort
            LOGGER.debug("zeroconf unregister failed: %s", exc)
        try:
            self._zeroconf.close()
        except Exception as exc:  # pragma: no cover
            LOGGER.debug("zeroconf close failed: %s", exc)


def _local_ipv4() -> str:
    """Best-effort local LAN IPv4 address (no network traffic generated)."""

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(0.0)
        # 8.8.8.8 is a sentinel; UDP socket connect() does not actually send.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def advertise_hub(
    *,
    port: int,
    protocol_version: int,
    token: str = "",
    instance_name: str | None = None,
) -> HubAdvertisement | None:
    """Advertise the running hub on the local LAN via mDNS.

    Returns ``None`` if ``zeroconf`` is not installed (logs a debug message).
    Otherwise returns a handle whose ``close()`` should be called on shutdown.
    """

    try:
        from zeroconf import IPVersion, ServiceInfo, Zeroconf
    except ImportError:
        LOGGER.debug("zeroconf not installed; skipping hub mDNS advertisement")
        return None

    hostname = socket.gethostname().split(".", 1)[0] or "forgewire-hub"
    name = instance_name or f"{hostname}.{SERVICE_TYPE}"
    address = _local_ipv4()
    properties = {
        "proto": str(protocol_version),
        "token_hash": _token_hash(token) if token else "",
        "path": "/",
    }
    try:
        info = ServiceInfo(
            type_=SERVICE_TYPE,
            name=name,
            addresses=[socket.inet_aton(address)],
            port=port,
            properties=properties,
            server=f"{hostname}.local.",
        )
        zc = Zeroconf(ip_version=IPVersion.V4Only)
        zc.register_service(info)
        LOGGER.info(
            "advertising %s on %s:%d via mDNS", SERVICE_TYPE.rstrip("."), address, port
        )
        return HubAdvertisement(_zeroconf=zc, _info=info)
    except Exception as exc:
        LOGGER.warning("mDNS advertisement failed: %s", exc)
        return None


def discover_hubs(timeout: float = 3.0) -> list[dict[str, Any]]:
    """Browse the local LAN for ``_forgewire-hub._tcp`` services.

    Returns a list of ``{host, port, protocol_version, addresses, name}`` dicts.
    Empty list if zeroconf is missing or no hubs answer in ``timeout`` seconds.
    """

    try:
        from zeroconf import IPVersion, ServiceBrowser, Zeroconf
    except ImportError:
        LOGGER.debug("zeroconf not installed; cannot discover hubs")
        return []

    found: list[dict[str, Any]] = []

    class _Listener:
        def add_service(self, zc: Any, type_: str, name: str) -> None:  # noqa: D401
            info = zc.get_service_info(type_, name, timeout=int(timeout * 1000))
            if not info:
                return
            addresses = [socket.inet_ntoa(a) for a in info.addresses or [] if len(a) == 4]
            host = addresses[0] if addresses else (info.server or "").rstrip(".")
            props = {
                k.decode("ascii", "ignore") if isinstance(k, bytes) else k: (
                    v.decode("ascii", "ignore") if isinstance(v, bytes) else v
                )
                for k, v in (info.properties or {}).items()
            }
            try:
                proto = int(props.get("proto", "0"))
            except ValueError:
                proto = 0
            found.append(
                {
                    "host": host,
                    "port": info.port,
                    "protocol_version": proto,
                    "addresses": addresses,
                    "name": name,
                    "token_hash": props.get("token_hash", ""),
                }
            )

        def update_service(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def remove_service(self, *_args: Any, **_kwargs: Any) -> None:
            pass

    import time as _time

    zc = Zeroconf(ip_version=IPVersion.V4Only)
    try:
        ServiceBrowser(zc, SERVICE_TYPE, listener=_Listener())
        _time.sleep(timeout)
    finally:
        zc.close()
    return found


def discover_hub_url(timeout: float = 4.0, want_token_hash: str = "") -> str | None:
    """Return the URL of the best hub on the LAN, or None.

    Discovery order:
    1. UDP beacon (Rust hub, stdlib-only, fast ~1 s)
    2. mDNS/Zeroconf (Python hub, requires zeroconf package)
    3. ``FORGEWIRE_HUB_URL`` env var fallback

    Picks the hub with the highest ``protocol_version`` when multiple are found.
    If *want_token_hash* is given, only same-cluster hubs are returned.
    """
    import os

    # 1. UDP beacon — works with the Rust hub and needs no extra packages.
    beacon_hubs = discover_hubs_beacon(timeout=min(timeout * 0.4, 1.5), want_token_hash=want_token_hash)
    if beacon_hubs:
        best = sorted(beacon_hubs, key=lambda h: h.get("protocol_version", 0), reverse=True)[0]
        url = f"http://{best['host']}:{best['port']}"
        LOGGER.info("beacon discovered hub at %s (proto=%s)", url, best.get("protocol_version"))
        return url

    # 2. mDNS — works with the Python hub.
    mdns_hubs = discover_hubs(timeout=max(timeout * 0.6, 2.0))
    if mdns_hubs:
        best = sorted(mdns_hubs, key=lambda h: h.get("protocol_version", 0), reverse=True)[0]
        url = f"http://{best['host']}:{best['port']}"
        LOGGER.info("mDNS discovered hub at %s", url)
        return url

    # 3. Env var fallback.
    env = os.environ.get("FORGEWIRE_HUB_URL", "").strip()
    if env:
        LOGGER.info("no hub found via beacon/mDNS; using FORGEWIRE_HUB_URL=%s", env)
        return env

    LOGGER.warning("no hub discovered via beacon or mDNS, and FORGEWIRE_HUB_URL not set")
    return None
