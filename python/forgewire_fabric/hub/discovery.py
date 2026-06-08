"""mDNS / Zeroconf hub advertisement and auto-discovery.

``zeroconf`` is a required dependency as of forgewire-fabric 0.14.0.
The hub auto-advertises on startup; runners and the VSIX auto-discover.

Service type: ``_forgewire-hub._tcp.local.`` -- distinct from the legacy
``_forgewire-runner._tcp.local`` brainstormed in todo 23 because the hub is
the always-on control plane; runners reach *it*, not the other way around.

TXT record fields:

* ``proto``      -- ``hub_protocol_version`` (e.g. ``2``)
* ``token_hash`` -- ``sha256(token)[:16]`` hex; same as the Rust beacon.
                    Clients that hold the token can confirm cluster membership
                    by comparing hashes. Never the token itself or a suffix.
* ``path``       -- always ``/`` (reserved for future REST prefixes).
"""

from __future__ import annotations

import hashlib
import logging
import socket
from dataclasses import dataclass
from typing import Any

LOGGER = logging.getLogger("forgewire_fabric.discovery")

SERVICE_TYPE = "_forgewire-hub._tcp.local."


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


def discover_hub_url(timeout: float = 4.0) -> str | None:
    """Return the URL of the best hub on the LAN, or None.

    Picks the hub with the highest protocol_version. Falls back to
    FORGEWIRE_HUB_URL env var if no hub is discovered via mDNS.
    """

    import os

    hubs = discover_hubs(timeout=timeout)
    if hubs:
        best = sorted(hubs, key=lambda h: h.get("protocol_version", 0), reverse=True)[0]
        return f"http://{best['host']}:{best['port']}"

    env = os.environ.get("FORGEWIRE_HUB_URL", "").strip()
    if env:
        LOGGER.info("no mDNS hub found; using FORGEWIRE_HUB_URL=%s", env)
        return env

    LOGGER.warning("no hub discovered via mDNS and FORGEWIRE_HUB_URL not set")
    return None
