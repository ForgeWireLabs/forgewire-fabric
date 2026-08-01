"""Python integration surface for the native ForgeWire hub.

The authoritative hub is the ``forgewire-hub`` Rust binary. This package
contains its async HTTP client, MCP adapters, and discovery/presence helpers.

Public surface:

* :class:`forgewire_fabric.hub.client.HubClient` — async HTTP client (canonical
  name; ``BlackboardClient`` is the legacy alias kept for one minor cycle).
* :func:`forgewire_fabric.hub.client.load_client_from_env` — convenience loader.
* :mod:`forgewire_fabric.hub.discovery` — optional mDNS advertise/browse.
"""

from forgewire_fabric.hub.client import (
    BlackboardClient,
    HubClient,
    load_client_from_env,
)

__all__ = ["BlackboardClient", "HubClient", "load_client_from_env"]
