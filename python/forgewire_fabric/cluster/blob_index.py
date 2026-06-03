"""Per-node CAS metadata index — in-memory with optional JSON sidecar.

Backs the chunked blob fabric (:mod:`forgewire_fabric.cluster.blobs_chunked`)
with records of digest → size/namespace/access-time. Data is held in memory
for fast access; an optional JSON sidecar persists entries across restarts so
the node does not have to re-fetch blobs it already holds.

SQLite was removed from the entire ForgeWire Fabric stack. rqlite is the only
persistent store, but blob metadata is node-local and does not belong in the
cluster-wide rqlite. In-memory + JSON sidecar is the correct replacement.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .cas import DEFAULT_CAS_NAMESPACE

CHUNKED_CAS_SCHEMA_VERSION = 1


@dataclass
class _BlobEntry:
    digest: str
    size: int
    namespace: str
    created_at: float
    last_accessed_at: float
    schema_version: int = CHUNKED_CAS_SCHEMA_VERSION


class LocalBlobIndex:
    """Per-node CAS metadata index (in-memory + optional JSON sidecar).

    Replaces the former ``SqliteBlobIndex`` — same public interface, no sqlite3.
    The sidecar is written on every mutation so restarts recover without
    re-fetching already-cached blobs. Pass ``sidecar_path=None`` to disable
    persistence (useful in tests).
    """

    def __init__(self, sidecar_path: Path | str | None = None) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, _BlobEntry] = {}
        self._sidecar: Path | None = Path(sidecar_path) if sidecar_path else None
        if self._sidecar and self._sidecar.exists():
            self._load_sidecar()

    # ------------------------------------------------------------------
    # Compat shim: accept an old sqlite3 db_path and derive sidecar name.
    # Callers that passed ``cas.sqlite3`` will get ``cas.json`` instead.
    # ------------------------------------------------------------------
    @classmethod
    def from_db_path(cls, db_path: Path | str) -> "LocalBlobIndex":
        """Construct with a sidecar next to where the old db file would be."""
        p = Path(db_path)
        sidecar = p.parent / (p.stem + ".json")
        return cls(sidecar_path=sidecar)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def upsert(
        self,
        *,
        digest: str,
        size: int,
        namespace: str = DEFAULT_CAS_NAMESPACE,
        created_at: float | None = None,
        last_accessed_at: float | None = None,
    ) -> None:
        now = time.time()
        key = digest.lower()
        with self._lock:
            existing = self._entries.get(key)
            self._entries[key] = _BlobEntry(
                digest=key,
                size=int(size),
                namespace=namespace,
                created_at=float(created_at if created_at is not None else (existing.created_at if existing else now)),
                last_accessed_at=float(last_accessed_at if last_accessed_at is not None else now),
            )
        self._flush()

    def touch(self, digest: str) -> None:
        key = digest.lower()
        with self._lock:
            if key in self._entries:
                self._entries[key].last_accessed_at = time.time()
        self._flush()

    def remove(self, digest: str) -> None:
        with self._lock:
            self._entries.pop(digest.lower(), None)
        self._flush()

    def get(self, digest: str) -> Mapping[str, Any] | None:
        with self._lock:
            e = self._entries.get(digest.lower())
        return asdict(e) if e else None

    def list_digests(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._entries.keys())

    def total_size(self) -> int:
        with self._lock:
            return sum(e.size for e in self._entries.values())

    def least_recently_accessed(self) -> Iterable[tuple[str, int]]:
        """Yield ``(digest, size)`` tuples in ascending access-time order."""
        with self._lock:
            ordered = sorted(self._entries.values(), key=lambda e: e.last_accessed_at)
        for e in ordered:
            yield e.digest, e.size

    def close(self) -> None:
        """No-op — kept for API compatibility with the old SqliteBlobIndex."""
        self._flush()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _flush(self) -> None:
        if self._sidecar is None:
            return
        try:
            self._sidecar.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                data = [asdict(e) for e in self._entries.values()]
            self._sidecar.write_text(
                json.dumps(data, separators=(",", ":")),
                encoding="utf-8",
            )
        except Exception:  # noqa: BLE001 — persistence is best-effort
            pass

    def _load_sidecar(self) -> None:
        try:
            raw = json.loads(self._sidecar.read_text(encoding="utf-8"))  # type: ignore[union-attr]
            for row in raw:
                e = _BlobEntry(**row)
                self._entries[e.digest] = e
        except Exception:  # noqa: BLE001 — corrupt sidecar is non-fatal
            pass


# ---------------------------------------------------------------------------
# Backward-compatibility alias — callers that used SqliteBlobIndex by name
# get LocalBlobIndex transparently.
# ---------------------------------------------------------------------------
SqliteBlobIndex = LocalBlobIndex

__all__ = ["CHUNKED_CAS_SCHEMA_VERSION", "LocalBlobIndex", "SqliteBlobIndex"]
