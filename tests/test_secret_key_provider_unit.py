from __future__ import annotations

import os
import stat
import sys

import pytest

from forgewire_fabric.hub.secret_broker import FileKeyProvider


def test_file_key_provider_creates_restrictive_key_file(tmp_path) -> None:
    path = tmp_path / "hub.db.secrets.key"
    key = FileKeyProvider(path).load()
    assert len(key) == 32
    assert path.read_bytes() == key
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode check")
def test_file_key_provider_rejects_group_or_world_accessible_key(tmp_path) -> None:
    path = tmp_path / "hub.db.secrets.key"
    path.write_bytes(b"x" * 32)
    os.chmod(path, 0o644)
    with pytest.raises(PermissionError):
        FileKeyProvider(path).load()
