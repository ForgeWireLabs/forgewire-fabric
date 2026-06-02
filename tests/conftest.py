"""Auto-patch BlackboardConfig.backend to 'sqlite' when rqlite cluster is offline."""
from __future__ import annotations
import dataclasses
import socket

def _rqlite_has_leader(host: str = "127.0.0.1", port: int = 4001) -> bool:
    try:
        import json, urllib.request
        with urllib.request.urlopen(f"http://{host}:{port}/status", timeout=2) as r:
            data = json.loads(r.read())
            return bool(data.get("store", {}).get("leader", {}).get("addr", ""))
    except Exception:
        return False

if not _rqlite_has_leader():
    try:
        import forgewire_fabric.hub.server as _srv
        # Re-create the dataclass with sqlite as the backend default
        _orig = _srv.BlackboardConfig
        _new_fields = []
        for f in dataclasses.fields(_orig):
            if f.name == "backend":
                _new_fields.append(dataclasses.field(default="sqlite"))
            else:
                _new_fields.append(f)
        # Monkeypatch __init__ to substitute the default
        _orig_init = _orig.__init__
        def _patched_init(self, db_path, token, host, port,
                          min_runner_version=_srv.DEFAULT_MIN_RUNNER_VERSION,
                          require_signed_dispatch=False,
                          policy_path=None,
                          backend="sqlite",  # patched default
                          rqlite_host="127.0.0.1",
                          rqlite_port=4001,
                          rqlite_consistency="strong",
                          approval_webhook_url=None,
                          labels_snapshot_path=None):
            self.db_path = db_path
            self.token = token
            self.host = host
            self.port = port
            self.min_runner_version = min_runner_version
            self.require_signed_dispatch = require_signed_dispatch
            self.policy_path = policy_path
            self.backend = backend
            self.rqlite_host = rqlite_host
            self.rqlite_port = rqlite_port
            self.rqlite_consistency = rqlite_consistency
            self.approval_webhook_url = approval_webhook_url
            self.labels_snapshot_path = labels_snapshot_path
        _srv.BlackboardConfig.__init__ = _patched_init
    except Exception as e:
        print(f"[conftest] backend patch failed: {e}")
