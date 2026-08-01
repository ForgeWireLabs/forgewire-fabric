"""Static security and shell guards for the 114B Tauri client boundary."""

from __future__ import annotations

import re
from pathlib import Path


FABRIC = Path(__file__).resolve().parents[1]
DESKTOP = FABRIC / "desktop"

_STRUCT = re.compile(
    # Visibility is `pub`, `pub(crate)`/`pub(super)`/etc., or nothing --
    # `pub(crate) struct PasskeyBridgeResult` (webauthn_bridge.rs) silently
    # matched zero structs under the earlier `pub[ \t]+` form, which only
    # covered bare `pub`. A regex this security-relevant returning an empty
    # result on a real struct is worse than one that raises: nothing here
    # would have failed loudly, only proven nothing.
    r"((?:^[ \t]*#\[[^\]]*\]\n)*)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?struct[ \t]+(\w+)[ \t]*\{(.*?)^\}",
    re.MULTILINE | re.DOTALL,
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _serializable_structs(rust: str) -> dict[str, str]:
    """Structs that derive Serialize, i.e. the ones able to reach the webview.

    A Tauri command can only return something serializable, so this is the set
    where a secret-bearing field would actually cross the boundary. Structs
    without Serialize are internal no matter what they hold.
    """
    return {
        name: body
        for attrs, name, body in _STRUCT.findall(rust)
        if "Serialize" in attrs
    }


def test_desktop_uses_typed_native_transport_without_webview_bearer_fetch() -> None:
    api = _read(DESKTOP / "src" / "api.ts")
    storage = _read(DESKTOP / "src" / "storage.ts")
    rust = _read(DESKTOP / "src-tauri" / "src" / "main.rs")
    assert "fetch(" not in api
    assert "Authorization" not in api
    assert "TOKEN_KEY" not in storage
    # No struct that can reach the webview may carry the token itself. Scoped
    # to Serialize-deriving structs rather than matched against the whole file:
    # as a bare string this guard passed only because load_hub_token returned
    # an unnamed 3-tuple, so naming those fields tripped it at identical
    # security. It rewarded opaque tuples over readable structs while proving
    # nothing about the boundary. `token_present`/`token_path`/`token_source`
    # are deliberately still allowed -- they are metadata, not the secret.
    for name, body in _serializable_structs(rust).items():
        assert not re.search(
            r"^\s*(?:pub\s+)?token\s*:\s*(?:Option<)?String", body, re.MULTILINE
        ), f"{name} derives Serialize and carries the token itself"
    assert "token_present: bool" in rust
    for command in (
        "load_fabric_snapshot",
        "load_task_stream",
        "load_task_audit",
        "cancel_task",
        "set_runner_drain",
        "decide_approval",
    ):
        assert command in rust
    assert "method: String" not in rust
    assert "proxy_request" not in rust
    assert "generic_request" not in rust


def test_webauthn_bridge_never_returns_session_secrets_to_the_webview() -> None:
    """114C.6 Slice 5d.

    Unlike Slice 5a's `SessionSecrets` (already, deliberately, IPC-exposed via
    save_session_secrets/load_session_secrets so a webview-side
    SessionCredentialStore implementation can round-trip it -- that design
    predates this test and is not what this one is about), a passkey login
    through the bridge writes straight into the OS keyring from Rust and
    hands the webview nothing more than an ok/error/credential_id summary.
    `PasskeyBridgeResult` is that summary type; this pins it so the property
    cannot regress silently -- e.g. by a future edit that, for convenience,
    starts threading the session back through the return value.
    """
    bridge = _read(DESKTOP / "src-tauri" / "src" / "webauthn_bridge.rs")
    structs = _serializable_structs(bridge)
    assert "PasskeyBridgeResult" in structs, "webauthn_bridge.rs must define PasskeyBridgeResult"
    body = structs["PasskeyBridgeResult"]
    for forbidden in ("access_secret", "refresh_secret", "session_id"):
        assert forbidden not in body, f"PasskeyBridgeResult must not carry {forbidden}"


def test_desktop_identity_and_csp_fail_closed() -> None:
    rust = _read(DESKTOP / "src-tauri" / "src" / "main.rs")
    config = _read(DESKTOP / "src-tauri" / "tauri.conf.json")
    assert "desktop_dispatcher_identity.json" in rust
    assert "load_or_create_dispatcher_identity" in rust
    assert "KeyPurpose::Dispatcher" in rust
    assert "dispatcher identity is required" in rust
    assert "http://*:*" not in config
    assert "https://*:*" not in config
    assert "connect-src ipc: http://ipc.localhost" in config


def test_double_sidebar_and_routed_workbench_accessibility_contract() -> None:
    main = _read(DESKTOP / "src" / "main.tsx")
    styles = _read(DESKTOP / "src" / "styles.css")
    route = _read(DESKTOP / "src" / "routing" / "hashRoute.ts")
    for label in (
        "Dashboard",
        "Fabric Explorer",
        "Hub / Fleet",
        "Tasks",
        "Agents",
        "Approvals",
        "Cost",
        "Audit",
        "Secrets",
        "Settings",
    ):
        assert label in main
    assert 'aria-label="Primary navigation"' in main
    assert 'role="tree"' in main
    assert 'role="separator"' in main
    assert "onKeyDown" in main
    assert "window.history.back()" in main
    assert "window.history.forward()" in main
    assert 'DEFAULT_ROUTE = "/dashboard"' in route
    assert ".activity-rail" in styles
    assert ".context-explorer" in styles
    assert ":focus-visible" in styles
    assert "@media" in styles


def test_role_limited_resource_does_not_redefine_session_health() -> None:
    rust = _read(DESKTOP / "src-tauri" / "src" / "main.rs")
    api = _read(DESKTOP / "src" / "api.ts")
    main = _read(DESKTOP / "src" / "main.tsx")
    assert "restrictions: BTreeMap<String, String>" in rust
    assert "role_policy_restriction" in rust
    assert "restrictions?: Record<string, string>" in api
    assert "restrictionKeys.has(key)" in api
    assert "Healthy · ${restrictedCount} restricted view" in main
    assert "Some views are limited by the installed automation token's role" in main


def test_workspace_has_one_lockfile_for_both_skins() -> None:
    assert (FABRIC / "package-lock.json").is_file()
    assert not (FABRIC / "desktop" / "package-lock.json").exists()
    assert not (FABRIC / "vscode" / "package-lock.json").exists()
