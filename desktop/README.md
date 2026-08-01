# ForgeWire Fabric Desktop

> A native Tauri 2 control panel for a [ForgeWire Fabric](https://github.com/ForgeWireLabs/forgewire-fabric) compute fabric. Windows-first today (macOS/Linux build but have had less soak). Apache-2.0.

Desktop is the second client for ForgeWire Fabric — a routed, single-window
workbench built on the same `@forgewire/fabric-client-core` domain/session/
command contract as the [VS Code extension](../vscode/README.md), so both
clients render the same account/session states, commands, and restrictions.
Unlike the extension, Desktop talks to the hub through a native Tauri/Rust
backend rather than a Node HTTP client — no bearer token or session secret is
held in the WebView any longer than a single authenticated call needs it.

## Layout

An activity rail on the left switches between eleven routed pages:

**Dashboard**, **Fabric Explorer** (a searchable tree over every live
object — hosts, runners, agents, tasks, approvals), **Hub / Fleet**,
**Tasks**, **Agents**, **Approvals**, **Cost**, **Audit**, **Secrets**
(metadata only — values never render), **Settings** (connection, hub
candidates/failover, dispatcher identity, diagnostics), and **Account**.

A status bar reports the active hub, connection state, and last-refresh
time; `Ctrl/Cmd+Shift+P` opens a searchable command palette over every
supported action.

## Account

The Account page is self-service by default, with an admin section that
appears automatically for a signed-in `admin`:

- **Self-service**: sign in with a passkey (opens a hub-served WebAuthn
  bridge page in the system browser — the session's own secret never enters
  that browser, only a public, single-use challenge does); profile, status,
  and role display; active-session list with per-session revoke; sign out
  (best-effort hub revoke, then an unconditional local credential clear —
  the machine ends up signed out even if the hub is unreachable); and a Step
  Up button that runs the same browser-relay ceremony to elevate the current
  session to `aal2` before a sensitive action.
- **Administration** (visible only when the signed-in human holds the
  `admin` role — enforced client-side via a `requiresHumanRole` command gate
  and, ultimately, by the hub itself): the full account list; Create Account
  (role choices come from the hub's own `auth-policy`, never a hardcoded
  list); per-account Disable/Enable (a compare-and-set on the account's
  revision); Grant/Revoke Role; and two-step account deletion (`Delete`
  marks the account `deletion_pending`; `Complete Deletion` tombstones it
  irreversibly). Both deletion actions run a fresh step-up ceremony first,
  using the rotated access secret it returns for the mutation itself — the
  client enforces this even though the hub does not yet require step-up on
  the deletion routes.

Session secrets are read fresh from the OS credential store (Windows
Credential Manager, via the `keyring` crate) on every call and are never
cached in React component state.

## Development

```bash
npm install                 # from the forgewire-fabric workspace root
npm run tauri:dev --workspace @forgewire/fabric-desktop
```

`npm run build --workspace @forgewire/fabric-desktop` type-checks and
produces a Vite production bundle; `npm test --workspace @forgewire/fabric-desktop`
runs the vitest suite (pure-logic unit tests plus, from 114C.7 Slice 6, a
jsdom-backed accessibility/keyboard/redaction suite for the Account page).
`npm run tauri:build` produces the native installer via `tauri-cli`.

## Settings

Connection settings (hub URL, hub candidates/failover priority, pinned hub,
refresh interval) live under the **Settings** page rather than a
`vscode`-style flat settings list, since Desktop has no host settings UI of
its own to integrate with. The installed hub token and any stored human
session secrets are never exposed to the page — only presence/absence
booleans cross the Tauri IPC boundary for the automation token; a signed-in
human session's access secret is read into the WebView only for the
duration of an authenticated call, matching the discipline described above.

## Security

- The WebView never holds the automation hub token; every hub call the
  WebView triggers is proxied through a native Tauri command that reads the
  token from disk (`~/.forgewire/hub.token` or the platform installer path)
  on each call.
- Passkey ceremonies run in the system browser, not the WebView: on
  Windows the WebView origin (`http://tauri.localhost`) is WebAuthn-eligible
  in principle, but the bridge-page approach keeps the same trust boundary
  on every platform rather than special-casing one.
- The hub speaks plain HTTP by default; put a TLS-terminating proxy in
  front of any hub reachable beyond a trusted LAN, exactly as documented in
  the [root README](../README.md#security).

## Reporting issues

Please file issues at <https://github.com/ForgeWireLabs/forgewire-fabric/issues>. Include the desktop app version, OS, and whether the hub is local or remote.
