# ForgeWire Fabric VS Code Extension

> Drive a [ForgeWire](https://github.com/ForgeWireLabs/forgewire-fabric) compute fabric from inside VS Code. Cross-platform (Windows / macOS / Linux). Apache-2.0.

ForgeWire turns any cluster of machines into a signed, scope-bounded task fabric. This extension is the GUI for it: connect to a hub, watch runners and tasks live, dispatch sealed briefs, and tail per-task stream output — all without leaving the editor. It can also start a hub or a runner locally with two clicks, so any computer running VS Code can join a cluster regardless of OS.

## Features

- **Activity-bar sidebar** with live tree views:
  - **Hosts**: every machine on the fabric with its roles (hub head, control, dispatch, command/agent runner), online/draining/offline state, and cluster health.
  - **Tasks**: recent dispatches with status icons, a `kind` chip (`[command]` / `[agent]` / `[agent·skill]`), branch, and per-task actions (tail stream, cancel, show JSON).
  - **Agents**: the Fabric runner registry from `GET /agents` — each agent runner with its `agent_type`, state, and the MCP servers it advertises, drilled down to the **Skills** (prompts), **Tools**, and **Resources** each server exposes. This is the capability set the hub routes `dispatch_skill` / `dispatch_tool` against.
- **Status bar item** showing the active hub host. Click to (re)connect.
- **Dispatch quick-pick**: prompt → scope globs → branch → base-commit → sent. The hub's terminal status is reported back; the extension can immediately start tailing the SSE stream into an output channel.
- **Local hub control**: *ForgeWire: Start Hub Here* runs `forgewire-fabric hub start` in a managed terminal with a freshly generated token (saved to VS Code SecretStorage).
- **Local runner control**: *ForgeWire: Start Runner Here* registers the current machine as a runner against the connected hub. Workspace root, tags, and scope prefixes are prompted with sensible defaults from the open folder.
- **CLI bootstrap**: *ForgeWire: Install / Update CLI* runs `pip install --upgrade forgewire-fabric` in your selected Python interpreter — no terminal commands required.
- **Token utilities**: generate cryptographically-random hub tokens; copy the active token to clipboard.
- **Auto-refresh**: runners and tasks views poll every N seconds (configurable, default 10s).

## Requirements

- VS Code **1.85+**.
- A **Python 3.10+** interpreter available on the machine (used only for the local hub/runner commands and the install bootstrap; you can drive a remote hub without any Python on this host).
- For local hub/runner: the `forgewire` Python package. The extension can install it for you on first use.

## Setup (90 seconds)

1. Install the extension.
2. Run **ForgeWire: Connect to Hub** from the command palette and paste the URL + bearer token shared by your hub operator. The token is stored in VS Code [SecretStorage](https://code.visualstudio.com/api/references/vscode-api#SecretStorage).
3. The sidebar now shows live runners and tasks. **ForgeWire: Dispatch Task** sends work; **Tail Task Stream** (right-click on a task) streams its output into the *ForgeWire* output channel.

## Human accounts

On top of the shared dispatcher/runner bearer token above, a hub with human
accounts enabled adds a per-user **Account** view:

- **Sign in with a passkey** opens the hub-served WebAuthn bridge page in
  your system browser — the extension host has no DOM to run a WebAuthn
  ceremony in, so it relays the result over a one-shot loopback listener
  instead. The session's own secret is written straight to VS Code
  SecretStorage; the view then shows your profile, status, roles, and active
  sessions (with a per-session **Revoke** action), plus **Sign Out** and
  **Step Up** (elevates the current session to `aal2` via the same
  browser-relay ceremony, ahead of a sensitive action).
- Signed-in **admins** additionally see an **Administration** section:
  every account on the realm, **Create Account** (role choices read live
  from the hub's own auth-policy), per-account **Disable**/**Enable**, role
  **Grant**/**Revoke**, and two-step account deletion — **Delete** marks an
  account for deletion, **Complete Deletion** (only offered once pending)
  tombstones it irreversibly. Both deletion actions require a fresh Step Up
  first, even though the hub does not yet enforce that itself.
- Admin actions are gated by the signed-in human's own account role, which
  is a categorically different thing from the dispatcher/runner bearer
  token above — the token can never carry `admin`, so automation credentials
  can never reach these commands.
- If the connected hub doesn't advertise human-accounts support (older hub,
  or the feature disabled), the Account view and its commands are simply
  absent — the legacy shared-token connection above continues to work
  unchanged.

### Joining a cluster from a fresh machine

If you've just installed VS Code on a new box and want to make it a runner:

1. Install the extension.
2. Run **ForgeWire: Install / Update CLI** (one click). Wait for `pip` to finish in the terminal.
3. Run **ForgeWire: Connect to Hub** with the cluster's URL + token.
4. Run **ForgeWire: Start Runner Here**. Pick the workspace root (defaults to the open folder), tags, and scope prefixes.

That's it — the runner is online and the hub will route matching tasks to it.

### Standing up a hub from a fresh machine

1. Install the extension on the host you want to be the hub.
2. Run **ForgeWire: Install / Update CLI**.
3. Run **ForgeWire: Start Hub Here**. Pick a port (default 8765); the extension generates a random token, copies it to your clipboard, and saves it.
4. Share the URL `http://<this-host>:<port>` and the token with anyone joining the cluster.

## MCP control plane (Loom + Fabric)

The extension's panes are the read-side GUI. To *drive* the fabric from an
LLM session (Copilot Chat, Claude Code) you load two MCP servers, split by
surface (Phase 2.8):

- **`forgewire-fabric`** (`forgewire_fabric.hub.fabric_mcp`) — send typed intent
  to a remote *agent*: `dispatch_skill`, `dispatch_tool`, `dispatch_prompt`,
  `list_agents`, plus result/stream tools.
- **`forgewire-loom`** (`forgewire_fabric.hub.loom_mcp`) — control a remote
  *host*: `run_command`, `start_process`, `send_input`, `list_hosts`, …

> Rule of thumb: **`forgewire-fabric` for agent intent, `forgewire-loom` for
> shell access.** A dispatcher session loads both.

Ready-to-edit config templates for both VS Code and Claude Code (dispatcher and
agent-runner roles) live in
[`../install/mcp-configs/`](../install/mcp-configs/README.md). `forgewire-fabric
mcp install` wires the VS Code user-scope `mcp.json` automatically. Skills are
MCP prompts advertised by an agent's manifest, not tags — see
[`SKILLS-AS-PROMPTS.md`](../install/mcp-configs/SKILLS-AS-PROMPTS.md).

### Install the four-role agent suite

Run **ForgeWire: Install / Update Agent Suite in Workspace**. The extension
copies its packaged dispatcher, runner, approver, and observer/reviewer
chatmodes into `.github/chatmodes/`, plus seven task prompts into
`.github/prompts/`. On upgrade, locally modified files are preserved unless
you explicitly confirm replacement.

The roles use the existing MCP topology: dispatchers load `forgewire-fabric`
and `forgewire-loom`; agent runners load `forgewire-fabric-runner`.
Approver and observer modes expose read-only evidence tools. Approval decisions
still use the Approvals pane so the approver identity and audit event remain on
the existing governed path. The suite does not embed an MCP server or store
hub credentials.

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `forgewire.hubUrl` | `""` | Base URL of the hub. |
| `forgewire.hubToken` | `""` | Bearer token. Prefer the *Set Hub Token* command (uses SecretStorage). |
| `forgewire.hubTokenFile` | `""` | File containing the bearer token. Used when `hubToken` is empty; falls back to `~/.forgewire/hub.token` if present. |
| `forgewire.pythonPath` | `""` | Python interpreter used for `pip install` / local hub / local runner. Empty = auto-detect. |
| `forgewire.refreshIntervalSeconds` | `10` | Tree-view refresh cadence. |
| `forgewire.autoStartHubPort` | `8765` | Default port for *Start Hub Here*. |

## Commands

All commands are under the **ForgeWire** category in the command palette:

- `Connect to Hub…` / `Set Hub Token…` / `Disconnect`
- `Install / Update Agent Suite in Workspace`
- `Install / Update CLI`
- `Start Hub Here…` / `Start Runner Here…`
- `Dispatch Task…`
- `Refresh`
- `Tail Task Stream` / `Cancel Task` / `Show Task` (also available from the right-click menu in the Tasks view)
- `Generate New Hub Token` / `Copy Hub Token to Clipboard`
- `Sign In with Passkey` / `Register a Passkey` / `Step Up` / `Sign Out` — human-account self-service, present only when the connected hub advertises the `human_accounts` feature
- `Revoke Session` / `Create Account` / `Disable Account` / `Enable Account` / `Grant Role` / `Revoke Role` / `Delete Account` / `Complete Account Deletion` — from the Account view; the account-management commands are admin-role-gated

### VS Code-specific commands

Most ForgeWire commands share a semantic contract with the desktop client. The
commands below intentionally use VS Code-owned terminals, files, or local
extension bootstrap behavior. Desktop exposes an explicit alternative instead
of pretending those host integrations are portable.

| Command ID | Desktop alternative |
|---|---|
| `forgewire.installAgentSuite` | No desktop equivalent: this installs VS Code chatmodes and prompt files into a workspace. |
| `forgewire.installCli` | Use the signed desktop installer or Settings > Runtime. |
| `forgewire.dr.installBackupTask` | Use the governed DR setup workflow outside the WebView. |
| `forgewire.dr.installChaosTask` | Use the governed DR setup workflow outside the WebView. |
| `forgewire.dr.provisionSshForSystem` | Use the privileged host provisioning workflow. |
| `forgewire.dr.openClusterYaml` | Open the cluster configuration through Settings diagnostics. |

## Security

- The hub token is saved in VS Code SecretStorage when set via *Set Hub Token* or *Connect to Hub*. Avoid putting it in your settings JSON if you sync settings.
- The extension talks to the hub over plain HTTP by default. **Always put a TLS-terminating proxy (Caddy, nginx, Traefik, or a tunnel like Tailscale Funnel) in front of any hub exposed beyond your trusted LAN.**
- Generated tokens are 128-bit and produced via `crypto.getRandomValues()`.
- A signed-in human session's access/refresh secrets also live in SecretStorage, read fresh on every call rather than cached in extension state. Passkey ceremonies (sign-in, registration, step-up) never bring that secret into the browser — only a public, single-use WebAuthn challenge/assertion crosses the loopback relay; the extension host makes every authenticated hub call itself.

## Limitations

- The extension **does not** verify hub TLS certificates differently from Node's defaults; for self-signed certs, route through a proxy or local DNS that already trusts the cert.
- LAN discovery uses the Fabric UDP beacon rather than mDNS; static and pinned hub candidates remain available when broadcast discovery is blocked.
- Dispatch is signed with the extension's SecretStorage-backed Ed25519 dispatcher identity when Web Crypto is available. The legacy unsigned path is used only when identity creation is unavailable and the selected hub explicitly permits it.

## Reporting issues

Please file issues at <https://github.com/ForgeWireLabs/forgewire-fabric/issues>. Include the extension version, VS Code version, and the OS of the failing machine.
