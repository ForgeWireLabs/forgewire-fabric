# ForgeWire Quickstart

A 10-minute path from zero to a working hub + runner, driven from your laptop
or your AI agent.

ForgeWire Fabric is a *signed task fabric*. One machine runs the **hub** (a
native Rust daemon that owns the task graph, backed by rqlite for HA). Other
machines run **runners** that claim work and stream output back. There are two
kinds of work, with separate queues:

- **Loom (command kind)** — direct host control: shell commands and processes,
  executed by a command runner. No LLM in the loop.
- **Fabric (agent kind)** — sealed briefs for a remote *agent* (e.g. a Claude
  Code session acting as a runner). The agent advertises its MCP tools and
  skills to the hub, which routes by capability.

A runner's kind is a property of the binary it runs — a command runner never
sees agent briefs, and vice versa. You dispatch from the CLI, VS Code, or an
MCP-capable agent on any machine that can reach the hub.

> **Threat model**: every dispatch / register / claim / heartbeat is
> ed25519-signed; the hub additionally validates a shared bearer token on
> every request. Anyone with the token can reach your cluster, so treat it
> like an SSH private key.

---

## 1. Install

The deployed substrate is the native Rust binaries. Either build them:

```bash
git clone https://github.com/ForgeWireLabs/forgewire-fabric.git
cd forgewire-fabric
cargo build --release   # forgewire-hub, forgewire-runner, forgewire-loom-runner, forgewire-fabric-cli
```

…or use the service installer (provisions rqlite + daemons under supervision —
see [operations/service-install.md](operations/service-install.md)).

On machines you dispatch *from*, install the Python integration package (the
dispatch CLI and the MCP servers):

```bash
pip install forgewire-fabric
```

---

## 2. Pick a hub host

Any always-on box on your network works (a NUC, a homelab box, a desktop
that's always plugged in).

### 2a. Generate a token (once)

```bash
forgewire-fabric token gen > hub.token
```

Share it over a secure channel with anyone who needs to dispatch or run
runners against this hub. **Anyone with this token can reach your cluster.**

### 2b. Start rqlite, then the hub

The hub's state lives in [rqlite](https://rqlite.io); the hub exits if it
cannot reach one. The service installer provisions rqlite for you — for a
manual/dev setup, start a single node first:

```bash
rqlited -node-id 1 ~/rqlite-data   # serves on 127.0.0.1:4001 by default
```

Then start the hub:

```powershell
# Windows
$env:FORGEWIRE_HUB_TOKEN_FILE = "C:\ProgramData\forgewire\hub.token"
$env:FORGEWIRE_HUB_HOST       = "0.0.0.0"
$env:FORGEWIRE_HUB_PORT       = "8765"
forgewire-hub.exe
```

```bash
# Linux / macOS
export FORGEWIRE_HUB_TOKEN_FILE=/etc/forgewire/hub.token
export FORGEWIRE_HUB_HOST=0.0.0.0
export FORGEWIRE_HUB_PORT=8765
./forgewire-hub
```

Verify from another shell:

```bash
curl -s http://<hub-host>:8765/healthz
# → {"status":"ok","rust_hub":true,"protocol_version":...,...}
```

For a long-lived hub, use
[operations/service-install.md](operations/service-install.md) — NSSM
(Windows), systemd (Linux), and the remote deploy recipe.

---

## 3. Add a command runner

On each worker machine, run the native runner (command kind — it executes
shell work in its workspace):

```bash
export FORGEWIRE_HUB_URL=http://<hub-host>:8765
export FORGEWIRE_HUB_TOKEN_FILE=/path/to/hub.token
export FORGEWIRE_RUNNER_WORKSPACE_ROOT=/path/to/your/repo
export FORGEWIRE_RUNNER_SCOPE_PREFIXES="src/,tests/"
export FORGEWIRE_RUNNER_TAGS="linux,gpu:nvidia,python:3.11"
./forgewire-runner
```

The runner generates an ed25519 identity on first launch and registers it
with the hub; restarts reuse the same identity, so its `runner_id` stays
stable. `SCOPE_PREFIXES` is the safety belt: a runner only claims tasks whose
`scope_globs` fall entirely within the prefixes you list.

> For a quick local experiment without building Rust, the Python reference
> runner works too: `forgewire-fabric runner start --workspace-root … --scope-prefixes …`.
> It is a test/parity implementation — use the native binary for anything
> long-running.

Confirm registration from anywhere:

```bash
forgewire-fabric runners list
```

---

## 4. Run work on a host (Loom)

Host commands are dispatched through the **`forgewire-loom` MCP server**,
which signs the command, cwd, and environment into the envelope. Wire it into
Claude Code or VS Code with the templates in
[../install/mcp-configs/](../install/mcp-configs/README.md), or:

```bash
forgewire-fabric mcp install --hub-url http://<hub-host>:8765
```

Then ask your agent:

> *"List the hosts on my fabric, then run `pytest tests/smoke -x` on the
> build box and show me the output."*

The agent calls `list_hosts`, then `run_command`; the runner spawns the
process with a clean brokered environment and streams stdout/stderr back live,
ending with the exit code. `start_process` / `send_input` / `kill_process`
cover long-running interactive work.

Watch any task from the CLI as well:

```bash
forgewire-fabric tasks list                # queued / running / done
forgewire-fabric tasks show 1              # full envelope incl. result
forgewire-fabric tasks stream 1            # tail stdout/stderr line by line
```

---

## 5. Dispatch a brief to an agent (Fabric)

Agent briefs are sealed instructions claimed by *agent* runners — for
example, a Claude Code session running the `forgewire-fabric-runner` MCP
server, which advertises that agent's skills and tools to the hub.

Queue a brief from any machine with the token:

```bash
forgewire-fabric keys init-dispatcher --label "$(hostname)"   # one-time, ed25519
forgewire-fabric dispatch "Investigate the flaky quorum test and propose a fix" \
  --scope "tests/**" \
  --branch "agent/laptop/quorum-flake" \
  --base-commit $(git rev-parse origin/main)
```

Dispatchers with the `forgewire-fabric` MCP server loaded can do the same
with capability routing: `dispatch_skill` / `dispatch_tool` go only to agents
that advertise the named skill or tool; `dispatch_prompt` is the freeform
fallback. Every brief carries an explicit `kind` — the hub rejects briefs
without one.

---

## 6. (Optional) Use the VS Code extension

A cross-platform GUI lives in [`vscode/`](../vscode). Install from the
packaged VSIX (marketplace listing pending):

```bash
cd vscode
npm install
npm run package
code --install-extension forgewire-*.vsix
```

Then in VS Code:

1. Open the **ForgeWire** activity bar item.
2. Run **ForgeWire: Connect to Hub** (Ctrl+Shift+P) and paste your URL +
   token (stored in VS Code SecretStorage).
3. Browse **Hosts**, **Tasks** (with kind chips), and **Agents** (each agent
   runner's advertised skills/tools/resources) live in the sidebar. Use
   **ForgeWire: Dispatch Task** to send an agent brief; right-click a task to
   **Tail Task Stream**.

See [`vscode/README.md`](../vscode/README.md) for the full command and
settings reference.

---

## Next steps

* [Protocol v3 spec](protocol-v3-spec.md) — signed envelopes, claim flow,
  replay protection.
* [Threat model](spec/phase-2.9/THREATMODEL.md) — what is and isn't trusted.
* [MCP config templates](../install/mcp-configs/README.md) — wiring Claude
  Code and VS Code as dispatchers or agent runners.
* [Operations: production hub install](operations/service-install.md) —
  NSSM, systemd, watchdogs.
* [Operations: TLS](operations/tls.md) — terminate TLS in front of any hub
  exposed beyond a trusted LAN.
* [Operations: backups](operations/dr-rqlite-backups.md) — rqlite backup and
  restore drills.

---

## Environment variables

### Hub

| Variable | Default | Purpose |
|----------|---------|---------|
| `FORGEWIRE_HUB_HOST` | `127.0.0.1` | Bind address (`0.0.0.0` for LAN) |
| `FORGEWIRE_HUB_PORT` | `8765` | Bind port |
| `FORGEWIRE_HUB_TOKEN_FILE` | `C:\ProgramData\forgewire\hub.token` (Win) / `/var/lib/forgewire/hub.token` (Linux) | Bearer token file |
| `FORGEWIRE_HUB_RQLITE_HOST` | `127.0.0.1` | rqlite node address |
| `FORGEWIRE_HUB_RQLITE_PORT` | `4001` | rqlite port |
| `FORGEWIRE_HUB_RQLITE_CONSISTENCY` | `strong` | `none`\|`weak`\|`strong` |
| `FORGEWIRE_HUB_STREAM_PROFILE` | `strict` | `strict`\|`balanced`\|`throughput` — runner output flush policy |

### Clients / dispatchers

| Variable | Purpose |
|----------|---------|
| `FORGEWIRE_HUB_URL` | Hub base URL for clients (`http://host:port`) |
| `FORGEWIRE_HUB_TOKEN` | Bearer token (alternative to `_TOKEN_FILE`) |
| `FORGEWIRE_HUB_TOKEN_FILE` | Path to a file containing the token |

### Runner

| Variable | Default | Purpose |
|----------|---------|---------|
| `FORGEWIRE_RUNNER_WORKSPACE_ROOT` | — | Working tree for the runner |
| `FORGEWIRE_RUNNER_TAGS` | — | Comma-separated routing tags |
| `FORGEWIRE_RUNNER_SCOPE_PREFIXES` | — | Path prefixes the runner accepts |
| `FORGEWIRE_RUNNER_MAX_CONCURRENT` | `1` | Max concurrent tasks |
| `FORGEWIRE_RUNNER_POLL_INTERVAL` | `5.0` | Seconds between empty-claim polls |

---

## Signed dispatch

The native Rust hub **always** requires signed dispatch: `POST /tasks`
returns `426 Upgrade Required` and clients must use `POST /tasks/v2` with a
registered dispatcher key. Even a leaked bearer token cannot impersonate a
developer.

One-time setup on each workstation:

```bash
forgewire-fabric keys init-dispatcher --label "$(hostname)"
```

This writes `~/.forgewire/dispatcher_identity.json` (mode 0o600 on POSIX).
The first `forgewire-fabric dispatch` call auto-registers the public key with
the hub; subsequent dispatches sign the envelope's immutable fields
(including `kind`, scope, branch, base commit, timestamp, and nonce) and
include the signature. For Loom command briefs, the signature additionally
covers the command, cwd, and an environment digest.

Inspect registered dispatchers:

```bash
forgewire-fabric dispatchers list
```
