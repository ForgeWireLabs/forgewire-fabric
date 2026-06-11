# ForgeWire MCP configs (Loom + Fabric)

Reference MCP server configs for wiring an editor/agent into a ForgeWire hub,
shipped as part of the install bundle. Phase 2.8 split the single
`forgewire-dispatcher` server into two surfaces:

| Server | Module | Surface | Use it to… |
| --- | --- | --- | --- |
| `forgewire-fabric` | `forgewire_fabric.hub.fabric_mcp` | **Fabric** (agent dispatch) | send typed intent (`dispatch_skill` / `dispatch_tool` / `dispatch_prompt`) to a remote *agent* (Claude Code, VS Code, Hermes, …) and read results. |
| `forgewire-loom` | `forgewire_fabric.hub.loom_mcp` | **Loom** (host control) | run shell commands / processes on a remote *host* (`run_command`, `start_process`, `send_input`, …). |

> **Rule of thumb:** `forgewire-fabric` for *agent intent*, `forgewire-loom` for
> *shell access*. A dispatcher session typically loads **both**.

There are two roles a machine can play, and they load different servers:

- **Dispatcher** (you driving other machines): load `forgewire-fabric` +
  `forgewire-loom` (the dispatcher MCPs). See [`vscode/mcp.json`](vscode/mcp.json),
  [`claude/forgewire-fabric.json`](claude/forgewire-fabric.json), and
  [`claude/forgewire-loom.json`](claude/forgewire-loom.json).
- **Fabric runner** (this machine *is* an agent that claims work): load
  `forgewire-fabric-runner` (`forgewire_fabric.hub.fabric_runner_mcp`). See
  [`vscode/mcp.runner.json`](vscode/mcp.runner.json) and
  [`claude/forgewire-fabric-runner.json`](claude/forgewire-fabric-runner.json).
  The runner introspects this machine's connected MCP servers and advertises a
  manifest to the hub; the skills/tools/resources it exposes show up in the
  VS Code **Agents** pane and drive capability-aware routing. Adding a skill =
  adding it to one of this machine's MCP servers — there is no separate tag.

Loom hosts (pure shell executors, no LLM) run the `forgewire-loom-runner`
binary as a service; they need no MCP editor config.

## Placeholders to edit

Every template uses these placeholders — replace them for your environment:

- **`command`** — `python` here means "the interpreter that has
  `forgewire-fabric` installed." Point it at your venv, e.g.
  `C:\\Projects\\forgewire\\.venv\\Scripts\\python.exe` on Windows.
- **`FORGEWIRE_HUB_URL`** — the hub base URL (`http://<hub-host>:8765`). The
  extension/CLI can also auto-discover the hub on the LAN, so `127.0.0.1:8765`
  is a safe default when running on the hub box.
- **`FORGEWIRE_HUB_TOKEN_FILE`** — path to the bearer token. The installer drops
  it at `~/.forgewire/hub.token`.
- **`FORGEWIRE_RUNNER_WORKSPACE_ROOT`** (runner only) — the repo/workspace the
  agent runner operates in.

## Where the files go

| Template | Copy to |
| --- | --- |
| `vscode/mcp.json` | VS Code user-scope `mcp.json` (or workspace `.vscode/mcp.json`). |
| `vscode/mcp.runner.json` | merge its `servers` entry into the same `mcp.json` on a box that is an agent runner. |
| `claude/forgewire-fabric.json` | `~/.claude/mcp/forgewire-fabric.json` |
| `claude/forgewire-loom.json` | `~/.claude/mcp/forgewire-loom.json` |
| `claude/forgewire-fabric-runner.json` | `~/.claude/mcp/forgewire-fabric-runner.json` |

The `forgewire-fabric mcp install` CLI wires the VS Code user-scope `mcp.json`
for you; these templates are the canonical reference and the source for the
Claude Code configs.
