# ForgeWire Fabric

**Private task dispatch for the machines you already trust.**

ForgeWire Fabric lets you send scoped work from your laptop, editor, or automation into a private fleet of runners. A central hub accepts signed work briefs, checks policy, routes each task to an eligible runner, streams output, records results, and leaves an audit trail you can inspect later.

Use it when you want the convenience of remote agents or build workers without handing execution, credentials, or source access to a third-party control plane.

> **Status:** early public release. The deployable hub and runner are Rust daemons; the Python package remains available for CLI compatibility, MCP/client integrations, and smoke tooling.

## Why Fabric?

Remote execution is easy to start and hard to trust. Fabric is built around operator control from day one:

- **Your infrastructure stays yours.** Run the hub and runners on local workstations, lab machines, office servers, or a LAN cluster.
- **Tasks are scoped before they run.** Dispatches include explicit `scope_globs`; runners only claim work that fits their declared workspace and capabilities.
- **Every important action is auditable.** Task lifecycle events, runner identity, stream output, approvals, and results are persisted for review.
- **Policy is enforced centrally.** Block forbidden paths, protect branches, require approval for risky operations, and set spending limits.
- **No shared runner credentials.** Runners keep stable identities and communicate with the hub through authenticated, signed protocol messages.
- **Graceful fallback matters.** Rust daemons are the primary runtime, while Python compatibility paths remain useful for integrations and recovery.

## What you can do with it

- Dispatch test, build, analysis, or agent tasks to trusted remote machines.
- Keep long-running runners near the hardware they need: GPUs, Windows hosts, private networks, or large local workspaces.
- Give VS Code and MCP-enabled tools a controlled way to submit and observe remote work.
- Add approval gates around writes, shell execution, network egress, pushes, merges, and other sensitive actions.
- Track task cost and enforce daily or weekly budget caps.
- Preserve task history for replay, debugging, and operational review.

## How it works

```text
Dispatcher / VS Code / MCP tool
          │
          │ signed task brief + scope_globs
          ▼
ForgeWire Fabric hub ── policy, routing, audit, cost, streams
          │
          │ claim + heartbeat + result reporting
          ▼
Trusted runners ── execute scoped work in local workspaces
```

The hub is the control plane. It receives task briefs, validates authorization, applies policy, stores task state, and exposes the API used by CLIs and editor clients.

Runners are the execution plane. Each runner registers with a stable identity, advertises capabilities, claims only eligible work, streams progress, and submits terminal results back to the hub.

## Repository contents

| Area | What it contains |
|---|---|
| `crates/` | Rust hub, runner, CLI, protocol, policy, audit, store, and client crates |
| `python/forgewire_fabric/` | Python CLI/client compatibility and MCP integration surface |
| `scripts/install/` | Platform installer and service-management scripts |
| `vscode/` | VS Code extension for connecting to a hub, browsing runners/tasks, and dispatching work |
| `docs/` | Quickstart, protocol notes, release distribution, and positioning docs |
| `tests/` | Python and parity tests for protocol, routing, installer sync, runtime behavior, and integrations |

## Install

### Native release path

The intended operator experience is a signed native release bundle containing:

- `forgewire-hub`
- `forgewire-runner`
- `forgewire-fabric-cli`
- platform service installers
- checksums, provenance, and rollback notes

See [docs/RELEASE_DISTRIBUTION.md](docs/RELEASE_DISTRIBUTION.md) for the release strategy and artifact expectations.

### From a source checkout

```bash
git clone https://github.com/DigitalHallucinations/forgewire-fabric.git
cd forgewire-fabric
cargo build --release
```

The native binaries are emitted under `target/release/`.

### Python integration package

```bash
pip install forgewire-fabric
```

The Python command is `forgewire-fabric`; the import package is `forgewire_fabric`. Use this path for client integrations, MCP adapters, compatibility checks, and smoke tooling. It is not the primary long-running daemon substrate.

## Quickstart: local hub and runner

The example below uses the Python compatibility CLI because it is the smallest cross-platform smoke path.

```bash
pip install forgewire-fabric
forgewire-fabric token gen > hub.token
export FORGEWIRE_HUB_TOKEN="$(cat hub.token)"
```

Start a hub:

```bash
forgewire-fabric hub start --host 127.0.0.1 --port 8765
```

Start a runner in another terminal:

```bash
export FORGEWIRE_HUB_URL=http://127.0.0.1:8765
export FORGEWIRE_HUB_TOKEN="$(cat hub.token)"

forgewire-fabric runner start --workspace-root /path/to/repo
```

Dispatch and observe a scoped task:

```bash
forgewire-fabric dispatch "pytest -q" --scope "tests/**"
forgewire-fabric tasks list
forgewire-fabric tasks stream <task-id>
```

For a fuller walkthrough, including native daemon setup and editor usage, see [docs/QUICKSTART.md](docs/QUICKSTART.md).

## Windows service install

The Windows installer path is designed for always-on hub and runner nodes using NSSM supervision, watchdogs, and rqlite-backed state.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/install/install-fabric.ps1 -WorkspaceRoot C:\Projects\your-repo
```

See `scripts/install/install-fabric.ps1` and [docs/RELEASE_DISTRIBUTION.md](docs/RELEASE_DISTRIBUTION.md) before using this on production hosts.

## Policy and approvals

Fabric includes a local policy file for common operator controls:

```yaml
protected_branches: [main, "release/*"]
forbidden_paths: [".github/workflows/**", "secrets/**"]
max_diff_lines: 2000
require_approval: [merge, push, network_egress]
egress_allowlist: ["pypi.org", "github.com"]
daily_budget_usd: 5.00
weekly_budget_usd: 25.00
```

Useful commands:

```bash
forgewire-fabric approvals list
forgewire-fabric approvals approve <approval-id>
forgewire-fabric approvals deny <approval-id> --reason "out of scope"
forgewire-fabric cost summary --since 7d --by model
forgewire-fabric cost budget
```

See [policy.yaml](policy.yaml) for an annotated example.

## VS Code and MCP

Install the VS Code extension from the `vscode/` workspace:

```bash
cd vscode
npm install
npm run package
code --install-extension forgewire-*.vsix
```

Install the MCP integration against a running hub:

```bash
forgewire-fabric mcp install --hub-url http://127.0.0.1:8765
forgewire-fabric mcp install --hub-url http://127.0.0.1:8765 --with-runner --workspace-root /path/to/repo
```

See [vscode/README.md](vscode/README.md) for extension commands and settings.

## Current capabilities

- Rust hub and runner daemons with Protocol v3 support.
- Authenticated dispatch with signed envelopes and nonce replay protection.
- Scope- and capability-aware runner claim routing.
- Structured task streams and persisted terminal results.
- Hash-chained audit log foundation.
- Runner identity persistence and trust registration.
- Policy gates for dispatch, runtime intent checks, and completion-time review.
- Approval inbox with CLI workflows and notification hooks.
- Cost ledger with per-task and period budget limits.
- Windows service installation path with NSSM supervision.
- Python CLI/client compatibility and MCP integration surface.
- VS Code extension for hub connection, runner/task browsing, dispatch, approvals, and task streams.

## Roadmap

Near-term work focuses on making Fabric easier to adopt outside its original parent project:

- Signed native release bundles for supported platforms.
- Clearer installer flows for hub-only, runner-only, and local smoke-test setups.
- Better replay and audit export workflows.
- Capability-aware dispatch routing with cost-aware runner selection.
- Stronger secret injection and egress enforcement.
- High-availability hub deployment patterns.
- Published VS Code extension packages and richer operator documentation.

Longer-term ideas include federated transport over QUIC, capability anycast URIs, stronger OS-level egress controls, external audit witnessing, and GUI/operator surfaces.

## What this is not

ForgeWire Fabric is not a hosted agent platform and does not phone home. It is also not the full ForgeWire application runtime: desktop shell features, personas, memory, and local assistant orchestration live outside this repository.

## Documentation

- [docs/QUICKSTART.md](docs/QUICKSTART.md) — hands-on setup guide
- [docs/POSITIONING.md](docs/POSITIONING.md) — product boundaries and relationship to the parent project
- [docs/protocol-v3-spec.md](docs/protocol-v3-spec.md) — protocol details
- [docs/RELEASE_DISTRIBUTION.md](docs/RELEASE_DISTRIBUTION.md) — release artifact strategy
- [vscode/README.md](vscode/README.md) — editor extension guide

## License

See [LICENSE](LICENSE).
