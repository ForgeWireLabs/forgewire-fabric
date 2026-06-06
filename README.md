# ForgeWire Fabric

**Private work-dispatch fabric for trusted remote runners.**

ForgeWire Fabric turns machines you control into a signed, policy-governed execution fabric. Dispatch work from your laptop, editor, automation, CI, or ForgeWire itself; Fabric routes each task to an eligible trusted runner, enforces scope and policy, streams execution, tracks cost, and records an audit trail.

Most infrastructure sees only one layer:

- VPNs see machines.
- Queues see messages.
- Schedulers see workloads.
- Hosted agent platforms see tasks.

**Fabric sees the work graph.** Every dispatch, claim, stream, result, approval, budget check, secret handoff, and audit event belongs to one execution chain.

> **Status:** Apache-2.0 alpha. Fabric is usable today for signed hub/runner dispatch, scoped runners, capability-aware claims, policy gates, approvals, cost tracking, structured streams, audit foundations, Python/MCP integrations, and VS Code workflows. Larger features such as federated QUIC transport, capability anycast, hub HA, stronger egress enforcement, and external audit witnessing are planned or in progress.

---

## Why Fabric exists

Remote execution is easy to start and hard to trust.

A shared SSH key works until you need to know which task touched which path. A queue works until you need per-task approval, secrets, egress, and replay. A scheduler works until the work is not just a container but a signed instruction with scope, capabilities, budget, and provenance. A hosted agent platform works until execution policy, credentials, source access, and audit logs live in somebody else's control plane.

Fabric exists for operators who want the convenience of remote agents, build workers, GPU boxes, lab machines, and private runners **without surrendering execution control**.

Fabric's core promise:

> **Send signed work to machines you trust, let only eligible runners claim it, enforce policy before and during execution, and preserve enough evidence to explain what happened later.**

---

## What Fabric does

- **Signed task dispatch** — dispatchers submit sealed work briefs with scoped execution intent.
- **Trusted hub/runner execution** — a hub owns task state; runners register identity, advertise capabilities, claim eligible work, and report results.
- **Scope-aware routing** — runners can be limited to declared workspace prefixes; tasks outside those scopes are invisible to them.
- **Capability-aware claims** — tasks can require tags, tools, workspace affinity, tenant affinity, and runner capabilities.
- **Policy gates** — dispatch, runtime intent, and completion can be allowed, denied, or held for approval.
- **Operator approvals** — risky operations such as writes, network egress, merges, pushes, or shell actions can pause for human approval.
- **Cost controls** — per-task and period budgets let the hub reject work before it exceeds configured caps.
- **Secret brokering and redaction** — secret names can be requested by a task, injected only at claim time, and redacted from stored outputs.
- **Structured streams** — stdout, stderr, info events, progress, notes, and terminal results are observable while work runs.
- **Audit foundations** — lifecycle events and results are retained for review, replay tooling, and future external witnessing.
- **Editor and tool surfaces** — CLI, MCP integration, and VS Code extension support dispatch and observation without giving tools unchecked access.

---

## The core model

```text
        signed brief + scope + policy metadata
┌────────────┐ ───────────────────────────────▶ ┌──────────────┐
│ Dispatcher │                                  │ Fabric Hub   │
│ CLI/VSCode │ ◀──── status / streams / audit ─ │ control plane│
│ MCP/tool   │                                  └──────┬───────┘
└────────────┘                                         │
                                                       │ claim by scope,
                                                       │ capability, tenant,
                                                       │ workspace, policy
                                                       ▼
                                                ┌──────────────┐
                                                │ Runner       │
                                                │ execution    │
                                                │ plane        │
                                                └──────┬───────┘
                                                       │
                                                       │ streams, result,
                                                       │ cost, audit events
                                                       ▼
                                                Operator evidence
```

### Dispatcher

A dispatcher is any trusted client that submits work: the CLI, VS Code extension, MCP-enabled tooling, automation, CI, ForgeWire, or a custom application. Dispatchers describe **what** should run, **where it is allowed to operate**, and **what capabilities or approvals it needs**.

### Hub

The hub is the control plane. It accepts dispatches, verifies authorization, enforces policy, stores task state, tracks cost, exposes task/runner/audit APIs, and decides which work an eligible runner may claim.

### Runner

A runner is the execution plane. It registers with a stable identity, advertises tags/tools/capabilities, limits itself to declared scopes, claims work from the hub, executes inside its local workspace, streams progress, and submits terminal results.

---

## Where Fabric fits

Fabric is not trying to be only a VPN, queue, scheduler, workflow engine, or hosted agent. It sits where those systems overlap: trusted remote work.

| If you would normally reach for... | It gives you... | Fabric adds... |
|---|---|---|
| **Tailscale / WireGuard / Headscale** | Private reachability | Work-aware dispatch, runner identity, policy, streams, audit, and future native overlay transport. |
| **NATS / gRPC / RabbitMQ** | Message movement | Signed work envelopes, runner claims, scoped execution, policy gates, and result provenance. |
| **Celery / Dramatiq / RQ** | Task queues and workers | Scope/capability routing, signed dispatch, approvals, costs, secrets, streams, and audit chain. |
| **Ray / Dask** | Distributed compute | Operator-owned policy, trusted runners, work provenance, and non-Python/agent/command task semantics. |
| **Kubernetes / Nomad** | Workload scheduling | Signed intent, task-level scope, capability-aware execution, and private work-control semantics. |
| **Temporal** | Durable workflow history | Runner identity, signed remote execution, scoped workspaces, streamed evidence, and operator policy gates. |
| **Hosted coding agents** | Agent/task execution UX | Private control plane, local credentials, budget/egress/secrets policy, approvals, and audit on infrastructure you operate. |

A useful shorthand:

> Tailscale connects machines. NATS moves messages. Kubernetes schedules workloads. Temporal records workflows. Ray runs distributed compute. Hosted agents run tasks for you. **Fabric governs trusted work across machines you control.**

---

## Current capabilities

Stable or usable today:

- Rust hub and runner daemons with Protocol v3 support.
- Python CLI/client compatibility surface for smoke tooling, MCP integration, and operator workflows.
- Authenticated dispatch with signed envelopes and nonce replay protection.
- Scope- and capability-aware runner claim routing.
- Runner identity persistence, trust registration, heartbeat, drain, and registry surfaces.
- Structured task streams and persisted terminal results.
- Hash-chained audit log foundation.
- Policy gates for dispatch, runtime intent checks, and completion-time review.
- Approval inbox with CLI workflows and notification hooks.
- Cost ledger with per-task, daily, and weekly budget limits.
- Secret broker foundation with encrypted storage, name-only audit, claim-time injection, and output redaction.
- rqlite-backed hub state path for replicated availability work.
- Windows service installation path with NSSM supervision and watchdogs.
- VS Code extension for hub connection, runner/task browsing, dispatch, approvals, and task streams.

Still alpha / evolving:

- Native release bundles are the intended primary distribution path and are still being hardened.
- Linux and macOS service installers are part of the cross-platform direction, but Windows has the most validated service path today.
- Hub HA, role-separated identity, stronger egress enforcement, and richer replay/export workflows are active roadmap items.
- Federated overlay transport, capability anycast, external witnessing, and GUI/operator surfaces are planned later-stage capabilities.

---

## Quickstart: local hub and runner

The smallest smoke path uses the Python compatibility CLI. Native daemons are the intended deployment substrate for long-running hosts, but the Python CLI remains useful for local tests and integrations.

```bash
pip install forgewire-fabric
forgewire-fabric token gen > hub.token
export FORGEWIRE_HUB_TOKEN="$(cat hub.token)"
```

Start a local hub:

```bash
forgewire-fabric hub start --host 127.0.0.1 --port 8765
```

Start a runner in another terminal:

```bash
export FORGEWIRE_HUB_URL=http://127.0.0.1:8765
export FORGEWIRE_HUB_TOKEN="$(cat hub.token)"

forgewire-fabric runner start --workspace-root /path/to/repo
```

Dispatch and observe scoped work:

```bash
forgewire-fabric dispatch "pytest -q" --scope "tests/**"
forgewire-fabric tasks list
forgewire-fabric tasks stream <task-id>
```

For native daemon setup, service installation, editor usage, and multi-machine walkthroughs, see [docs/QUICKSTART.md](docs/QUICKSTART.md).

---

## Install and distribution

### Native release path

The intended operator experience is a signed native release bundle containing:

- `forgewire-hub`
- `forgewire-runner`
- `forgewire-fabric-cli`
- platform service installers
- checksums, provenance, rollback notes, and release metadata

See [docs/RELEASE_DISTRIBUTION.md](docs/RELEASE_DISTRIBUTION.md) for release artifact expectations.

### From source

```bash
git clone https://github.com/DigitalHallucinations/forgewire-fabric.git
cd forgewire-fabric
cargo build --release
```

Native binaries are emitted under `target/release/`.

### Python integration package

```bash
pip install forgewire-fabric
```

The Python command is `forgewire-fabric`; the import package is `forgewire_fabric`. Use this package for CLI compatibility, MCP adapters, client integrations, smoke tests, and fallback tooling. It is not the preferred long-running daemon substrate.

---

## Policy and operator control

Fabric can load a repository-local policy file that governs dispatch, runtime intent, and completion.

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

See [policy.yaml](policy.yaml) for an annotated policy example.

---

## VS Code and MCP

Fabric includes editor and tool integration surfaces so operators can dispatch and observe work without giving tools uncontrolled direct access to runners.

Build and install the VS Code extension from the `vscode/` workspace:

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

---

## Roadmap

The public roadmap is intentionally described by capability rather than internal milestone number. Detailed engineering sequencing lives outside this README.

Near-term focus:

- Signed native release bundles for supported platforms.
- Clearer hub-only, runner-only, and local-smoke installer flows.
- Better audit export and replay workflows.
- Capability-aware dispatch routing with cost-aware runner selection.
- Stronger secret injection and egress enforcement.
- Hub HA and role-scoped identity.
- Published VS Code packages and richer operator documentation.

Longer-term direction:

- Federated transport over Noise/QUIC with relay fallback.
- Capability anycast URIs such as `forgewire://capability/<expression>`.
- Task-bound egress enforcement with userspace-first and OS-native tiers.
- Per-task stream QoS and transport-level usage accounting.
- External audit witnessing and signed export manifests.
- GUI/operator surfaces and Kubernetes-native deployment options.

---

## What this is not

- **Not a hosted agent platform.** Fabric does not phone home and does not require third-party execution control.
- **Not the full ForgeWire application runtime.** Desktop shell features, personas, memory, local assistant orchestration, and broader ForgeWire UX live outside this repository.
- **Not just a message broker.** Fabric carries work semantics, identity, scope, policy, cost, streams, and audit, not only messages.
- **Not a Kubernetes replacement.** Fabric can coexist with schedulers, but it focuses on signed remote work and trusted runner control.
- **Not production-hard by default.** It is alpha software. Treat public exposure, tokens, secrets, and runner permissions with the same caution you would apply to SSH or CI credentials.

---

## Repository map

| Area | What it contains |
|---|---|
| `crates/` | Rust hub, runner, CLI, protocol, policy, audit, store, client, streams, beacon, and claim-router crates. |
| `python/forgewire_fabric/` | Python CLI/client compatibility, hub/runner adapters, MCP integration, policy helpers, cluster helpers, and installer assets. |
| `scripts/install/` | Platform installer and service-management scripts. |
| `scripts/dr/` | rqlite backup, restore, and chaos-drill support scripts. |
| `vscode/` | VS Code extension for connecting to a hub, browsing runners/tasks, dispatching work, approvals, and streams. |
| `docs/` | Quickstart, positioning, protocol, release distribution, and operations docs. |
| `tests/` | Protocol, routing, installer sync, runtime parity, hub, runner, cluster, and integration tests. |

---

## Documentation

- [docs/QUICKSTART.md](docs/QUICKSTART.md) — hands-on setup guide.
- [docs/POSITIONING.md](docs/POSITIONING.md) — product boundaries and relationship to the parent project.
- [docs/protocol-v3-spec.md](docs/protocol-v3-spec.md) — signed dispatch envelope details.
- [docs/RELEASE_DISTRIBUTION.md](docs/RELEASE_DISTRIBUTION.md) — release artifact strategy.
- [docs/operations/service-install.md](docs/operations/service-install.md) — long-running service installation.
- [docs/operations/tls.md](docs/operations/tls.md) — TLS/reverse-proxy guidance.
- [vscode/README.md](vscode/README.md) — editor extension guide.

---

## License

ForgeWire Fabric is released under the Apache License 2.0. See [LICENSE](LICENSE).
