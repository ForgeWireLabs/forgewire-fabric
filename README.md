# ForgeWire Fabric

> Work-graph-aware compute fabric: signed dispatch, scope-bound capability tokens, operator control plane, federated overlay.

ForgeWire Fabric turns machines you already control into a private execution fabric. Dispatchers issue sealed, signed work briefs to trusted runners. The hub enforces policy, tracks cost, audits every state transition, and routes to the right runner by capability — no shared credentials, no ad hoc SSH, no implicit trust.

**Current release: v0.7.0 (Rust/runner) · v0.16.0 (Python) · v0.4.0 (VSIX) · Protocol v3**

## What this is

An authenticated, auditable work-dispatch control plane for teams operating private compute. Two deployment profiles today:

| Profile | Topology | Use case |
|---|---|---|
| **Standalone** | 1 node | Laptop dev, local CI |
| **LAN cluster** | 2–20 nodes | Home/office fleet, zero external deps |

A federated overlay (Noise\_IK over QUIC, capability anycast, scope-bound egress) is in active development.

## What this is not

ForgeWire Fabric is not the full ForgeWire/PhrenForge platform. It does not include the desktop shell, persona ecosystem, memory system, local blackboard, or broader assistant runtime. Those belong to the parent platform and integrate with Fabric via the hub HTTP API.

---

## Install

ForgeWire Fabric is now Rust-first for daemon deployment. The operator-facing release should be a signed native bundle containing `forgewire-hub`, `forgewire-runner`, `forgewire-fabric-cli`, platform service installers, checksums, SBOM/provenance, and rollback notes. See [Release Distribution Strategy](docs/RELEASE_DISTRIBUTION.md).

```bash
# Python integration path, not the primary daemon substrate
pip install forgewire-fabric
```

The Python CLI entry point is `forgewire-fabric`. The package import is `forgewire_fabric`. Use it for client/MCP integration, smoke tooling, and fallback compatibility while Rust hub/runner daemons own the normal runtime path.

## One-command cluster install (Windows)

```powershell
irm https://raw.githubusercontent.com/DigitalHallucinations/forgewire-fabric/main/install-fabric.ps1 | iex
```

Installs rqlite, Raft nodes, `forgewire-hub`, `forgewire-runner`, and the VS Code extension as NSSM services in a single pass. No Python required at runtime.

## Smoke test

```bash
# Python compatibility smoke path
pip install forgewire-fabric
forgewire-fabric token gen > hub.token
export FORGEWIRE_HUB_TOKEN=$(cat hub.token)

# Terminal 1: hub
forgewire-fabric hub start --host 127.0.0.1 --port 8765

# Terminal 2: runner
forgewire-fabric runner start --workspace-root /path/to/repo

# Terminal 3: dispatch + observe
forgewire-fabric dispatch "pytest -q" --scope "tests/**"
forgewire-fabric tasks list
forgewire-fabric tasks stream <task-id>
```

---

## Operator control plane (M2.5 — active)

Phase 2.5 ships the operator moat against Devin / Copilot Workspace / Cline / Aider. All controls run on the operator's own hub — nothing phones home.

### Policy gates (M2.5.1 ✅)

Every state transition runs through a structured `PolicyDecision`. Configure `policy.yaml` at the repo root:

```yaml
protected_branches: [main, "release/*"]
forbidden_paths: [".github/workflows/**", "secrets/**"]
max_diff_lines: 2000
require_approval: [merge, push, network_egress]
egress_allowlist: ["pypi.org", "github.com", "api.anthropic.com"]
```

Three gate points:
- **`dispatch_task`** — scope/branch/forbidden-path checks before a task enters the queue
- **`POST /tasks/{id}/intent`** — runner calls this before gated actions (`fs_write`, `network_egress`, `shell_exec`, `destructive_fs`, `merge`, `push`); hub returns 200/403/428
- **`submit_result`** — completion-time diff-line and path checks

Approval inbox:
```bash
forgewire-fabric approvals list
forgewire-fabric approvals approve <id>
forgewire-fabric approvals deny <id> --reason "out of scope"
forgewire-fabric approvals watch          # tail mode
```

Notifications: `--approval-ntfy` (mobile push), `--approval-slack` (incoming webhook), `--approval-webhook` (generic JSON POST).

### Cost ledger + hard budgets (M2.5.2 ✅)

Per-task and period spend caps enforced at dispatch time:

```yaml
# policy.yaml
daily_budget_usd: 5.00
weekly_budget_usd: 25.00
weekly_alert_threshold: 0.8
```

Per-brief cap on the dispatch:
```bash
forgewire-fabric dispatch "refactor auth" --scope "src/**" --max-cost 0.50
```

Runners report actuals at completion (model, tokens, cost, wall time). Hub persists to `cost_ledger` (rqlite) and enforces caps at next dispatch.

```bash
forgewire-fabric cost summary --since 7d --by model
forgewire-fabric cost export --since 30d --format csv > spend.csv
forgewire-fabric cost burndown --weeks 8
forgewire-fabric cost budget                            # daily + weekly vs caps
```

---

## Rust-first runtime (M2.7 ✅ — shipped 2026-06-03)

Hub and runner are native Rust daemons. Python is an optional integration surface (MCP adapters, CLI, migration tooling), never the deployed daemon.

| Component | Version | Notes |
|---|---|---|
| `forgewire-hub` | 0.7.0 | axum, rqlite backend, Protocol v3 |
| `forgewire-runner` | 0.7.0 | FW\_INTENT interception, bounded stream buffers |
| Python package | 0.16.0 | CLI, MCP adapters, parity bridge |
| VS Code extension | 0.4.0 | Hub badge, runner tree, approval inbox |
| Protocol | v3 | Stable wire format — v2 parity preserved |

Deployment: both cluster nodes (DESKTOP-38GVF8D + DESKTOP-228U8GL) running 0.7.0, backend=rqlite, NSSM-supervised.

---

## VS Code and agent workflows

```bash
cd vscode && npm install && npm run package
code --install-extension forgewire-*.vsix
```

MCP setup:
```bash
forgewire-fabric mcp install --hub-url http://127.0.0.1:8765
forgewire-fabric mcp install --hub-url http://127.0.0.1:8765 --with-runner --workspace-root /path/to/repo
```

See [vscode/README.md](vscode/README.md) for extension commands and settings.

---

## Stable today

- Authenticated hub/runner dispatch (bearer + ed25519 signed envelopes, nonce replay rejection)
- Protocol v3 — structured capabilities, tenant/workspace, egress, cost caps, approval, sandbox in signed payload
- Scope/capability-aware claim routing with structured rejection diagnostics
- Structured stream events, persisted terminal results, hash-chained audit log
- Runner identity persistence, trust registration, FW\_INTENT gate interception
- **Policy gate**: dispatch/intent/completion enforcement against `policy.yaml`; approval inbox with ntfy.sh + Slack + webhook transports
- **Cost ledger**: per-task and daily/weekly budget caps; rqlite persistence; `cost summary|export|burndown|budget` CLI
- Bounded stream buffers (`strict`/`balanced`/`throughput` durability profiles)
- Windows OOTB service install (NSSM + rqlite + watchdog), one-command installer
- Core CLI: `tasks`, `runners`, `audit`, `approvals`, `cost`, `secrets`, `dispatchers`, `setup`, `identity`, `doctor`

## In active development (Phase 2.5)

- **M2.5.3** Append-only hash-chained audit export + `forgewire-fabric replay <task_id>`
- **M2.5.4** Structured capability tags + cheapest-fit dispatch routing
- **M2.5.5** Egress allowlist enforcement + sealed secret broker (per-task env injection)
- **M2.5.6** Hub HA (active-passive + active-active) + role-separated identity tokens
- **M2.5.7** Task provenance + HTMX dashboard (8 read pages, one-click replay)
- **M2.5.8** VS Code agent suite (4 chatmodes + 7 skills) + 15-page user guide + Marketplace publish at v0.5
- **M2.5.9** Unified settings store + `forgewire-fabric doctor`
- **M2.5.10** Self-upgrading fabric (`forgewire-fabric upgrade` distributes binaries via runner channel)

## Planned (Phase 3+)

- Noise\_IK over QUIC federated transport
- Capability anycast (`forgewire://capability/<expr>` URIs)
- Kernel-level scope-bound egress (eBPF / WFP)
- External witness co-signing + Sigstore Rekor audit anchoring
- Tauri GUI, Kubernetes operator, distributed Blackboard transport

---

## Project lineage

ForgeWire Fabric began as the remote dispatch layer inside the larger ForgeWire/PhrenForge platform. It was extracted into a standalone project so developers can use the remote runner fabric independently while still allowing the parent platform to integrate via the hub HTTP API.

The canonical implementation lives in the `forgewire-fabric/` subtree of the ForgeWire repository. This repository is a reviewed synchronization mirror.

## Additional documentation

- [docs/QUICKSTART.md](docs/QUICKSTART.md)
- [docs/POSITIONING.md](docs/POSITIONING.md)
- [docs/protocol-v3-spec.md](docs/protocol-v3-spec.md)
- [policy.yaml](policy.yaml) — annotated policy schema reference
