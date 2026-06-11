# Threat Model — Phase 2.9 Loom Integrity Parity

> **Status**: Ratified 2026-06-10. This document is the security spec for the
> Loom command surface. It supplements the phase doc at
> `forgewire/todos/114-forgewire-fabric/phase-2.9-loom-integrity-parity.md`.

---

## Scope

This model covers the **Loom command surface** (`kind = "command"` dispatch)
introduced in Phase 2.8. The Fabric agent surface (`kind = "agent"`) is
unchanged from Phase 2.7; its trust properties are not re-analyzed here.

Out of scope: per-task ephemeral keys (Phase 3), kernel-level egress enforcement
(Phase 4), multi-hub federation (Phase 3).

---

## Trust Principals

| Principal | Trust Level | Credentials |
|---|---|---|
| **Dispatcher** | Outer trust boundary | Ed25519 keypair (registered via `/dispatchers/register`) |
| **Hub** | Cluster authority | Bearer token; rqlite store; owns policy evaluation |
| **Runner** | Execution agent | Ed25519 keypair (registered via `/runners/v2`); trusts hub outputs fully |
| **Operator** | Human admin | Approves held tasks; authors `policy.yaml` |

Runners do **not** re-verify the dispatcher signature on claimed tasks — they
trust the hub. This is intentional (Phase 3 adds per-task capability tokens if
per-runner verification is needed). The hub's job is therefore to be the sole
admission gate.

---

## Trust Chain

```
Dispatcher signs command brief
  → Hub verifies signature (covers command/cwd/env-digest)
    → Hub evaluates dispatch policy (forbidden-path, scope, approval-hold)
      → Hub stores task
        → Runner claims task (trusts hub)
          → Runner calls intent gate (shell_exec) before spawn
            → Runner spawns in clean env (allowlist + brief env only)
              → Output streamed back; secrets redacted
```

Break any link → the command either never runs or the audit chain captures the
failure. The signature's two jobs: **(1) dispatcher attribution** in the audit
chain; **(2) tamper-evidence** — a bearer holder cannot substitute argv
post-signing without breaking the signature check.

---

## Attacker Scenarios and Controls

### A1: Bearer-holder substitutes `command` after signing

**Scenario**: An attacker holds the cluster bearer token and intercepts or
replays a task dispatch, swapping `command` or `cwd` for a different payload
while keeping the dispatcher signature unchanged.

**Control**: The dispatcher signature covers `loom_command`, `loom_cwd`,
`loom_env_keys`, and `loom_env_digest` (M2.9.1 / F1). A mismatch between the
signed envelope and the stored brief causes a `403` at dispatch; the runner also
recomputes the env digest before spawn as defense-in-depth.

**Residual risk**: Bearer compromise still allows creation of new tasks, but
cannot create tasks that *appear* signed by a legitimate dispatcher.

### A2: Forged-author stdin injection

**Scenario**: An attacker posts a task note with `author: "dispatcher:stdin"` to
inject bytes into a running process's stdin.

**Control**: Stdin is now delivered via `POST /tasks/{id}/input` with a
dispatcher Ed25519 signature (M2.9.4 / F4). The route verifies the signature,
enforces `dispatcher_id == task.dispatcher_id`, rejects terminal tasks, and
consumes the nonce. The old note-transport path is removed.

**Residual risk**: A dispatcher with a valid keypair can still inject stdin into
their own task — this is intended behavior.

### A3: Service-env secret exfiltration via `env` dump

**Scenario**: A task sends `command: ["printenv"]` or `command: ["env"]` to
extract the runner service's ambient environment, which on an NSSM host includes
`FORGEWIRE_HUB_TOKEN`, SSH key paths, and secret-broker material.

**Control**: The Rust `loom-runner` (and Python parity reference) performs
`.env_clear()` before spawn and builds the process env from an explicit allowlist
(`PATH`, `HOME`, `USERPROFILE`, `SYSTEMROOT`, `SYSTEMDRIVE`, `TEMP`, `TMP`,
`TMPDIR`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `COMPUTERNAME`, `USERNAME`) plus
the brief's `loom_env` map (M2.9.3 / F3). Service-env variables are never
inherited.

**Residual risk**: Variables in the allowlist are inherited. Operators requiring
tighter isolation must run loom-runner as a restricted service account.

### A4: Scope escape via `cwd` outside allowed prefixes

**Scenario**: A dispatcher signs a command brief with `cwd: "C:/Windows/System32"`,
targeting a path outside their allowed scope.

**Control**: The hub's dispatch gate (M2.9.2 / F2) evaluates `cwd` against
`forbidden_paths` and `scope_prefixes` before the task is queued; the runner
also checks `cwd` containment before spawn (belt-and-suspenders). Out-of-scope
`cwd` → `dispatch_denied` audit event + `403`.

### A5: Approval hold bypass — task queued before approval

**Scenario**: A `shell_exec`-gated Loom brief skips the approval inbox and
enters `queued` status.

**Control**: The dispatch gate evaluates `require_approval` actions before
`create_task`. On `needs_approval`, the hub creates an approval record, sets
task status to `held`, and returns `202 { status: "held", approval_id: ... }`.
The claim path does not surface `held` tasks — only `queued` tasks are
claimable (M2.9.2 / F2 + follow-up held→inbox fix).

### A6: Replay of a previously-dispatched signed command

**Scenario**: An attacker replays an old signed command brief verbatim.

**Control**: Dispatch nonces are consumed on first use via `consume_dispatcher_nonce`
(stored in the rqlite `dispatcher_nonces` table with a TTL). A replay of the
same `(dispatcher_id, nonce)` pair returns `403` with reason `nonce_already_used`.
Signed stdin nonces are similarly consumed (M2.9.4 / fix-up #3).

### A7: Policy gates constructed but never called on the Rust hub

**Scenario**: A `DispatchGate` is wired into `HubState` but has zero call sites;
all policy evaluation is silently skipped.

**Status (as of M2.9.2)**: Resolved. `evaluate_dispatch` is called in
`dispatch_task_signed` for all kinds, verified by `grep evaluate_dispatch
crates/fabric-hub/src/routes/`. The absence of call sites was the original F2
defect; Hard Rule 17 ("No queue without admission") prevents regression.

---

## Audit Chain Coverage

A Loom task's `dispatch` audit event records:

```json
{
  "task_id": <int>,
  "title": "<string>",
  "base_commit": "<hash>",
  "branch": "<string>",
  "scope_globs": [...],
  "signed": true,
  "dispatcher_id": "<uuid>",
  "loom_command": [...],
  "loom_cwd": "<string>",
  "loom_env_keys": [...]
}
```

Env *values* are excluded (they may carry secrets); `loom_env_keys` records
which variables were set. Replay of a Loom task from the audit chain can
reconstruct exactly what was asked to run. (F5, M2.9.1)

---

## Non-Goals

- **Per-task ephemeral keys / capability tokens** — Phase 3 M3.1. The runner
  trusts the hub; this model scopes to hub-enforced guarantees only.
- **Kernel-level egress enforcement** (eBPF / Windows Firewall rules per task) —
  Phase 4 M4.2. This phase provides `forbidden_paths` + clean-env + scope
  containment.
- **Multi-hub federation** or cross-cluster trust — Phase 3 M3.4.
- **Federated dispatcher identity** — the dispatcher keypair is cluster-local.

---

## Hard Rules Introduced by This Phase

| # | Rule |
|---|---|
| 16 | Executable bytes are signed bytes. |
| 17 | No task reaches `queued` without passing the dispatch policy gate on the deployed Rust hub. |
| 18 | Loom runners spawn in a clean environment; no service-env inheritance. |
| 19 | State-changing input (stdin, cancel) is signed by dispatcher Ed25519. |
| 20 | A command task's dispatch audit event records `command`, `cwd`, and `env_keys`. |

---

## References

- Phase doc (defect ledger, milestones): `forgewire/todos/114-forgewire-fabric/phase-2.9-loom-integrity-parity.md`
- Frozen surface: `forgewire-fabric/AGENTS.md §3`
- Thesis (binding properties): `forgewire/docs/thesis.md`
- Cross-language fixtures: `forgewire-fabric/tests/fixtures/phase_2_9/`
