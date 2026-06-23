# Phase 2.8 — Frozen Spec for Fixtures

> **Status:** locked at M2.8.0 (2026-06-08). Subsequent milestones (M2.8.1+) implement against this contract.
> **Phase doc:** [`todos/114-forgewire-fabric/phase-2.8-loom-fabric-surface-split.md`](../../../../work/active/114-forgewire-fabric/README.md)

These fixtures are the byte-exact contract that the Rust + Python implementations must round-trip through. Any change to the JSON shapes here must be a deliberate, versioned spec amendment, not a side effect of code changes.

## Field name lock

### Runner registration adds (additive over v3 envelope)

| Field | Type | Required | Notes |
|---|---|---|---|
| `kinds` | array of `"agent" \| "command"` | yes for v4-aware runners | Backfilled to `["agent"]` for missing-key legacy registrations. |
| `agent_type` | string \| null | yes | NULL when `kinds == ["command"]`. Free-form (`claude-code`, `vscode-copilot`, `forgewire-orchestrator`, `hermes`, `open-claw`, ...). |
| `mcp_manifest` | object \| null | yes for agent kind | NULL when `kinds == ["command"]`. Schema below. |

### `mcp_manifest` shape

```
{
  "schema_version": 1,
  "servers": [
    {
      "server_id": <string>,
      "tools":     [{ "name": <string>, "description": <string>, "input_schema": <json> }, ...],
      "resources": [{ "uri": <string>, "name": <string>, "mime_type": <string> }, ...],
      "prompts":   [{ "name": <string>, "description": <string>, "arguments": <array> }, ...]
    },
    ...
  ]
}
```

Any of `tools` / `resources` / `prompts` may be empty arrays; a server entry MUST contain at least one of the three keys. `server_id` is unique within a single manifest.

### Task brief discriminators (additive over the existing brief)

| Field | Type | Notes |
|---|---|---|
| `kind` | `"agent" \| "command"` | First-class task routing. Missing key → backfill `"agent"` with `legacy_dispatch_shape` audit event (M2.8.2). Hard 400 after M2.8.9. |
| `dispatch` | `"skill" \| "tool" \| "prompt" \| null` | NULL when `kind == "command"`. Required when `kind == "agent"` for v4-aware dispatchers; missing → backfill `"prompt"`. |

Command briefs add:
- `command` — array of argv strings (REQUIRED).
- `cwd` — string \| null.
- `env` — object<string,string> \| {}.
- `stdin` — string \| null.
- `timeout_seconds` — integer.
- `streaming` — bool.
- `target.host_alias` / `target.host_id` / `target.required_tools` / `target.tenant`.

Agent skill briefs add:
- `skill` — string (name of an advertised prompt).
- `args` — object (per the advertised prompt's argument schema).
- `context.repo` / `context.base_commit` / `context.branch` / `context.scope_globs`.
- `target.agent_type` / `target.runner_id` / `target.required_tools` / `target.required_resources` / `target.tenant`.

Agent tool briefs add:
- `tool` — string (name of an advertised tool).
- `input` — object (per the advertised tool's input schema).
- `context` + `target` as above.

Agent prompt briefs add:
- `title` — string.
- `prompt` — string.
- `context` + `target` as above.

## Normalization rules

### `runner_capabilities` projection

Given a registration with `runner_id = R` and `mcp_manifest = M`, the normalized `runner_capabilities` rows for `R` are the union over each `server` in `M.servers` of:

```
for tool in server.tools:
    row(R, kind="tool",     name=tool.name,    source_server=server.server_id,
        description=tool.description, extra={ "input_schema": tool.input_schema })
for resource in server.resources:
    row(R, kind="resource", name=resource.uri, source_server=server.server_id,
        description=resource.name, extra={ "mime_type": resource.mime_type })
for prompt in server.prompts:
    row(R, kind="prompt",   name=prompt.name,  source_server=server.server_id,
        description=prompt.description, extra={ "arguments": prompt.arguments })
```

Conflict resolution within a single manifest (two servers advertising the same `(kind, name)`): keep the **first occurrence** in `servers[]` order. The capability index is `(runner_id, capability_kind, name)` unique, so the second loses with a deterministic tiebreak (no error, no surprise — see `capability_index.json` test case `multi_server_collision`).

### Cross-runner ambiguity

When multiple runners advertise the same `(kind, name)`, the capability router returns the multi-match set and applies M2.5.4 capability-fit + load-tiebreak. `target.runner_id` pin always wins. See `routing_decisions.json` for the exact decision matrix.

## Backfill (schema v3 → v4)

Applied once at hub boot via `run_additive_migrations` + a one-shot backfill query:

| Existing state | New value |
|---|---|
| `runners.tags` contains `kind:command` | `runners.kinds = ["command"]`, `runners.agent_type = NULL`, `runners.mcp_manifest = NULL` |
| `runners.tags` contains `kind:agent` (or no `kind:*` tag at all) | `runners.kinds = ["agent"]`, `runners.agent_type = NULL`, `runners.mcp_manifest = NULL` |
| `tasks.kind == 'command'` | `tasks.dispatch = NULL` (Loom briefs have no dispatch discriminator) |
| `tasks.kind == 'agent'` | `tasks.dispatch = 'prompt'` (existing behavior was prompt-only) |
| `runners.mcp_manifest_version` | `0` for backfilled rows; bumps to `1` on first v4-aware registration that carries a manifest. |

After backfill, the `kind:*` tag is **no longer authoritative**. The `runners.tags` array stays as-is (operators may continue to use opaque routing tags), but `runners.kinds` is the only column the queue-split routing consults.

## Audit-chain compat

Adding `kinds` / `agent_type` / `mcp_manifest` to a registration envelope and `dispatch` to a task brief MUST not change the hash of an existing v3 envelope. The canonical-JSON hash function (`fabric-protocol::canonical_json`) sorts keys alphabetically; a v3 envelope without the new keys hashes identically before and after schema v4 lands. The cross-language fixture `audit_compat.json` (Python side, alongside the existing `tests/fixtures/audit/`) verifies this.
