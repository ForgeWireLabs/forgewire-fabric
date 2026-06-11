# Skills are MCP prompts (Phase 2.8 audit)

Phase 2.8 removed skills (and personas/tools) as opaque routing **tags** and
made them first-class **MCP capabilities**. This file is the M2.8.8 audit of
that reframing for the packaged Phase 2.5.8 skill bundle.

## The model

A Fabric runner *is* an agent. On registration and on every heartbeat where the
connected-server topology changes, it introspects its local MCP servers and
sends a manifest to the hub:

```json
{
  "schema_version": 1,
  "servers": [
    {
      "server_id": "claude-skills",
      "prompts": [
        { "name": "code-review", "description": "...", "arguments": [{ "name": "effort", "required": false }] },
        { "name": "debug",       "description": "...", "arguments": [] }
      ]
    }
  ]
}
```

- **A skill is an MCP prompt** advertised at `mcp_manifest.servers[*].prompts[*]`.
- The hub normalizes every prompt into `runner_capabilities` with
  `capability_kind = 'prompt'`, so `dispatch_skill <name>` routes to any agent
  advertising that prompt (capability-aware routing, hard rule #14).
- **Adding a skill = adding a prompt to one of the agent's MCP servers** (e.g.
  the agent's `.claude/skills/` directory or a VS Code MCP server). The hub
  auto-discovers it on the next heartbeat. The hub never defines skills
  (hard rule #13).

## Audit results

| Check | Result |
| --- | --- |
| Manifest carries prompts as skills | ✅ `runner/mcp_introspection.py::build_mcp_manifest` emits `prompts: [{name, description, arguments:[{name, description, required}]}]`. |
| No `skill:*` capability tags emitted by the runner | ✅ `apply_kind_tag` removed in M2.8.3; no `skill:` / `persona:` / `tool:` capability-tag emission remains in `forgewire_fabric/` (only unrelated title/error strings). `FORGEWIRE_RUNNER_TAGS` survives as *opaque routing tags only*, not capability advertisement. |
| Hub indexes prompts for routing | ✅ `runner_capabilities (capability_kind='prompt')`; `query_runners_by_capability` + `GET /capabilities/prompt/{name}`. |
| Dispatcher validates the skill before queuing | ✅ `hub/fabric_mcp.py::dispatch_skill` checks `/capabilities/prompt/{name}` and surfaces `no_runner_advertises_capability`. |
| Skills are visible to operators | ✅ VS Code **Agents** pane (M2.8.8) renders each agent → MCP server → **Skills** (prompts) / Tools / Resources, read from `GET /agents`. |

## For bundle authors

The Phase 2.5.8 packaged skills are no longer shipped as a tag list. To make a
skill available on an agent:

1. Expose it as an MCP **prompt** on one of that agent's connected MCP servers
   (for a Claude Code agent runner, drop it in `.claude/skills/`).
2. Restart or let the runner heartbeat — `build_mcp_manifest` picks it up and
   the hub indexes it.
3. Confirm it appears under the agent in the VS Code **Agents** pane, or query
   `GET /capabilities/prompt/<skill-name>`.

No hub-side change, no manifest editing, no tag wiring.
