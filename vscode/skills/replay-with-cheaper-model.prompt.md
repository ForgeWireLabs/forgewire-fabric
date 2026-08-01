---
description: Prepare a governed cheaper-model replay plan and compare evidence without silently executing it.
mode: agent
tools: ['forgewire-fabric/get_task', 'forgewire-fabric/read_stream', 'forgewire-fabric/read_notes', 'codebase', 'search', 'searchResults']
---

# Plan a cheaper-model replay

Inspect the original task, result, cost evidence supplied by the operator, and
scope. Produce the exact governed replay plan, cheaper model choice, unchanged
inputs, acceptance comparison, budget ceiling, and stop conditions. Do not
execute the replay: the current Fabric/Loom MCP pair has no replay tool. Hand
the plan to the operator's audited replay CLI/client path and compare the
result only after that evidence is returned.

Never reconstruct missing secret values or move the replay to Loom.
