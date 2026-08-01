---
description: Select the cheapest capable Fabric agent path within an explicit budget and dispatch it.
mode: agent
tools: ['forgewire-fabric/list_agents', 'forgewire-fabric/dispatch_skill', 'forgewire-fabric/dispatch_tool', 'forgewire-fabric/dispatch_prompt', 'forgewire-fabric/stream_progress', 'forgewire-fabric/await_result', 'forgewire-fabric/get_task']
---

# Dispatch cost-aware work

Classify task complexity and required MCP capability before considering model
cost. Use advertised agent manifests to form the capable set, then select the
lowest-cost acceptable route using the operator-provided budget evidence.
Include an explicit cost ceiling and stop condition in the brief. Never invent
prices, capability, or remaining budget; if evidence is unavailable, state
that and ask the operator to use the VSIX Cost pane before dispatch.

Use Fabric typed intent. Do not substitute Loom host execution to evade budget
or policy gates.
