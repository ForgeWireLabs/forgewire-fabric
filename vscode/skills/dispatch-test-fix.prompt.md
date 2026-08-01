---
description: Build and dispatch a bounded failing-test repair brief to a capable Fabric agent.
mode: agent
tools: ['forgewire-fabric/list_agents', 'forgewire-fabric/dispatch_skill', 'forgewire-fabric/dispatch_prompt', 'forgewire-fabric/stream_progress', 'forgewire-fabric/await_result', 'forgewire-fabric/get_task']
---

# Dispatch a test fix

Collect the exact failing command and error, identify the narrowest writable
source and test globs, and query advertised agent capabilities. Prefer
`dispatch_skill` for an advertised test-fix prompt; otherwise use
`dispatch_prompt`. The sealed brief must reproduce first, preserve unrelated
work, fix root cause, run the focused test and its nearest suite, and report
exact results. Monitor to terminal state and review the returned diff evidence.

Do not use Loom for an agent repair and do not include credentials or secret
values in the brief.
