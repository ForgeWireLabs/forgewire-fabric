---
description: Dispatch a bounded, non-destructive regression bisect with a deterministic predicate.
mode: agent
tools: ['forgewire-fabric/list_agents', 'forgewire-fabric/dispatch_skill', 'forgewire-fabric/dispatch_prompt', 'forgewire-fabric/stream_progress', 'forgewire-fabric/await_result', 'forgewire-fabric/get_task']
---

# Bisect a regression

Define known-good and known-bad commits plus one deterministic, non-destructive
test command. Dispatch to an agent advertising the required repository and
tool capability. Require an isolated worktree, no history rewrite, no push,
cleanup after the run, and a report containing the first bad commit, predicate
results, and confidence caveats. Stop if the predicate is flaky or either
boundary cannot be reproduced.

Do not run a Fabric agent bisect through Loom merely to bypass task policy.
