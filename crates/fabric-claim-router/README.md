# fabric-claim-router

Capability-aware task selection for ForgeWire Fabric: matches queued tasks to eligible runners by required capability and scope.

## What's here

- `CandidateTask`, `RunnerView` — the minimal task/runner shape the router needs.
- `matches(task, runner)` — whether a single task is eligible for a single runner.
- `pick_task(tasks, runner)` — selects the best-priority eligible task for a runner from a queue.
- `scopes_within()` / `glob_static_prefix()` — glob-scope containment checks used to enforce that a runner only claims tasks within its granted path scope.

## License

Apache-2.0
