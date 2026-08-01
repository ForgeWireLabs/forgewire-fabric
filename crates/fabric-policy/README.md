# fabric-policy

Deterministic dispatch and completion policy evaluation for ForgeWire Fabric: forbidden paths, protected branches, diff-size caps, egress allowlists, and budget enforcement.

## What's here

- `FabricPolicy` — the declarative policy document (forbidden paths, protected branches, `max_diff_lines`, egress allowlist, approval-required operation kinds).
- `PolicyEngine` — evaluates a `DispatchRequest`/`CompletionRequest` against a `FabricPolicy`, returning a `PolicyDecision` with named violated rules.
- `BudgetPolicy`, `BudgetEnforcer` — daily/weekly cost-cap enforcement, evaluated alongside path/branch/egress policy.
- `PolicyError` — malformed policy documents or evaluation failures.

## License

Apache-2.0
