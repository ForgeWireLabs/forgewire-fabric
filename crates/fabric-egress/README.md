# fabric-egress

Per-task userspace egress enforcement for ForgeWire runners: a local proxy that allows or denies outbound network requests from a running task against its egress policy.

## What's here

- `EgressProxy` — the local proxy a runner routes a task's outbound traffic through.
- `EgressPolicy` — the allowlist a proxy instance enforces.
- `EgressDenial` — a structured record of a blocked request (host, reason), suitable for audit.
- `EgressError` — proxy setup/runtime failures.

## License

Apache-2.0
