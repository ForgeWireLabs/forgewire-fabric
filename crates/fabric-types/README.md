# forgewire-fabric-types

Shared domain types for ForgeWire Fabric — no HTTP or database coupling.

Published as `forgewire-fabric-types` (the short name `fabric-types` collides with an unrelated crate already on crates.io); internal consumers keep importing this as `fabric_types` via a package-rename alias.

## What's here

- `TaskStatus`, `TaskKind`, `StreamChannel`, `AuditKind` — the enums every hub/runner/client crate agrees on for task state and stream framing.
- `SignedDispatchV2` — the frozen v2 signed-dispatch envelope shape.
- `KeyPurpose` — dispatcher/runner/hub/node key-role tagging (see `fabric-identity`).
- `check_timestamp_skew()` — the ±300s signature timestamp window every signed-request path in Fabric enforces identically.

## License

Apache-2.0
