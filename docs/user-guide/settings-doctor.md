# Unified settings and doctor

Fabric settings resolve in deterministic order:

1. immutable compiled defaults;
2. hub-wide rqlite overlay;
3. repo/task policy overlay.

The JSON Schema rejects unknown keys, wrong types, invalid enums, out-of-range
values, duplicate array entries, and writes to derived read-only fields.
Sensitive fields such as the history DSN and secret key-file path are redacted
from snapshots and diffs.

## CLI

Use:

```text
forgewire-fabric-cli settings list
forgewire-fabric-cli settings schema
forgewire-fabric-cli settings set KEY JSON --expected-revision N
forgewire-fabric-cli settings reset KEY --expected-revision N
```

Mutations use revision compare-and-swap and reviewer authority. The hub audits
redacted changes. Desktop and VSIX read the same effective snapshot.

## Doctor

`forgewire-fabric-cli doctor --json` emits
`forgewire.fabric.doctor.v1`. Exit 0 is healthy, 2 is degraded/warnings, and 1
is failure. Checks cover rqlite readiness/leader/suffrage, hub protocol and
queues, capabilities, hosts/agents, token and identities, settings, history
mode, audit tail, TLS posture, clock drift, binaries, and free disk.

Thin history is informational. A configured but unreachable history sink is a
failure because the operator explicitly requested it.

