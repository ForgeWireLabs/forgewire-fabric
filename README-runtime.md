# forgewire-runtime — Rust workspace

Native Rust hub and runner substrate for ForgeWire Fabric. As of M2.7 (2026-06-02)
the Rust binaries are the **normal deployed runtime**. Python remains available as a
reference oracle and fallback during the migration window.

## Deployed binaries (Tier 1 — Windows x64)

| Binary | Service name | Default port | Notes |
|--------|-------------|--------------|-------|
| `forgewire-hub` | `ForgeWireHub` | 8765 | rqlite backend, loopback default |
| `forgewire-runner` | `ForgeWireRunner` | — | polls hub, claims tasks |
| `forgewire-fabric-cli` | — | — | operator CLI: health, doctor, audit, identity |

Binaries live at `C:\ProgramData\forgewire\bin\` on installed hosts.

## Crates

| Crate | Responsibility | Status |
|-------|---------------|--------|
| `fabric-types` | Shared domain types (TaskStatus, StreamChannel, SignedDispatchV2, …) | ✅ |
| `fabric-protocol` | Canonical JSON + Ed25519 sign/verify, v2 envelopes | ✅ |
| `fabric-identity` | Durable dispatcher/runner/node identities, key load/gen/save | ✅ |
| `fabric-audit` | Hash-chained audit log, GENESIS hash, expected-tail CAS, chain verify | ✅ |
| `fabric-policy` | Allow/deny/require-approval evaluation, budget enforcement | ✅ |
| `fabric-store` | Store trait definitions (TaskStore, StreamStore, AuditStore, …) | ✅ |
| `fabric-store-sqlite` | SQLite backend (unit tests / single-node fallback) | ✅ |
| `fabric-store-rqlite` | rqlite HA backend, leader redirect, quorum-loss detection | ✅ |
| `fabric-claim-router` | Capability-aware task routing, structured rejection diagnostics | ✅ |
| `fabric-streams` | Per-task seq counter + bounded write buffer + named durability profiles | ✅ |
| `fabric-client` | Typed hub HTTP client (reqwest, retry, backoff) | ✅ |
| `fabric-runner` | Native runner daemon: register, heartbeat, claim, subprocess, streams | ✅ |
| `fabric-hub` | Native hub daemon: axum, auth, routes, health, graceful shutdown | ✅ |
| `fabric-cli` | Operator CLI: version, health, identity, audit, doctor | ✅ |
| `fabric-py` | PyO3 bindings, Python identity compat shim (migration window) | ✅ |

## Build

```powershell
cd forgewire-fabric
cargo build --release
# Outputs: target\release\{forgewire-hub.exe, forgewire-runner.exe, forgewire-fabric-cli.exe}
```

## Key environment variables (hub)

| Variable | Default | Purpose |
|----------|---------|---------|
| `FORGEWIRE_HUB_HOST` | `127.0.0.1` | Bind address |
| `FORGEWIRE_HUB_PORT` | `8765` | Bind port |
| `FORGEWIRE_HUB_TOKEN_FILE` | `C:\ProgramData\forgewire\hub.token` | Bearer token path |
| `FORGEWIRE_HUB_RQLITE_HOST` | `127.0.0.1` | rqlite host |
| `FORGEWIRE_HUB_RQLITE_PORT` | `4001` | rqlite port |
| `FORGEWIRE_HUB_RQLITE_CONSISTENCY` | `strong` | `none`\|`weak`\|`strong` |
| `FORGEWIRE_HUB_STREAM_PROFILE` | `strict` | `strict`\|`balanced`\|`throughput` — stream write buffer durability |

### Stream durability profiles

| Profile | Flush after N lines | Loss window on hard kill | Use case |
|---------|--------------------|--------------------------| ---------|
| `strict` | 1 (write-through) | none | Default — strongest guarantee |
| `balanced` | 50 | up to 50 lines | High-volume output, graceful shutdown force-flushes |
| `throughput` | 200 | up to 200 lines | Maximum throughput — operator opt-in only |

`submit_result` always force-flushes the buffer before writing terminal state, regardless of profile.

## Remote deploy (Precision → OptiPlex)

From FORGEWIRE-BUILD, the SSH host alias `forgewire` (key `~/.ssh/id_ed25519_forgewire`,
user `jerem`, host `192.0.2.10`) gives access to the hub host.

```powershell
# 1. Build
cd C:\Projects\forgewire\forgewire-fabric
cargo build --release -p fabric-hub   # or -p fabric-runner / --release for all

# 2. Stage the binary (avoids locked-file errors on the running service)
scp target\release\forgewire-hub.exe forgewire:"C:/ProgramData/forgewire/bin/forgewire-hub-new.exe"

# 3. Stop, swap, restart, verify
ssh forgewire "powershell -Command `"
  nssm stop ForgeWireHub;
  Move-Item 'C:\ProgramData\forgewire\bin\forgewire-hub.exe' 'C:\ProgramData\forgewire\bin\forgewire-hub.bak.exe' -Force;
  Move-Item 'C:\ProgramData\forgewire\bin\forgewire-hub-new.exe' 'C:\ProgramData\forgewire\bin\forgewire-hub.exe' -Force;
  nssm start ForgeWireHub;
  Start-Sleep 3;
  Invoke-RestMethod http://127.0.0.1:8765/healthz | ConvertTo-Json
`""

# Runner (same pattern, service name ForgeWireRunner)
scp target\release\forgewire-runner.exe forgewire:"C:/ProgramData/forgewire/bin/forgewire-runner-new.exe"
ssh forgewire "powershell -Command `"
  nssm stop ForgeWireRunner;
  Move-Item 'C:\ProgramData\forgewire\bin\forgewire-runner.exe' 'C:\ProgramData\forgewire\bin\forgewire-runner.bak.exe' -Force;
  Move-Item 'C:\ProgramData\forgewire\bin\forgewire-runner-new.exe' 'C:\ProgramData\forgewire\bin\forgewire-runner.exe' -Force;
  nssm start ForgeWireRunner
`""
```

The `.bak.exe` copy is the previous binary — roll back by reversing the swap.

## Rollback

```powershell
ssh forgewire "powershell -Command `"
  nssm stop ForgeWireHub;
  Move-Item 'C:\ProgramData\forgewire\bin\forgewire-hub.bak.exe' 'C:\ProgramData\forgewire\bin\forgewire-hub.exe' -Force;
  nssm start ForgeWireHub
`""
```

## License

Apache-2.0.

