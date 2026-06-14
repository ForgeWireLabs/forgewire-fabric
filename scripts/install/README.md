# ForgeWire Fabric — install / uninstall

Scripts to stand up (or tear down) a ForgeWire node. Every node runs rqlite (a
Raft member), a Rust hub, a Rust runner, and liveness watchdogs; the first node
also bootstraps the hub. Clients/peers discover hubs over the LAN, so the
cluster survives DHCP lease changes.

## Requirements

- **PowerShell 7 (`pwsh`)** — `install-fabric.ps1` uses PS7 language features and
  declares `#Requires -Version 7.0`. Run it with `pwsh`, **not** the built-in
  Windows PowerShell 5.1 `powershell` (under 5.1 you get a clear "requires
  version 7.0" message instead of cryptic parse errors). Install with:
  `winget install Microsoft.PowerShell`. (`uninstall-fabric.ps1` runs under
  either edition.)
- **nssm** on `PATH` — `winget install nssm.nssm`.
- **Rust daemon binaries** in `<FabricRoot>\target\release\` (or pre-placed in
  `BinDir`): `forgewire-hub.exe`, `forgewire-runner.exe`,
  `forgewire-fabric-cli.exe`. Build with
  `cargo build --release -p fabric-hub -p fabric-runner -p fabric-cli`.
- Admin rights — both scripts self-elevate via UAC.

## Quick start

First node (bootstraps the hub + rqlite, generates the cluster token):

```powershell
pwsh -File install-fabric.ps1 -WorkspaceRoot C:\Projects\forgewire -ForceHub
```

It prints the bearer token. Copy it to each joining node:

```powershell
pwsh -File install-fabric.ps1 -WorkspaceRoot C:\Projects\forgewire `
    -Token "<token-from-hub>" `
    -HubUrl "http://<hub-hostname>:8765" `
    -RqliteJoinAddr "<hub-hostname>:4002"
```

The token is the sole cluster-admission gate — treat it like an SSH key.

## Verify

```powershell
# Each hub (every node runs one against its local rqlite):
(Invoke-RestMethod http://127.0.0.1:8765/healthz).package_version    # daemon version
# Raft membership (should list every node):
(Invoke-RestMethod http://127.0.0.1:4001/status).store.nodes.id
```

Two nodes give replication + read-failover; three give automatic write-failover
(Raft needs a quorum majority).

## Teardown

```powershell
pwsh -File uninstall-fabric.ps1 -Yes -NoBackup     # full wipe, no backup
pwsh -File uninstall-fabric.ps1 -KeepData          # remove services, keep data
```

Removes services, scheduled tasks, `C:\ProgramData\forgewire`, `C:\rqlite`, and
the per-user token at `%USERPROFILE%\.forgewire\hub.token`. Without `-NoBackup`
it first backs up identities, the rqlite snapshot, and config.

## Known gotchas (fixed in the scripts; documented here so they don't recur)

1. **Wrong PowerShell edition.** Launching the installer with `powershell` (5.1)
   used to fail with cryptic "missing closing '}'" parse errors. The
   `#Requires -Version 7.0` directive now fails fast with a clear message. Use
   `pwsh`.

2. **Hostname resolves to a public IPv6.** On some networks a bare LAN hostname
   (e.g. `DESKTOP-ABC`) resolves via the ISP resolver to a *public* IPv6 (AAAA)
   while the only reachable address is IPv4 served by mDNS as `<host>.local`.
   The installer's .NET token-verification probe then hangs until timeout and
   reports an empty HTTP status that looks like a rejected token. `install-fabric.ps1`
   now resolves a hostname `-HubUrl` to a LAN-reachable IPv4 (preferring private
   ranges, trying the `.local` form) **for that one probe only** — the rqlite
   Raft layer still advertises the bare hostname, keeping the cluster
   DHCP-proof. If you ever hit a token-verify failure against a hostname URL,
   pass the hub's LAN IPv4 to `-HubUrl` as a workaround.

3. **Stale VSIX shadowing the current build.** Old `.vsix` files accumulate in
   `vscode\` and `vscode\dist\`, under two extension names (`forgewire` and the
   legacy `forgewire-fabric`). The installer used to grab the first directory
   with any match — so an old artifact in `dist\` shadowed the current build in
   `vscode\`, installing the wrong (and wrong-named) extension. It now installs
   the `.vsix` matching the current `vscode\package.json` name+version exactly,
   falling back to the globally-highest version across all search dirs. Prune
   old `.vsix` files periodically; they are build artifacts, not tracked in git.
