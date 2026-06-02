# Operations: install hub & runner as a service

> **As of M2.7 (2026-06-02) the standard deployment uses the native Rust binaries.**
> The Python hub/runner remain available as a fallback during the migration window.
> See the [Rust-first section](#windows-nssm--rust-first) for the current install path.
> The [Python legacy section](#python-legacy-path) is preserved for rollback reference.

---

## Windows — NSSM (Rust-first)

[NSSM](https://nssm.cc/) wraps any console program as a Windows service.
The installer scripts below are idempotent: re-running them will update the
service definition in place. **Run as Administrator.**

### Install the hub (Rust)

```powershell
# As Administrator, from the forgewire-fabric repo
pwsh -File scripts\install\nssm-install-hub.ps1 `
    -Token "<paste your hub bearer token>" `
    -Port 8765 `
    -RqliteHost 127.0.0.1 `
    -RqlitePort 4001
```

Result:

- Service **ForgeWireHub** runs `C:\ProgramData\forgewire\bin\forgewire-hub.exe`
- Backend: rqlite (HA, strongly-consistent). SQLite is not a supported hub backend.
- Bind address defaults to `0.0.0.0:8765` for LAN access.
- Token loaded from `C:\ProgramData\forgewire\hub.token` (never in service args).
- Logs at `C:\ProgramData\forgewire\logs\hub.{out,err}.log` (10 MB rotation, 5 generations).
- Auto-start on boot, auto-restart on crash (10 s back-off).

#### Stream durability profile (optional)

Set `FORGEWIRE_HUB_STREAM_PROFILE` in the service environment to tune runner output buffering:

| Value | Flush after | Loss window on hard kill |
|-------|-------------|--------------------------|
| `strict` *(default)* | every line | none |
| `balanced` | 50 lines | ≤ 50 lines |
| `throughput` | 200 lines | ≤ 200 lines |

`submit_result` always force-flushes regardless of profile.

```powershell
nssm set ForgeWireHub AppEnvironmentExtra "FORGEWIRE_HUB_STREAM_PROFILE=balanced"
nssm restart ForgeWireHub
```

### Install a runner (Rust)

```powershell
pwsh -File scripts\install\nssm-install-runner.ps1 `
    -HubUrl "http://192.0.2.10:8765" `
    -Token "<bearer token>" `
    -WorkspaceRoot "C:\Work\repo" `
    -Tags "windows,gpu:nvidia" `
    -ScopePrefixes "src/,tests/"
```

Service name: **ForgeWireRunner**.

### Manage services

```powershell
nssm status  ForgeWireHub
nssm status  ForgeWireRunner
nssm restart ForgeWireHub
nssm restart ForgeWireRunner
nssm edit    ForgeWireHub        # GUI to tweak args/env after install
nssm remove  ForgeWireHub confirm
```

### Verify

```powershell
Invoke-RestMethod http://127.0.0.1:8765/healthz | ConvertTo-Json
# Expect: rust_hub=true, backend=rqlite:..., stream_profile=strict
```

---

## Remote deploy — Precision → OptiPlex (FORGEWIRE-HUB)

From FORGEWIRE-BUILD, the SSH host alias `forgewire` gives access to the hub host.
SSH config lives at `~/.ssh/config`; key is `~/.ssh/id_ed25519_forgewire`.

### Hub

```powershell
# 1. Build (from repo root)
cd C:\Projects\forgewire\forgewire-fabric
cargo build --release -p fabric-hub

# 2. Stage (avoids locked-file error on the running service)
scp target\release\forgewire-hub.exe forgewire:"C:/ProgramData/forgewire/bin/forgewire-hub-new.exe"

# 3. Stop → swap → start → verify
ssh forgewire "powershell -Command `"
  nssm stop ForgeWireHub;
  Move-Item 'C:\ProgramData\forgewire\bin\forgewire-hub.exe' 'C:\ProgramData\forgewire\bin\forgewire-hub.bak.exe' -Force;
  Move-Item 'C:\ProgramData\forgewire\bin\forgewire-hub-new.exe' 'C:\ProgramData\forgewire\bin\forgewire-hub.exe' -Force;
  nssm start ForgeWireHub;
  Start-Sleep 3;
  Invoke-RestMethod http://127.0.0.1:8765/healthz | ConvertTo-Json
`""
```

### Runner

```powershell
cargo build --release -p fabric-runner
scp target\release\forgewire-runner.exe forgewire:"C:/ProgramData/forgewire/bin/forgewire-runner-new.exe"
ssh forgewire "powershell -Command `"
  nssm stop ForgeWireRunner;
  Move-Item 'C:\ProgramData\forgewire\bin\forgewire-runner.exe' 'C:\ProgramData\forgewire\bin\forgewire-runner.bak.exe' -Force;
  Move-Item 'C:\ProgramData\forgewire\bin\forgewire-runner-new.exe' 'C:\ProgramData\forgewire\bin\forgewire-runner.exe' -Force;
  nssm start ForgeWireRunner
`""
```

### Rollback

```powershell
ssh forgewire "powershell -Command `"
  nssm stop ForgeWireHub;
  Move-Item 'C:\ProgramData\forgewire\bin\forgewire-hub.bak.exe' 'C:\ProgramData\forgewire\bin\forgewire-hub.exe' -Force;
  nssm start ForgeWireHub
`""
```

---

## Linux — systemd

The unit files in `scripts/install/systemd/` are templates. Edit the
`User=`, `WorkingDirectory=`, and `Environment=` lines before installing.

### Install the hub

```bash
sudo install -d -o forgewire -g forgewire /var/lib/forgewire /var/log/forgewire
sudo cp scripts/install/systemd/forgewire-hub.service /etc/systemd/system/
sudo install -m 0640 -o forgewire -g forgewire \
    your-token-file /etc/forgewire/hub.token
# Edit /etc/systemd/system/forgewire-hub.service to set binary path and rqlite env vars
sudo systemctl daemon-reload
sudo systemctl enable --now forgewire-hub.service
sudo systemctl status forgewire-hub.service
```

### Install a runner

```bash
sudo cp scripts/install/systemd/forgewire-runner.service /etc/systemd/system/
sudo systemctl edit forgewire-runner.service  # set HUB_URL, WORKSPACE_ROOT, TAGS, SCOPE_PREFIXES
sudo systemctl daemon-reload
sudo systemctl enable --now forgewire-runner.service
```

### Logs

```bash
journalctl -u forgewire-hub.service -f
journalctl -u forgewire-runner.service -f
```

---

## macOS — launchd

```bash
sudo cp scripts/install/launchd/com.forgewire_fabric.hub.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.forgewire_fabric.hub.plist
sudo chmod 0644 /Library/LaunchDaemons/com.forgewire_fabric.hub.plist
sudo launchctl load -w /Library/LaunchDaemons/com.forgewire_fabric.hub.plist
```

Set `FORGEWIRE_HUB_TOKEN_FILE`, `FORGEWIRE_HUB_RQLITE_HOST`, and
`FORGEWIRE_HUB_STREAM_PROFILE` in the `<dict>` environment block.

---

## Backups

The hub state lives in rqlite (default). Take a snapshot via the rqlite HTTP API:

```bash
curl -o hub-backup-$(date -u +%Y%m%dT%H%M%SZ).db \
    "http://localhost:4001/db/snapshot"
```

For single-node SQLite fallback (non-production):

```bash
sqlite3 /var/lib/forgewire/hub.sqlite3 \
    ".backup '/var/backups/forgewire/hub-$(date -u +%Y%m%dT%H%M%SZ).sqlite3'"
```

See [`dr-rqlite-backups.md`](dr-rqlite-backups.md) for the full rqlite DR procedure.

---

## Uninstall

| Platform | Command |
|---|---|
| Windows | `nssm remove ForgeWireHub confirm` (and `ForgeWireRunner`) |
| Linux | `sudo systemctl disable --now forgewire-hub.service && sudo rm /etc/systemd/system/forgewire-hub.service && sudo systemctl daemon-reload` |
| macOS | `sudo launchctl unload -w /Library/LaunchDaemons/com.forgewire_fabric.hub.plist && sudo rm /Library/LaunchDaemons/com.forgewire_fabric.hub.plist` |

Removing the service does not delete the rqlite data directory or token file.

---

## Python legacy path

The Python hub and runner remain deployable as a rollback path. **Do not use Python as the
primary hub in a fresh install** — use the Rust binaries above.

```powershell
# Python hub (rollback only)
pwsh -File scripts\install\nssm-install-hub.ps1 `
    -UsePython `
    -PythonExe "C:\Python311\python.exe" `
    -Token "<token>" `
    -Port 8765

# Python runner (pending Precision admin switch to Rust)
pwsh -File scripts\install\nssm-install-runner.ps1 `
    -UsePython `
    -PythonExe "C:\Python311\python.exe" `
    -HubUrl "http://192.0.2.10:8765" `
    -Token "<token>" `
    -WorkspaceRoot "C:\Work\repo"
```

To switch an existing Python NSSM service to Rust (requires admin):

```powershell
pwsh -File scripts\install\switch-to-rust-services.ps1
```

