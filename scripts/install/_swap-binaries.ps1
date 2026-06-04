<#
.SYNOPSIS
    In-place swap of ForgeWire Rust service binaries from a staging dir.
.DESCRIPTION
    Stops the hub + runner services, replaces the binaries in the install bin dir
    with the ones staged in -StageDir, restarts the services, and (optionally)
    installs a VSIX found in the stage dir. Keeps identities, tokens, and rqlite
    data untouched. Intended to be run elevated (locally or over an elevated SSH
    session).
#>
[CmdletBinding()]
param(
    [string]$StageDir = 'C:\Temp\fwdeploy',
    [string]$BinDir   = 'C:\ProgramData\forgewire\bin',
    [switch]$InstallVsix
)
$ErrorActionPreference = 'Continue'

Write-Host "== Stopping services =="
Stop-Service ForgeWireHub, ForgeWireRunner -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Get-Process forgewire-hub, forgewire-runner -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

Write-Host "== Swapping binaries =="
foreach ($f in 'forgewire-hub.exe', 'forgewire-runner.exe', 'forgewire-fabric-cli.exe') {
    $src = Join-Path $StageDir $f
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $BinDir $f) -Force
        Write-Host "  swapped $f"
    } else {
        Write-Host "  MISSING in stage: $f"
    }
}

Write-Host "== Starting services =="
Start-Service ForgeWireRqlite -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Service ForgeWireHub -ErrorAction SilentlyContinue
Start-Service ForgeWireRunner -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

Write-Host "== Health =="
try {
    $h = (Invoke-WebRequest 'http://127.0.0.1:8765/healthz' -UseBasicParsing -TimeoutSec 6).Content
    Write-Host "  healthz: $h"
} catch {
    Write-Host "  healthz FAILED: $($_.Exception.Message)"
}

if ($InstallVsix) {
    $vsix = Get-ChildItem $StageDir -Filter 'forgewire-*.vsix' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    $code = (Get-Command code -ErrorAction SilentlyContinue).Source
    if ($vsix -and $code) {
        Write-Host "== Installing VSIX $($vsix.Name) =="
        & $code --install-extension $vsix.FullName --force 2>&1 | Out-Host
    } else {
        Write-Host "== VSIX skip (vsix=$($vsix.Name) code=$code) =="
    }
}
Write-Host "== Done =="
