<#
.SYNOPSIS
    Safely refresh and redeploy a maintained standalone Fabric clone.

.DESCRIPTION
    Preserves any local edits on an operator branch plus an external git bundle,
    fast-forwards main, builds the Rust services, performs the guarded binary
    update, and replays every registered operator overlay. No hard reset is used.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = 'C:\Projects\forgewire-fabric',
    [string]$Remote = 'origin',
    [string]$Branch = 'main'
)

$ErrorActionPreference = 'Stop'
$sync = Join-Path $RepoRoot 'scripts\install\sync-deployment-clone.ps1'
if (-not (Test-Path -LiteralPath $sync)) { throw "clone sync script missing: $sync" }
& $sync -RepoRoot $RepoRoot -Remote $Remote -Branch $Branch
if (-not $?) { throw 'deployment clone synchronization failed' }

Set-Location -LiteralPath $RepoRoot
& cargo build --release -p fabric-hub -p fabric-runner -p fabric-cli -p loom-runner
if ($LASTEXITCODE -ne 0) { throw 'release build failed' }

$updater = Join-Path $RepoRoot 'scripts\install\update-fabric.ps1'
& $updater -StageDir (Join-Path $RepoRoot 'target\release')
if (-not $?) { throw 'guarded Fabric binary update failed' }

$replay = Join-Path $RepoRoot 'scripts\install\replay-operator-overlays.ps1'
& $replay -FabricRoot $RepoRoot -Build -StartServices
if (-not $?) { throw 'operator overlay replay failed' }

$health = Invoke-RestMethod -Uri 'http://127.0.0.1:8765/healthz' -TimeoutSec 10
Write-Host "HEALTHZ_STATUS=200"
Write-Host "HEALTHZ_BODY=$($health | ConvertTo-Json -Compress)"
Write-Host "DEPLOYMENT_HEAD=$(git rev-parse HEAD)"
