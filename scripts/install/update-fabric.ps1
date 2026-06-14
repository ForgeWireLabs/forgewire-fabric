<#
.SYNOPSIS
    Update the ForgeWire Rust binaries on THIS node, safely and in place.

.DESCRIPTION
    The node-local primitive for the self-updating fabric. Replaces the hub /
    runner / cli binaries with newer ones, keeping identities, the token, and the
    rqlite control-plane data untouched. rqlite itself is left running so the
    node keeps its place in the Raft cluster (quorum preserved).

    Safety:
      - version/hash check: if the staged binaries are identical to the running
        ones, it is a no-op.
      - backup: current binaries are copied to *.bak.exe first.
      - health gate: after restart the hub must report /healthz ok within
        -HealthTimeoutSec, or the update auto-rolls-back to the .bak binaries.

    Sources (pick one):
      -StageDir <dir>   a folder containing forgewire-*.exe (and optional *.vsix)
      -FromHub  <url>   pull the staged binaries from a hub's /admin/binaries
                        manifest, verifying each file's SHA-256.

    Spawned detached by the hub's POST /admin/update for OOTB cluster rollouts,
    or run by an operator directly.

.PARAMETER StageDir
    Folder with the new binaries. Mutually exclusive with -FromHub.

.PARAMETER FromHub
    Hub base URL to pull staged binaries from (e.g. http://10.0.0.5:8765).

.PARAMETER BinDir
    Install bin dir. Default C:\ProgramData\forgewire\bin

.PARAMETER DryRun
    Show what would change; do not stop services or swap anything.

.PARAMETER NoRollback
    Do not auto-rollback if the health gate fails (leave the new binaries).

.PARAMETER IncludeVsix
    Also install a forgewire-*.vsix found in the source.

.EXAMPLE
    pwsh -File update-fabric.ps1 -StageDir C:\new-binaries

.EXAMPLE
    pwsh -File update-fabric.ps1 -FromHub http://forgewire-hub:8765
#>
[CmdletBinding(DefaultParameterSetName = 'Stage')]
param(
    [Parameter(ParameterSetName = 'Stage')][string]$StageDir,
    [Parameter(ParameterSetName = 'Hub')][string]$FromHub,
    # Stage mode: copy the binaries from -StageDir into this node's hub staging
    # dir (…\bin\staged) + write VERSION, so the hub can serve them to the
    # cluster. Does NOT apply locally. Pair with `forgewire-fabric-cli update`.
    [switch]$Stage,
    [string]$Version         = '',
    [string]$BinDir          = 'C:\ProgramData\forgewire\bin',
    [int]$HubPort            = 8765,
    [string]$TokenFile       = 'C:\ProgramData\forgewire\hub.token',
    [switch]$DryRun,
    [switch]$NoRollback,
    [switch]$IncludeVsix,
    [int]$HealthTimeoutSec   = 45,
    [string]$LogFile         = 'C:\ProgramData\forgewire\logs\update.log'
)

$ErrorActionPreference = 'Stop'
$BINARIES = @('forgewire-hub.exe', 'forgewire-runner.exe', 'forgewire-fabric-cli.exe')

# ── Self-elevation ────────────────────────────────────────────────────────────
# Already privileged if Administrator OR running as LocalSystem (the hub's
# scheduled-task self-update runs as SYSTEM, for which IsInRole(Administrator)
# can return false even though SYSTEM is fully privileged). Without the IsSystem
# check the SYSTEM task would try a non-interactive RunAs and silently bail.
$winId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($winId)
if (-not ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) -or $winId.IsSystem)) {
    $fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) { if ($kv.Value.IsPresent) { $fwd += "-$($kv.Key)" } }
        else { $fwd += "-$($kv.Key)"; $fwd += "$($kv.Value)" }
    }
    Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $fwd -Verb RunAs
    return
}

function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $msg"
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch {}
}

function Read-Token {
    if (Test-Path $TokenFile) { return (Get-Content $TokenFile -Raw).Trim() }
    return ''
}

function Hub-Version {
    try { return ((Invoke-WebRequest "http://127.0.0.1:$HubPort/healthz" -UseBasicParsing -TimeoutSec 5).Content | ConvertFrom-Json).version }
    catch { return $null }
}

Log "=== update-fabric on $env:COMPUTERNAME (mode: $(if($Stage){'STAGE'}else{'APPLY'})) ==="

# ── STAGE MODE: publish binaries to the local hub's staging dir ──────────────
if ($Stage) {
    if (-not $StageDir -or -not (Test-Path $StageDir)) { Log "ERROR: -Stage needs a valid -StageDir"; exit 1 }
    $stagedDir = Join-Path $BinDir 'staged'
    New-Item -ItemType Directory -Force -Path $stagedDir | Out-Null
    $copied = 0
    foreach ($b in $BINARIES) {
        $src = Join-Path $StageDir $b
        if (Test-Path $src) { Copy-Item $src (Join-Path $stagedDir $b) -Force; $copied++; Log "  staged $b" }
    }
    Get-ChildItem $StageDir -Filter 'forgewire-*.vsix' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1 |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $stagedDir $_.Name) -Force; Log "  staged $($_.Name)" }
    $ver = if ($Version) { $Version } else { (Get-Date -Format 'yyyyMMdd-HHmmss') }
    Set-Content -Path (Join-Path $stagedDir 'VERSION') -Value $ver -Encoding ASCII
    Log "Staged $copied binar(ies) as version $ver into $stagedDir"
    Log "Now roll the cluster with:  forgewire-fabric-cli update"
    return
}

# ── 1. Resolve the source binaries into a temp dir ───────────────────────────
$srcDir = $null
$cleanupSrc = $false
if ($FromHub) {
    $token = Read-Token
    if (-not $token) { Log "ERROR: no token to authenticate to $FromHub"; exit 1 }
    $hdr = @{ Authorization = "Bearer $token" }
    Log "Fetching manifest from $FromHub ..."
    $manifest = Invoke-RestMethod -Uri "$FromHub/admin/binaries/manifest" -Headers $hdr -TimeoutSec 15
    $srcDir = Join-Path $env:TEMP "fw-update-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $srcDir | Out-Null
    $cleanupSrc = $true
    foreach ($f in $manifest.files) {
        $out = Join-Path $srcDir $f.name
        Log "  downloading $($f.name) ($($f.size) bytes) ..."
        Invoke-WebRequest -Uri "$FromHub/admin/binaries/$($f.name)" -Headers $hdr -OutFile $out -TimeoutSec 120
        $got = (Get-FileHash -Path $out -Algorithm SHA256).Hash.ToLower()
        if ($got -ne $f.sha256.ToLower()) {
            Log "ERROR: sha256 mismatch for $($f.name): expected $($f.sha256), got $got"
            Remove-Item $srcDir -Recurse -Force -ErrorAction SilentlyContinue
            exit 1
        }
    }
    Log "Manifest version $($manifest.version); all SHA-256 verified."
} elseif ($StageDir) {
    if (-not (Test-Path $StageDir)) { Log "ERROR: StageDir $StageDir not found"; exit 1 }
    $srcDir = $StageDir
} else {
    Log "ERROR: provide -StageDir or -FromHub"; exit 1
}

# ── 2. Version/hash check — skip if identical ────────────────────────────────
$changed = @()
foreach ($b in $BINARIES) {
    $newP = Join-Path $srcDir $b
    $curP = Join-Path $BinDir $b
    if (-not (Test-Path $newP)) { continue }
    $newH = (Get-FileHash $newP -Algorithm SHA256).Hash
    $curH = if (Test-Path $curP) { (Get-FileHash $curP -Algorithm SHA256).Hash } else { '' }
    if ($newH -ne $curH) { $changed += $b }
}
if ($changed.Count -eq 0) {
    Log "Already up to date (binary hashes identical). Nothing to do."
    if ($cleanupSrc) { Remove-Item $srcDir -Recurse -Force -ErrorAction SilentlyContinue }
    return
}
Log "Will update: $($changed -join ', ')  (running hub v$(Hub-Version))"

if ($DryRun) {
    Log "DRY RUN — no changes made."
    if ($cleanupSrc) { Remove-Item $srcDir -Recurse -Force -ErrorAction SilentlyContinue }
    return
}

# ── 3. Back up current binaries ──────────────────────────────────────────────
foreach ($b in $changed) {
    $cur = Join-Path $BinDir $b
    if (Test-Path $cur) { Copy-Item $cur (Join-Path $BinDir ($b -replace '\.exe$', '.bak.exe')) -Force }
}
Log "Backed up current binaries to *.bak.exe"

# ── 4. Stop hub + runner (LEAVE rqlite running to hold Raft quorum) ──────────
Log "Stopping ForgeWireHub + ForgeWireRunner (rqlite stays up)..."
Stop-Service ForgeWireHub, ForgeWireRunner -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Get-Process forgewire-hub, forgewire-runner -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# ── 5. Swap binaries ─────────────────────────────────────────────────────────
$swapOk = $true
foreach ($b in $changed) {
    try { Copy-Item (Join-Path $srcDir $b) (Join-Path $BinDir $b) -Force; Log "  swapped $b" }
    catch { Log "  FAILED to swap $b : $($_.Exception.Message)"; $swapOk = $false }
}

# ── 6. Restart services ──────────────────────────────────────────────────────
Start-Service ForgeWireRqlite -ErrorAction SilentlyContinue  # ensure data node is up
Start-Service ForgeWireHub -ErrorAction SilentlyContinue
Start-Service ForgeWireRunner -ErrorAction SilentlyContinue

# ── 7. Health gate ───────────────────────────────────────────────────────────
$healthy = $false
$deadline = (Get-Date).AddSeconds($HealthTimeoutSec)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    $v = Hub-Version
    if ($v) { $healthy = $true; break }
}

if ($healthy -and $swapOk) {
    Log "UPDATE OK — hub healthy at v$(Hub-Version)."
    # VSIX (optional)
    if ($IncludeVsix) {
        $vsix = Get-ChildItem $srcDir -Filter 'forgewire-*.vsix' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        $code = (Get-Command code -ErrorAction SilentlyContinue).Source
        if ($vsix -and $code) { & $code --install-extension $vsix.FullName --force 2>&1 | Out-Null; Log "  installed $($vsix.Name)" }
    }
    if ($cleanupSrc) { Remove-Item $srcDir -Recurse -Force -ErrorAction SilentlyContinue }
    return
}

# ── 8. Rollback ──────────────────────────────────────────────────────────────
Log "HEALTH GATE FAILED (hub not healthy in ${HealthTimeoutSec}s)."
if ($NoRollback) {
    Log "Left new binaries in place (-NoRollback)."
    exit 1
}
Log "Rolling back to .bak binaries..."
Stop-Service ForgeWireHub, ForgeWireRunner -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Get-Process forgewire-hub, forgewire-runner -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
foreach ($b in $changed) {
    $bak = Join-Path $BinDir ($b -replace '\.exe$', '.bak.exe')
    if (Test-Path $bak) { Copy-Item $bak (Join-Path $BinDir $b) -Force }
}
Start-Service ForgeWireHub, ForgeWireRunner -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
if (Hub-Version) { Log "Rolled back; hub healthy at v$(Hub-Version)." } else { Log "Rollback done but hub still not healthy — check $LogFile." }
if ($cleanupSrc) { Remove-Item $srcDir -Recurse -Force -ErrorAction SilentlyContinue }
exit 1
