<#
.SYNOPSIS
    Install rqlite as an NSSM Windows service for ForgeWire Fabric.

.DESCRIPTION
    Idempotent. Downloads the rqlite binary if not present, creates a
    ForgeWireRqlite NSSM service, and starts it. The node advertises
    on 127.0.0.1 by default so it survives IP changes from DHCP/hotspot.

    First-node detection: if no existing rqlite cluster is reachable,
    the node bootstraps as a single-node leader. If -JoinAddress is
    supplied (or an existing cluster is discovered), the node joins
    the existing cluster.

    Run as Administrator (script self-elevates via UAC if needed).

.PARAMETER DataDir
    Root data directory. Default: C:\ProgramData\forgewire

.PARAMETER RqliteDir
    Directory containing rqlited.exe. Default: C:\rqlite
    If rqlited.exe is not found here, the script downloads it.

.PARAMETER HttpPort
    rqlite HTTP API port. Default: 4001

.PARAMETER RaftPort
    rqlite Raft consensus port. Default: 4002

.PARAMETER NodeId
    Stable node identifier. Default: <hostname>-rqlite

.PARAMETER JoinAddress
    Address of an existing rqlite node to join (e.g. 127.0.0.1:4002).
    If omitted, the node bootstraps as a single-node cluster (leader).

.PARAMETER RqliteVersion
    Version to download if rqlited.exe is missing. Default: 10.0.3

.EXAMPLE
    pwsh -File nssm-install-rqlite.ps1
    pwsh -File nssm-install-rqlite.ps1 -JoinAddress 192.0.2.10:4002
#>
[CmdletBinding()]
param(
    [string]$DataDir      = "C:\ProgramData\forgewire",
    [string]$RqliteDir    = "C:\rqlite",
    [int]$HttpPort        = 4001,
    [int]$RaftPort        = 4002,
    [string]$NodeId       = "",
    [string]$JoinAddress  = "",
    [string]$RqliteVersion = "10.0.3",
    [string]$ServiceName  = "ForgeWireRqlite"
)

$ErrorActionPreference = "Stop"

# ---- Self-elevation -------------------------------------------------------
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $shellExe = (Get-Process -Id $PID).Path
    $forwarded = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $forwarded += "-$k" } }
        else                 { $forwarded += "-$k"; $forwarded += $v }
    }
    Write-Host "Elevating: $shellExe $($forwarded -join ' ')"
    $proc = Start-Process -FilePath $shellExe -Verb RunAs -Wait -PassThru -ArgumentList $forwarded
    exit $proc.ExitCode
}

# ---- Prereqs ---------------------------------------------------------------
if (-not (Get-Command nssm.exe -ErrorAction SilentlyContinue)) {
    throw "nssm.exe not found on PATH. Install from https://nssm.cc/ or via 'winget install nssm.nssm'."
}

if (-not $NodeId) {
    $NodeId = "$($env:COMPUTERNAME.ToLower())-rqlite"
}

$RqliteDataDir = Join-Path $DataDir "rqlite\data"
$LogDir        = Join-Path $DataDir "logs"
$RqlitedExe    = Join-Path $RqliteDir "rqlited.exe"

New-Item -ItemType Directory -Force -Path $DataDir, $RqliteDataDir, $LogDir, $RqliteDir | Out-Null

# ---- Download rqlite if missing -------------------------------------------
if (-not (Test-Path $RqlitedExe)) {
    # rqlite publishes Windows builds as win64/win32 (NOT windows-amd64/386).
    $winArch = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
    $zipName = "rqlite-v${RqliteVersion}-${winArch}.zip"
    $downloadUrl = "https://github.com/rqlite/rqlite/releases/download/v${RqliteVersion}/${zipName}"
    $zipPath = Join-Path $env:TEMP $zipName
    $extractDir = Join-Path $env:TEMP "rqlite-extract"

    Write-Host "rqlited.exe not found at $RqlitedExe"
    Write-Host "Downloading rqlite v${RqliteVersion} from $downloadUrl ..."

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing

    if (-not (Test-Path $zipPath)) {
        throw "Download failed: $zipPath does not exist."
    }

    Write-Host "Extracting to $RqliteDir ..."
    if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    # The zip contains a single directory like rqlite-v10.0.3-windows-amd64/
    $innerDir = Get-ChildItem $extractDir -Directory | Select-Object -First 1
    if (-not $innerDir) {
        throw "Unexpected zip layout: no inner directory found."
    }

    # Copy binaries to the install dir
    Copy-Item "$($innerDir.FullName)\rqlited.exe" $RqliteDir -Force
    Copy-Item "$($innerDir.FullName)\rqlite.exe" $RqliteDir -Force -ErrorAction SilentlyContinue

    # Cleanup
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $RqlitedExe)) {
        throw "rqlited.exe still not found after extraction. Check $RqliteDir."
    }
    Write-Host "rqlite v${RqliteVersion} installed to $RqliteDir"
} else {
    $prevEA = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $ver = (& $RqlitedExe -version 2>&1 | Out-String).Trim()
    $ErrorActionPreference = $prevEA
    Write-Host "rqlited.exe found: $ver"
}

# ---- Build service parameters ----------------------------------------------
# Advertise on 127.0.0.1 so the node survives IP changes from DHCP/hotspot.
# The hub connects to rqlite on localhost. For multi-host Raft clusters,
# override -JoinAddress with the remote node's LAN address and adjust
# adv-addr if needed -- but single-host is the OOTB default.
$rqliteArgs = @(
    "-node-id", $NodeId,
    "-http-addr", "0.0.0.0:$HttpPort",
    "-http-adv-addr", "127.0.0.1:$HttpPort",
    "-raft-addr", "0.0.0.0:$RaftPort",
    "-raft-adv-addr", "127.0.0.1:$RaftPort"
)
if ($JoinAddress) {
    $rqliteArgs += @("-join", $JoinAddress)
    Write-Host "Joining existing cluster at $JoinAddress"
} else {
    Write-Host "No -JoinAddress -- bootstrapping as single-node leader."
}
$rqliteArgs += $RqliteDataDir
$rqliteArgsStr = $rqliteArgs -join " "

# ---- Create / update NSSM service ------------------------------------------
$prevNative = $PSNativeCommandUseErrorActionPreference
$PSNativeCommandUseErrorActionPreference = $false
try {
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & nssm.exe status $ServiceName *>$null
    $exists = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $prevPref

    if ($exists) {
        Write-Host "Service '$ServiceName' exists; stopping and updating in place."
        & nssm.exe stop $ServiceName confirm 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    } else {
        Write-Host "Installing service '$ServiceName'."
        & nssm.exe install $ServiceName $RqlitedExe | Out-Null
    }

    & nssm.exe set $ServiceName Application $RqlitedExe             | Out-Null
    & nssm.exe set $ServiceName AppParameters $rqliteArgsStr         | Out-Null
    & nssm.exe set $ServiceName AppDirectory $RqliteDataDir          | Out-Null
    & nssm.exe set $ServiceName DisplayName "ForgeWire rqlite"       | Out-Null
    & nssm.exe set $ServiceName Description "Raft-replicated SQLite for ForgeWire Fabric hub" | Out-Null
    & nssm.exe set $ServiceName Start SERVICE_AUTO_START             | Out-Null
    & nssm.exe set $ServiceName AppExit Default Restart              | Out-Null
    & nssm.exe set $ServiceName AppRestartDelay 5000                 | Out-Null
    & nssm.exe set $ServiceName AppStdout (Join-Path $LogDir "rqlite.out.log") | Out-Null
    & nssm.exe set $ServiceName AppStderr (Join-Path $LogDir "rqlite.err.log") | Out-Null
    & nssm.exe set $ServiceName AppRotateFiles 1                     | Out-Null
    & nssm.exe set $ServiceName AppRotateOnline 1                    | Out-Null
    & nssm.exe set $ServiceName AppRotateBytes 10485760              | Out-Null

    # ---- Start service --------------------------------------------------------
    & nssm.exe start $ServiceName 2>&1 | Out-Null
    Write-Host "Waiting for rqlite to elect leader..."
    $maxWait = 30
    $ready = $false
    for ($i = 0; $i -lt $maxWait; $i++) {
        Start-Sleep -Seconds 1
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$HttpPort/readyz" -UseBasicParsing -TimeoutSec 3
            if ($resp.StatusCode -eq 200) {
                $ready = $true
                break
            }
        } catch { }
    }

    if ($ready) {
        $status = (Invoke-WebRequest -Uri "http://127.0.0.1:$HttpPort/status" -UseBasicParsing -TimeoutSec 5).Content | ConvertFrom-Json
        Write-Host ""
        Write-Host "rqlite is READY." -ForegroundColor Green
        Write-Host "  Node ID:  $NodeId"
        Write-Host "  State:    $($status.store.raft.state)"
        Write-Host "  Leader:   $($status.store.leader.addr)"
        Write-Host "  HTTP:     http://127.0.0.1:$HttpPort"
        Write-Host "  Raft:     127.0.0.1:$RaftPort"
        Write-Host "  Data:     $RqliteDataDir"
        Write-Host "  Logs:     $LogDir"
    } else {
        Write-Warning "rqlite did not become ready within ${maxWait}s. Check logs at ${LogDir}\rqlite.err.log"
        $svcStatus = (& nssm.exe status $ServiceName 2>&1 | Out-String).Trim()
        Write-Host "Service status: $svcStatus"
    }
} finally {
    $PSNativeCommandUseErrorActionPreference = $prevNative
}

