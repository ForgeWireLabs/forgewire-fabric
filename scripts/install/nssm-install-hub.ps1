<#
.SYNOPSIS
    Install the ForgeWire Hub (native Rust) as a Windows service via NSSM.

.DESCRIPTION
    Idempotent. If the service already exists it is updated in place.
    NSSM must be on PATH (https://nssm.cc/).

    Default backend: rqlite (HA, strongly-consistent Raft cluster).
    SQLite is a single-node fallback only; do NOT use it in production.

    The script:
      1. Writes the bearer token to a file (restrictive ACL).
      2. Installs/updates the "ForgeWireHub" NSSM service pointing at
         forgewire-hub.exe (native Rust binary — no Python dependency).
      3. Configures rqlite or SQLite backend via environment variables.
      4. Installs the /healthz watchdog scheduled task (unless -NoWatchdog).

    Run as Administrator.

.PARAMETER BinDir
    Directory containing forgewire-hub.exe. Default: C:\ProgramData\forgewire\bin

.PARAMETER Token
    Bearer token string (minimum 16 chars). REQUIRED on first install; omit to
    reuse the existing token file on reinstall.

.PARAMETER Port
    Hub listen port. Default: 8765.

.PARAMETER BindHost
    Hub bind address. Default: 0.0.0.0 (all interfaces — required for LAN access).

.PARAMETER Backend
    "rqlite" (default, recommended) or "sqlite" (single-node fallback).

.PARAMETER RqliteHost
    rqlite node address. Default: 127.0.0.1.

.PARAMETER RqlitePort
    rqlite HTTP API port. Default: 4001.

.PARAMETER RqliteConsistency
    rqlite read consistency. Default: strong (Raft round-trip per read —
    required for audit-chain integrity). Do not weaken without benchmarking.

.PARAMETER DataDir
    Service data directory. Default: C:\ProgramData\forgewire.

.PARAMETER ServiceName
    Windows service name. Default: ForgeWireHub.

.PARAMETER NoWatchdog
    Skip /healthz watchdog scheduled task install.

.EXAMPLE
    # First install (rqlite backend, default):
    pwsh -File nssm-install-hub.ps1 -Token (Get-Content hub.token -Raw)

    # Reinstall with explicit rqlite node:
    pwsh -File nssm-install-hub.ps1 `
        -Token (Get-Content hub.token -Raw) `
        -RqliteHost 192.0.2.10

    # SQLite fallback (single-node only):
    pwsh -File nssm-install-hub.ps1 `
        -Token (Get-Content hub.token -Raw) `
        -Backend sqlite
#>
[CmdletBinding()]
param(
    [string]$BinDir        = "C:\ProgramData\forgewire\bin",
    [string]$Token         = "",
    [int]$Port             = 8765,
    [string]$BindHost      = "0.0.0.0",
    [ValidateSet("rqlite","sqlite")][string]$Backend = "rqlite",
    [string]$RqliteHost    = "127.0.0.1",
    [int]$RqlitePort       = 4001,
    [ValidateSet("none","weak","strong","linearizable")][string]$RqliteConsistency = "strong",
    [string]$DbPath        = "C:\ProgramData\forgewire\hub.sqlite3",
    [string]$DataDir       = "C:\ProgramData\forgewire",
    [string]$ServiceName   = "ForgeWireHub",
    [switch]$NoWatchdog
)

$ErrorActionPreference = "Stop"

# ---- Self-elevation -------------------------------------------------------
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $shellExe  = (Get-Process -Id $PID).Path
    $forwarded = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $forwarded += "-$k" } }
        else                 { $forwarded += "-$k"; $forwarded += $v }
    }
    $proc = Start-Process -FilePath $shellExe -Verb RunAs -Wait -PassThru -ArgumentList $forwarded
    exit $proc.ExitCode
}

if (-not (Get-Command nssm.exe -ErrorAction SilentlyContinue)) {
    throw "nssm.exe not found on PATH. Install from https://nssm.cc/ or 'winget install nssm.nssm'."
}

$HubExe   = Join-Path $BinDir "forgewire-hub.exe"
if (-not (Test-Path $HubExe)) {
    throw "forgewire-hub.exe not found at $HubExe. Run 'cargo build --release' and copy binaries to $BinDir."
}

$LogDir   = Join-Path $DataDir "logs"
$TokenFile = Join-Path $DataDir "hub.token"
New-Item -ItemType Directory -Force -Path $DataDir, $LogDir | Out-Null

# ---- Token file -----------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($Token)) {
    if (-not (Test-Path $TokenFile)) {
        throw "No -Token supplied and $TokenFile does not exist. Provide the bearer token on first install."
    }
    Write-Host "Reusing existing token file: $TokenFile"
} else {
    [System.IO.File]::WriteAllText($TokenFile, $Token.Trim())
    # Use Get-Acl/Set-Acl (FileInfo.GetAccessControl was removed in PowerShell 7).
    $acl = Get-Acl -Path $TokenFile
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
    foreach ($p in @("NT AUTHORITY\SYSTEM","BUILTIN\Administrators")) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($p,"FullControl","Allow"))
    }
    Set-Acl -Path $TokenFile -AclObject $acl
    Write-Host "Token written to $TokenFile"
}

# ---- Firewall: hub HTTP (TCP) + discovery beacon (UDP) --------------------
# So runners and the VS Code extension on other machines can reach this hub and
# receive its LAN discovery beacon.
$beaconPort = if ($env:FORGEWIRE_BEACON_PORT) { [int]$env:FORGEWIRE_BEACON_PORT } else { 48765 }
$fwRules = @(
    @{ Name = "ForgeWire hub $Port";       Proto = "TCP"; Port = $Port },
    @{ Name = "ForgeWire beacon $beaconPort"; Proto = "UDP"; Port = $beaconPort }
)
foreach ($r in $fwRules) {
    if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
        try {
            New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Action Allow `
                -Protocol $r.Proto -LocalPort $r.Port -Profile Any -ErrorAction Stop | Out-Null
            Write-Host "  firewall: opened $($r.Proto) $($r.Port)"
        } catch { Write-Host "  firewall: could not open $($r.Proto) $($r.Port) ($($_.Exception.Message))" }
    }
}

# ---- NSSM service setup ---------------------------------------------------
$prevNative = $PSNativeCommandUseErrorActionPreference
$PSNativeCommandUseErrorActionPreference = $false
& nssm.exe status $ServiceName *>$null
$exists = ($LASTEXITCODE -eq 0)
$PSNativeCommandUseErrorActionPreference = $prevNative

if ($exists) {
    Write-Host "Service '$ServiceName' exists; updating in place."
    & nssm.exe stop $ServiceName confirm 2>&1 | Out-Null
    Start-Sleep -Seconds 2
} else {
    Write-Host "Installing service '$ServiceName'."
    & nssm.exe install $ServiceName $HubExe | Out-Null
}

& nssm.exe set $ServiceName Application         $HubExe                            | Out-Null
& nssm.exe set $ServiceName AppParameters       ""                                  | Out-Null
& nssm.exe set $ServiceName AppDirectory        $DataDir                            | Out-Null
& nssm.exe set $ServiceName DisplayName         "ForgeWire Hub (Rust)"              | Out-Null
& nssm.exe set $ServiceName Description         "ForgeWire Fabric native Rust hub daemon" | Out-Null
& nssm.exe set $ServiceName Start               SERVICE_AUTO_START                  | Out-Null
& nssm.exe set $ServiceName AppExit Default     Restart                             | Out-Null
& nssm.exe set $ServiceName AppRestartDelay     10000                               | Out-Null
& nssm.exe set $ServiceName AppStdout           (Join-Path $LogDir "hub.out.log")   | Out-Null
& nssm.exe set $ServiceName AppStderr           (Join-Path $LogDir "hub.err.log")   | Out-Null
& nssm.exe set $ServiceName AppRotateFiles      1                                   | Out-Null
& nssm.exe set $ServiceName AppRotateOnline     1                                   | Out-Null
& nssm.exe set $ServiceName AppRotateBytes      10485760                            | Out-Null

# ---- Environment variables ------------------------------------------------
$envExtra = @(
    "FORGEWIRE_HUB_TOKEN_FILE=$TokenFile",
    "FORGEWIRE_HUB_HOST=$BindHost",
    "FORGEWIRE_HUB_PORT=$Port",
    "FORGEWIRE_HUB_BACKEND=$Backend"
)
if ($Backend -eq "rqlite") {
    $envExtra += "FORGEWIRE_HUB_RQLITE_HOST=$RqliteHost"
    $envExtra += "FORGEWIRE_HUB_RQLITE_PORT=$RqlitePort"
    $envExtra += "FORGEWIRE_HUB_RQLITE_CONSISTENCY=$RqliteConsistency"
} else {
    $envExtra += "FORGEWIRE_HUB_DB_PATH=$DbPath"
}
& nssm.exe set $ServiceName AppEnvironmentExtra $envExtra | Out-Null

# ---- Start ----------------------------------------------------------------
$PSNativeCommandUseErrorActionPreference = $false
try {
    function Get-SvcStatus { (& nssm.exe status $ServiceName 2>&1 | Out-String).Trim() }
    $s = Get-SvcStatus
    switch -Regex ($s) {
        'SERVICE_PAUSED'  { & nssm.exe continue $ServiceName 2>&1 | Out-Null }
        'SERVICE_STOPPED' { & nssm.exe start    $ServiceName 2>&1 | Out-Null }
        'SERVICE_RUNNING' { }
        default           { & nssm.exe start    $ServiceName 2>&1 | Out-Null }
    }
    Start-Sleep -Seconds 3
    $s = Get-SvcStatus
    if ($s -ne 'SERVICE_RUNNING') { throw "Service in unexpected state: $s. Check $LogDir." }
} finally { $PSNativeCommandUseErrorActionPreference = $prevNative }

Write-Host "Service state: $s"
Write-Host ""
Write-Host "Hub URL    : http://${BindHost}:${Port}"
Write-Host "Backend    : $Backend$(if($Backend -eq 'rqlite'){ " rqlite=$RqliteHost`:$RqlitePort consistency=$RqliteConsistency" })"
Write-Host "Token file : $TokenFile"
Write-Host "Binary     : $HubExe"
Write-Host "Logs       : $LogDir"

# ---- Watchdog -------------------------------------------------------------
if (-not $NoWatchdog) {
    $wd = Join-Path $PSScriptRoot "install-hub-watchdog.ps1"
    if (Test-Path $wd) {
        Write-Host "`nInstalling /healthz watchdog..."
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $wd `
            -ServiceName $ServiceName -HealthzUrl "http://127.0.0.1:$Port/healthz"
    }
}

