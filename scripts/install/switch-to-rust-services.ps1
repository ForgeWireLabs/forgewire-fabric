<#
.SYNOPSIS
    Switch ForgeWireRunner (and optionally ForgeWireHub) NSSM services from
    Python to native Rust binaries. Run as Administrator.

.DESCRIPTION
    Idempotent — safe to re-run. Updates existing NSSM services in place;
    does not recreate them.

    Requires Administrator. Self-elevates via UAC if needed.

.PARAMETER DataDir
    Service data directory. Default: C:\ProgramData\forgewire

.PARAMETER BinDir
    Directory containing forgewire-hub.exe and forgewire-runner.exe.
    Default: C:\ProgramData\forgewire\bin

.PARAMETER SwitchHub
    Also switch the hub service. Default: $false (hub already switched on hub host).

.PARAMETER HubUrl
    Hub URL for runner. Default: reads from existing service env.

.PARAMETER RqliteHost
    rqlite host for hub. Default: 127.0.0.1

.PARAMETER WorkspaceRoot
    Runner workspace root. Default: reads from existing service env.

.EXAMPLE
    # Switch runner only (typical for spoke nodes):
    pwsh -File switch-to-rust-services.ps1

    # Switch both hub and runner (hub node):
    pwsh -File switch-to-rust-services.ps1 -SwitchHub
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$DataDir       = "C:\ProgramData\forgewire",
    [string]$BinDir        = "C:\ProgramData\forgewire\bin",
    [switch]$SwitchHub,
    [string]$HubUrl        = "",
    [string]$RqliteHost    = "127.0.0.1",
    [int]$RqlitePort       = 4001,
    [string]$WorkspaceRoot = ""
)

$ErrorActionPreference = "Stop"

# Self-elevation
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
    Write-Host "Requesting elevation..."
    $proc = Start-Process -FilePath $shellExe -Verb RunAs -Wait -PassThru -ArgumentList $forwarded
    exit $proc.ExitCode
}

function Switch-NssmService {
    param(
        [string]$ServiceName,
        [string]$AppExe,
        [string]$DisplayName,
        [string[]]$EnvExtra
    )
    $prevNative = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false

    Write-Host "`n── $ServiceName ──"
    & nssm.exe status $ServiceName *>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Service '$ServiceName' not found — skipping."
        $PSNativeCommandUseErrorActionPreference = $prevNative
        return
    }

    Write-Host "Stopping $ServiceName..."
    & nssm.exe stop $ServiceName confirm 2>&1 | Out-Null
    Start-Sleep -Seconds 3

    Write-Host "Updating Application → $AppExe"
    & nssm.exe set $ServiceName Application  $AppExe      | Out-Null
    & nssm.exe set $ServiceName AppParameters ""           | Out-Null
    & nssm.exe set $ServiceName DisplayName  $DisplayName | Out-Null
    & nssm.exe set $ServiceName AppEnvironmentExtra $EnvExtra | Out-Null

    Write-Host "Starting $ServiceName..."
    & nssm.exe start $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 4

    $s = (& nssm.exe status $ServiceName 2>&1 | Out-String).Trim()
    Write-Host "State: $s"
    if ($s -ne 'SERVICE_RUNNING') {
        Write-Warning "$ServiceName not running ($s). Check logs in $DataDir\logs\"
    }
    $PSNativeCommandUseErrorActionPreference = $prevNative
}

$TokenFile    = Join-Path $DataDir "hub.token"
$IdentityFile = Join-Path $DataDir "runner_identity.json"

# ── Runner service ─────────────────────────────────────────────────────────
$RunnerExe = Join-Path $BinDir "forgewire-runner.exe"
if (-not (Test-Path $RunnerExe)) {
    throw "forgewire-runner.exe not found at $RunnerExe. Copy release binary first."
}

# Read HubUrl + WorkspaceRoot from existing service env if not supplied
if ([string]::IsNullOrWhiteSpace($HubUrl)) {
    $existingEnv = (& nssm.exe get ForgeWireRunner AppEnvironmentExtra 2>&1 | Out-String)
    $m = [regex]::Match($existingEnv, 'FORGEWIRE_HUB_URL=([^\s\r\n]+)')
    $HubUrl = if ($m.Success) { $m.Groups[1].Value } else { "http://127.0.0.1:8765" }
}
if ([string]::IsNullOrWhiteSpace($WorkspaceRoot)) {
    $existingEnv = (& nssm.exe get ForgeWireRunner AppEnvironmentExtra 2>&1 | Out-String)
    $m = [regex]::Match($existingEnv, 'FORGEWIRE_RUNNER_WORKSPACE_ROOT=([^\s\r\n]+)')
    $WorkspaceRoot = if ($m.Success) { $m.Groups[1].Value } else { "C:\Projects\forgewire" }
}

Switch-NssmService `
    -ServiceName "ForgeWireRunner" `
    -AppExe $RunnerExe `
    -DisplayName "ForgeWire Runner (Rust)" `
    -EnvExtra @(
        "FORGEWIRE_HUB_URL=$HubUrl",
        "FORGEWIRE_HUB_TOKEN_FILE=$TokenFile",
        "FORGEWIRE_RUNNER_IDENTITY_PATH=$IdentityFile",
        "FORGEWIRE_RUNNER_WORKSPACE_ROOT=$WorkspaceRoot",
        "FORGEWIRE_RUNNER_MAX_CONCURRENT=1",
        "FORGEWIRE_RUNNER_SCOPE_PREFIXES=$WorkspaceRoot",
        "PYTHONUNBUFFERED=1"
    )

# ── Hub service (only if requested) ────────────────────────────────────────
if ($SwitchHub) {
    $HubExe = Join-Path $BinDir "forgewire-hub.exe"
    if (-not (Test-Path $HubExe)) {
        throw "forgewire-hub.exe not found at $HubExe. Copy release binary first."
    }
    Switch-NssmService `
        -ServiceName "ForgeWireHub" `
        -AppExe $HubExe `
        -DisplayName "ForgeWire Hub (Rust)" `
        -EnvExtra @(
            "FORGEWIRE_HUB_TOKEN_FILE=$TokenFile",
            "FORGEWIRE_HUB_HOST=0.0.0.0",
            "FORGEWIRE_HUB_PORT=8765",
            "FORGEWIRE_HUB_BACKEND=rqlite",
            "FORGEWIRE_HUB_RQLITE_HOST=$RqliteHost",
            "FORGEWIRE_HUB_RQLITE_PORT=$RqlitePort",
            "FORGEWIRE_HUB_RQLITE_CONSISTENCY=strong"
        )
}

Write-Host "`n✓ Done. Verify with: curl http://127.0.0.1:8765/healthz"
