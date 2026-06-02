<#
.SYNOPSIS
    Install the ForgeWire Runner (native Rust, default) as a Windows service via NSSM.

.DESCRIPTION
    Idempotent. Creates/updates the "ForgeWireRunner" NSSM service pointing at
    forgewire-runner.exe (native Rust — no Python dependency).

    Python runner is available as fallback via -UsePython during migration window only.

.PARAMETER BinDir
    Directory containing forgewire-runner.exe. Default: C:\ProgramData\forgewire\bin

.PARAMETER HubUrl
    Hub base URL. REQUIRED.

.PARAMETER Token
    Bearer token string. REQUIRED.

.PARAMETER WorkspaceRoot
    Workspace root path on this machine. REQUIRED.

.PARAMETER Tags
    Comma-separated runner tags (e.g. "kind:command,gpu:nvidia"). "kind:command" for
    shell-exec runners; omit or "kind:agent" for Copilot-Chat agent runners.

.PARAMETER ScopePrefixes
    Comma-separated allowed path prefixes. Defaults to WorkspaceRoot.

.PARAMETER MaxConcurrent
    Maximum concurrent tasks. Default: 1.

.PARAMETER UsePython
    Fallback: use Python runner instead of native Rust binary. Migration window only.

.PARAMETER PythonExe
    Python interpreter path. Required when -UsePython is set and python.exe is not on PATH.

.EXAMPLE
    # Standard Rust runner install:
    pwsh -File nssm-install-runner.ps1 `
        -HubUrl http://192.0.2.10:8765 `
        -Token (Get-Content hub.token -Raw) `
        -WorkspaceRoot C:\Projects\forgewire

    # Command runner with kind:command tag:
    pwsh -File nssm-install-runner.ps1 `
        -HubUrl http://192.0.2.10:8765 `
        -Token (Get-Content hub.token -Raw) `
        -WorkspaceRoot C:\Projects\forgewire `
        -Tags "kind:command"

    # Python fallback (migration window only):
    pwsh -File nssm-install-runner.ps1 `
        -HubUrl http://192.0.2.10:8765 `
        -Token (Get-Content hub.token -Raw) `
        -WorkspaceRoot C:\Projects\forgewire `
        -UsePython
#>
[CmdletBinding()]
param(
    [string]$BinDir                      = "C:\ProgramData\forgewire\bin",
    [Parameter(Mandatory)][string]$HubUrl,
    [Parameter(Mandatory)][string]$Token,
    [Parameter(Mandatory)][string]$WorkspaceRoot,
    [string]$Tags                        = "",
    [string]$ScopePrefixes               = "",
    [int]$MaxConcurrent                  = 1,
    [string]$DataDir                     = "C:\ProgramData\forgewire",
    [string]$ServiceName                 = "ForgeWireRunner",
    [switch]$NoWatchdog,
    [switch]$UsePython,
    [string]$PythonExe                   = "",
    # ---- Cross-host hub failover (unchanged from previous version) -------
    [string]$HubSshHost                  = "",
    [string]$HubSshUser                  = "",
    [string]$HubSshKeyFile               = "",
    [string]$HubServiceName              = "ForgeWireHub",
    [string]$HubHealthzUrl               = "",
    [switch]$NoHubWatchdog
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
    throw "nssm.exe not found on PATH. Install from https://nssm.cc/."
}

$LogDir       = Join-Path $DataDir "logs"
$TokenFile    = Join-Path $DataDir "hub.token"
$IdentityFile = Join-Path $DataDir "runner_identity.json"
New-Item -ItemType Directory -Force -Path $DataDir, $LogDir | Out-Null
[System.IO.File]::WriteAllText($TokenFile, $Token.Trim())

# ---- Binary selection -------------------------------------------------------
if ($UsePython) {
    if ([string]::IsNullOrWhiteSpace($PythonExe)) {
        $PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
        if (-not $PythonExe) { throw "Python not found. Provide -PythonExe or drop -UsePython." }
    }
    $AppExe    = $PythonExe
    $AppParams = "-m forgewire_fabric.cli runner start"
    Write-Warning "Using Python runner (migration fallback). Switch to -UsePython:`$false when Rust runner is validated."
} else {
    $AppExe    = Join-Path $BinDir "forgewire-runner.exe"
    if (-not (Test-Path $AppExe)) {
        throw "forgewire-runner.exe not found at $AppExe. Copy the release binary there first."
    }
    $AppParams = ""
    Write-Host "Using native Rust runner: $AppExe"
}

# ---- NSSM service setup ---------------------------------------------------
$prevNative = $PSNativeCommandUseErrorActionPreference
$PSNativeCommandUseErrorActionPreference = $false
& nssm.exe status $ServiceName *>$null
$exists = ($LASTEXITCODE -eq 0)
$PSNativeCommandUseErrorActionPreference = $prevNative

if ($exists) {
    Write-Host "Service '$ServiceName' exists; updating."
    & nssm.exe stop $ServiceName confirm 2>&1 | Out-Null
    Start-Sleep -Seconds 2
} else {
    Write-Host "Installing service '$ServiceName'."
    & nssm.exe install $ServiceName $AppExe | Out-Null
}

& nssm.exe set $ServiceName Application     $AppExe                                          | Out-Null
& nssm.exe set $ServiceName AppParameters   $AppParams                                       | Out-Null
& nssm.exe set $ServiceName AppDirectory    $WorkspaceRoot                                   | Out-Null
& nssm.exe set $ServiceName DisplayName     "ForgeWire Runner$(if (-not $UsePython){ ' (Rust)' })" | Out-Null
& nssm.exe set $ServiceName Description     "ForgeWire Fabric task runner daemon"            | Out-Null
& nssm.exe set $ServiceName Start           SERVICE_AUTO_START                               | Out-Null
& nssm.exe set $ServiceName AppExit Default Restart                                          | Out-Null
& nssm.exe set $ServiceName AppRestartDelay 10000                                            | Out-Null
& nssm.exe set $ServiceName AppStdout       (Join-Path $LogDir "runner.out.log")             | Out-Null
& nssm.exe set $ServiceName AppStderr       (Join-Path $LogDir "runner.err.log")             | Out-Null
& nssm.exe set $ServiceName AppRotateFiles  1                                                | Out-Null
& nssm.exe set $ServiceName AppRotateOnline 1                                                | Out-Null
& nssm.exe set $ServiceName AppRotateBytes  10485760                                         | Out-Null

$scope     = if ($ScopePrefixes) { $ScopePrefixes } else { $WorkspaceRoot }
$envExtra  = @(
    "FORGEWIRE_HUB_URL=$HubUrl",
    "FORGEWIRE_HUB_TOKEN_FILE=$TokenFile",
    "FORGEWIRE_RUNNER_IDENTITY_PATH=$IdentityFile",
    "FORGEWIRE_RUNNER_WORKSPACE_ROOT=$WorkspaceRoot",
    "FORGEWIRE_RUNNER_SCOPE_PREFIXES=$scope",
    "FORGEWIRE_RUNNER_MAX_CONCURRENT=$MaxConcurrent",
    "PYTHONUNBUFFERED=1"
)
if ($Tags) { $envExtra += "FORGEWIRE_RUNNER_TAGS=$Tags" }
& nssm.exe set $ServiceName AppEnvironmentExtra $envExtra | Out-Null

# ---- Start ---------------------------------------------------------------
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
    if ($s -ne 'SERVICE_RUNNING') { throw "Service '$ServiceName' unexpected state: $s. Check $LogDir." }
} finally { $PSNativeCommandUseErrorActionPreference = $prevNative }

Write-Host "Service state : $s"
Write-Host "Hub URL       : $HubUrl"
Write-Host "WorkspaceRoot : $WorkspaceRoot"
Write-Host "Tags          : $(if ($Tags) { $Tags } else { '(none)' })"
Write-Host "Binary        : $AppExe"
Write-Host "Identity      : $IdentityFile"
Write-Host "Logs          : $LogDir"

# ---- Runner watchdog (stale-heartbeat recovery) --------------------------
if (-not $NoWatchdog) {
    $wd = Join-Path $PSScriptRoot "install-runner-watchdog.ps1"
    if (Test-Path $wd) {
        Write-Host "`nInstalling runner watchdog..."
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $wd `
            -ServiceName $ServiceName -HubUrl $HubUrl -TokenFile $TokenFile
    }
}

# ---- Cross-host hub watchdog (optional SSH-based failover) ---------------
if (-not $NoHubWatchdog -and $HubSshHost -and $HubSshUser -and $HubSshKeyFile) {
    $hwatchdog = Join-Path $PSScriptRoot "install-hub-watchdog.ps1"
    if (Test-Path $hwatchdog) {
        Write-Host "`nInstalling cross-host hub watchdog (SSH to $HubSshHost)..."
        $sshDest = Join-Path $DataDir "ssh\hub_failover.key"
        New-Item -ItemType Directory -Force -Path (Split-Path $sshDest) | Out-Null
        Copy-Item $HubSshKeyFile $sshDest -Force
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $hwatchdog `
            -ServiceName $HubServiceName `
            -HealthzUrl  (if ($HubHealthzUrl) { $HubHealthzUrl } else { $HubUrl.TrimEnd('/') + "/healthz" }) `
            -SshHost $HubSshHost -SshUser $HubSshUser -SshKeyFile $sshDest
    }
}

