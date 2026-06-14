<#
.SYNOPSIS
    ADDR-5b: install the rqlite suffrage self-heal as a SYSTEM scheduled task.

.DESCRIPTION
    Mirrors the hub/runner watchdog pattern. Runs rqlite-suffrage-selfheal.ps1
    every -IntervalMinutes as SYSTEM; that script no-ops unless THIS node is in
    the 2-voter quorum trap, in which case it self-demotes to non-voter (the
    only fix on rqlite v10, which has no runtime HTTP suffrage mutation).
    Idempotent installer. Self-elevates. ASCII-only.
#>
[CmdletBinding()]
param(
    [string]$ScriptPath = "",                 # defaults to the sibling self-heal script
    [int]$IntervalMinutes = 10,
    [string]$TaskName = "ForgeWireSuffrageSelfHeal"
)
$ErrorActionPreference = "Stop"

$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $shellExe = (Get-Process -Id $PID).Path
    $fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    foreach ($k in $PSBoundParameters.Keys) { $fwd += "-$k"; $fwd += $PSBoundParameters[$k] }
    $p = Start-Process -FilePath $shellExe -Verb RunAs -Wait -PassThru -ArgumentList $fwd
    exit $p.ExitCode
}

if (-not $ScriptPath) { $ScriptPath = Join-Path $PSScriptRoot "rqlite-suffrage-selfheal.ps1" }
if (-not (Test-Path $ScriptPath)) { throw "self-heal script not found: $ScriptPath" }

$pwshCandidates = @(
    "$env:ProgramFiles\PowerShell\7\pwsh.exe",
    "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe",
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
)
$psHost = $null
foreach ($c in $pwshCandidates) { if ($c -and (Test-Path $c)) { $psHost = $c; break } }
if (-not $psHost) { throw "No SYSTEM-reachable PowerShell host found." }

$argLine    = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
$action     = New-ScheduledTaskAction -Execute $psHost -Argument $argLine
$trigger    = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
                -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$principalT = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings   = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable `
                -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
                -MultipleInstances IgnoreNew

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principalT -Settings $settings `
    -Description "ForgeWire rqlite suffrage self-heal (ADDR-5b). Demotes this node to non-voter if caught in the 2-voter quorum trap. No-ops otherwise." | Out-Null

Write-Host "Installed scheduled task '$TaskName' (every $IntervalMinutes min, SYSTEM)."
Write-Host "Script: $ScriptPath"
