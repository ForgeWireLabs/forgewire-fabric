<#
.SYNOPSIS
    Remove the current user's ForgeWire Fabric desktop client installation.

.DESCRIPTION
    Removes only UI artifacts: process, installed executable, shortcuts, and
    HKCU uninstall registration. It intentionally does not remove Fabric hub,
    runner, rqlite, hub tokens, dispatcher identities, or ProgramData state.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\ForgeWire Fabric"),
    [switch]$Yes
)

$ErrorActionPreference = "Stop"

function Remove-IfExists {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force -Recurse
        Write-Host "Removed: $Path" -ForegroundColor Green
    }
}

if (-not $Yes) {
    $answer = Read-Host "Remove ForgeWire Fabric desktop UI for $env:USERNAME? [y/N]"
    if ($answer -notmatch "^(y|yes)$") {
        Write-Host "Aborted."
        return
    }
}

$target = Join-Path $InstallDir "ForgeWire Fabric.exe"
Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $target -or $_.ProcessName -eq "ForgeWire Fabric" -or $_.ProcessName -eq "forgewire-fabric-desktop" } |
    Stop-Process -Force -ErrorAction SilentlyContinue

Remove-IfExists (Join-Path ([Environment]::GetFolderPath("Desktop")) "ForgeWire Fabric.lnk")
Remove-IfExists (Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\ForgeWire Fabric.lnk")
Remove-IfExists $InstallDir

$uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ForgeWire Fabric Desktop"
if (Test-Path $uninstallKey) {
    Remove-Item -Path $uninstallKey -Force -Recurse
    Write-Host "Removed: $uninstallKey" -ForegroundColor Green
}

Write-Host "ForgeWire Fabric desktop UI removed. Fabric services and secrets were left intact." -ForegroundColor Green
