<#
.SYNOPSIS
    Install the ForgeWire Fabric Tauri desktop client for the current Windows user.

.DESCRIPTION
    This installer is intentionally user-scope. It does not require elevation and
    can be run over SSH on runner hosts. It installs the desktop client under
    %LOCALAPPDATA%\Programs\ForgeWire Fabric, creates Desktop and Start Menu
    shortcuts, and registers an HKCU Add/Remove Programs uninstaller entry.

    It does not create or store Fabric secrets. The app reads the installed hub
    token and dispatcher identity from the normal Fabric locations at runtime.
#>
[CmdletBinding()]
param(
    [string]$SourceExe = "",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\ForgeWire Fabric"),
    [switch]$NoDesktopShortcut,
    [switch]$NoStartMenuShortcut
)

$ErrorActionPreference = "Stop"

function Resolve-SourceExe {
    param([string]$Candidate)
    if ($Candidate) {
        $resolved = Resolve-Path -LiteralPath $Candidate -ErrorAction Stop
        return $resolved.Path
    }
    $packageRoot = Split-Path -Parent $PSCommandPath
    foreach ($name in @("ForgeWire Fabric.exe", "forgewire-fabric-desktop.exe")) {
        $path = Join-Path $packageRoot $name
        if (Test-Path -LiteralPath $path) { return $path }
    }
    throw "Could not find ForgeWire Fabric executable beside installer. Pass -SourceExe."
}

function New-Shortcut {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$WorkingDirectory
    )
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $Target
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.IconLocation = "$Target,0"
    $shortcut.Description = "ForgeWire Fabric desktop control panel"
    $shortcut.Save()
}

$source = Resolve-SourceExe $SourceExe
$target = Join-Path $InstallDir "ForgeWire Fabric.exe"
$uninstaller = Join-Path $InstallDir "uninstall-forgewire-fabric-desktop.ps1"

Write-Host "ForgeWire Fabric Desktop Installer" -ForegroundColor Cyan
Write-Host "Source : $source"
Write-Host "Target : $target"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $target } |
    Stop-Process -Force -ErrorAction SilentlyContinue

Copy-Item -LiteralPath $source -Destination $target -Force
Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $PSCommandPath) "uninstall-forgewire-fabric-desktop.ps1") -Destination $uninstaller -Force

if (-not $NoDesktopShortcut) {
    $desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "ForgeWire Fabric.lnk"
    New-Shortcut -Path $desktopShortcut -Target $target -WorkingDirectory $InstallDir
    Write-Host "Desktop shortcut : $desktopShortcut" -ForegroundColor Green
}

if (-not $NoStartMenuShortcut) {
    $startMenu = [Environment]::GetFolderPath("StartMenu")
    $startShortcut = Join-Path $startMenu "Programs\ForgeWire Fabric.lnk"
    New-Shortcut -Path $startShortcut -Target $target -WorkingDirectory $InstallDir
    Write-Host "Start menu       : $startShortcut" -ForegroundColor Green
}

$uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ForgeWire Fabric Desktop"
New-Item -Path $uninstallKey -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "DisplayName" -Value "ForgeWire Fabric" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "DisplayVersion" -Value "0.1.0" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "Publisher" -Value "ForgeWire" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "InstallLocation" -Value $InstallDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "DisplayIcon" -Value "$target,0" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "UninstallString" -Value "pwsh -NoProfile -ExecutionPolicy Bypass -File `"$uninstaller`" -Yes" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "QuietUninstallString" -Value "pwsh -NoProfile -ExecutionPolicy Bypass -File `"$uninstaller`" -Yes" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "NoModify" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "NoRepair" -Value 1 -PropertyType DWord -Force | Out-Null

Write-Host "Installed ForgeWire Fabric desktop for $env:USERNAME." -ForegroundColor Green
