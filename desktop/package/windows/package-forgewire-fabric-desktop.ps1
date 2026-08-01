<#
.SYNOPSIS
    Build a complete Windows installer package for ForgeWire Fabric Desktop.

.DESCRIPTION
    Builds the Tauri release executable unless -SkipBuild is passed, then creates
    a zip package containing:
      - ForgeWire Fabric.exe
      - install-forgewire-fabric-desktop.ps1
      - uninstall-forgewire-fabric-desktop.ps1
      - test-forgewire-fabric-desktop.ps1

    The resulting package is suitable for local install, SSH install on the
    second Fabric host, and teardown/reinstall smoke tests.
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$desktopRoot = Resolve-Path (Join-Path $scriptDir "..\..")
if (-not $OutputDir) {
    $OutputDir = Join-Path $desktopRoot "dist-installer"
}
$packageDir = Join-Path $OutputDir "ForgeWire-Fabric-Desktop-Windows-x64"
$zipPath = Join-Path $OutputDir "ForgeWire-Fabric-Desktop-Windows-x64.zip"
$releaseExe = Join-Path $desktopRoot "src-tauri\target\release\forgewire-fabric-desktop.exe"

if (-not $SkipBuild) {
    Push-Location $desktopRoot
    try {
        npm run tauri -- build --no-bundle
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path -LiteralPath $releaseExe)) {
    throw "Missing release executable: $releaseExe. Build first or remove -SkipBuild."
}

if (Test-Path -LiteralPath $packageDir) {
    Remove-Item -LiteralPath $packageDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null

Copy-Item -LiteralPath $releaseExe -Destination (Join-Path $packageDir "ForgeWire Fabric.exe") -Force
Copy-Item -LiteralPath (Join-Path $scriptDir "install-forgewire-fabric-desktop.ps1") -Destination $packageDir -Force
Copy-Item -LiteralPath (Join-Path $scriptDir "uninstall-forgewire-fabric-desktop.ps1") -Destination $packageDir -Force
Copy-Item -LiteralPath (Join-Path $scriptDir "test-forgewire-fabric-desktop.ps1") -Destination $packageDir -Force

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $zipPath -Force

[pscustomobject]@{
    PackageDirectory = $packageDir
    ZipPath = $zipPath
    Executable = Join-Path $packageDir "ForgeWire Fabric.exe"
    Installer = Join-Path $packageDir "install-forgewire-fabric-desktop.ps1"
    Uninstaller = Join-Path $packageDir "uninstall-forgewire-fabric-desktop.ps1"
    Validator = Join-Path $packageDir "test-forgewire-fabric-desktop.ps1"
} | Format-List
