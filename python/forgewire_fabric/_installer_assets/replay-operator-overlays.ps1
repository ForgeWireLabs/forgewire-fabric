<#
.SYNOPSIS
    Replay every registered operator overlay after install or deployment.
#>
[CmdletBinding()]
param(
    [string]$FabricRoot = '',
    [string]$OperatorStateRoot = 'C:\ProgramData\forgewire-operator',
    [switch]$Build,
    [switch]$StartServices,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
$manifestDirectory = Join-Path $OperatorStateRoot 'manifests'
if (-not (Test-Path -LiteralPath $manifestDirectory)) {
    Write-Host "No registered operator overlays at $manifestDirectory"
    return
}

$installer = Join-Path $PSScriptRoot 'install-operator-overlay.ps1'
$manifests = @(Get-ChildItem -LiteralPath $manifestDirectory -Filter '*.json' -File | Sort-Object Name)
foreach ($manifest in $manifests) {
    Write-Host "Replaying operator overlay $($manifest.BaseName)..." -ForegroundColor Cyan
    & $installer -ManifestPath $manifest.FullName -FabricRoot $FabricRoot `
        -OperatorStateRoot $OperatorStateRoot -Build:$Build `
        -StartServices:$StartServices -ValidateOnly:$ValidateOnly
    if (-not $?) { throw "overlay replay failed: $($manifest.FullName)" }
}
