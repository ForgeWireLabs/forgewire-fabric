<#
.SYNOPSIS
    Preserve local deployment edits, then fast-forward a standalone clone.

.DESCRIPTION
    Dirty work is committed to an operator/<host>/<timestamp> branch and saved
    as a git bundle outside the clone before main advances. The public mirror is
    never force-reset and no preserved branch is pushed to the public remote.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = 'C:\Projects\forgewire-fabric',
    [string]$Remote = 'origin',
    [string]$Branch = 'main',
    [string]$BackupRoot = 'C:\ProgramData\forgewire-operator\source-backups',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
Push-Location $RepoRoot
try {
    if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot '.git'))) {
        throw "not a standalone git clone: $RepoRoot"
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Net.Dns]::GetHostName() }
    $archiveBranch = "operator/$hostName/$stamp"
    $dirty = @(git status --porcelain=v1)

    if ($dirty.Count -gt 0) {
        Write-Host "Preserving $($dirty.Count) local change(s) on $archiveBranch" -ForegroundColor Yellow
        if (-not $DryRun) {
            git switch -c $archiveBranch
            if ($LASTEXITCODE -ne 0) { throw 'could not create operator archive branch' }
            git add -A
            git commit -m "chore(operator): preserve $hostName deployment edits before sync"
            if ($LASTEXITCODE -ne 0) { throw 'could not commit operator archive branch' }
            New-Item -ItemType Directory -Force -Path $BackupRoot | Out-Null
            $bundle = Join-Path $BackupRoot "$($archiveBranch.Replace('/', '-')).bundle"
            git bundle create $bundle $archiveBranch
            if ($LASTEXITCODE -ne 0) { throw 'could not create operator archive bundle' }
            Write-Host "ARCHIVE_BRANCH=$archiveBranch"
            Write-Host "ARCHIVE_BUNDLE=$bundle"
        }
    }

    if ($DryRun) {
        Write-Host "DRY_RUN: git fetch $Remote; git switch $Branch; git merge --ff-only $Remote/$Branch"
        return
    }

    git fetch $Remote
    if ($LASTEXITCODE -ne 0) { throw "git fetch $Remote failed" }
    git switch $Branch
    if ($LASTEXITCODE -ne 0) { throw "git switch $Branch failed" }
    git merge --ff-only "$Remote/$Branch"
    if ($LASTEXITCODE -ne 0) {
        throw "deployment clone diverged from $Remote/$Branch; preserved state was not overwritten"
    }
    Write-Host "DEPLOYMENT_HEAD=$(git rev-parse HEAD)" -ForegroundColor Green
} finally {
    Pop-Location
}
