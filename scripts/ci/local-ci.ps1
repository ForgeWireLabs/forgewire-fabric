#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("Fast", "Full", "Live")]
    [string]$Mode = "Fast",

    [Parameter()]
    [switch]$AllowLiveCluster
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$LiveClusterEnv = "FORGEWIRE_TEST_ALLOW_LIVE_CLUSTER"
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = (
    Resolve-Path -LiteralPath (
        Join-Path $ScriptDirectory "..\.."
    )
).Path

$PreviousLiveClusterValue = [Environment]::GetEnvironmentVariable(
    $LiveClusterEnv,
    "Process"
)

function Assert-Tool {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required local-CI tool is unavailable: $Name"
    }
}

function Invoke-ExternalStep {
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory)]
        [string]$Command,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    Write-Host "`n== $Label =="

    & $Command @Arguments
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode."
    }
}

function Test-PowerShellSyntax {
    Write-Host "`n== PowerShell syntax =="

    $scriptRoot = Join-Path $RepositoryRoot "scripts"
    $files = Get-ChildItem `
        -LiteralPath $scriptRoot `
        -Recurse `
        -File `
        -Filter "*.ps1"

    $failures = [System.Collections.Generic.List[string]]::new()

    foreach ($file in $files) {
        $tokens = $null
        $parseErrors = $null

        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $file.FullName,
            [ref]$tokens,
            [ref]$parseErrors
        )

        foreach ($parseError in $parseErrors) {
            $failures.Add(
                "$($file.FullName):" +
                "$($parseError.Extent.StartLineNumber): " +
                $parseError.Message
            )
        }
    }

    if ($failures.Count -gt 0) {
        throw (
            "PowerShell syntax validation failed:`n" +
            ($failures -join "`n")
        )
    }

    Write-Host "Parsed $($files.Count) PowerShell scripts."
}

function Invoke-FastChecks {
    Test-PowerShellSyntax

    Invoke-ExternalStep `
        -Label "Python syntax" `
        -Command "python" `
        -Arguments @(
            "-m",
            "compileall",
            "-q",
            "python",
            "tests"
        )

    Invoke-ExternalStep `
        -Label "Rust formatting" `
        -Command "cargo" `
        -Arguments @(
            "fmt",
            "--all",
            "--",
            "--check"
        )

    Invoke-ExternalStep `
        -Label "Focused Python contracts" `
        -Command "python" `
        -Arguments @(
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "tests/test_installer_assets_in_sync.py",
            "tests/test_versioning_doc_matches_sources.py",
            "tests/test_local_ci_contract.py",
            "-q"
        )
}

Push-Location $RepositoryRoot

try {
    Assert-Tool -Name "pwsh"
    Assert-Tool -Name "python"
    Assert-Tool -Name "cargo"

    if ($Mode -eq "Live") {
        if (-not $AllowLiveCluster) {
            throw (
                "Live mode requires -AllowLiveCluster because these tests " +
                "may read, mutate, or clean shared rqlite state."
            )
        }

        Set-Item `
            -Path "Env:$LiveClusterEnv" `
            -Value "1"
    }
    else {
        Remove-Item `
            -Path "Env:$LiveClusterEnv" `
            -ErrorAction SilentlyContinue
    }

    switch ($Mode) {
        "Fast" {
            Invoke-FastChecks
        }

        "Full" {
            Invoke-FastChecks

            Invoke-ExternalStep `
                -Label "Deterministic Python suite" `
                -Command "python" `
                -Arguments @(
                    "-m",
                    "pytest",
                    "-p",
                    "no:cacheprovider",
                    "-m",
                    "not live_cluster",
                    "-q"
                )

            Invoke-ExternalStep `
                -Label "Rust workspace suite" `
                -Command "cargo" `
                -Arguments @(
                    "test",
                    "--workspace"
                )
        }

        "Live" {
            Invoke-ExternalStep `
                -Label "Live-cluster Python suite" `
                -Command "python" `
                -Arguments @(
                    "-m",
                    "pytest",
                    "-p",
                    "no:cacheprovider",
                    "-m",
                    "live_cluster",
                    "-q"
                )
        }
    }

    Write-Host "`nLocal CI mode '$Mode' passed."
}
finally {
    if ($null -eq $PreviousLiveClusterValue) {
        Remove-Item `
            -Path "Env:$LiveClusterEnv" `
            -ErrorAction SilentlyContinue
    }
    else {
        Set-Item `
            -Path "Env:$LiveClusterEnv" `
            -Value $PreviousLiveClusterValue
    }

    Pop-Location
}
