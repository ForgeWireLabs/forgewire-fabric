<#
.SYNOPSIS
    Validate an installed ForgeWire Fabric Desktop package against a real Hub.

.DESCRIPTION
    Performs a read-only package smoke test: installation/registry checks,
    process launch, dedicated desktop identity bootstrap, authenticated Hub
    reads, and exact real-host topology verification. The bearer token is read
    only to construct the Authorization header and is never emitted.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\ForgeWire Fabric"),
    [string]$HubUrl = "http://127.0.0.1:8765",
    [string[]]$ExpectedHostnames = @("DESKTOP-228U8GL", "DESKTOP-38GVF8D"),
    [int]$LaunchSeconds = 5
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "ForgeWire Fabric.exe"
$uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ForgeWire Fabric Desktop"
if (-not (Test-Path -LiteralPath $exe)) { throw "Desktop executable is not installed: $exe" }
if (-not (Test-Path -LiteralPath $uninstallKey)) { throw "Desktop uninstall registration is missing" }

$tokenPath = @(
    (Join-Path $env:USERPROFILE ".forgewire\hub.token"),
    (Join-Path $env:ProgramData "forgewire\hub.token")
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $tokenPath) { throw "No installed Fabric Hub token is available" }
$token = (Get-Content -Raw -LiteralPath $tokenPath).Trim()
if (-not $token) { throw "Installed Fabric Hub token is empty" }
$headers = @{ Authorization = "Bearer $token" }

$health = Invoke-RestMethod -Uri "$($HubUrl.TrimEnd('/'))/healthz" -TimeoutSec 10
$hosts = Invoke-RestMethod -Uri "$($HubUrl.TrimEnd('/'))/hosts" -Headers $headers -TimeoutSec 10
$runners = Invoke-RestMethod -Uri "$($HubUrl.TrimEnd('/'))/runners" -Headers $headers -TimeoutSec 10
$actualHosts = @($hosts.hosts | ForEach-Object { [string]$_.hostname } | Sort-Object -Unique)
$expected = @($ExpectedHostnames | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
$actual = @($actualHosts | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
if (($actual -join ',') -ne ($expected -join ',')) {
    throw "Live host inventory mismatch. Expected=$($expected -join ',') Actual=$($actual -join ',')"
}

$process = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
try {
    Start-Sleep -Seconds ([Math]::Max(2, $LaunchSeconds))
    $running = Get-Process -Id $process.Id -ErrorAction Stop
    $workingSet = $running.WorkingSet64
    $cpu = $running.CPU
} finally {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
}

$identityPath = Join-Path $env:USERPROFILE ".forgewire\desktop_dispatcher_identity.json"
if (-not (Test-Path -LiteralPath $identityPath)) {
    throw "Dedicated desktop dispatcher identity was not bootstrapped"
}

[pscustomobject]@{
    Machine = $env:COMPUTERNAME
    PackageSha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    Health = $health.status
    Version = $health.version
    Protocol = $health.protocol_version
    Hosts = $actualHosts
    RunnerCount = @($runners.runners).Count
    IdentityPresent = $true
    WorkingSetBytes = $workingSet
    CpuSeconds = $cpu
} | ConvertTo-Json -Depth 5

