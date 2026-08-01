<#
.SYNOPSIS
    Validate, register, and apply operator-owned ForgeWire service overlays.

.DESCRIPTION
    Operator overlays are declarative JSON manifests owned by a consumer repo.
    Registered manifests are copied under C:\ProgramData\forgewire-operator,
    outside the Fabric data tree removed by uninstall-fabric.ps1. Replaying an
    overlay rebuilds declared Cargo packages, migrates durable identity files,
    installs or repairs NSSM services, and optionally starts them.

    Secret values do not belong in manifests. Point services at ACL-protected
    token/key files instead.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [string]$FabricRoot = '',
    [string]$OperatorStateRoot = 'C:\ProgramData\forgewire-operator',
    [switch]$Build,
    [switch]$Register,
    [switch]$StartServices,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'

function Expand-OverlayPath {
    param([Parameter(Mandatory)][string]$Path)
    [Environment]::ExpandEnvironmentVariables($Path)
}

function Assert-AbsolutePath {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)
    $expanded = Expand-OverlayPath $Path
    if (-not [IO.Path]::IsPathRooted($expanded)) {
        throw "$Label must be absolute: $Path"
    }
    $expanded
}

function Set-SystemAdminAcl {
    param([Parameter(Mandatory)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($principal in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            'FullControl',
            'Allow'
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Resolve-Nssm {
    $command = Get-Command nssm.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    foreach ($serviceName in @('ForgeWireHub', 'ForgeWireRunner')) {
        $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
        $imagePath = (Get-ItemProperty $serviceKey -ErrorAction SilentlyContinue).ImagePath
        if ($imagePath) {
            $candidate = $imagePath.Trim('"')
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }
    }
    throw 'nssm.exe was not found on PATH or through an installed ForgeWire service.'
}

function Invoke-Nssm {
    param(
        [Parameter(Mandatory)][string]$Nssm,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    & $Nssm @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "nssm failed ($LASTEXITCODE): $($Arguments -join ' ')"
    }
}

$resolvedManifest = (Resolve-Path -LiteralPath $ManifestPath).Path
$manifest = Get-Content -LiteralPath $resolvedManifest -Raw | ConvertFrom-Json

if ($manifest.schema_version -ne 1) { throw 'overlay schema_version must be 1' }
if ($manifest.name -notmatch '^[a-z0-9][a-z0-9-]{1,62}$') {
    throw 'overlay name must be 2-63 lowercase letters, digits, or hyphens'
}
if (-not $manifest.services -or @($manifest.services).Count -eq 0) {
    throw 'overlay must declare at least one service'
}

$serviceNames = @{}
foreach ($service in @($manifest.services)) {
    if ($service.name -notmatch '^ForgeWire[A-Za-z0-9_-]+$') {
        throw "invalid ForgeWire service name: $($service.name)"
    }
    if ($serviceNames.ContainsKey($service.name)) {
        throw "duplicate service name: $($service.name)"
    }
    $serviceNames[$service.name] = $true
    [void](Assert-AbsolutePath $service.executable "service $($service.name) executable")
    [void](Assert-AbsolutePath $service.working_directory "service $($service.name) working_directory")
    if ($service.startup -notin @('automatic', 'manual', 'disabled')) {
        throw "service $($service.name) startup must be automatic, manual, or disabled"
    }
    foreach ($property in $service.environment.PSObject.Properties) {
        if ($property.Name -notmatch '^[A-Z][A-Z0-9_]*$') {
            throw "invalid environment key on $($service.name): $($property.Name)"
        }
        $value = [string]$property.Value
        if ($value.Contains("`r") -or $value.Contains("`n") -or $value.Contains([char]0)) {
            throw "environment value for $($property.Name) contains a forbidden control character"
        }
        if ($property.Name -match '(TOKEN|SECRET|PASSWORD|PRIVATE_KEY)$' -and
            $property.Name -notmatch '(_FILE|_PATH)$') {
            throw "secret value key $($property.Name) is forbidden; use an ACL-protected *_FILE path"
        }
    }
}

foreach ($artifact in @($manifest.artifacts | Where-Object { $null -ne $_ })) {
    if (-not $artifact.source -or -not $artifact.destination) {
        throw 'each artifact requires source and destination'
    }
    [void](Assert-AbsolutePath $artifact.destination 'artifact destination')
}
foreach ($migration in @($manifest.migrate_files | Where-Object { $null -ne $_ })) {
    [void](Assert-AbsolutePath $migration.source 'migration source')
    [void](Assert-AbsolutePath $migration.destination 'migration destination')
}

Write-Host "Overlay '$($manifest.name)' is valid ($(@($manifest.services).Count) service(s))." -ForegroundColor Green
if ($ValidateOnly) { return }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $shellExe = (Get-Process -Id $PID).Path
    $forwarded = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $value = $entry.Value
        if ($value -is [switch]) {
            if ($value.IsPresent) { $forwarded += "-$($entry.Key)" }
        } else {
            $forwarded += "-$($entry.Key)"
            $forwarded += [string]$value
        }
    }
    $process = Start-Process -FilePath $shellExe -Verb RunAs -Wait -PassThru -ArgumentList $forwarded
    exit $process.ExitCode
}

if (-not $FabricRoot) {
    $FabricRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
} else {
    $FabricRoot = (Resolve-Path -LiteralPath $FabricRoot).Path
}

if ($Build) {
    $packages = @($manifest.artifacts | ForEach-Object { $_.cargo_package } |
        Where-Object { $_ } | Sort-Object -Unique)
    foreach ($package in $packages) {
        Write-Host "Building Cargo package $package..." -ForegroundColor Cyan
        Push-Location $FabricRoot
        try {
            & cargo build --release -p $package
            if ($LASTEXITCODE -ne 0) { throw "cargo build failed for $package" }
        } finally {
            Pop-Location
        }
    }
}

foreach ($migration in @($manifest.migrate_files | Where-Object { $null -ne $_ })) {
    $source = Assert-AbsolutePath $migration.source 'migration source'
    $destination = Assert-AbsolutePath $migration.destination 'migration destination'
    if (-not (Test-Path -LiteralPath $destination) -and (Test-Path -LiteralPath $source)) {
        New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination -Force
        if ($migration.acl -eq 'system-admin') { Set-SystemAdminAcl $destination }
        Write-Host "Migrated durable state to $destination"
    }
}

$nssm = Resolve-Nssm
$resolvedArtifacts = @()
foreach ($artifact in @($manifest.artifacts | Where-Object { $null -ne $_ })) {
    $source = [string]$artifact.source
    if (-not [IO.Path]::IsPathRooted($source)) { $source = Join-Path $FabricRoot $source }
    if (-not (Test-Path -LiteralPath $source) -and $artifact.cached_source) {
        $source = Assert-AbsolutePath $artifact.cached_source 'artifact cached_source'
    }
    $resolvedArtifacts += [pscustomobject]@{
        Source = (Resolve-Path -LiteralPath $source).Path
        Destination = Assert-AbsolutePath $artifact.destination 'artifact destination'
    }
}

$wasRunning = @{}
foreach ($service in @($manifest.services)) {
    $existingService = Get-Service -Name $service.name -ErrorAction SilentlyContinue
    $wasRunning[[string]$service.name] = $existingService -and $existingService.Status -eq 'Running'
    Stop-Service -Name $service.name -Force -ErrorAction SilentlyContinue
}

try {
foreach ($artifact in $resolvedArtifacts) {
    $source = $artifact.Source
    $destination = $artifact.Destination
    New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
    $temporary = "$destination.new"
    Copy-Item -LiteralPath $source -Destination $temporary -Force
    Move-Item -LiteralPath $temporary -Destination $destination -Force
    Write-Host "Installed artifact $destination"
}

foreach ($service in @($manifest.services)) {
    $name = [string]$service.name
    $executable = Assert-AbsolutePath $service.executable "service $name executable"
    $workingDirectory = Assert-AbsolutePath $service.working_directory "service $name working_directory"
    if (-not (Test-Path -LiteralPath $executable)) { throw "missing service executable: $executable" }
    if (-not (Test-Path -LiteralPath $workingDirectory)) { throw "missing working directory: $workingDirectory" }

    if (-not (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
        Invoke-Nssm $nssm @('install', $name, $executable)
    }
    Invoke-Nssm $nssm @('set', $name, 'Application', $executable)
    Invoke-Nssm $nssm @('set', $name, 'AppDirectory', $workingDirectory)
    $parametersKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$name\Parameters"
    New-ItemProperty -Path $parametersKey -Name AppParameters -Value '' `
        -PropertyType String -Force | Out-Null
    if ($service.display_name) { Invoke-Nssm $nssm @('set', $name, 'DisplayName', [string]$service.display_name) }
    if ($service.description) { Invoke-Nssm $nssm @('set', $name, 'Description', [string]$service.description) }
    $startMode = @{
        automatic = 'SERVICE_AUTO_START'
        manual = 'SERVICE_DEMAND_START'
        disabled = 'SERVICE_DISABLED'
    }[[string]$service.startup]
    Invoke-Nssm $nssm @('set', $name, 'Start', $startMode)
    Invoke-Nssm $nssm @('set', $name, 'AppExit', 'Default', 'Restart')
    Invoke-Nssm $nssm @('set', $name, 'AppRestartDelay', '10000')

    foreach ($stream in @('stdout', 'stderr')) {
        $logPath = [string]$service.$stream
        if ($logPath) {
            $logPath = Assert-AbsolutePath $logPath "service $name $stream"
            New-Item -ItemType Directory -Force -Path (Split-Path $logPath -Parent) | Out-Null
            $nssmKey = if ($stream -eq 'stdout') { 'AppStdout' } else { 'AppStderr' }
            Invoke-Nssm $nssm @('set', $name, $nssmKey, $logPath)
        }
    }
    Invoke-Nssm $nssm @('set', $name, 'AppRotateFiles', '1')
    Invoke-Nssm $nssm @('set', $name, 'AppRotateOnline', '1')
    Invoke-Nssm $nssm @('set', $name, 'AppRotateBytes', '10485760')

    $environment = @($service.environment.PSObject.Properties |
        Sort-Object Name | ForEach-Object { "$($_.Name)=$([string]$_.Value)" })
    Invoke-Nssm $nssm (@('set', $name, 'AppEnvironmentExtra') + $environment)

    $shouldRun = ($StartServices -and $service.desired_state -eq 'running') -or
        (-not $StartServices -and $wasRunning[$name])
    if ($shouldRun) {
        Start-Service -Name $name
        (Get-Service -Name $name).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
    }
    $status = (Get-Service -Name $name).Status
    Write-Host "$name configured (startup=$($service.startup), status=$status)" -ForegroundColor Green
}
} catch {
    $errorDirectory = Join-Path $OperatorStateRoot 'logs'
    New-Item -ItemType Directory -Force -Path $errorDirectory | Out-Null
    $errorPath = Join-Path $errorDirectory 'last-overlay-error.txt'
    ($_ | Format-List * -Force | Out-String) | Set-Content -LiteralPath $errorPath -Encoding UTF8
    foreach ($service in @($manifest.services)) {
        if ($wasRunning[[string]$service.name]) {
            Start-Service -Name $service.name -ErrorAction SilentlyContinue
        }
    }
    Write-Error "Operator overlay failed; diagnostic saved at $errorPath"
    throw
}

$lastErrorPath = Join-Path (Join-Path $OperatorStateRoot 'logs') 'last-overlay-error.txt'
if (Test-Path -LiteralPath $lastErrorPath) {
    Remove-Item -LiteralPath $lastErrorPath -Force
}

if ($Register) {
    $manifestDirectory = Join-Path $OperatorStateRoot 'manifests'
    $artifactDirectory = Join-Path $OperatorStateRoot "artifacts\$($manifest.name)"
    New-Item -ItemType Directory -Force -Path $manifestDirectory | Out-Null
    New-Item -ItemType Directory -Force -Path $artifactDirectory | Out-Null
    foreach ($artifact in @($manifest.artifacts | Where-Object { $null -ne $_ })) {
        $installed = Assert-AbsolutePath $artifact.destination 'artifact destination'
        $cached = Join-Path $artifactDirectory (Split-Path $installed -Leaf)
        Copy-Item -LiteralPath $installed -Destination $cached -Force
        if ($artifact.PSObject.Properties['cached_source']) {
            $artifact.cached_source = $cached
        } else {
            $artifact | Add-Member -NotePropertyName cached_source -NotePropertyValue $cached
        }
    }
    $registeredPath = Join-Path $manifestDirectory "$($manifest.name).json"
    $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $registeredPath -Encoding UTF8
    Write-Host "Registered overlay at $registeredPath" -ForegroundColor Green
}
