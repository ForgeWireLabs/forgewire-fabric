<#
.SYNOPSIS
    One-command ForgeWire Fabric installer. Sets up the entire stack OOTB.

.DESCRIPTION
    Run this on any Windows machine to join the ForgeWire Fabric cluster.
    The script auto-detects whether this is the first node (installs hub +
    rqlite + runner) or a joining node (discovers existing hub, installs
    runner only).

    What gets installed:
      1. rqlite    — Raft-replicated database (NSSM service)
      2. Hub       — Signed dispatch control plane (NSSM service, first node only)
      3. Runner    — Command runner background service (NSSM service)
      4. Watchdogs — Hub + runner liveness probes (scheduled tasks)
      5. VSIX      — VS Code extension for the Fabric sidebar
      6. MCP       — Dispatcher + agent-runner MCP server registration
      7. Identity  — Ed25519 keypair + signed dispatcher registration

    Subsequent nodes only install runner + watchdog + VSIX + MCP and point
    at the discovered hub. Hub + rqlite are skipped unless -ForceHub is set.

.PARAMETER WorkspaceRoot
    Absolute path the runner clones / executes inside. REQUIRED.

.PARAMETER Token
    Bearer token for hub authentication. On the first node this is
    auto-generated if omitted. On joining nodes this MUST match the
    hub's token (copy from the first node's C:\ProgramData\forgewire\hub.token).

.PARAMETER FabricRoot
    Path to the forgewire-fabric repo checkout. Default: auto-detected
    from the location of this script (../../).

.PARAMETER ForceHub
    Install the hub even if an existing hub is discovered on the LAN.

.PARAMETER HubUrl
    Explicit hub URL to use instead of auto-discovery.

.PARAMETER SkipVsix
    Skip VS Code extension installation.

.PARAMETER SkipMcp
    Skip MCP server registration.

.EXAMPLE
    # First node (auto-generates token, installs everything):
    pwsh -File install-fabric.ps1 -WorkspaceRoot C:\Projects\forgewire

    # Joining node (provide the token from the first node):
    pwsh -File install-fabric.ps1 -WorkspaceRoot C:\Projects\forgewire `
        -Token (Get-Content \\first-node\ProgramData\forgewire\hub.token -Raw)

    # Explicit hub URL (skip discovery):
    pwsh -File install-fabric.ps1 -WorkspaceRoot C:\Projects\forgewire `
        -HubUrl http://10.43.106.95:8765 `
        -Token (Get-Content $HOME\.forgewire\hub.token -Raw)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WorkspaceRoot,
    [string]$Token = "",
    [string]$FabricRoot = "",
    [switch]$ForceHub,
    [string]$HubUrl = "",
    [switch]$SkipVsix,
    [switch]$SkipMcp,
    [string]$DataDir = "C:\ProgramData\forgewire",
    [int]$HubPort = 8765,
    [int]$RqliteHttpPort = 4001,
    [int]$RqliteRaftPort = 4002,
    [string]$Tags = "",
    [string]$ScopePrefixes = "",
    [int]$MaxConcurrent = 1
)

$ErrorActionPreference = "Stop"

# ---- Locate fabric root ----------------------------------------------------
if (-not $FabricRoot) {
    $FabricRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
if (-not (Test-Path (Join-Path $FabricRoot "pyproject.toml"))) {
    throw "Cannot find pyproject.toml at $FabricRoot. Pass -FabricRoot explicitly."
}
Write-Host "Fabric root: $FabricRoot" -ForegroundColor Cyan

# ---- Locate Python ----------------------------------------------------------
$PythonExe = $null
$candidates = @(
    (Join-Path $FabricRoot ".venv\Scripts\python.exe"),
    (Join-Path $WorkspaceRoot ".venv\Scripts\python.exe")
)
foreach ($cand in $candidates) {
    if (Test-Path $cand) { $PythonExe = $cand; break }
}
if (-not $PythonExe) {
    $PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
}
if (-not $PythonExe -or -not (Test-Path $PythonExe)) {
    throw "Python not found. Create a venv at $FabricRoot\.venv or install Python globally."
}
Write-Host "Python: $PythonExe"

# ---- Ensure forgewire-fabric is installed -----------------------------------
$importTest = & $PythonExe -c "import forgewire_fabric; print(forgewire_fabric.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing forgewire-fabric into the venv..."
    & $PythonExe -m pip install -e "$FabricRoot[mdns]" --quiet
    $importTest = & $PythonExe -c "import forgewire_fabric; print(forgewire_fabric.__version__)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install forgewire-fabric: $importTest"
    }
}
Write-Host "forgewire-fabric v$($importTest.Trim())"

# ---- Token generation or validation ----------------------------------------
if (-not $Token) {
    $existingTokenFile = Join-Path $DataDir "hub.token"
    if (Test-Path $existingTokenFile) {
        $Token = (Get-Content $existingTokenFile -Raw -ErrorAction SilentlyContinue)
        if ($Token) {
            $Token = $Token.Trim()
            Write-Host "Using existing token from $existingTokenFile"
        }
    }
}
if (-not $Token) {
    # Generate a new token (first node)
    $Token = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
    Write-Host "Generated new bearer token (first node install)." -ForegroundColor Yellow
    Write-Host "  Save this token for joining nodes: $Token"
}
if ($Token.Length -lt 16) {
    throw "Token must be >= 16 characters."
}

# Also write to user home for VSIX / CLI use
$userTokenDir = Join-Path $HOME ".forgewire"
$userTokenFile = Join-Path $userTokenDir "hub.token"
New-Item -ItemType Directory -Force -Path $userTokenDir | Out-Null
[System.IO.File]::WriteAllText($userTokenFile, $Token)
Write-Host "Token written to $userTokenFile"

# ---- Discover existing hub --------------------------------------------------
$discoveredHub = ""
if (-not $HubUrl -and -not $ForceHub) {
    Write-Host ""
    Write-Host "Scanning LAN for existing ForgeWire hub (mDNS)..." -ForegroundColor Cyan
    $discovery = & $PythonExe -c "
import json
try:
    from forgewire_fabric.hub.discovery import discover_hubs
    hubs = discover_hubs(timeout=4.0)
    print(json.dumps(hubs))
except Exception as e:
    print(json.dumps([]))
" 2>&1 | Out-String
    try {
        $hubs = $discovery.Trim() | ConvertFrom-Json
    } catch {
        $hubs = @()
    }
    if ($hubs.Count -gt 0) {
        $best = $hubs | Sort-Object { $_.protocol_version } -Descending | Select-Object -First 1
        $discoveredHub = "http://$($best.host):$($best.port)"
        Write-Host "  Discovered hub: $discoveredHub (protocol v$($best.protocol_version))" -ForegroundColor Green
    } else {
        Write-Host "  No hub found on LAN. This node will become the hub." -ForegroundColor Yellow
    }
}

$effectiveHubUrl = if ($HubUrl) { $HubUrl } elseif ($discoveredHub) { $discoveredHub } else { "" }
$isHubNode = (-not $effectiveHubUrl) -or $ForceHub

# ---- Step 1: rqlite (hub nodes only) ----------------------------------------
if ($isHubNode) {
    Write-Host ""
    Write-Host "==[ Step 1/7 ]== Installing rqlite..." -ForegroundColor Cyan
    $rqliteInstaller = Join-Path $PSScriptRoot "nssm-install-rqlite.ps1"
    if (-not (Test-Path $rqliteInstaller)) {
        throw "nssm-install-rqlite.ps1 not found at $rqliteInstaller"
    }
    & $rqliteInstaller -DataDir $DataDir -HttpPort $RqliteHttpPort -RaftPort $RqliteRaftPort
    Write-Host "==[ Step 1/7 ]== rqlite installed." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "==[ Step 1/7 ]== Skipping rqlite (joining existing hub at $effectiveHubUrl)." -ForegroundColor DarkGray
}

# ---- Step 2: Hub (hub nodes only) ------------------------------------------
if ($isHubNode) {
    Write-Host ""
    Write-Host "==[ Step 2/7 ]== Installing hub..." -ForegroundColor Cyan
    $hubInstaller = Join-Path $PSScriptRoot "nssm-install-hub.ps1"
    & $hubInstaller `
        -PythonExe $PythonExe `
        -Token $Token `
        -Port $HubPort `
        -Backend "rqlite" `
        -RqliteHost "127.0.0.1" `
        -RqlitePort $RqliteHttpPort
    $effectiveHubUrl = "http://127.0.0.1:$HubPort"
    Write-Host "==[ Step 2/7 ]== Hub installed." -ForegroundColor Green

    # Wait for hub to start advertising via mDNS
    Write-Host "Waiting for hub to become reachable..."
    $hubReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $resp = Invoke-WebRequest -Uri "$effectiveHubUrl/healthz" -UseBasicParsing -TimeoutSec 3
            if ($resp.StatusCode -eq 200) {
                $hubReady = $true
                break
            }
        } catch {}
    }
    if (-not $hubReady) {
        Write-Warning "Hub did not respond within 30s — check logs at $DataDir\logs\hub.err.log"
    } else {
        Write-Host "Hub is reachable at $effectiveHubUrl" -ForegroundColor Green
    }
} else {
    Write-Host ""
    Write-Host "==[ Step 2/7 ]== Skipping hub install (using discovered hub)." -ForegroundColor DarkGray
}

# ---- Step 3: Runner ----------------------------------------------------------
Write-Host ""
Write-Host "==[ Step 3/7 ]== Installing runner..." -ForegroundColor Cyan
$runnerInstaller = Join-Path $PSScriptRoot "nssm-install-runner.ps1"
$runnerArgs = @{
    PythonExe     = $PythonExe
    HubUrl        = $effectiveHubUrl
    Token         = $Token
    WorkspaceRoot = $WorkspaceRoot
    MaxConcurrent = $MaxConcurrent
}
if ($Tags)          { $runnerArgs["Tags"] = $Tags }
if ($ScopePrefixes) { $runnerArgs["ScopePrefixes"] = $ScopePrefixes }
& $runnerInstaller @runnerArgs
Write-Host "==[ Step 3/7 ]== Runner installed." -ForegroundColor Green

# ---- Step 4: Watchdogs -------------------------------------------------------
Write-Host ""
Write-Host "==[ Step 4/7 ]== Installing watchdogs..." -ForegroundColor Cyan
$hubWatchdog = Join-Path $PSScriptRoot "install-hub-watchdog.ps1"
$runnerWatchdog = Join-Path $PSScriptRoot "install-runner-watchdog.ps1"
if ($isHubNode -and (Test-Path $hubWatchdog)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $hubWatchdog `
        -ServiceName "ForgeWireHub" `
        -HealthzUrl "http://127.0.0.1:$HubPort/healthz"
    Write-Host "  Hub watchdog installed."
}
if (Test-Path $runnerWatchdog) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runnerWatchdog `
        -ServiceName "ForgeWireRunner" `
        -HubUrl $effectiveHubUrl
    Write-Host "  Runner watchdog installed."
}
Write-Host "==[ Step 4/7 ]== Watchdogs installed." -ForegroundColor Green

# ---- Step 5: VSIX ------------------------------------------------------------
if (-not $SkipVsix) {
    Write-Host ""
    Write-Host "==[ Step 5/7 ]== Installing VS Code extension..." -ForegroundColor Cyan
    $vsixDir = Join-Path $FabricRoot "vscode"
    if (-not (Get-Command code -ErrorAction SilentlyContinue) -and
        -not (Get-Command code.cmd -ErrorAction SilentlyContinue)) {
        Write-Warning "VS Code not found on PATH. Skipping VSIX install."
    } else {
        # Find the latest pre-built vsix
        $vsixFile = Get-ChildItem $vsixDir -Filter "forgewire-fabric-*.vsix" -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            Select-Object -First 1
        if ($vsixFile) {
            $codeCmd = if (Get-Command code.cmd -ErrorAction SilentlyContinue) { "code.cmd" } else { "code" }
            & $codeCmd --install-extension $vsixFile.FullName --force 2>&1 | Out-Null
            Write-Host "  Installed $($vsixFile.Name)"
        } else {
            # Try to build the vsix if npm is available
            if (Get-Command npx -ErrorAction SilentlyContinue) {
                Write-Host "  No pre-built VSIX found. Building..."
                Push-Location $vsixDir
                try {
                    $pkgVersion = (Get-Content "package.json" -Raw | ConvertFrom-Json).version
                    $built = "forgewire-fabric-$pkgVersion.vsix"
                    npx --yes @vscode/vsce package --out $built 2>&1 | Out-Null
                    if (Test-Path $built) {
                        $codeCmd = if (Get-Command code.cmd -ErrorAction SilentlyContinue) { "code.cmd" } else { "code" }
                        & $codeCmd --install-extension $built --force 2>&1 | Out-Null
                        Write-Host "  Built and installed $built"
                    } else {
                        Write-Warning "VSIX build failed. Install manually later."
                    }
                } finally { Pop-Location }
            } else {
                Write-Warning "No pre-built VSIX and npx not available. Install VSIX manually."
            }
        }

        # Write VS Code workspace settings with the hub URL
        $vsWorkspace = Join-Path $WorkspaceRoot ".vscode"
        New-Item -ItemType Directory -Force -Path $vsWorkspace | Out-Null
        $vsSettingsPath = Join-Path $vsWorkspace "settings.json"
        $vsSettings = @{}
        if (Test-Path $vsSettingsPath) {
            try { $vsSettings = Get-Content $vsSettingsPath -Raw | ConvertFrom-Json -AsHashtable } catch {}
        }
        # For hub nodes, use 127.0.0.1 as primary (always reachable)
        # For joining nodes, use the discovered hub URL
        $primaryUrl = if ($isHubNode) { "http://127.0.0.1:$HubPort" } else { $effectiveHubUrl }
        $vsSettings["forgewireFabric.hubUrl"] = $primaryUrl
        $vsSettings["forgewireFabric.hubTokenFile"] = $userTokenFile
        $vsSettings["forgewireFabric.hubCandidates"] = @(
            @{ url = $primaryUrl; label = "Primary"; priority = 1 }
        )
        $vsSettings | ConvertTo-Json -Depth 4 | Set-Content $vsSettingsPath -Encoding UTF8
        Write-Host "  VS Code workspace settings updated: $vsSettingsPath"
    }
    Write-Host "==[ Step 5/7 ]== VSIX installed." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "==[ Step 5/7 ]== Skipping VSIX install (-SkipVsix)." -ForegroundColor DarkGray
}

# ---- Step 6: MCP registration ------------------------------------------------
if (-not $SkipMcp) {
    Write-Host ""
    Write-Host "==[ Step 6/7 ]== Registering MCP servers..." -ForegroundColor Cyan
    $oldHubUrl = $env:FORGEWIRE_HUB_URL
    $oldHubToken = $env:FORGEWIRE_HUB_TOKEN
    try {
        $env:FORGEWIRE_HUB_URL = $effectiveHubUrl
        $env:FORGEWIRE_HUB_TOKEN = $Token.Trim()

        # Register dispatcher + runner MCP
        & $PythonExe -m forgewire_fabric.cli mcp install --hub-url $effectiveHubUrl --with-runner --workspace-root $WorkspaceRoot 2>&1 | Out-Null
        Write-Host "  MCP servers registered in user mcp.json."

        # Register signed dispatcher identity
        & $PythonExe -m forgewire_fabric.cli dispatchers register --hostname $env:COMPUTERNAME 2>&1 | Out-Null
        Write-Host "  Dispatcher identity registered with hub."
    } catch {
        Write-Warning "MCP/dispatcher registration failed: $($_.Exception.Message)"
        Write-Warning "You can retry manually: forgewire-fabric mcp install --hub-url $effectiveHubUrl --with-runner"
    } finally {
        $env:FORGEWIRE_HUB_URL = $oldHubUrl
        $env:FORGEWIRE_HUB_TOKEN = $oldHubToken
    }
    Write-Host "==[ Step 6/7 ]== MCP registered." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "==[ Step 6/7 ]== Skipping MCP registration (-SkipMcp)." -ForegroundColor DarkGray
}

# ---- Step 7: Report host roles -----------------------------------------------
Write-Host ""
Write-Host "==[ Step 7/7 ]== Reporting host roles to hub..." -ForegroundColor Cyan
$headers = @{ Authorization = "Bearer $($Token.Trim())" }
$roles = @("command_runner")
if ($isHubNode) { $roles += "hub_head" }
foreach ($role in $roles) {
    $body = @{
        hostname = $env:COMPUTERNAME
        role     = $role
        enabled  = $true
        status   = "installed"
        metadata = @{ installer = "install-fabric.ps1"; timestamp = (Get-Date).ToUniversalTime().ToString("o") }
    } | ConvertTo-Json -Depth 4
    try {
        Invoke-RestMethod -Method Post -Uri "$effectiveHubUrl/hosts/roles" `
            -Headers $headers -ContentType "application/json" -Body $body -TimeoutSec 5 | Out-Null
        Write-Host "  Reported: $role"
    } catch {
        Write-Warning "Could not report role '$role': $($_.Exception.Message)"
    }
}
Write-Host "==[ Step 7/7 ]== Host roles reported." -ForegroundColor Green

# ---- Summary -----------------------------------------------------------------
Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host " ForgeWire Fabric installation complete!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""
if ($isHubNode) {
    Write-Host "  This node is: HUB + RUNNER" -ForegroundColor White
    Write-Host "  Hub URL:      $effectiveHubUrl"
    Write-Host "  rqlite:       http://127.0.0.1:$RqliteHttpPort"
} else {
    Write-Host "  This node is: RUNNER (hub at $effectiveHubUrl)" -ForegroundColor White
}
Write-Host "  Runner:       ForgeWireRunner (NSSM service)"
Write-Host "  Token:        $userTokenFile"
Write-Host "  Workspace:    $WorkspaceRoot"
Write-Host "  Logs:         $DataDir\logs"
Write-Host ""
Write-Host "  To add another node to this cluster:" -ForegroundColor Yellow
Write-Host "    1. Copy the token: scp $($env:COMPUTERNAME):$userTokenFile .\hub.token"
Write-Host "    2. On the new machine:"
Write-Host "       pwsh -File install-fabric.ps1 -WorkspaceRoot C:\Projects\forgewire ``"
Write-Host "           -Token (Get-Content .\hub.token -Raw)"
Write-Host ""
Write-Host "  VSIX: Reload VS Code (Ctrl+Shift+P > Developer: Reload Window)" -ForegroundColor Yellow
