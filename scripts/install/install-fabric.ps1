<#
.SYNOPSIS
    One-command ForgeWire Fabric installer. Installs rqlite, hub, runner, watchdogs, VSIX.

.DESCRIPTION
    Run this on any Windows machine to join the ForgeWire Fabric cluster.
    Every node gets: rqlite (Raft member), runner, watchdogs, and VSIX.
    The first node (or -ForceHub) also gets the hub.

    No Python required. All daemons are native Rust binaries from BinDir.

    What gets installed on EVERY node:
      1. rqlite         - Raft-replicated database (NSSM service, all nodes)
      2. Hub            - Signed dispatch control plane (NSSM, hub node only)
      3. Runner         - Command runner background service (NSSM)
      4. Watchdogs      - Hub + runner liveness probes (scheduled tasks)
      5. VSIX           - VS Code extension for the Fabric sidebar
      6. MCP (optional) - Dispatcher MCP registration (requires Python in venv)

    Hub nodes are auto-detected via mDNS LAN scan; if no hub is found this
    machine becomes the hub. Pass -ForceHub to override.

.PARAMETER WorkspaceRoot
    Absolute path the runner executes inside. REQUIRED.

.PARAMETER Token
    Bearer token. Auto-generated on first (hub) node. Must be provided on
    joining nodes - copy from hub: Get-Content C:\ProgramData\forgewire\hub.token

.PARAMETER BinDir
    Directory containing forgewire-hub.exe and forgewire-runner.exe.
    Default: C:\ProgramData\forgewire\bin
    Binaries are copied here from FabricRoot\target\release\ if not present.

.PARAMETER FabricRoot
    Path to the forgewire-fabric repo checkout. Auto-detected from script location.

.PARAMETER ForceHub
    Force hub+rqlite bootstrap even if a hub is discovered on the LAN.

.PARAMETER HubUrl
    Explicit hub URL (skip mDNS discovery).

.PARAMETER RqliteJoinAddr
    rqlite raft address of an existing cluster member to join (host:raftPort).
    Required when joining a multi-node cluster where bootstrap is already done.
    Example: 192.0.2.10:4002

.PARAMETER Tags
    Comma-separated runner tags (e.g. "kind:command,gpu:nvidia").

.PARAMETER SkipVsix
    Skip VS Code extension installation.

.PARAMETER SkipMcp
    Skip MCP server registration (MCP requires Python; core install works without it).

.EXAMPLE
    # First node - bootstraps hub, rqlite, runner, VSIX:
    pwsh -File install-fabric.ps1 -WorkspaceRoot C:\Projects\forgewire

    # Joining node - discovers hub via mDNS, joins rqlite cluster:
    pwsh -File install-fabric.ps1 -WorkspaceRoot C:\Projects\forgewire `
        -Token (Get-Content \\hub-node\c$\ProgramData\forgewire\hub.token -Raw) `
        -RqliteJoinAddr 192.0.2.10:4002

    # Explicit hub URL (skip mDNS):
    pwsh -File install-fabric.ps1 -WorkspaceRoot C:\Projects\forgewire `
        -HubUrl http://192.0.2.10:8765 `
        -Token (Get-Content hub.token -Raw) `
        -RqliteJoinAddr 192.0.2.10:4002
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WorkspaceRoot,
    [string]$Token           = "",
    [string]$BinDir          = "C:\ProgramData\forgewire\bin",
    [string]$FabricRoot      = "",
    [switch]$ForceHub,
    [string]$HubUrl          = "",
    [string]$RqliteJoinAddr  = "",
    [string]$Tags            = "",
    [string]$ScopePrefixes   = "",
    [int]$MaxConcurrent      = 1,
    [string]$DataDir         = "C:\ProgramData\forgewire",
    [int]$HubPort            = 8765,
    [int]$RqliteHttpPort     = 4001,
    [int]$RqliteRaftPort     = 4002,
    [switch]$SkipVsix,
    [switch]$SkipMcp
)

$ErrorActionPreference = "Stop"

# ── Self-elevation ────────────────────────────────────────────────────────────
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $shellExe  = (Get-Process -Id $PID).Path
    $forwarded = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $forwarded += "-$k" } }
        else                 { $forwarded += "-$k"; $forwarded += $v }
    }
    Write-Host "Requesting elevation..."
    $proc = Start-Process -FilePath $shellExe -Verb RunAs -Wait -PassThru -ArgumentList $forwarded
    exit $proc.ExitCode
}

if (-not (Get-Command nssm.exe -ErrorAction SilentlyContinue)) {
    throw "nssm.exe not found on PATH. Install: winget install nssm.nssm"
}

# ── Locate fabric root ────────────────────────────────────────────────────────
if (-not $FabricRoot) {
    $FabricRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
Write-Host "Fabric root  : $FabricRoot" -ForegroundColor Cyan

# ── Locate or copy Rust binaries ──────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$binaries = @("forgewire-hub.exe", "forgewire-runner.exe", "forgewire-fabric-cli.exe")
$releaseDir = Join-Path $FabricRoot "target\release"

foreach ($bin in $binaries) {
    $dest = Join-Path $BinDir $bin
    if (-not (Test-Path $dest)) {
        $src = Join-Path $releaseDir $bin
        if (Test-Path $src) {
            Copy-Item $src $dest
            Write-Host "  Copied $bin from $releaseDir"
        } elseif ($bin -ne "forgewire-fabric-cli.exe") {
            throw "$bin not found in $BinDir or $releaseDir. Run: cargo build --release -p fabric-hub -p fabric-runner"
        }
    }
}

$HubExe    = Join-Path $BinDir "forgewire-hub.exe"
$RunnerExe = Join-Path $BinDir "forgewire-runner.exe"
$CliExe    = Join-Path $BinDir "forgewire-fabric-cli.exe"

Write-Host "Hub binary   : $HubExe" -ForegroundColor Cyan
Write-Host "Runner binary: $RunnerExe" -ForegroundColor Cyan

# ── Discover existing hub FIRST — determines whether token is required ────────
$discoveredHub = ""
if (-not $HubUrl -and -not $ForceHub) {
    Write-Host ""
    Write-Host "Scanning LAN for existing ForgeWire hub..." -ForegroundColor Cyan

    # Build candidate list dynamically from all detected subnets
    $localIps = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.PrefixOrigin -in @('Dhcp','Manual') -and $_.IPAddress -notlike '169.*' }
    $subnets = @($localIps | ForEach-Object { $_.IPAddress -replace '\.\d+$', '' }) | Select-Object -Unique
    if (-not $subnets) { $subnets = @("192.0.2") }

    $candidates = @("127.0.0.1")
    foreach ($s in $subnets) { 1..20 | ForEach-Object { $candidates += "${s}.$_" } }
    $candidates = $candidates | Select-Object -Unique

    Write-Host "  Probing $($candidates.Count) addresses on detected subnets: $($subnets -join ', ')"
    foreach ($candidate in $candidates) {
        try {
            $resp = Invoke-WebRequest -Uri "http://${candidate}:${HubPort}/healthz" `
                -UseBasicParsing -TimeoutSec 1 -ErrorAction SilentlyContinue
            if ($resp.StatusCode -eq 200) {
                $discoveredHub = "http://${candidate}:${HubPort}"
                Write-Host "  Found hub: $discoveredHub" -ForegroundColor Green
                break
            }
        } catch {}
    }

    # Fallback: Python mDNS if available
    if (-not $discoveredHub) {
        $python = (Get-Command python.exe -ErrorAction SilentlyContinue) ??
                  (Get-Command python3.exe -ErrorAction SilentlyContinue)
        if ($python) {
            $discovered = & $python.Source -c @"
import json
try:
    from forgewire_fabric.hub.discovery import discover_hubs
    hubs = discover_hubs(timeout=4.0)
    print(json.dumps(hubs))
except:
    print('[]')
"@ 2>$null | Out-String
            try {
                $hubs = $discovered.Trim() | ConvertFrom-Json
                if ($hubs.Count -gt 0) {
                    $best = $hubs | Sort-Object { $_.protocol_version } -Descending | Select-Object -First 1
                    $discoveredHub = "http://$($best.host):$($best.port)"
                    Write-Host "  mDNS discovered hub: $discoveredHub" -ForegroundColor Green
                }
            } catch {}
        }
    }

    if (-not $discoveredHub) {
        Write-Host "  No existing hub found — this node will bootstrap as hub." -ForegroundColor Yellow
    }
}

$effectiveHubUrl = if ($HubUrl) { $HubUrl } elseif ($discoveredHub) { $discoveredHub } else { "" }
$isHubNode       = (-not $effectiveHubUrl) -or $ForceHub

# ── Token — required to join; auto-generated only when bootstrapping a new hub ─
#
# Security model (current):  bearer token is the sole cluster admission gate.
#   Hub node  → token is auto-generated, written to a locked file, and shown
#               once. Operator must copy it to every joining node.
#   Joining node → token MUST be provided explicitly via -Token. The installer
#               will verify it authenticates against the hub before writing any
#               services. A wrong or missing token is a hard failure.
#
# Future: User accounts + OAuth will replace the shared token with per-operator
# credentials. Until then, treat the token like an SSH private key — rotate it
# if it is ever exposed, and distribute it only over secure channels.

if ($isHubNode) {
    # Hub bootstrap: use an existing token or generate a cryptographically
    # strong one. Never silently fall through to a weak default.
    if (-not $Token) {
        $existingTokenFile = Join-Path $DataDir "hub.token"
        if (Test-Path $existingTokenFile) {
            $Token = (Get-Content $existingTokenFile -Raw).Trim()
            Write-Host ""
            Write-Host "Reusing existing hub token from $existingTokenFile" -ForegroundColor Cyan
        }
    }
    if (-not $Token) {
        # 32 random bytes → 64-char hex string
        $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[] 32
        $rng.GetBytes($bytes)
        $Token = ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ''
        Write-Host ""
        Write-Host "┌─────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "│  NEW HUB TOKEN GENERATED — copy this to joining nodes   │" -ForegroundColor Yellow
        Write-Host "│                                                         │" -ForegroundColor Yellow
        Write-Host "│  $Token  │" -ForegroundColor White
        Write-Host "│                                                         │" -ForegroundColor Yellow
        Write-Host "│  Treat this like a password. Rotate if ever exposed.    │" -ForegroundColor Yellow
        Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    # Joining node: token is REQUIRED. Without it this machine cannot be
    # admitted to the cluster and there is nothing useful to install.
    if (-not $Token) {
        Write-Host ""
        Write-Host "ERROR: A hub was found at $effectiveHubUrl but no -Token was provided." -ForegroundColor Red
        Write-Host ""
        Write-Host "Joining a cluster requires the hub bearer token. Get it from the hub node:" -ForegroundColor Yellow
        Write-Host "  Get-Content C:\ProgramData\forgewire\hub.token"
        Write-Host "  # or from your hub operator."
        Write-Host ""
        Write-Host "Then re-run with:"
        Write-Host "  pwsh -File install-fabric.ps1 -WorkspaceRoot <path> -Token <token>"
        Write-Host ""
        throw "Token required to join cluster at $effectiveHubUrl. Aborting."
    }

    # Verify the token actually authenticates against the discovered hub BEFORE
    # writing any services. A wrong token means a broken install.
    Write-Host ""
    Write-Host "Verifying token against hub at $effectiveHubUrl ..." -ForegroundColor Cyan
    try {
        $authCheck = Invoke-WebRequest `
            -Uri "$effectiveHubUrl/runners" `
            -Headers @{ Authorization = "Bearer $($Token.Trim())" } `
            -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($authCheck.StatusCode -eq 200) {
            Write-Host "  Token verified." -ForegroundColor Green
        } else {
            throw "Unexpected status $($authCheck.StatusCode)"
        }
    } catch {
        $status = $_.Exception.Response?.StatusCode?.value__
        Write-Host ""
        Write-Host "ERROR: Token rejected by hub (HTTP $status)." -ForegroundColor Red
        Write-Host "  The token you provided does not match the hub at $effectiveHubUrl."
        Write-Host "  Get the correct token from the hub node:"
        Write-Host "    Get-Content C:\ProgramData\forgewire\hub.token"
        Write-Host ""
        throw "Token authentication failed against $effectiveHubUrl. Aborting."
    }
}

if ($Token.Length -lt 16) { throw "Token must be >= 16 characters." }

# Write token to the local data dir (locked ACL) and user home dir
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$sysTokenFile = Join-Path $DataDir "hub.token"
[System.IO.File]::WriteAllText($sysTokenFile, $Token)
try {
    # Restrict system token file to SYSTEM + Administrators only
    $acl  = Get-Acl $sysTokenFile
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($id in @("NT AUTHORITY\SYSTEM","BUILTIN\Administrators")) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $id, "FullControl", "Allow")
        $acl.AddAccessRule($rule)
    }
    Set-Acl $sysTokenFile $acl
} catch {
    Write-Warning "Could not restrict ACL on $sysTokenFile (non-fatal): $($_.Exception.Message)"
}
$userTokenDir = Join-Path $HOME ".forgewire"
New-Item -ItemType Directory -Force -Path $userTokenDir | Out-Null
[System.IO.File]::WriteAllText((Join-Path $userTokenDir "hub.token"), $Token)

# == STEP 1 - rqlite (EVERY node joins the Raft cluster) ══════════════════════
Write-Host ""
Write-Host "-- 1/6 -- rqlite (Raft member on every node)..." -ForegroundColor Cyan
$rqliteInstaller = Join-Path $PSScriptRoot "nssm-install-rqlite.ps1"
if (-not (Test-Path $rqliteInstaller)) {
    throw "nssm-install-rqlite.ps1 not found at $rqliteInstaller"
}
$rqliteArgs = @{
    DataDir  = $DataDir
    HttpPort = $RqliteHttpPort
    RaftPort = $RqliteRaftPort
}
# Joining nodes provide a -JoinAddr so rqlite connects to the existing cluster.
# Hub nodes bootstrap a new cluster (no JoinAddr).
if ($RqliteJoinAddr) {
    $rqliteArgs["JoinAddr"] = $RqliteJoinAddr
    Write-Host "  Joining existing rqlite cluster at $RqliteJoinAddr"
} elseif ($isHubNode) {
    Write-Host "  Bootstrapping new rqlite cluster (single-node or future multi-node)"
}
& $rqliteInstaller @rqliteArgs
Write-Host "-- 1/6 -- rqlite OK" -ForegroundColor Green

# == STEP 2 - hub (hub node only) ══════════════════════════════════════════════
if ($isHubNode) {
    Write-Host ""
    Write-Host "-- 2/6 -- Hub (Rust binary, rqlite backend)..." -ForegroundColor Cyan
    $hubInstaller = Join-Path $PSScriptRoot "nssm-install-hub.ps1"
    & $hubInstaller `
        -BinDir   $BinDir `
        -Token    $Token `
        -Port     $HubPort `
        -RqliteHost "127.0.0.1" `
        -RqlitePort $RqliteHttpPort `
        -NoWatchdog  # watchdog installed in step 4
    $effectiveHubUrl = "http://127.0.0.1:$HubPort"

    Write-Host "  Waiting for hub to be reachable..."
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            if ((Invoke-WebRequest -Uri "$effectiveHubUrl/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) {
                $ready = $true; break
            }
        } catch {}
    }
    if (-not $ready) {
        Write-Warning "Hub did not respond in 30s. Check: $DataDir\logs\hub.err.log"
    } else {
        Write-Host "  Hub ready at $effectiveHubUrl" -ForegroundColor Green
    }
    Write-Host "-- 2/6 -- Hub OK" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "-- 2/6 -- Hub - joining node, using $effectiveHubUrl" -ForegroundColor DarkGray
}

# == STEP 3 - Runner (Rust binary) ══════════════════════════════════════════════
Write-Host ""
Write-Host "-- 3/6 -- Runner (Rust binary)..." -ForegroundColor Cyan
$runnerInstaller = Join-Path $PSScriptRoot "nssm-install-runner.ps1"
$scope = if ($ScopePrefixes) { $ScopePrefixes } else { $WorkspaceRoot }
& $runnerInstaller `
    -BinDir       $BinDir `
    -HubUrl       $effectiveHubUrl `
    -Token        $Token `
    -WorkspaceRoot $WorkspaceRoot `
    -ScopePrefixes $scope `
    -MaxConcurrent $MaxConcurrent `
    -Tags         $Tags `
    -NoWatchdog  # watchdog installed in step 4
Write-Host "-- 3/6 -- Runner OK" -ForegroundColor Green

# == STEP 4 - Watchdogs ══════════════════════════════════════════════════════════
Write-Host ""
Write-Host "-- 4/6 -- Watchdogs..." -ForegroundColor Cyan
$hubWd    = Join-Path $PSScriptRoot "install-hub-watchdog.ps1"
$runnerWd = Join-Path $PSScriptRoot "install-runner-watchdog.ps1"
if ($isHubNode -and (Test-Path $hubWd)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $hubWd `
        -ServiceName "ForgeWireHub" -HealthzUrl "http://127.0.0.1:$HubPort/healthz"
    Write-Host "  Hub watchdog installed"
}
if (Test-Path $runnerWd) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runnerWd `
        -ServiceName "ForgeWireRunner" -HubUrl $effectiveHubUrl
    Write-Host "  Runner watchdog installed"
}
Write-Host "-- 4/6 -- Watchdogs OK" -ForegroundColor Green

# == STEP 5 - VSIX ══════════════════════════════════════════════════════════════
if (-not $SkipVsix) {
    Write-Host ""
    Write-Host "-- 5/6 -- VSIX..." -ForegroundColor Cyan
    $codeCmds = @("code","code.cmd")
    $codeExe  = $null
    foreach ($c in $codeCmds) {
        if (Get-Command $c -ErrorAction SilentlyContinue) { $codeExe = $c; break }
    }

    if (-not $codeExe) {
        Write-Warning "VS Code not on PATH. Skipping VSIX. Install manually later."
    } else {
        # Find latest pre-built VSIX in dist/ first, then root vscode/
        $vsixDirs = @(
            (Join-Path $FabricRoot "vscode\dist"),
            (Join-Path $FabricRoot "vscode"),
            $BinDir,
            $DataDir
        )
        $vsixFile = $null
        foreach ($d in $vsixDirs) {
            $vsixFile = Get-ChildItem $d -Filter "forgewire-fabric-*.vsix" -ErrorAction SilentlyContinue |
                Sort-Object { [version]($_.BaseName -replace 'forgewire-fabric-','') } -Descending |
                Select-Object -First 1
            if ($vsixFile) { break }
        }

        if ($vsixFile) {
            & $codeExe --install-extension $vsixFile.FullName --force 2>&1 | Out-Null
            Write-Host "  Installed $($vsixFile.Name)"
        } else {
            Write-Warning "No pre-built VSIX found. Build with: cd $FabricRoot\vscode && npm run compile && npx vsce package"
        }

        # Configure VS Code workspace settings
        $vsWorkspace = Join-Path $WorkspaceRoot ".vscode"
        New-Item -ItemType Directory -Force -Path $vsWorkspace | Out-Null
        $vsSettingsPath = Join-Path $vsWorkspace "settings.json"
        $vsSettings = @{}
        if (Test-Path $vsSettingsPath) {
            try { $vsSettings = Get-Content $vsSettingsPath -Raw | ConvertFrom-Json -AsHashtable -ErrorAction SilentlyContinue } catch {}
        }
        $tokenFilePath = Join-Path $DataDir "hub.token"
        $primaryUrl    = if ($isHubNode) { "http://127.0.0.1:$HubPort" } else { $effectiveHubUrl }
        $vsSettings["forgewireFabric.hubUrl"]       = $primaryUrl
        $vsSettings["forgewireFabric.hubTokenFile"] = $tokenFilePath
        $vsSettings["forgewireFabric.hubCandidates"] = @(
            @{ url = $primaryUrl; label = "Primary"; priority = 1 }
        )
        $vsSettings | ConvertTo-Json -Depth 5 | Set-Content $vsSettingsPath -Encoding UTF8
        Write-Host "  Workspace settings: $vsSettingsPath"
    }
    Write-Host "-- 5/6 -- VSIX OK" -ForegroundColor Green
} else {
    Write-Host "-- 5/6 -- VSIX skipped (-SkipVsix)" -ForegroundColor DarkGray
}

# == STEP 6 - MCP + host roles (optional, requires Python) ════════════════════
Write-Host ""
Write-Host "-- 6/6 -- MCP + host roles..." -ForegroundColor Cyan

# Report host roles via native CLI or direct HTTP
$headers = @{ Authorization = "Bearer $($Token.Trim())" }
$roles   = @("command_runner")
if ($isHubNode) { $roles += "hub_head" }
foreach ($role in $roles) {
    $body = @{
        hostname = $env:COMPUTERNAME
        role     = $role
        enabled  = $true
        status   = "installed"
        metadata = @{ installer = "install-fabric.ps1 (Rust)"; timestamp = (Get-Date).ToUniversalTime().ToString("o") }
    } | ConvertTo-Json -Depth 4
    try {
        Invoke-RestMethod -Method Post -Uri "$effectiveHubUrl/hosts/roles" `
            -Headers $headers -ContentType "application/json" -Body $body -TimeoutSec 5 | Out-Null
        Write-Host "  Host role reported: $role"
    } catch {
        Write-Warning "Could not report host role '$role': $($_.Exception.Message)"
    }
}

# MCP registration (optional - requires Python integration layer)
if (-not $SkipMcp) {
    $pythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
    $python = if ($pythonCmd) { $pythonCmd.Source } else { $null }
    if (-not $python) {
        $venvPython = Join-Path $FabricRoot ".venv\Scripts\python.exe"
        if (Test-Path $venvPython) { $python = $venvPython }
    }
    if ($python) {
        try {
            $env:FORGEWIRE_HUB_URL   = $effectiveHubUrl
            $env:FORGEWIRE_HUB_TOKEN = $Token.Trim()
            & $python -m forgewire_fabric.cli mcp install --hub-url $effectiveHubUrl --with-runner --workspace-root $WorkspaceRoot 2>&1 | Out-Null
            & $python -m forgewire_fabric.cli dispatchers register --hostname $env:COMPUTERNAME 2>&1 | Out-Null
            Write-Host "  MCP servers registered and dispatcher identity recorded"
        } catch {
            Write-Warning "MCP registration failed (non-fatal): $($_.Exception.Message)"
        }
    } else {
        Write-Host "  Python not found - skipping MCP registration (add later: forgewire-fabric mcp install)"
    }
}
Write-Host "-- 6/6 -- Done" -ForegroundColor Green

# == Write config/cluster.yaml (hub node only) ════════════════════════════════
# cluster.yaml is gitignored (machine-specific). The installer creates/updates
# it so chaos drills and DR backup scripts work without manual setup.
if ($isHubNode) {
    $configDir  = Join-Path $FabricRoot "config"
    $clusterYml = Join-Path $configDir "cluster.yaml"
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null

    $localIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.PrefixOrigin -in @('Dhcp','Manual') -and $_.IPAddress -notlike '169.*' } |
        Select-Object -First 1).IPAddress
    if (-not $localIp) { $localIp = "127.0.0.1" }

    $clusterYmlContent = @"
# ForgeWire rqlite cluster topology.
# Generated by install-fabric.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm') UTC
# This file is gitignored. Re-run install-fabric.ps1 to regenerate.

cluster_id: forgewire-prod-1
hub_protocol_version: 3

voters:
  - label: node1
    node_id: $($env:COMPUTERNAME.ToLower())-rqlite
    host: $localIp
    port: $RqliteHttpPort
    raft_port: $RqliteRaftPort
    role: voter
    priority: 1
    tags: [primary, hub]
    service: ForgeWireRqlite
    ssh_alias: forgewire-hub

preferred_node: node1

backups:
  root: '$DataDir\rqlite-backups'
  cadence_minutes: 5
  retention_hours: 24
  min_bytes: 1024
  timeout_seconds: 60

chaos:
  enabled: false
  cadence_minutes: 1440
  drills: 'kill-leader,lose-quorum'
  driver_node: node1
  log_root: '$DataDir\rqlite-chaos'
  retention_days: 30
  ssh:
    provision_for_system: false
    key_source: '~\.ssh\id_ed25519_forgewire'
    aliases:
      - alias: forgewire-hub
        hostname: $localIp
        user: $($env:USERNAME)
"@
    Set-Content -Path $clusterYml -Value $clusterYmlContent -Encoding UTF8
    Write-Host "  cluster.yaml written: $clusterYml" -ForegroundColor DarkGray
}

# == Summary ════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "#================================================" -ForegroundColor Green
Write-Host "#  ForgeWire Fabric installed successfully!" -ForegroundColor Green
Write-Host "#================================================" -ForegroundColor Green
Write-Host ""
if ($isHubNode) {
    Write-Host "  Role        : HUB + RUNNER (Rust)" -ForegroundColor White
    Write-Host "  Hub URL     : $effectiveHubUrl"
    Write-Host "  rqlite      : http://127.0.0.1:$RqliteHttpPort  (raft: :$RqliteRaftPort)"
} else {
    Write-Host "  Role        : RUNNER (Rust, hub @ $effectiveHubUrl)" -ForegroundColor White
    Write-Host "  rqlite      : local member, joined cluster"
}
Write-Host "  Workspace   : $WorkspaceRoot"
Write-Host "  Binaries    : $BinDir"
Write-Host "  Token       : $DataDir\hub.token"
Write-Host "  Logs        : $DataDir\logs"
Write-Host ""
Write-Host "  To add another node:" -ForegroundColor Yellow
Write-Host "    1. Copy the token and this script to the new machine"
Write-Host "    2. Run on the new machine:"
Write-Host "       pwsh -File install-fabric.ps1 -WorkspaceRoot C:\Projects\forgewire ``"
Write-Host "           -Token `"$Token`" ``"
Write-Host "           -RqliteJoinAddr $($env:COMPUTERNAME):$RqliteRaftPort"
Write-Host ""
Write-Host "  Reload VS Code (Ctrl+Shift+P → Developer: Reload Window)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Security posture:" -ForegroundColor Cyan
Write-Host "  The hub bearer token is the sole cluster admission gate." -ForegroundColor DarkGray
Write-Host "  Anyone with the token can dispatch tasks to this cluster." -ForegroundColor DarkGray
Write-Host "  Rotate it with: forgewire-fabric token rotate" -ForegroundColor DarkGray
Write-Host "  Future versions will add per-operator accounts and OAuth." -ForegroundColor DarkGray

# == Quick smoke test ════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "Running quick smoke test..." -ForegroundColor Cyan
try {
    $healthz = Invoke-RestMethod -Uri "$effectiveHubUrl/healthz" -TimeoutSec 5
    if ($healthz.rust_hub -and $healthz.backend -like "rqlite*") {
        Write-Host "  PASS hub healthz: v$($healthz.version) backend=$($healthz.backend)" -ForegroundColor Green
    } else {
        Write-Warning "  WARN hub healthz returned unexpected fields: $($healthz | ConvertTo-Json -Compress)"
    }
} catch {
    Write-Warning "  FAIL hub healthz unreachable: $($_.Exception.Message)"
}


