<#
.SYNOPSIS
    Install rqlite as an NSSM Windows service for ForgeWire Fabric.

.DESCRIPTION
    Idempotent. Downloads the rqlite binary if not present, creates a
    ForgeWireRqlite NSSM service, and starts it. The node advertises
    on 127.0.0.1 by default so it survives IP changes from DHCP/hotspot.

    First-node detection: if no existing rqlite cluster is reachable,
    the node bootstraps as a single-node leader. If -JoinAddress is
    supplied (or an existing cluster is discovered), the node joins
    the existing cluster.

    Run as Administrator (script self-elevates via UAC if needed).

.PARAMETER DataDir
    Root data directory. Default: C:\ProgramData\forgewire

.PARAMETER RqliteDir
    Directory containing rqlited.exe. Default: C:\rqlite
    If rqlited.exe is not found here, the script downloads it.

.PARAMETER HttpPort
    rqlite HTTP API port. Default: 4001

.PARAMETER RaftPort
    rqlite Raft consensus port. Default: 4002

.PARAMETER NodeId
    Stable node identifier. Default: <hostname>-rqlite

.PARAMETER JoinAddress
    Address of an existing rqlite node to join (e.g. 127.0.0.1:4002).
    If omitted, the node bootstraps as a single-node cluster (leader).

.PARAMETER RqliteVersion
    Version to download if rqlited.exe is missing. Default: 10.0.3

.EXAMPLE
    pwsh -File nssm-install-rqlite.ps1
    pwsh -File nssm-install-rqlite.ps1 -JoinAddress 192.0.2.10:4002
#>
[CmdletBinding()]
param(
    [string]$DataDir      = "C:\ProgramData\forgewire",
    [string]$RqliteDir    = "C:\rqlite",
    [int]$HttpPort        = 4001,
    [int]$RaftPort        = 4002,
    [string]$NodeId       = "",
    # JoinAddress is OPTIONAL — leave empty to auto-discover via LAN beacon.
    # Only set this if you want to force a specific join target.
    [string]$JoinAddress  = "",
    # Address other nodes use to reach THIS node's raft/http. Auto-detected
    # from the LAN IP if empty. Override only for unusual network topologies.
    [string]$AdvertiseHost = "",
    [string]$RqliteVersion = "10.0.3",
    [string]$ServiceName  = "ForgeWireRqlite",
    # UDP beacon port — must match FORGEWIRE_BEACON_PORT on the hub.
    [int]$BeaconPort      = 48765,
    # How long to listen for a beacon before assuming this is the first node.
    [int]$BeaconTimeoutMs = 3000
)

$ErrorActionPreference = "Stop"

# ---- Self-elevation -------------------------------------------------------
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $shellExe = (Get-Process -Id $PID).Path
    $forwarded = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $forwarded += "-$k" } }
        else                 { $forwarded += "-$k"; $forwarded += $v }
    }
    Write-Host "Elevating: $shellExe $($forwarded -join ' ')"
    $proc = Start-Process -FilePath $shellExe -Verb RunAs -Wait -PassThru -ArgumentList $forwarded
    exit $proc.ExitCode
}

# ---- Prereqs ---------------------------------------------------------------
if (-not (Get-Command nssm.exe -ErrorAction SilentlyContinue)) {
    throw "nssm.exe not found on PATH. Install from https://nssm.cc/ or via 'winget install nssm.nssm'."
}

if (-not $NodeId) {
    $NodeId = "$($env:COMPUTERNAME.ToLower())-rqlite"
}

$RqliteDataDir = Join-Path $DataDir "rqlite\data"
$LogDir        = Join-Path $DataDir "logs"
$RqlitedExe    = Join-Path $RqliteDir "rqlited.exe"

New-Item -ItemType Directory -Force -Path $DataDir, $RqliteDataDir, $LogDir, $RqliteDir | Out-Null

# ---- Auto-detect LAN IP if not specified -----------------------------------
if (-not $AdvertiseHost) {
    $AdvertiseHost = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Sort-Object -Property InterfaceMetric |
        Select-Object -First 1).IPAddress
    if (-not $AdvertiseHost) { $AdvertiseHost = "127.0.0.1" }
    Write-Host "Auto-detected LAN address: $AdvertiseHost"
}

# ---- LAN beacon discovery --------------------------------------------------
# Listen for ForgeWire hub beacons on the LAN. The beacon carries the rqlite
# Raft address so this node can join the existing cluster without any operator
# configuration. If no beacon arrives within the timeout, this is the first
# node and will bootstrap as the single voter leader.
#
# Beacon format (JSON over UDP): { magic:"FWBEACON", role:"hub", port:<hub_http>,
#   raft_port:<rqlite_raft>, rqlite_http_port:<rqlite_http>,
#   rqlite_voters:<n>, rqlite_nodes:<n>, ... }

function Invoke-BeaconDiscovery {
    param([int]$ListenPort, [int]$TimeoutMs)

    Write-Host "Listening for ForgeWire cluster beacon on UDP $ListenPort (${TimeoutMs}ms)..." -ForegroundColor Cyan

    $udp = $null
    try {
        $udp = [System.Net.Sockets.UdpClient]::new($ListenPort)
        $udp.EnableBroadcast = $true
        $udp.Client.ReceiveTimeout = $TimeoutMs

        # Send a query broadcast so existing hubs reply immediately.
        $query = [System.Text.Encoding]::UTF8.GetBytes(
            '{"magic":"FWBEACON","v":1,"role":"query","hub_id":"","port":0,"proto":0,"name":"","token_hash":"","ts":0,"raft_port":0,"rqlite_http_port":0,"rqlite_voters":0,"rqlite_nodes":0}'
        )
        $broadcast = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Broadcast, $ListenPort)
        $udp.Send($query, $query.Length, $broadcast) | Out-Null

        $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $bytes  = $udp.Receive([ref]$remote)
        $json   = [System.Text.Encoding]::UTF8.GetString($bytes)
        $beacon = $json | ConvertFrom-Json

        if ($beacon.magic -eq 'FWBEACON' -and $beacon.role -eq 'hub') {
            $sourceIp = $remote.Address.ToString()
            Write-Host "  Beacon received from $sourceIp (hub: $($beacon.name))" -ForegroundColor Green
            return @{
                SourceIp       = $sourceIp
                RaftPort       = if ($beacon.raft_port -gt 0) { $beacon.raft_port } else { 4002 }
                RqliteHttpPort = if ($beacon.rqlite_http_port -gt 0) { $beacon.rqlite_http_port } else { 4001 }
                RqliteVoters   = $beacon.rqlite_voters
                RqliteNodes    = $beacon.rqlite_nodes
                HubName        = $beacon.name
            }
        }
    } catch [System.Net.Sockets.SocketException] {
        # Timeout — no beacon received.
    } catch {
        Write-Warning "Beacon discovery error: $($_.Exception.Message)"
    } finally {
        if ($udp) { $udp.Close() }
    }
    return $null
}

$discoveredCluster = $null
if (-not $JoinAddress) {
    $discoveredCluster = Invoke-BeaconDiscovery -ListenPort $BeaconPort -TimeoutMs $BeaconTimeoutMs
    if ($discoveredCluster) {
        $JoinAddress = "$($discoveredCluster.SourceIp):$($discoveredCluster.RaftPort)"
        Write-Host "  Auto-join target: $JoinAddress" -ForegroundColor Green
        Write-Host "  Cluster state:    $($discoveredCluster.RqliteVoters) voter(s) / $($discoveredCluster.RqliteNodes) node(s) total"
    } else {
        Write-Host "  No beacon — this is the FIRST node. Bootstrapping as single-voter leader." -ForegroundColor Yellow
    }
} else {
    Write-Host "Join address explicitly set: $JoinAddress"
}

# ---- Download rqlite if missing -------------------------------------------
if (-not (Test-Path $RqlitedExe)) {
    # rqlite publishes Windows builds as win64/win32 (NOT windows-amd64/386).
    $winArch = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
    $zipName = "rqlite-v${RqliteVersion}-${winArch}.zip"
    $downloadUrl = "https://github.com/rqlite/rqlite/releases/download/v${RqliteVersion}/${zipName}"
    $zipPath = Join-Path $env:TEMP $zipName
    $extractDir = Join-Path $env:TEMP "rqlite-extract"

    Write-Host "rqlited.exe not found at $RqlitedExe"
    Write-Host "Downloading rqlite v${RqliteVersion} from $downloadUrl ..."

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing

    if (-not (Test-Path $zipPath)) {
        throw "Download failed: $zipPath does not exist."
    }

    Write-Host "Extracting to $RqliteDir ..."
    if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    # The binaries may sit at the zip root (win64 layout) or inside a single
    # directory like rqlite-v10.0.3-windows-amd64/ (older layout). Find rqlited
    # wherever it landed.
    $rqlitedSrc = Get-ChildItem $extractDir -Recurse -Filter 'rqlited.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $rqlitedSrc) {
        throw "rqlited.exe not found in downloaded archive."
    }
    $srcDir = $rqlitedSrc.Directory.FullName

    # Copy binaries to the install dir
    Copy-Item (Join-Path $srcDir 'rqlited.exe') $RqliteDir -Force
    Copy-Item (Join-Path $srcDir 'rqlite.exe')  $RqliteDir -Force -ErrorAction SilentlyContinue

    # Cleanup
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $RqlitedExe)) {
        throw "rqlited.exe still not found after extraction. Check $RqliteDir."
    }
    Write-Host "rqlite v${RqliteVersion} installed to $RqliteDir"
} else {
    $prevEA = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $ver = (& $RqlitedExe -version 2>&1 | Out-String).Trim()
    $ErrorActionPreference = $prevEA
    Write-Host "rqlited.exe found: $ver"
}

# ---- Build service parameters ----------------------------------------------
# adv-addr is what PEERS use to reach this node. 127.0.0.1 for single-host;
# the LAN IP (-AdvertiseHost) for a multi-host cluster. node-id is the stable
# identity, so the advertised address may change across restarts/DHCP and the
# cluster re-forms when the node re-announces.
Write-Host "Advertising rqlite as $AdvertiseHost (raft :$RaftPort, http :$HttpPort)"

# Open the rqlite ports so peer nodes can form a multi-host Raft cluster. Without
# these inbound rules, a joining node times out connecting to the raft port even
# though the bind succeeds locally (confirmed: new ports are dropped by default).
foreach ($p in @($HttpPort, $RaftPort)) {
    $ruleName = "ForgeWire rqlite $p"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        try {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort $p -Profile Any -ErrorAction Stop | Out-Null
            Write-Host "  firewall: opened TCP $p"
        } catch { Write-Host "  firewall: could not open TCP $p ($($_.Exception.Message))" }
    }
}
# ---- Determine voter / standby role -----------------------------------------
# Cluster topology rules (enforced here and by the hub's cluster_manager):
#
#   1 node   — voter (bootstrapping single leader)
#   2 nodes  — 1 voter (stable leader) + 1 non-voter (hot standby)
#              No quorum loss if one node is slow; leader never steps down.
#   3+ nodes — all voters (full Raft quorum, N/2+1 fault tolerance)
#
# On a 2-node cluster the second node joins as a non-voter. The hub's
# background cluster manager promotes it to voter automatically when a
# third node joins, and demotes back to standby if the cluster shrinks.

# ---- Determine voter / standby role -----------------------------------------
# Topology rules (enforced here at install time; the hub's cluster_manager
# monitors and corrects at runtime):
#
#   1 node   → voter (bootstrap single leader)
#   2 nodes  → new node joins as NON-VOTER (hot standby, never votes)
#              Single stable leader; no Raft elections on slow heartbeats.
#   3+ nodes → all voters (full Raft quorum)
#
# The decision is made from beacon data (already fetched above) or by probing
# the existing cluster's /nodes endpoint. NO operator input required.

$joinAsVoter = $true  # default: first node or 3+-node join

if ($JoinAddress) {
    # We have a join target (either from beacon or explicit param).
    # Determine voter count from beacon if available, otherwise probe rqlite.
    $voterCount = 0
    $totalCount = 0

    if ($discoveredCluster) {
        # Beacon already told us the cluster state — use it directly.
        $voterCount = [int]$discoveredCluster.RqliteVoters
        $totalCount = [int]$discoveredCluster.RqliteNodes
        Write-Host "Cluster state from beacon: $voterCount voter(s), $totalCount total node(s)."
    } else {
        # Explicit -JoinAddress without beacon — probe rqlite directly.
        $joinHost   = $JoinAddress.Split(":")[0]
        $leaderHttp = "http://${joinHost}:$HttpPort"
        Write-Host "Probing cluster at $leaderHttp ..."
        try {
            $nodes      = Invoke-RestMethod -Uri "$leaderHttp/nodes?nonvoters" -TimeoutSec 5 -ErrorAction Stop
            $voterCount = ($nodes.PSObject.Properties.Value | Where-Object { $_.voter -eq $true }).Count
            $totalCount = $nodes.PSObject.Properties.Count
            Write-Host "  Cluster has $totalCount node(s), $voterCount voter(s)."
        } catch {
            Write-Warning "Could not probe $leaderHttp — joining as voter (safe default)."
            $voterCount = 99  # unknown, treat as 3+ so we join as voter
        }
    }

    if ($voterCount -le 1 -and $totalCount -le 1) {
        # Only 1 existing node (the leader) — this is the 2nd node.
        # Join as non-voter (hot standby). Promoted automatically if 3rd joins.
        $joinAsVoter = $false
        Write-Host "  → 2-node topology: joining as NON-VOTER (hot standby)." -ForegroundColor Cyan
        Write-Host "     The hub cluster manager will promote to voter when a 3rd node joins."
    } else {
        # 3rd or later node — join as voter (full quorum).
        $joinAsVoter = $true
        Write-Host "  → 3+ node topology: joining as VOTER (full Raft quorum)." -ForegroundColor Green
    }
}

# ---- Build rqlite startup arguments -----------------------------------------
$rqliteArgs = @(
    "-node-id", $NodeId,
    "-http-addr", "0.0.0.0:$HttpPort",
    "-http-adv-addr", "${AdvertiseHost}:$HttpPort",
    "-raft-addr", "0.0.0.0:$RaftPort",
    "-raft-adv-addr", "${AdvertiseHost}:$RaftPort",
    # Use stable, generous Raft timeouts. 1 s (rqlite default) is too tight when
    # Bolt I/O or a snapshot runs long. 3 s heartbeat + 5 s election gives ample
    # slack while still electing within a few seconds of a real failure.
    "-raft-heartbeat-timeout", "3s",
    "-raft-election-timeout",  "5s",
    "-raft-leader-lease-timeout", "2s"
)

if ($JoinAddress) {
    $rqliteArgs += @("-join", $JoinAddress)
    Write-Host "Joining existing cluster at $JoinAddress"
    if (-not $joinAsVoter) {
        # -raft-non-voter makes this node a read-only standby from startup.
        # The hub's cluster_manager will promote it to voter if a 3rd node joins.
        $rqliteArgs += @("-raft-non-voter")
        Write-Host "Starting as non-voter (hot standby) — will auto-promote to voter when 3rd node joins."
    }
} else {
    Write-Host "No -JoinAddress -- bootstrapping as single-node leader."
}
$rqliteArgs += $RqliteDataDir
$rqliteArgsStr = $rqliteArgs -join " "

# ---- Create / update NSSM service ------------------------------------------
$prevNative = $PSNativeCommandUseErrorActionPreference
$PSNativeCommandUseErrorActionPreference = $false
try {
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & nssm.exe status $ServiceName *>$null
    $exists = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $prevPref

    if ($exists) {
        Write-Host "Service '$ServiceName' exists; stopping and updating in place."
        & nssm.exe stop $ServiceName confirm 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    } else {
        Write-Host "Installing service '$ServiceName'."
        & nssm.exe install $ServiceName $RqlitedExe | Out-Null
    }

    & nssm.exe set $ServiceName Application $RqlitedExe             | Out-Null
    & nssm.exe set $ServiceName AppParameters $rqliteArgsStr         | Out-Null
    & nssm.exe set $ServiceName AppDirectory $RqliteDataDir          | Out-Null
    & nssm.exe set $ServiceName DisplayName "ForgeWire rqlite"       | Out-Null
    & nssm.exe set $ServiceName Description "Raft-replicated SQLite for ForgeWire Fabric hub" | Out-Null
    & nssm.exe set $ServiceName Start SERVICE_AUTO_START             | Out-Null
    & nssm.exe set $ServiceName AppExit Default Restart              | Out-Null
    & nssm.exe set $ServiceName AppRestartDelay 5000                 | Out-Null
    & nssm.exe set $ServiceName AppStdout (Join-Path $LogDir "rqlite.out.log") | Out-Null
    & nssm.exe set $ServiceName AppStderr (Join-Path $LogDir "rqlite.err.log") | Out-Null
    & nssm.exe set $ServiceName AppRotateFiles 1                     | Out-Null
    & nssm.exe set $ServiceName AppRotateOnline 1                    | Out-Null
    & nssm.exe set $ServiceName AppRotateBytes 10485760              | Out-Null

    # ---- Start service --------------------------------------------------------
    & nssm.exe start $ServiceName 2>&1 | Out-Null
    Write-Host "Waiting for rqlite to elect leader..."
    $maxWait = 30
    $ready = $false
    for ($i = 0; $i -lt $maxWait; $i++) {
        Start-Sleep -Seconds 1
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$HttpPort/readyz" -UseBasicParsing -TimeoutSec 3
            if ($resp.StatusCode -eq 200) {
                $ready = $true
                break
            }
        } catch { }
    }

    if ($ready) {
        $status = (Invoke-WebRequest -Uri "http://127.0.0.1:$HttpPort/status" -UseBasicParsing -TimeoutSec 5).Content | ConvertFrom-Json

        Write-Host ""
        Write-Host "rqlite is READY." -ForegroundColor Green
        Write-Host "  Node ID:  $NodeId"
        Write-Host "  Role:     $(if ($JoinAddress -and -not $joinAsVoter) { 'non-voter (hot standby)' } elseif ($JoinAddress) { 'voter (cluster member)' } else { 'voter (single leader)' })"
        Write-Host "  State:    $($status.store.raft.state)"
        Write-Host "  Leader:   $($status.store.leader.addr)"
        Write-Host "  HTTP:     http://127.0.0.1:$HttpPort"
        Write-Host "  Raft:     127.0.0.1:$RaftPort"
        Write-Host "  Data:     $RqliteDataDir"
        Write-Host "  Logs:     $LogDir"
        Write-Host "  Heartbeat timeout: 3s  Election timeout: 5s"
    } else {
        Write-Warning "rqlite did not become ready within ${maxWait}s. Check logs at ${LogDir}\rqlite.err.log"
        $svcStatus = (& nssm.exe status $ServiceName 2>&1 | Out-String).Trim()
        Write-Host "Service status: $svcStatus"
    }
} finally {
    $PSNativeCommandUseErrorActionPreference = $prevNative
}

