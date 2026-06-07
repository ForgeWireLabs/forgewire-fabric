<#
.SYNOPSIS
    Convert the local rqlite node to a non-voter (hot standby).

.DESCRIPTION
    Run this ONCE on the machine that should be the standby (non-leader).
    Typically DESKTOP-228U8GL (Precision).  The other machine (DESKTOP-38GVF8D,
    OptiPlex) should be left running as the single voter/leader.

    What this script does:
    1. Updates the NSSM service parameters to add -raft-non-voter and the
       corrected Raft timeouts (3 s heartbeat, 5 s election).
    2. Restarts the ForgeWireRqlite service.
    3. Waits for the node to rejoin the cluster as a non-voter.
    4. Verifies the topology: 1 voter (OptiPlex), 1 non-voter (Precision).

    Run as Administrator (script self-elevates via UAC).

.PARAMETER LeaderHost
    Hostname or IP of the current rqlite leader (voter node).
    Default: DESKTOP-38GVF8D

.PARAMETER HttpPort
    rqlite HTTP port. Default: 4001

.PARAMETER RaftPort
    rqlite Raft port. Default: 4002

.PARAMETER ServiceName
    NSSM service name. Default: ForgeWireRqlite
#>
[CmdletBinding()]
param(
    [string]$LeaderHost   = "DESKTOP-38GVF8D",
    [int]$HttpPort        = 4001,
    [int]$RaftPort        = 4002,
    [string]$ServiceName  = "ForgeWireRqlite"
)

$ErrorActionPreference = "Stop"

# Self-elevate
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $shellExe = (Get-Process -Id $PID).Path
    $forwarded = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $forwarded += "-$k" } }
        else { $forwarded += "-$k"; $forwarded += $v }
    }
    Start-Process -FilePath $shellExe -Verb RunAs -Wait -PassThru -ArgumentList $forwarded | Out-Null
    exit 0
}

Write-Host "=== ForgeWire Fabric: Apply Standby Topology ===" -ForegroundColor Cyan
Write-Host "Converting THIS node to non-voter (hot standby)."
Write-Host "Leader: $LeaderHost"
Write-Host ""

# ---- Read current AppParameters -----------------------------------------------
$currentParams = (Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters" `
    -Name AppParameters -ErrorAction Stop).AppParameters

Write-Host "Current params: $currentParams"
Write-Host ""

# ---- Strip existing raft timeout / non-voter flags ----------------------------
$stripped = $currentParams `
    -replace "\s*-raft-heartbeat-timeout\s+\S+", "" `
    -replace "\s*-raft-election-timeout\s+\S+",  "" `
    -replace "\s*-raft-leader-lease-timeout\s+\S+", "" `
    -replace "\s*-raft-non-voter", ""

# ---- Inject the standby flags before the data-dir (last arg) -----------------
# The data dir is always the final argument (no flag prefix).
# Identify the data-dir: it is the last token that starts with a path char
# and does not begin with '-'. Split on whitespace, take the last non-flag token.
$tokens = $stripped.Trim() -split "\s+"
$dataDir = ($tokens | Where-Object { $_ -notmatch "^-" } | Select-Object -Last 1)
# Build the flag portion: everything except the data-dir at the end
$flagsPart = ($tokens | Where-Object { $_ -ne $dataDir }) -join " "

$newParams = "$($flagsPart.Trim()) " +
             "-raft-heartbeat-timeout 3s " +
             "-raft-election-timeout 5s " +
             "-raft-leader-lease-timeout 2s " +
             "-raft-non-voter " +
             $dataDir

Write-Host "New params:     $newParams" -ForegroundColor Green
Write-Host ""

# ---- Apply and restart -------------------------------------------------------
Write-Host "Updating NSSM service parameters ..."
nssm set $ServiceName AppParameters $newParams | Out-Null

Write-Host "Stopping $ServiceName ..."
nssm stop $ServiceName confirm 2>&1 | Out-Null
Start-Sleep -Seconds 3

Write-Host "Starting $ServiceName ..."
nssm start $ServiceName 2>&1 | Out-Null

# ---- Wait for rejoin ---------------------------------------------------------
Write-Host "Waiting for node to rejoin as non-voter ..."
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    try {
        $r = Invoke-WebRequest "http://127.0.0.1:$HttpPort/readyz" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
}

if (-not $ready) {
    Write-Warning "Node did not become ready within 30s. Check: nssm status $ServiceName"
    exit 1
}

# ---- Verify topology ---------------------------------------------------------
Start-Sleep -Seconds 2  # let Raft configuration propagate
$nodes = Invoke-RestMethod "http://$LeaderHost`:$HttpPort/nodes?nonvoters" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Cluster Topology ===" -ForegroundColor Cyan
if ($nodes) {
    foreach ($id in $nodes.PSObject.Properties.Name) {
        $n = $nodes.$id
        $role = if ($n.leader) { "LEADER (voter)" } elseif ($n.voter) { "voter" } else { "non-voter (standby)" }
        Write-Host "  $id  →  $role" -ForegroundColor $(if ($n.leader) { "Green" } elseif (-not $n.voter) { "Cyan" } else { "Yellow" })
    }
} else {
    Write-Warning "Could not reach leader at $LeaderHost`:$HttpPort — verify cluster state manually."
}

Write-Host ""
Write-Host "Done. This node is now a hot standby." -ForegroundColor Green
Write-Host "The hub's cluster manager will auto-promote it to voter when a 3rd node joins."
