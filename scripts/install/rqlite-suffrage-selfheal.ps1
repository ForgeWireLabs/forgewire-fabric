<#
.SYNOPSIS
    ADDR-5b: node-local rqlite suffrage self-heal. Demotes THIS node to
    non-voter if it is caught in the 2-voter quorum trap (rqlite v10 has no
    runtime HTTP suffrage mutation, so the only fix is a local restart with
    -raft-non-voter).

.DESCRIPTION
    Idempotent + safe. Queries the LOCAL rqlite node. Acts ONLY when ALL hold:
      * the cluster has exactly 2 nodes,
      * THIS node is a voter,
      * THIS node is NOT the leader.
    In that case it self-demotes: remove-self (commits under quorum-2, leader
    keeps quorum and leadership), then restart local rqlite as a non-voter
    rejoining the leader. The LEADER node is never touched, so the cluster
    stays writable throughout; only this standby's rqlite blips.

    No-ops in every other state (healthy 1-voter+1-nonvoter, single node,
    3+ nodes, or when THIS node is the leader). A cooldown marker prevents
    re-firing within -CooldownMinutes. Honor FORGEWIRE_SUFFRAGE_SELFHEAL=0 to
    disable. Designed to run as a SYSTEM scheduled task (watchdog pattern).
    Always exits 0 unless it actually performed a demote that failed.
    ASCII-only (Windows PowerShell 5.1 codepage safety).
#>
[CmdletBinding()]
param(
    [int]$HttpPort = 4001,
    [string]$ServiceName = "ForgeWireRqlite",
    [string]$DataDir = "C:\ProgramData\forgewire\rqlite\data",
    [int]$CooldownMinutes = 10,
    [switch]$WhatIfOnly   # detect + report, never act (for testing)
)
$ErrorActionPreference = "Continue"
$local = "http://127.0.0.1:$HttpPort"
$marker = "C:\ProgramData\forgewire\suffrage-selfheal.last"

function Log($m) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }

if ($env:FORGEWIRE_SUFFRAGE_SELFHEAL -eq "0") { Log "disabled via env; exit"; exit 0 }

# --- Read local cluster view -------------------------------------------------
try {
    $nodes = (Invoke-WebRequest "$local/nodes?nonvoters" -TimeoutSec 8 -UseBasicParsing).Content | ConvertFrom-Json
} catch { Log "local rqlite /nodes unreachable ($($_.Exception.Message)); no-op"; exit 0 }

# Parse my node-id from the service args (-node-id <id>).
$argsStr = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters" -ErrorAction SilentlyContinue).AppParameters
$myId = $null
if ($argsStr -match "-node-id\s+(\S+)") { $myId = $Matches[1] }
if (-not $myId) { Log "cannot determine local node-id; no-op"; exit 0 }

$all = @($nodes.PSObject.Properties.Value)
$total = $all.Count
$me = $all | Where-Object { $_.id -eq $myId } | Select-Object -First 1
$leader = $all | Where-Object { $_.leader -eq $true } | Select-Object -First 1

if (-not $me) { Log "this node ($myId) not in /nodes yet; no-op"; exit 0 }

$trapped = ($total -eq 2) -and ($me.voter -eq $true) -and ($me.leader -ne $true)
Log ("state: total=$total myId=$myId voter=$($me.voter) leader=$($me.leader) -> trapped=$trapped")

if (-not $trapped) { Log "not in the 2-voter trap; no-op"; exit 0 }
if ($WhatIfOnly) { Log "WHATIF: would self-demote $myId to non-voter"; exit 0 }

# --- Cooldown ----------------------------------------------------------------
if (Test-Path $marker) {
    $age = (Get-Date) - (Get-Item $marker).LastWriteTime
    if ($age.TotalMinutes -lt $CooldownMinutes) {
        Log ("cooldown active ({0:N1} min < $CooldownMinutes); skip" -f $age.TotalMinutes); exit 0
    }
}

if (-not $leader) { Log "trapped but no leader visible; refusing to act (unsafe); no-op"; exit 0 }
$leaderApi  = $leader.api_addr               # http://<leaderhost>:4001
$leaderRaft = $leader.addr                   # <leaderhost>:4002
Log "SELF-DEMOTE: removing $myId via leader $leaderApi, will rejoin as non-voter at -join $leaderRaft"

# --- 1. remove self (commits under quorum-2; leader keeps quorum) ------------
$removed = $false
foreach ($endpoint in @($local, $leaderApi)) {
    try {
        Invoke-WebRequest "$endpoint/remove" -Method DELETE -Body (@{ id = $myId } | ConvertTo-Json) `
            -ContentType "application/json" -TimeoutSec 15 -UseBasicParsing | Out-Null
        $removed = $true; Log "removed self via $endpoint"; break
    } catch { Log "remove via $endpoint failed: $($_.Exception.Message)" }
}
if (-not $removed) { Log "could not remove self from cluster; aborting (no restart)"; exit 2 }
Start-Sleep -Seconds 3

# --- 2. restart local rqlite as a non-voter rejoining the leader -------------
& nssm stop $ServiceName confirm 2>&1 | Out-Null
Start-Sleep -Seconds 2

# Build args: keep node-id + adv addrs + timeouts; force -raft-non-voter; -join leader.
$advHost = $env:COMPUTERNAME
$newArgs = "-node-id $myId " +
           "-http-addr 0.0.0.0:$HttpPort -http-adv-addr ${advHost}:$HttpPort " +
           "-raft-addr 0.0.0.0:4002 -raft-adv-addr ${advHost}:4002 " +
           "-raft-heartbeat-timeout 3s -raft-election-timeout 5s -raft-leader-lease-timeout 2s " +
           "-join $leaderRaft -raft-non-voter " +
           "$DataDir"
& nssm set $ServiceName AppParameters $newArgs 2>&1 | Out-Null

if (Test-Path $DataDir) { Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force $DataDir | Out-Null

& nssm start $ServiceName 2>&1 | Out-Null

# --- 3. verify nonvoter ------------------------------------------------------
$ok = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    try {
        $after = (Invoke-WebRequest "$local/nodes?nonvoters" -TimeoutSec 4 -UseBasicParsing).Content | ConvertFrom-Json
        $m2 = @($after.PSObject.Properties.Value) | Where-Object { $_.id -eq $myId } | Select-Object -First 1
        if ($m2 -and $m2.voter -eq $false) { $ok = $true; break }
    } catch { }
}
Set-Content -Path $marker -Value (Get-Date -Format "o") -Encoding ascii
if ($ok) { Log "SUCCESS: $myId is now a non-voter; quorum trap cleared."; exit 0 }
else { Log "WARN: did not confirm non-voter within 60s; check $ServiceName logs."; exit 2 }
