<#
.SYNOPSIS
    Completely remove a ForgeWire Fabric installation from this machine.

.DESCRIPTION
    Stops and removes every Fabric artifact this node's installer created:
      - NSSM services: ForgeWireHub, ForgeWireRunner, ForgeWireRqlite,
        ForgeWireRqliteNode1/2/3, ForgeWireAgentRunner
      - Scheduled tasks: ForgeWireHubWatchdog, ForgeWireRunnerWatchdog
      - Install directories: C:\ProgramData\forgewire and C:\rqlite
      - (optional) the ForgeWire VS Code extension

    BEFORE removing anything it offers to back up the things you cannot
    regenerate or would not want to lose:
      - Node identities (ed25519 keys) and bearer tokens  -> losing these means
        re-enrolling/re-approving the node on the cluster
      - The rqlite control-plane snapshot (tasks, audit chain, cost ledger,
        approvals, secrets metadata, budget_state)
      - A self-verifying audit-log export (provenance / compliance history)
      - Cluster/policy/settings config (cluster.yaml, policy.yaml, hubs.yaml, ...)
      - User/agent state: the agent-sandbox workspace and the ssh dir
      - Recent logs

    The backup is written OUTSIDE the install tree (default under your user
    profile) so it survives the uninstall, then optionally zipped.

    Self-elevates via UAC if not already running as Administrator.

.PARAMETER BackupRoot
    Where to write the backup. Default: $env:USERPROFILE\ForgeWire-Backups

.PARAMETER NoBackup
    Skip the backup entirely (still prompts to confirm unless -Yes).

.PARAMETER KeepData
    Remove services/tasks but LEAVE C:\ProgramData\forgewire and C:\rqlite on
    disk (e.g. you only want to swap binaries / re-register services).

.PARAMETER RemoveVsix
    Also uninstall the ForgeWire VS Code extension(s).

.PARAMETER Yes
    Non-interactive: assume "yes, back up then remove" for all prompts.

.PARAMETER DataDir
    Install data dir. Default: C:\ProgramData\forgewire

.PARAMETER RqliteDir
    rqlite binary dir. Default: C:\rqlite

.EXAMPLE
    # Interactive: prompts to back up, then removes everything.
    pwsh -File uninstall-fabric.ps1

.EXAMPLE
    # Unattended full wipe with a backup to a custom location.
    pwsh -File uninstall-fabric.ps1 -Yes -BackupRoot D:\fw-backups -RemoveVsix

.EXAMPLE
    # Tear down services only, keep the data on disk, no backup.
    pwsh -File uninstall-fabric.ps1 -KeepData -NoBackup -Yes
#>
[CmdletBinding()]
param(
    [string]$BackupRoot = (Join-Path $env:USERPROFILE 'ForgeWire-Backups'),
    [switch]$NoBackup,
    [switch]$KeepData,
    [switch]$RemoveVsix,
    [switch]$Yes,
    [string]$DataDir   = 'C:\ProgramData\forgewire',
    [string]$RqliteDir = 'C:\rqlite',
    [int]$RqliteHttpPort = 4001
)

$ErrorActionPreference = 'Stop'

# ── Self-elevation (mirrors install-fabric.ps1) ───────────────────────────────
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevation required - relaunching as Administrator..." -ForegroundColor Yellow
    $shellExe  = (Get-Process -Id $PID).Path
    $forwarded = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) { if ($kv.Value.IsPresent) { $forwarded += "-$($kv.Key)" } }
        else { $forwarded += "-$($kv.Key)"; $forwarded += "$($kv.Value)" }
    }
    Start-Process -FilePath $shellExe -ArgumentList $forwarded -Verb RunAs
    return
}

$SERVICES = @(
    'ForgeWireHub','ForgeWireRunner','ForgeWireAgentRunner',
    'ForgeWireRqlite','ForgeWireRqliteNode1','ForgeWireRqliteNode2','ForgeWireRqliteNode3'
)
$TASKS = @('ForgeWireHubWatchdog','ForgeWireRunnerWatchdog')
$PROCS = @('forgewire-hub','forgewire-runner','forgewire-fabric-cli','rqlited','rqlite')

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    [ok] $msg" -ForegroundColor Green }
function Write-Skip($msg) { Write-Host "    [skip] $msg" -ForegroundColor DarkGray }
function Write-Warn2($msg){ Write-Host "    [warn] $msg" -ForegroundColor Yellow }

function Confirm-Or-Default($prompt, $defaultYes) {
    if ($Yes) { return $true }
    $suffix = if ($defaultYes) { '[Y/n]' } else { '[y/N]' }
    $ans = Read-Host "$prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($ans)) { return $defaultYes }
    return $ans -match '^(y|yes)$'
}

Write-Host ""
Write-Host "ForgeWire Fabric Uninstaller" -ForegroundColor White
Write-Host "============================" -ForegroundColor White
Write-Host "This will STOP and REMOVE the Fabric installation on $env:COMPUTERNAME." -ForegroundColor White
Write-Host ""

# ── 1. Detect what is present ─────────────────────────────────────────────────
Write-Step "Detecting installed artifacts"
$presentServices = @()
foreach ($s in $SERVICES) {
    if (Get-Service -Name $s -ErrorAction SilentlyContinue) { $presentServices += $s; Write-Ok "service: $s" }
}
$presentTasks = @()
foreach ($t in $TASKS) {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { $presentTasks += $t; Write-Ok "task: $t" }
}
$dataExists   = Test-Path $DataDir
$rqliteExists = Test-Path $RqliteDir
if ($dataExists)   { Write-Ok "data dir: $DataDir" }
if ($rqliteExists) { Write-Ok "rqlite dir: $RqliteDir" }
if (-not ($presentServices -or $presentTasks -or $dataExists -or $rqliteExists)) {
    Write-Host "Nothing to uninstall - no Fabric artifacts found." -ForegroundColor Yellow
    return
}

# ── 2. Offer to back up the irreplaceable state ───────────────────────────────
$backupPath = $null
if (-not $NoBackup -and $dataExists) {
    Write-Host ""
    Write-Step "Backup"
    Write-Host "    Recommended to keep (cannot be regenerated):" -ForegroundColor White
    Write-Host "      - node identities (ed25519 keys) + bearer tokens" -ForegroundColor Gray
    Write-Host "      - rqlite control-plane snapshot (tasks, audit chain, cost ledger, approvals)" -ForegroundColor Gray
    Write-Host "      - self-verifying audit-log export" -ForegroundColor Gray
    Write-Host "      - cluster/policy/settings config, agent-sandbox, ssh, recent logs" -ForegroundColor Gray
    Write-Host ""
    if (Confirm-Or-Default "Back up this state before removing?" $true) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backupPath = Join-Path $BackupRoot "fabric-uninstall-$stamp"
        New-Item -ItemType Directory -Force -Path $backupPath | Out-Null

        # 2a. Identities + tokens (small, critical)
        Write-Step "Saving identities and tokens"
        $idDir = Join-Path $backupPath 'identities'
        New-Item -ItemType Directory -Force -Path $idDir | Out-Null
        Get-ChildItem -Path $DataDir -Filter '*_identity.json' -ErrorAction SilentlyContinue | Copy-Item -Destination $idDir -Force
        Get-ChildItem -Path $DataDir -Filter 'runner_identity.json' -ErrorAction SilentlyContinue | Copy-Item -Destination $idDir -Force
        Get-ChildItem -Path $DataDir -Filter '*.token' -ErrorAction SilentlyContinue | Copy-Item -Destination $idDir -Force
        Write-Ok "identities/tokens -> $idDir"

        # 2b. rqlite control-plane snapshot (live backup if up, else copy data dir)
        Write-Step "Saving rqlite control-plane snapshot"
        $snap = Join-Path $backupPath 'rqlite-snapshot.sqlite'
        $live = $false
        try {
            Invoke-WebRequest -Uri "http://127.0.0.1:$RqliteHttpPort/db/backup" -OutFile $snap -TimeoutSec 20 -UseBasicParsing
            if ((Test-Path $snap) -and (Get-Item $snap).Length -gt 0) { $live = $true; Write-Ok "live rqlite backup -> $snap" }
        } catch { }
        if (-not $live) {
            $rqData = Join-Path $DataDir 'rqlite'
            if (Test-Path $rqData) {
                Copy-Item -Path $rqData -Destination (Join-Path $backupPath 'rqlite-data') -Recurse -Force -ErrorAction SilentlyContinue
                Write-Ok "rqlite data dir copied (hub not reachable for live backup)"
            } else { Write-Skip "no rqlite data found" }
        }

        # 2c. Self-verifying audit-log export (best-effort; needs hub + cli + token)
        Write-Step "Exporting audit log"
        $cli   = Join-Path $DataDir 'bin\forgewire-fabric-cli.exe'
        $token = Join-Path $DataDir 'hub.token'
        if ((Test-Path $cli) -and (Test-Path $token)) {
            $auditDir = Join-Path $backupPath 'audit'
            New-Item -ItemType Directory -Force -Path $auditDir | Out-Null
            $exported = 0
            foreach ($offset in 0..13) {
                $day = (Get-Date).AddDays(-$offset).ToString('yyyy-MM-dd')
                $out = Join-Path $auditDir "audit-$day.jsonl"
                try {
                    & $cli audit export --day $day --token-file $token 2>$null | Set-Content -Path $out -Encoding UTF8
                    if ((Test-Path $out) -and (Get-Item $out).Length -gt 0) { $exported++ } else { Remove-Item $out -ErrorAction SilentlyContinue }
                } catch { }
            }
            if ($exported -gt 0) { Write-Ok "$exported day(s) of audit events -> $auditDir" }
            else { Write-Skip "no audit events exported (hub may be down; snapshot still holds the chain)" }
        } else { Write-Skip "cli/token absent - audit chain preserved inside the rqlite snapshot" }

        # 2d. Config, user/agent state, logs
        Write-Step "Saving config, user state, and logs"
        foreach ($f in 'cluster.yaml','policy.yaml','hubs.yaml','settings.yaml','config.toml') {
            $p = Join-Path $DataDir $f
            if (Test-Path $p) { Copy-Item $p -Destination $backupPath -Force }
        }
        foreach ($d in 'agent-sandbox','ssh','rqlite-backups') {
            $p = Join-Path $DataDir $d
            if (Test-Path $p) { Copy-Item $p -Destination (Join-Path $backupPath $d) -Recurse -Force -ErrorAction SilentlyContinue }
        }
        $logSrc = Join-Path $DataDir 'logs'
        if (Test-Path $logSrc) {
            $logDst = Join-Path $backupPath 'logs'
            New-Item -ItemType Directory -Force -Path $logDst | Out-Null
            # keep only logs touched in the last 14 days to bound size
            Get-ChildItem $logSrc -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) } |
                Copy-Item -Destination $logDst -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "config/state/logs saved"

        # 2e. Manifest + zip
        $manifest = [ordered]@{
            machine    = $env:COMPUTERNAME
            created_at = (Get-Date).ToString('o')
            data_dir   = $DataDir
            rqlite_dir = $RqliteDir
            services   = $presentServices
            tasks      = $presentTasks
        } | ConvertTo-Json -Depth 4
        Set-Content -Path (Join-Path $backupPath 'MANIFEST.json') -Value $manifest -Encoding UTF8

        try {
            $zip = "$backupPath.zip"
            Compress-Archive -Path "$backupPath\*" -DestinationPath $zip -Force
            Write-Ok "backup archived -> $zip"
        } catch { Write-Warn2 "zip failed; backup left as a folder: $backupPath" }
        Write-Host ""
        Write-Host "    BACKUP COMPLETE: $backupPath" -ForegroundColor Green
    } else {
        Write-Skip "backup declined by operator"
    }
}

# ── 3. Final confirmation before destructive removal ──────────────────────────
Write-Host ""
$what = if ($KeepData) { "services and scheduled tasks (data dirs kept)" } else { "services, tasks, AND all data ($DataDir, $RqliteDir)" }
if (-not (Confirm-Or-Default "Proceed to REMOVE $what?" $false)) {
    Write-Host "Aborted. Nothing was removed." -ForegroundColor Yellow
    if ($backupPath) { Write-Host "Your backup is at: $backupPath" -ForegroundColor Green }
    return
}

# ── 4. Stop + remove services ─────────────────────────────────────────────────
$nssm = (Get-Command nssm -ErrorAction SilentlyContinue).Source
Write-Step "Stopping and removing services"
foreach ($s in $presentServices) {
    try { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue } catch { }
    if ($nssm) {
        try { & $nssm stop $s confirm 2>$null | Out-Null } catch { }
        try { & $nssm remove $s confirm 2>$null | Out-Null; Write-Ok "removed $s (nssm)" }
        catch { Write-Warn2 "nssm remove failed for $s" }
    } else {
        try { sc.exe delete $s | Out-Null; Write-Ok "removed $s (sc)" } catch { Write-Warn2 "sc delete failed for $s" }
    }
}

# ── 5. Kill any stragglers ────────────────────────────────────────────────────
Write-Step "Killing residual processes"
foreach ($p in $PROCS) {
    Get-Process -Name $p -ErrorAction SilentlyContinue | ForEach-Object {
        try { Stop-Process -Id $_.Id -Force; Write-Ok "killed $p ($($_.Id))" } catch { Write-Warn2 "could not kill $p ($($_.Id))" }
    }
}

# ── 6. Remove scheduled tasks ─────────────────────────────────────────────────
Write-Step "Removing scheduled tasks"
foreach ($t in $presentTasks) {
    try { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction Stop; Write-Ok "removed task $t" }
    catch { Write-Warn2 "could not remove task $t" }
}

# ── 7. Remove install directories ─────────────────────────────────────────────
if ($KeepData) {
    Write-Step "Keeping data directories (-KeepData)"
    Write-Skip "$DataDir and $RqliteDir left in place"
} else {
    Write-Step "Removing install directories"
    foreach ($d in @($DataDir, $RqliteDir)) {
        if (Test-Path $d) {
            try { Remove-Item -Path $d -Recurse -Force -ErrorAction Stop; Write-Ok "removed $d" }
            catch { Write-Warn2 "could not fully remove $d ($($_.Exception.Message)) - a file may still be locked" }
        }
    }

    # install-fabric.ps1 also mirrors the bearer token to the per-user home dir
    # ($HOME\.forgewire\hub.token) so the VS Code / MCP client can read it without
    # admin. A full uninstall must clear that too, otherwise a stale token from a
    # previous cluster lingers across a "fresh" reinstall. Remove the token (and
    # the .forgewire dir if it is left empty).
    $userForgewire = Join-Path $env:USERPROFILE ".forgewire"
    $userToken     = Join-Path $userForgewire "hub.token"
    if (Test-Path $userToken) {
        try { Remove-Item -Path $userToken -Force -ErrorAction Stop; Write-Ok "removed $userToken" }
        catch { Write-Warn2 "could not remove $userToken ($($_.Exception.Message))" }
    }
    if ((Test-Path $userForgewire) -and -not (Get-ChildItem -Force $userForgewire -ErrorAction SilentlyContinue)) {
        try { Remove-Item -Path $userForgewire -Force -ErrorAction Stop; Write-Ok "removed empty $userForgewire" } catch {}
    }
}

# ── 8. VS Code extension (optional) ───────────────────────────────────────────
if ($RemoveVsix) {
    Write-Step "Removing VS Code extension"
    $code = (Get-Command code -ErrorAction SilentlyContinue).Source
    if ($code) {
        # Match both the current (forgewirelabs) and legacy (digitalhallucinations)
        # publisher so upgrades from an old-publisher install are also cleaned up.
        $exts = & $code --list-extensions 2>$null | Where-Object { $_ -match '^(forgewirelabs|digitalhallucinations)\.forgewire' }
        foreach ($e in $exts) {
            try { & $code --uninstall-extension $e 2>$null | Out-Null; Write-Ok "uninstalled $e" } catch { Write-Warn2 "could not uninstall $e" }
        }
        if (-not $exts) { Write-Skip "no forgewire extension installed" }
    } else { Write-Skip "code CLI not on PATH" }
}

# ── 9. Summary ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "ForgeWire Fabric uninstalled from $env:COMPUTERNAME." -ForegroundColor Green
if ($backupPath) {
    Write-Host "Backup saved at: $backupPath" -ForegroundColor Green
    Write-Host "  (and $backupPath.zip if archiving succeeded)" -ForegroundColor DarkGray
}
if ($KeepData) { Write-Host "Data directories were kept (-KeepData)." -ForegroundColor Yellow }
Write-Host "Re-install with: install-fabric.ps1 -WorkspaceRoot <path>" -ForegroundColor Gray
