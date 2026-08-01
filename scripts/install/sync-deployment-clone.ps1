<#
.SYNOPSIS
    Preserve local deployment edits, then fast-forward a standalone clone.

.DESCRIPTION
    Dirty work is committed to an operator/<host>/<timestamp> branch and saved
    as a git bundle outside the clone before main advances. The public mirror is
    never force-reset and no preserved branch is pushed to any remote.

    Operator-owned files that git ignores (notably `config/cluster.yaml`) are
    force-added into the archive commit so the bundle is a true point-in-time
    restore. Build artefacts that are also ignored (`target/`, `__pycache__/`,
    `.venv/`, `vscode/dist/`, `*.vsix`) are deliberately NOT captured -- they
    are reproducible, and including them would turn a ~10 KB bundle into a
    multi-gigabyte one. Adjust with -OperatorPath / -ExcludePath.

    The archive branch and its bundle may contain host-specific deployment
    configuration. They are local artefacts only: this script never pushes
    them, and refuses to run against a remote-tracking checkout it would have
    to force-update.

.PARAMETER Mode
    Sync   - preserve dirty state, then fast-forward (default).
    Export - preserve dirty state to a portable bundle, then stop. Does not
             modify the checked-out branch.
    Import - restore operator state from a previously exported bundle.

.EXAMPLE
    ./sync-deployment-clone.ps1
    Preserve local edits and fast-forward the clone to origin/main.

.EXAMPLE
    ./sync-deployment-clone.ps1 -Mode Export -BundlePath D:\backup\precision.bundle
    Capture current operator state without touching the working tree.

.EXAMPLE
    ./sync-deployment-clone.ps1 -Mode Import -BundlePath D:\backup\precision.bundle
    Re-apply a captured operator state onto this clone.
#>
[CmdletBinding()]
param(
    [ValidateSet('Sync', 'Export', 'Import')]
    [string]$Mode = 'Sync',
    [string]$RepoRoot = 'C:\Projects\forgewire-fabric',
    [string]$Remote = 'origin',
    [string]$Branch = 'main',
    [string]$BackupRoot = 'C:\ProgramData\forgewire-operator\source-backups',
    [string]$BundlePath,
    # Ignored-but-operator-owned paths to force into the archive commit.
    [string[]]$OperatorPath = @(
        'config/cluster.yaml',
        'config/*.local.yaml',
        '.env.local'
    ),
    # Never captured, even if they match an -OperatorPath glob.
    [string[]]$ExcludePath = @(
        'target/*',
        '*/__pycache__/*',
        '.venv/*',
        'vscode/dist/*',
        '*.vsix',
        '*.pdb'
    ),
    # Use this identity for the archive commit when the host has none
    # configured, instead of failing.
    [switch]$AutoIdentity,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Assert-Git {
    param([string]$What)
    if ($LASTEXITCODE -ne 0) { throw $What }
}

# Run git, routing its output to the verbose stream, and throw $FailureMessage
# on a non-zero exit.
#
# The $ErrorActionPreference dance is load-bearing, not defensive noise. git
# writes ordinary progress ("Switched to a new branch ...") to STDERR. Under
# Windows PowerShell 5.1 with $ErrorActionPreference = 'Stop', merging a native
# command's stderr (`2>&1`) turns those benign lines into terminating
# NativeCommandError records -- so a perfectly successful `git switch` aborts
# the script. pwsh 7 does not do this, which is why this only shows up on hosts
# invoked through `powershell.exe`. Suspending the preference around the call,
# and deciding success from $LASTEXITCODE instead, behaves identically on both.
function Invoke-Git {
    param([string[]]$GitArgs, [string]$FailureMessage)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & git @GitArgs 2>&1 | Out-String
        if ($output.Trim()) { Write-Verbose $output.Trim() }
    }
    finally {
        $ErrorActionPreference = $previous
    }
    if ($LASTEXITCODE -ne 0) { throw $FailureMessage }
}

# --- Identity guard -------------------------------------------------------
# Runs BEFORE any branch switch. `git commit` fails without an identity, and
# failing after the switch would strand the clone on a half-built archive
# branch -- the exact failure this ordering prevents.
function Resolve-CommitIdentity {
    $name = (git config user.name 2>$null)
    $email = (git config user.email 2>$null)
    if ($name -and $email) {
        Write-Verbose "commit identity: $name <$email>"
        return @()
    }
    if ($AutoIdentity) {
        $fallbackName = "forgewire-operator@$env:COMPUTERNAME"
        $fallbackEmail = "operator@$($env:COMPUTERNAME.ToLower()).forgewire.invalid"
        Write-Host "No git identity configured; using $fallbackName <$fallbackEmail> for the archive commit only." -ForegroundColor Yellow
        # Passed per-invocation via -c so the host's config is left untouched.
        return @('-c', "user.name=$fallbackName", '-c', "user.email=$fallbackEmail")
    }
    throw @"
No git identity is configured for this clone, so the archive commit would fail.
Fix once on this host:
    git config --global user.name  "<name>"
    git config --global user.email "<email>"
Or re-run with -AutoIdentity to use a generated per-host identity for the
archive commit only (leaves host config untouched).
"@
}

# --- Operator-owned ignored files ----------------------------------------
function Get-OperatorIgnoredFiles {
    $ignored = @(git ls-files --others --ignored --exclude-standard)
    if (-not $ignored) { return @() }
    $keep = New-Object System.Collections.Generic.List[string]
    foreach ($file in $ignored) {
        $isExcluded = $false
        foreach ($pattern in $ExcludePath) {
            if ($file -like $pattern) { $isExcluded = $true; break }
        }
        if ($isExcluded) { continue }
        foreach ($pattern in $OperatorPath) {
            if ($file -like $pattern) { $keep.Add($file); break }
        }
    }
    return $keep.ToArray()
}

# Ignored operator files are force-added into the archive commit, which makes
# them *tracked* on that branch. Switching back to a branch where they are not
# tracked would then DELETE them from the working tree -- silently destroying
# the live deployment's config. They are therefore copied aside first and
# restored verbatim afterwards, so the working tree ends up byte-identical for
# every ignored path regardless of the branch gymnastics in between.
function Backup-OperatorFiles {
    param([string[]]$Files)
    if ($Files.Count -eq 0) { return $null }
    $stage = Join-Path ([IO.Path]::GetTempPath()) "fw-operator-$([Guid]::NewGuid().ToString('n'))"
    foreach ($file in $Files) {
        $src = Join-Path (Get-Location).Path $file
        if (-not (Test-Path -LiteralPath $src)) { continue }
        $dest = Join-Path $stage $file
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
        Copy-Item -LiteralPath $src -Destination $dest -Force
    }
    return $stage
}

function Restore-OperatorFiles {
    param([string]$Stage, [string[]]$Files)
    if (-not $Stage -or -not (Test-Path -LiteralPath $Stage)) { return }
    foreach ($file in $Files) {
        $src = Join-Path $Stage $file
        if (-not (Test-Path -LiteralPath $src)) { continue }
        $dest = Join-Path (Get-Location).Path $file
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
        Copy-Item -LiteralPath $src -Destination $dest -Force
    }
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
}

function New-OperatorArchive {
    param([string]$ArchiveBranch, [string[]]$IdentityArgs, [string]$Destination)

    $tracked = @(git status --porcelain=v1)
    $operatorFiles = @(Get-OperatorIgnoredFiles)

    if ($tracked.Count -eq 0 -and $operatorFiles.Count -eq 0) {
        Write-Host 'No local modifications to preserve.' -ForegroundColor Green
        return $null
    }

    Write-Host "Preserving $($tracked.Count) tracked change(s) and $($operatorFiles.Count) operator-owned ignored file(s) on $ArchiveBranch" -ForegroundColor Yellow
    foreach ($file in $operatorFiles) { Write-Host "  + $file (ignored, operator-owned)" }

    if ($DryRun) {
        Write-Host 'DRY_RUN: no archive branch, commit, or bundle was created.'
        return $null
    }

    $script:OperatorStage = Backup-OperatorFiles -Files $operatorFiles
    $script:OperatorFiles = $operatorFiles

    $startingRef = (git rev-parse --abbrev-ref HEAD)
    $script:StartingRef = $startingRef
    Invoke-Git @('switch', '-c', $ArchiveBranch) 'could not create operator archive branch'
    try {
        Invoke-Git @('add', '-A') 'could not stage tracked changes'
        if ($operatorFiles.Count -gt 0) {
            # -f is required: these paths are ignored by design, and are being
            # captured deliberately rather than un-ignored.
            Invoke-Git (@('add', '-f', '--') + $operatorFiles) 'could not stage operator-owned ignored files'
        }
        Invoke-Git ($IdentityArgs + @('commit', '-m', "chore(operator): preserve $env:COMPUTERNAME deployment edits before sync")) 'could not commit operator archive branch'

        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
        Invoke-Git @('bundle', 'create', $Destination, $ArchiveBranch) 'could not create operator archive bundle'

        # Sidecar manifest so a restore does not require guessing provenance.
        $manifest = [ordered]@{
            schema           = 'forgewire.operator-archive/v1'
            host             = $env:COMPUTERNAME
            created_utc      = (Get-Date).ToUniversalTime().ToString('o')
            archive_branch   = $ArchiveBranch
            archive_commit   = (git rev-parse HEAD)
            base_commit      = (git rev-parse "$ArchiveBranch^")
            tracked_changes  = $tracked.Count
            operator_files   = $operatorFiles
            bundle           = $Destination
        }
        $manifestPath = [IO.Path]::ChangeExtension($Destination, '.json')
        $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

        Write-Host "ARCHIVE_BRANCH=$ArchiveBranch"
        Write-Host "ARCHIVE_BUNDLE=$Destination"
        Write-Host "ARCHIVE_MANIFEST=$manifestPath"
        return $ArchiveBranch
    }
    catch {
        # Leave the operator on the branch they started from rather than
        # stranded mid-archive. This is the recovery path, so it must not be
        # able to fail for the same PS 5.1 native-stderr reason the rest of
        # this script guards against -- suspend the preference here too, and
        # swallow anything that still goes wrong so the original error (which
        # is the useful one) propagates rather than being masked.
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & git switch $startingRef 2>&1 | Out-Null } catch { }
        finally { $ErrorActionPreference = $previous }
        throw
    }
}

# Set by New-OperatorArchive; consumed by the outer finally so ignored
# operator files are restored on every exit path, success or failure.
$script:OperatorStage = $null
$script:OperatorFiles = @()
$script:StartingRef = $null

Push-Location $RepoRoot
try {
    $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
    if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot '.git'))) {
        throw "not a standalone git clone: $RepoRoot"
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Net.Dns]::GetHostName() }
    $archiveBranch = "operator/$hostName/$stamp"

    if ($Mode -eq 'Import') {
        if (-not $BundlePath) { throw '-BundlePath is required for -Mode Import' }
        if (-not (Test-Path -LiteralPath $BundlePath)) { throw "bundle not found: $BundlePath" }
        Invoke-Git @('bundle', 'verify', $BundlePath) "bundle failed verification: $BundlePath"
        $restoreBranch = "operator-restore/$stamp"
        if ($DryRun) {
            Write-Host "DRY_RUN: git fetch `"$BundlePath`" '*:refs/heads/$restoreBranch/*'"
            return
        }
        Invoke-Git @('fetch', $BundlePath, "+refs/heads/*:refs/heads/$restoreBranch/*") 'could not fetch refs from bundle'
        Write-Host "RESTORED_REFS=refs/heads/$restoreBranch/*" -ForegroundColor Green
        Write-Host 'Review with: git log --oneline --all | Select-String operator-restore'
        Write-Host "Apply with:  git checkout <restored-ref> -- <path>"
        return
    }

    $identityArgs = Resolve-CommitIdentity

    $bundle = if ($BundlePath) { $BundlePath }
              else { Join-Path $BackupRoot "$($archiveBranch.Replace('/', '-')).bundle" }
    $created = New-OperatorArchive -ArchiveBranch $archiveBranch -IdentityArgs $identityArgs -Destination $bundle

    if ($Mode -eq 'Export') {
        # Export is a snapshot, not a mutation: it must leave the clone on the
        # branch it started on AND leave uncommitted work in place. Switching
        # back alone is not enough -- that reverts the working tree to the
        # branch's committed state, silently discarding the operator's
        # in-progress edits. Replay the archived content over the working tree
        # and unstage it, so the tree is byte-identical to how it was found.
        if ($created -and $script:StartingRef) {
            $archiveCommit = (git rev-parse $created)
            Invoke-Git @('switch', $script:StartingRef) "could not return to $($script:StartingRef) after export"
            Invoke-Git @('checkout', $archiveCommit, '--', '.') 'could not replay archived working-tree state after export'
            Invoke-Git @('reset') 'could not unstage replayed working-tree state after export'
        }
        if ($created) { Write-Host 'EXPORT_COMPLETE' -ForegroundColor Green }
        else { Write-Host 'EXPORT_EMPTY: nothing to preserve.' -ForegroundColor Green }
        return
    }

    if ($DryRun) {
        Write-Host "DRY_RUN: git fetch $Remote; git switch $Branch; git merge --ff-only $Remote/$Branch"
        return
    }

    Invoke-Git @('fetch', $Remote) "git fetch $Remote failed"
    Invoke-Git @('switch', $Branch) "git switch $Branch failed"
    Invoke-Git @('merge', '--ff-only', "$Remote/$Branch") `
        "deployment clone diverged from $Remote/$Branch; preserved state was not overwritten (see $bundle)"
    Write-Host "DEPLOYMENT_HEAD=$(git rev-parse HEAD)" -ForegroundColor Green
    if ($created) {
        Write-Host "Operator state preserved on $created and in $bundle" -ForegroundColor Green
    }
}
finally {
    # Restore ignored operator files before releasing the location, so the
    # working tree is left exactly as found for every ignored path.
    if ($script:OperatorStage) {
        Restore-OperatorFiles -Stage $script:OperatorStage -Files $script:OperatorFiles
        Write-Host "Restored $($script:OperatorFiles.Count) operator-owned ignored file(s) to the working tree." -ForegroundColor Green
    }
    Pop-Location
}
