# sync_mirror.ps1 — M2.9.6 (F8) mirror sync lane
#
# Pushes the forgewire-fabric subtree from the monorepo to the standalone
# mirror remotes.
#
# APPROACH: direct tree-commit push (fast path)
# -------------------------------------------------
# DO NOT use `git subtree split` or `git subtree push`. On a repo with 4,500+
# commits the split traversal takes several minutes and is often rejected by
# GitHub (connection timeout). The split is also not required — the mirror is a
# published artifact, not a peer branch.
#
# Instead we:
#   1. Extract the tree SHA for the subtree path at HEAD in one lookup:
#        git rev-parse HEAD:<Prefix>
#   2. Fetch the current mirror HEAD so the new commit can chain to it (avoids
#      --force-with-lease rejecting a non-ancestor push on clean histories).
#   3. Create a synthetic commit object pointing to that tree:
#        git commit-tree <treeSha> -p <mirrorHead> -m "sync: ..."
#   4. Force-push that commit SHA directly to refs/heads/main.
#
# The resulting mirror history is a linear chain of synthetic commits, one per
# sync, each containing the exact tree state of forgewire-fabric/ at the
# corresponding monorepo HEAD. History is shallow but the tree is always exact.
# After the first push subsequent runs can still fast-forward (each commit's
# parent is the previous mirror HEAD).
#
# Usage:
#   .\sync_mirror.ps1 [-MonorepoPath <path>] [-MirrorRemote <remote>]
#                     [-MiniRemote <remote>] [-SkipMini] [-DryRun]
#
# NOTE: .github/workflows/** is a frozen surface (AGENTS.md Hard rule).
# CI integration of this script requires a human-reviewed workflow PR.

param(
    [string]$MonorepoPath = "C:\Projects\forgewire",
    [string]$Prefix       = "forgewire-fabric",
    [string]$MirrorRemote = "mirror",
    [string]$MiniRemote   = "mini",
    [switch]$SkipMini,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$checkScript = Join-Path $scriptDir "check_mirror_sync.ps1"

Write-Host "=== ForgeWire Mirror Sync ===" -ForegroundColor Cyan
Write-Host "Monorepo:  $MonorepoPath\$Prefix"
Write-Host "Remote:    $MirrorRemote (GitHub)"
if (-not $SkipMini) { Write-Host "Mini:      $MiniRemote (OptiPlex)" }
Write-Host ""

# 1. Show current state
Write-Host "--- Pre-sync check ---" -ForegroundColor Yellow
& $checkScript -MonorepoPath "$MonorepoPath\$Prefix" 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host ""

# Resolve the tree SHA and monorepo HEAD.
$monoHead  = (git -C $MonorepoPath rev-parse HEAD 2>&1).Trim()
$shortHead = (git -C $MonorepoPath rev-parse --short HEAD 2>&1).Trim()
$treeSha   = (git -C $MonorepoPath rev-parse "HEAD:$Prefix" 2>&1).Trim()

Write-Host "Monorepo HEAD: $monoHead"
Write-Host "Subtree tree:  $treeSha"
Write-Host ""

if ($DryRun) {
    Write-Host "DRY RUN: would execute tree-commit push for each remote." -ForegroundColor Yellow
    Write-Host "  tree SHA: $treeSha"
    Write-Host "  commit msg: sync: forgewire-fabric from monorepo $shortHead"
    exit 0
}

function Push-TreeCommit([string]$Remote, [string]$Label) {
    Write-Host "--- Pushing to $Remote ($Label) ---" -ForegroundColor Yellow

    # Fetch current mirror HEAD to use as parent (enables fast-forward on
    # subsequent runs and keeps history connected). Must fetch the object into
    # the local repo before commit-tree can reference it.
    $mirrorRef = $null
    $lsRemote  = git -C $MonorepoPath ls-remote $Remote "refs/heads/main" 2>&1
    if ($LASTEXITCODE -eq 0 -and "$lsRemote" -match "^([0-9a-f]{40})") {
        $mirrorRef = $Matches[1]
        Write-Host "  Mirror HEAD: $mirrorRef (fetching into local repo)"
        # Fetch just this one commit so commit-tree can use it as a parent.
        git -C $MonorepoPath fetch $Remote "refs/heads/main:refs/remotes/$Remote/main" --no-tags 2>&1 | Out-Null
        Write-Host "  Fetch done"
    } else {
        Write-Host "  Mirror HEAD: (empty — first push)"
    }

    # Full SHA in the message lets check_mirror_sync.ps1 locate the base commit.
    $commitMsg = "sync: forgewire-fabric from monorepo $monoHead"

    if ($mirrorRef) {
        $parentRef = "refs/remotes/$Remote/main"
        $commitSha = git -C $MonorepoPath commit-tree $treeSha -p $parentRef -m $commitMsg
    } else {
        $commitSha = git -C $MonorepoPath commit-tree $treeSha -m $commitMsg
    }
    $commitSha = "$commitSha".Trim()

    if ($LASTEXITCODE -ne 0 -or $commitSha.Length -ne 40) {
        Write-Host "FAIL: commit-tree failed (exit $LASTEXITCODE): $commitSha" -ForegroundColor Red
        return $false
    }
    Write-Host "  Commit SHA:  $commitSha"

    git -C $MonorepoPath push $Remote "${commitSha}:refs/heads/main" --force-with-lease
    $ok = ($LASTEXITCODE -eq 0)

    if ($ok) {
        Write-Host "OK: pushed to $Remote" -ForegroundColor Green
        # If the mirror has a corresponding local clone, fast-forward it so
        # check_mirror_sync.ps1 (which reads the local clone) sees the new HEAD.
        $localMirror = "C:\Projects\forgewire-fabric"
        if (Test-Path (Join-Path $localMirror ".git")) {
            Write-Host "  Updating local mirror clone at $localMirror"
            git -C $localMirror fetch origin 2>&1 | Out-Null
            git -C $localMirror reset --hard origin/main 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  Local clone updated" -ForegroundColor Green
            } else {
                Write-Host "  WARN: local clone update failed (non-fatal)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "FAIL: push to $Remote failed" -ForegroundColor Red
    }
    Write-Host ""
    return $ok
}

# 2. Push to GitHub mirror.
$mirrorOk = Push-TreeCommit $MirrorRemote "GitHub"
if (-not $mirrorOk) { exit 1 }

# 3. Optionally push to mini (OptiPlex).
if (-not $SkipMini) {
    $miniOk = Push-TreeCommit $MiniRemote "OptiPlex"
    if (-not $miniOk) {
        Write-Host "WARN: mini push failed — OptiPlex may be offline; mirror sync still complete." -ForegroundColor Yellow
    }
}

# 4. Re-run the check script — tree hashes should match after sync.
Write-Host "--- Post-sync check ---" -ForegroundColor Yellow
& $checkScript -MonorepoPath "$MonorepoPath\$Prefix" 2>&1 | ForEach-Object { Write-Host $_ }
