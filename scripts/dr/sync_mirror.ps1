# sync_mirror.ps1 — M2.9.6 (F8) mirror sync lane
#
# Publishes the forgewire-fabric subtree from the monorepo to the GitHub mirror
# repo only. This script DOES NOT touch any local working copy on the cluster
# machines (Precision C:\Projects\forgewire-fabric, OptiPlex `mini` remote).
# Those are pulled manually by the operator — keep it that way.
#
# SCOPE (intentional):
#   - Push the subtree tree to the GitHub mirror remote (`mirror`).
#   - That's it. The monorepo `origin` push is a separate, normal `git push`.
#   - Do NOT fast-forward C:\Projects\forgewire-fabric (operator pulls manually).
#   - Do NOT push to the OptiPlex `mini` remote (operator pulls manually).
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
#   5. Verify against the remote (ls-remote), NOT a local clone.
#
# The resulting mirror history is a linear chain of synthetic commits, one per
# sync, each containing the exact tree state of forgewire-fabric/ at the
# corresponding monorepo HEAD. History is shallow but the tree is always exact.
#
# Usage:
#   .\sync_mirror.ps1 [-MonorepoPath <path>] [-MirrorRemote <remote>] [-DryRun]
#
# NOTE: .github/workflows/** is a frozen surface (AGENTS.md Hard rule).
# CI integration of this script requires a human-reviewed workflow PR.

param(
    [string]$MonorepoPath = "C:\Projects\forgewire",
    [string]$Prefix       = "forgewire-fabric",
    [string]$MirrorRemote = "mirror",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "=== ForgeWire Mirror Sync (GitHub only) ===" -ForegroundColor Cyan
Write-Host "Monorepo:  $MonorepoPath\$Prefix"
Write-Host "Remote:    $MirrorRemote (GitHub)"
Write-Host "Note:      local clones on Precision/OptiPlex are NOT touched — pull manually."
Write-Host ""

# Resolve the tree SHA and monorepo HEAD.
$monoHead  = (git -C $MonorepoPath rev-parse HEAD 2>&1).Trim()
$shortHead = (git -C $MonorepoPath rev-parse --short HEAD 2>&1).Trim()
$treeSha   = (git -C $MonorepoPath rev-parse "HEAD:$Prefix" 2>&1).Trim()

Write-Host "Monorepo HEAD: $monoHead"
Write-Host "Subtree tree:  $treeSha"
Write-Host ""

if ($DryRun) {
    Write-Host "DRY RUN: would push tree-commit to $MirrorRemote." -ForegroundColor Yellow
    Write-Host "  tree SHA: $treeSha"
    Write-Host "  commit msg: sync: forgewire-fabric from monorepo $monoHead"
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
        # Fetch just this one ref so commit-tree can use it as a parent.
        git -C $MonorepoPath fetch $Remote "refs/heads/main:refs/remotes/$Remote/main" --no-tags 2>&1 | Out-Null
        Write-Host "  Fetch done"
    } else {
        Write-Host "  Mirror HEAD: (empty — first push)"
    }

    # Full SHA in the message records provenance (monorepo base commit).
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
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: push to $Remote failed" -ForegroundColor Red
        return $false
    }
    Write-Host "OK: pushed to $Remote" -ForegroundColor Green
    Write-Host ""
    return $true
}

# Push to GitHub mirror.
$mirrorOk = Push-TreeCommit $MirrorRemote "GitHub"
if (-not $mirrorOk) { exit 1 }

# Verify against the remote (no local clone involved). The mirror commit carries
# the exact subtree tree, so the remote HEAD's tree must equal $treeSha.
Write-Host "--- Post-sync verify (remote) ---" -ForegroundColor Yellow
$remoteHead = git -C $MonorepoPath ls-remote $MirrorRemote "refs/heads/main" 2>&1
if ($LASTEXITCODE -eq 0 -and "$remoteHead" -match "^([0-9a-f]{40})") {
    $remoteSha = $Matches[1]
    git -C $MonorepoPath fetch $MirrorRemote "refs/heads/main:refs/remotes/$MirrorRemote/main" --no-tags 2>&1 | Out-Null
    $remoteTree = (git -C $MonorepoPath rev-parse "${remoteSha}:" 2>&1).Trim()
    Write-Host "  Mirror HEAD:      $remoteSha"
    Write-Host "  Mirror tree:      $remoteTree"
    Write-Host "  Monorepo subtree: $treeSha"
    if ($remoteTree -eq $treeSha) {
        Write-Host "OK: GitHub mirror tree matches monorepo subtree." -ForegroundColor Green
    } else {
        Write-Host "FAIL: GitHub mirror tree does not match monorepo subtree." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "WARN: could not read mirror HEAD for verification." -ForegroundColor Yellow
}
