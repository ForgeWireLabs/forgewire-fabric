# check_mirror_sync.ps1 — M2.9.6 (F8) mirror provenance guard
#
# Verifies that the standalone forgewire-fabric mirror at $MirrorPath is in
# sync with the in-tree subtree at the base commit recorded in the mirror's
# HEAD commit message.
#
# Usage:
#   .\check_mirror_sync.ps1 [-MirrorPath <path>] [-MonorepoPath <path>]
#
# Exit codes:
#   0  mirror is in sync
#   1  mirror diverges from the subtree at the recorded base commit
#   2  required tooling missing or paths not found
#
# This script is intended for:
#   - Developer "doctor" runs (scripts/dr/) before any sync-commit
#   - CI pipelines that gate on mirror integrity
#
# NOTE: .github/workflows/** is a frozen surface (AGENTS.md Hard rule).
# CI integration requires a human-reviewed workflow change — coordinate
# before wiring this script into a workflow file.

param(
    [string]$MirrorPath  = "C:\Projects\forgewire-fabric",
    [string]$MonorepoPath = "C:\Projects\forgewire\forgewire-fabric"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$msg, [int]$code = 1) {
    Write-Host "FAIL: $msg" -ForegroundColor Red
    exit $code
}

function Pass([string]$msg) {
    Write-Host "OK:   $msg" -ForegroundColor Green
}

# ── prerequisites ──────────────────────────────────────────────────────────────

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Fail "git not found in PATH" 2
}

if (-not (Test-Path $MirrorPath)) {
    Fail "Mirror path not found: $MirrorPath" 2
}

if (-not (Test-Path $MonorepoPath)) {
    Fail "Monorepo subtree path not found: $MonorepoPath" 2
}

# ── extract base commit from mirror HEAD ──────────────────────────────────────
# Convention: sync commits include "monorepo <hash>" or "M<x>.<y>.<z>" in the
# message. We look for the pattern "M2.\d+\.\d+" or a 40-char hex commit ref.

$mirrorHead = git -C $MirrorPath log --format="%H %s" -1 2>&1
if ($LASTEXITCODE -ne 0) {
    Fail "Could not read mirror HEAD: $mirrorHead" 2
}

Write-Host "Mirror HEAD: $mirrorHead"

# Try to extract a monorepo commit hash from the mirror sync commit message.
# Sync commits are expected to include "monorepo <40-hex>" or "→ <40-hex>".
$baseCommit = $null
if ($mirrorHead -match '[0-9a-f]{40}') {
    # Exclude the mirror's own commit hash (first 40 chars of the line).
    $mirrorOwnHash = ($mirrorHead -split ' ')[0]
    $allHashes = [regex]::Matches($mirrorHead, '[0-9a-f]{40}') | ForEach-Object { $_.Value }
    $baseCommit = $allHashes | Where-Object { $_ -ne $mirrorOwnHash } | Select-Object -First 1
}

if (-not $baseCommit) {
    Write-Host "WARN: No base commit found in mirror HEAD message — falling back to comparing working trees." -ForegroundColor Yellow
    # Fall back: compare current subtree tree against mirror HEAD tree.
    # Compute prefix relative to git root first (same logic as the base-commit branch).
    $gitRootFb  = (git -C $MonorepoPath rev-parse --show-toplevel 2>&1).Trim().Replace('/', '\')
    $relPrefixFb = $MonorepoPath.TrimEnd('\').Replace($gitRootFb, "").TrimStart('\', '/')
    $headRef = if ($relPrefixFb) { "HEAD:${relPrefixFb}" } else { "HEAD:" }
    $monorepoTree = git -C $gitRootFb rev-parse $headRef 2>&1
    $mirrorTree   = git -C $MirrorPath rev-parse "HEAD:" 2>&1
    if ($monorepoTree -eq $mirrorTree) {
        Pass "Mirror tree hash matches monorepo subtree HEAD (no base commit recorded)."
        exit 0
    }
    Fail "Mirror tree ($mirrorTree) diverges from monorepo subtree ($monorepoTree). Run sync_mirror.ps1."
}

Write-Host "Base commit: $baseCommit"

# ── compare tree hashes at the recorded base commit ───────────────────────────
# $MonorepoPath may be a subdirectory of the git repo (e.g. the subtree path
# itself). We need the tree for that specific subdirectory, not the repo root.
# Compute the relative prefix from the actual git root.

$gitRoot   = (git -C $MonorepoPath rev-parse --show-toplevel 2>&1).Trim().Replace('/', '\')
$relPrefix = $MonorepoPath.TrimEnd('\').Replace($gitRoot, "").TrimStart('\', '/')
# If $MonorepoPath IS the repo root, $relPrefix will be empty and the colon
# syntax "commit:" refers to the root tree — which is also correct for a
# single-subtree repo.
$treeRef = if ($relPrefix) { "${baseCommit}:${relPrefix}" } else { "${baseCommit}:" }

$monorepoTreeAtBase = git -C $gitRoot rev-parse $treeRef 2>&1
if ($LASTEXITCODE -ne 0) {
    Fail "Base commit $baseCommit not found in monorepo (ref: $treeRef). History may have been rewritten." 2
}

$mirrorTree = git -C $MirrorPath rev-parse "HEAD:" 2>&1
if ($LASTEXITCODE -ne 0) {
    Fail "Could not resolve mirror HEAD tree." 2
}

Write-Host "Monorepo subtree tree @ $($baseCommit.Substring(0,12)): $monorepoTreeAtBase"
Write-Host "Mirror HEAD tree:                                          $mirrorTree"

if ($monorepoTreeAtBase -eq $mirrorTree) {
    Pass "Mirror is in sync with monorepo subtree at $($baseCommit.Substring(0,12))."
    exit 0
}

# ── divergence — show diff summary ───────────────────────────────────────────

Write-Host ""
Write-Host "Divergence detected. Files changed in mirror vs monorepo subtree:" -ForegroundColor Yellow
git -C $gitRoot diff --name-status "${baseCommit}:${relPrefix}" "HEAD:${relPrefix}" 2>&1 | Select-Object -First 40
Write-Host ""
Fail "Mirror diverges from monorepo subtree at $($baseCommit.Substring(0,12)). Run sync_mirror.ps1 to resync."
