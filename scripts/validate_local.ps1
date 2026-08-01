param(
  [switch]$NoFmt,
  [switch]$NoClippy,
  [switch]$NoTests,
  [switch]$NoLint,
  [switch]$NoGovernance,
  [switch]$Fix
)

# Local CI validation for forgewire-fabric. Runs the same checks
# `.github/workflows/ci.yml` and `lint.yml` declare -- those files live in
# this subdirectory's `.github/workflows/`, which GitHub Actions never
# discovers (it only reads workflows from the repo root, and this directory
# is a subdirectory of the `forgewire` monorepo, not a repo root itself) --
# plus the repo-wide RepoPact governance check. This script is the actual
# gate until a root-level workflow is wired up; run it before every commit,
# not just before a PR.
#
# Usage:
#   scripts\validate_local.ps1                 # everything
#   scripts\validate_local.ps1 -NoTests         # skip the (slower) test suite
#   scripts\validate_local.ps1 -Fix             # `cargo fmt` in place instead of --check
#
# Prerequisite as of 114C.6: fabric-hub depends on webauthn-rs, which links
# native OpenSSL. On Windows this needs vcpkg + VCPKG_ROOT set -- see the
# comment above the webauthn-rs entry in crates/fabric-hub/Cargo.toml for the
# one-time setup.

$ErrorActionPreference = "Stop"
$fabricRoot = Split-Path -Parent $PSScriptRoot
$monorepoRoot = Split-Path -Parent $fabricRoot
$desktopCrate = Join-Path $fabricRoot "desktop\src-tauri"

$failed = @()

function Run-Step {
  param([string]$Name, [scriptblock]$Body)
  Write-Host ""
  Write-Host "== $Name =="
  & $Body
  if ($LASTEXITCODE -ne 0) {
    $script:failed += $Name
    Write-Host "-- FAILED: $Name (exit $LASTEXITCODE)" -ForegroundColor Red
  }
}

Write-Host "== forgewire-fabric local validation =="
Write-Host "fabric root:    $fabricRoot"
Write-Host "monorepo root:  $monorepoRoot"

Push-Location $fabricRoot
try {
  # desktop/src-tauri declares its own empty [workspace], so it is NOT a member of
  # the fabric workspace: neither `--all` nor `--workspace` below reaches it. Every
  # cargo check here needs a matching desktop-crate run or that crate silently
  # drifts (which is exactly how two clippy errors sat unnoticed until 114C.6).
  if (-not $NoFmt) {
    # The desktop steps deliberately omit `--all`. Unlike clippy/test below
    # (where `--all-targets` selects targets, not packages), `cargo fmt --all`
    # run from desktop/src-tauri escapes that crate's own workspace and walks
    # the parent fabric tree: it reports diffs in crates/fabric-hub/**, so a
    # misformatted *fabric* file failed both fmt steps and looked like desktop
    # drift that did not exist. Plain `cargo fmt --check` stays scoped to the
    # desktop crate -- verified by misformatting desktop/src-tauri/src/main.rs
    # and confirming this form still catches it.
    if ($Fix) {
      Run-Step "cargo fmt (writing)" { cargo fmt --all }
      Run-Step "cargo fmt (writing, desktop)" {
        Push-Location $desktopCrate
        try { cargo fmt } finally { Pop-Location }
      }
    } else {
      Run-Step "cargo fmt --check" { cargo fmt --all -- --check }
      Run-Step "cargo fmt --check (desktop)" {
        Push-Location $desktopCrate
        try { cargo fmt --check } finally { Pop-Location }
      }
    }
  }

  if (-not $NoClippy) {
    Run-Step "cargo clippy -D warnings" { cargo clippy --workspace --all-targets -- -D warnings }
    Run-Step "cargo clippy -D warnings (desktop)" {
      Push-Location $desktopCrate
      try { cargo clippy --all-targets -- -D warnings } finally { Pop-Location }
    }
  }

  if (-not $NoTests) {
    Run-Step "cargo test --workspace" { cargo test --workspace --all-targets }
    Run-Step "cargo test (desktop)" {
      Push-Location $desktopCrate
      try { cargo test --all-targets } finally { Pop-Location }
    }

    # This gate ran zero TypeScript before this point: fabric-client-core's 60+
    # vitest tests, desktop's TS vitest suite, and the VSIX's own compile
    # (typecheck + bundle + verify:bundle + verify:package, its only
    # correctness check -- it has no test runner) all passed only because
    # someone happened to run them by hand. Found while shipping 114C.6 Slice
    # 5c: nothing here would have caught a break in either.
    #
    # Build client-core first and always: desktop and the VSIX both import it
    # from `dist/`, not `src/`, so a stale build silently tests old code --
    # already hit once this milestone (VSIX typecheck failed on exports that
    # existed in source but not in a stale dist).
    Run-Step "npm build (fabric-client-core)" { npm run build --workspace @forgewire/fabric-client-core }
    Run-Step "npm test (fabric-client-core)" { npx vitest run --root packages/fabric-client-core }
    Run-Step "npm test (desktop, TS)" { npx vitest run --root desktop }
    Run-Step "npm compile (vscode)" { npm run compile --workspace forgewire }
  }

  if (-not $NoLint) {
    Run-Step "ruff check" { ruff check python/forgewire_fabric tests }

    # ruff only lints; it runs no assertions. These four files are static
    # cross-language contract guards -- canonical command/view IDs vs the VSIX
    # package.json, client-core's no-DOM/no-node purity, and the desktop
    # webview boundary -- and nothing in this gate was executing them. A
    # desktop contract regression sat green through a full local validation
    # and a merged PR because of that.
    #
    # Deliberately this subset, not `pytest tests`: the full suite is ~11
    # minutes, which is too slow for the pre-commit gate. These run in ~2s.
    Run-Step "pytest (static contracts)" {
      python -m pytest -q `
        tests/test_client_core_architecture.py `
        tests/test_desktop_114b_contract.py `
        tests/test_mcp_and_vscode_surface.py `
        tests/test_vscode_agent_suite.py
    }
  }
} finally {
  Pop-Location
}

if (-not $NoGovernance) {
  Run-Step "repopact validate" {
    python -m repopact_cli validate --root $monorepoRoot
  }
}

Write-Host ""
Write-Host "== Git status (forgewire-fabric) =="
Push-Location $fabricRoot
git status --short
Pop-Location

Write-Host ""
if ($failed.Count -eq 0) {
  Write-Host "Local validation complete: all checks passed." -ForegroundColor Green
  exit 0
} else {
  Write-Host "Local validation FAILED: $($failed -join ', ')" -ForegroundColor Red
  exit 1
}
