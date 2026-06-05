# Release Distribution Strategy

> Decision note for the Rust-first ForgeWire Fabric release line. Last reviewed: 2026-06-05.

## Recommendation

Do **not** treat PyPI as the primary publication channel for ForgeWire Fabric anymore.

PyPI remains useful, but only as a secondary integration channel for Python clients, MCP adapters, installer helpers, and the Python fallback path. The primary release channel should follow the runtime ownership boundary that now exists in the codebase: Rust hub, Rust runner, native operator CLI, signed native artifacts, and platform installers.

## Why PyPI is no longer the center

- The Rust workspace owns the deployable substrate: `forgewire-hub`, `forgewire-runner`, and `forgewire-fabric-cli` are native binaries, with rqlite as the default hub backend.
- Python is explicitly a compatibility and integration layer. It preserves parity, client ergonomics, and rollback safety, but it is no longer the normal daemon runtime.
- Production installation is service-oriented. Windows NSSM and Linux/macOS service managers need native binaries, watchdogs, identity files, rqlite wiring, audit exports, SBOMs, signatures, and rollback metadata; a Python wheel is the wrong unit of trust for that surface.
- Publishing daemon behavior primarily through PyPI would obscure the supply-chain boundary: operators would install a Python package while actually depending on Rust daemons and installer-side operational state.

## Recommended artifact tiers

1. **Tier 0 — GitHub release / mirrored release bundle**
   - Signed native binaries for `forgewire-hub`, `forgewire-runner`, and `forgewire-fabric-cli`.
   - Platform installers and service scripts.
   - Checksums, SBOM, provenance/attestation, release notes, and rollback instructions.
   - This is the primary operator-facing release artifact.
2. **Tier 1 — crates.io, only for stable Rust API crates**
   - Publish reusable libraries only when their public APIs are stable enough to support downstream semver.
   - Avoid publishing internal daemon crates merely to reserve names or mirror the workspace layout.
   - Candidate crates should use `forgewire-`-prefixed public names if the current `fabric-*` names are too generic for public registry ownership.
3. **Tier 2 — PyPI integration package**
   - Keep `forgewire-fabric` as a Python package for client libraries, MCP/automation adapters, compatibility fallback, and Python-driven smoke tooling.
   - The wheel must advertise itself as an integration layer, not the canonical deployment substrate.
   - The wheel may depend on or discover native binaries, but it should not be the only supported way to obtain or supervise them.
4. **Tier 3 — VS Code Marketplace and future GUI installers**
   - Publish editor or desktop surfaces as clients/dispatchers that talk to the hub API.
   - Keep these artifacts downstream of the signed native release bundle.

## Registry posture

As of the 2026-06-05 review, direct registry checks returned 404 for `forgewire-fabric` on PyPI and for likely public Rust names such as `forgewire-fabric`, `forgewire-hub`, `fabric-hub`, and `fabric-cli` on crates.io. That means the names appeared unclaimed at review time, but availability is not a release strategy.

Reserve names only when there is a real artifact plan:

- Use a pre-release package if name-squatting risk is high and the package metadata clearly states the Rust-first distribution model.
- Do not publish empty placeholder crates or wheels that users could mistake for the supported runtime.
- Re-check registry availability during every release cut because namespace state can change.

## Release checklist impact

A release is not ready merely because `pip install forgewire-fabric` works. The Rust-first release gate should require:

- Native hub and runner binaries built in release mode for supported platforms.
- Installer scripts tested from a clean host or VM for each Tier 1 platform.
- Service supervision and watchdog behavior verified after reboot or simulated process failure.
- rqlite bootstrap, recovery, and rollback notes attached to the release.
- Python fallback smoke-tested against the same Rust hub/rqlite state until the separate operator-confirmed Python-removal milestone closes.
- PyPI publication either skipped with rationale or performed as an integration-package release, not as the primary operator release.
