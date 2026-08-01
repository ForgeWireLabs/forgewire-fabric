# ForgeWire Fabric operator guide

This guide describes the shared Fabric experience across the VS Code extension
and the Tauri 2 desktop client. The VSIX remains the behavioral reference:
navigation labels, task states, policy outcomes, freshness semantics, and
operator workflows should mean the same thing in both skins.

## Start here

1. [Quick start and topology](quick-start-topology.md)
2. [Desktop client](desktop.md)
3. [VS Code extension](vsix.md)
4. [Tasks and dispatch](tasks.md)
5. [Settings and doctor](settings-doctor.md)

## Governance and operations

- [Agent suite](agent-suite.md)
- [Approvals](approvals.md)
- [Secrets and egress](secrets-egress.md)
- [Role tokens](role-tokens.md)
- [Provenance and policy](provenance-policy.md)
- [HA and third-voter readiness](ha-third-voter.md)
- [Optional history sink](history-sink.md)
- [Releases, updater, and rollback](releases-updater-rollback.md)
- [Troubleshooting and security](security.md)

## Current validation boundary

The currently proven fleet is two physical Windows machines: Precision
`DESKTOP-228U8GL` and OptiPlex `DESKTOP-38GVF8D`. This proves two-host
operation, not voter-loss quorum. macOS and Linux release execution, platform
signing, and notarization remain unproven until those hosts and credentials are
available. The Linux release lane also fails closed on
`GHSA-wrw7-89jp-8q8g` while Tauri's GTK stack remains on vulnerable `glib`.
