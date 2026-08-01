# Desktop client

The Tauri 2 desktop client is a VSIX-aligned workbench, not a browser wrapper.
Authenticated hub traffic runs through typed native commands; bearer tokens and
dispatcher private keys are not exposed to renderer JavaScript.

## Layout

The far-left activity rail selects a domain. The contextual sidebar shows the
VSIX-shaped tree for that domain. The main workbench route shows dashboards,
lists, details, and governed actions. The dashboard is the default landing
page.

The supported domains are Hub, Hosts, Tasks, Agents, Approvals, Cost, Audit,
Secrets, and Settings. Selection and route state survive refreshes. Last-good
data remains visible during an outage and is labeled stale rather than being
replaced by false empty state.

## Operator workflow

- Use Settings to install the hub token, load the dedicated dispatcher
  identity, manage discovery preference, inspect hub settings, and check signed
  desktop updates.
- Use Tasks for dispatch, stream, cancel, redispatch, provenance, and results.
- Use Approvals for examination and decision.
- Use Secrets only for governed mutation; values are never rendered.

The updater is registered only when the build embeds a non-empty updater public
key. Update checks are explicit, installation requires confirmation, and Tauri
verifies signed metadata before running an installer.

Current packaged proof is Windows-only. See
[releases and rollback](releases-updater-rollback.md) before calling another
platform supported.

