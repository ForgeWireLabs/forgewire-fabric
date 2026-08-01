# VS Code agent suite

The packaged suite supplies four least-privilege chatmodes and seven reusable
skills. ForgeWire is the system name, not a persona.

## Chatmodes

- Dispatcher prepares sealed briefs and dispatches through governed Fabric
  paths.
- Runner performs bounded assigned work and reports evidence.
- Approver examines risk and recommends a decision; the actual approval or
  denial is submitted through the governed client surface.
- Observer is read-only and suitable for status, policy, provenance, and audit
  inspection.

## Skills

The bundle includes dispatch-test-fix, dispatch-docs-sync,
bisect-regression, triage-pending-approvals, replay-with-cheaper-model,
enroll-runner, and dispatch-cost-aware. Each skill is a prompt workflow, not a
new authority. It must still obey role tokens, signed briefs, policy gates,
scope limits, and audit requirements.

## Installation

Use the VSIX install command or the manifest under
`install/mcp-configs/vscode/agent-suite.manifest.json`. Review conflicts before
replacing a local customization. The packaged assets are also checked during
VSIX bundle/package validation.

The suite assumes two MCP surfaces: dispatcher/operator functions and
runner/agent functions. Do not collapse them into a single over-privileged
mode. See [role tokens](role-tokens.md) and [approvals](approvals.md).

