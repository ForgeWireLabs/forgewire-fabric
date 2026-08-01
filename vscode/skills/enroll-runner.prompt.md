---
description: Guide a safe BYO Fabric agent-runner enrollment using the shipped installer and runner MCP.
mode: agent
tools: ['forgewire-fabric/list_agents', 'forgewire-fabric/discover_hub', 'codebase', 'search', 'searchResults']
---

# Enroll a Fabric runner

Determine the operator's platform, workspace, and intended agent type. Explain
the shipped install/setup path, then have the operator configure
`forgewire-fabric-runner` from `install/mcp-configs/vscode/mcp.runner.json`.
Verify the new runner appears in `list_agents` and advertises its real MCP
manifest. Do not manufacture runner rows, capabilities, identities, or tokens.

Credentials stay in the installer-managed token file. Never ask the operator
to paste a bearer token into chat or a tracked configuration file.
