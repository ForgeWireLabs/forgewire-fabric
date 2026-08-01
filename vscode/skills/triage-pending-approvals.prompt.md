---
description: Summarize pending approvals for a human approver without making the decision.
mode: agent
tools: ['forgewire-fabric/get_task', 'forgewire-fabric/list_tasks', 'forgewire-fabric/read_stream', 'forgewire-fabric/read_notes', 'codebase', 'search', 'searchResults']
---

# Triage pending approvals

Use the pending records displayed in the VSIX Approvals pane as the approval
queue. For each record, inspect its task evidence and summarize requested
action, policy trigger, scope, blast radius, reversibility, secret/egress
impact, missing evidence, and a recommended approve/deny/defer reason.

Do not dispatch, cancel, drain, execute Loom commands, call raw hub endpoints,
or make the decision. The operator completes it in the VSIX so the approver
identity and audit event remain authoritative.
