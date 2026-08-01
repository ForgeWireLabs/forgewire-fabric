# Approvals

Approvals are durable hub records tied to a protected operation. They are not
local modal confirmations.

## Examination

Before deciding, inspect the approval identifier, task, dispatcher, branch,
scope, requested operation, policy reason, creation time, and related
provenance. Defer/snooze is a client review convenience; approve and deny are
governed hub decisions.

The approver role may decide approvals. Reviewer authority also permits the
operation. Observer and dispatcher roles may read only the subsets authorized
by the role matrix.

## Decision evidence

Supply an approver identity and a reason, especially for denial. The hub updates
the approval record, appends policy/provenance evidence to the task, and writes
an audit event. If ForgeLink HITL routing is configured, it is the decision
surface for protected kinds; otherwise the Fabric approval pane remains the
parity path.

Never approve based only on a notification. Re-read the active approval and
ensure its envelope, scope, and task state still match the reviewed request.
See [role tokens](role-tokens.md) and
[provenance](provenance-policy.md).

