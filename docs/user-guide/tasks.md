# Tasks and dispatch

Fabric supports `agent` and `command` tasks. Agent dispatch may select
`prompt`, `skill`, or `tool`; command tasks remain a separate Loom execution
surface.

## Before dispatch

Define a title, branch, base commit, scope globs, bounded brief, timeout, and
required capabilities. Add secret names and egress policy only when required.
The dispatcher signs the canonical v2 payload; new provenance fields remain
sidecar data so the frozen wire contract does not drift.

## Lifecycle

Typical states are queued, held, claimed, running, done, failed, cancelled, and
timed out. A held task awaits approval. Claiming binds the registered runner
and host. Intent and completion pass through policy checks. Terminal results
record runtime, cost evidence when supplied, and an explicit exit reason.

## Client behavior

Both clients show active and historical tasks, detail, streams, audit, policy
decisions, approval counts, and actor/host provenance. Last-good task state is
retained during partial outages. Redispatch creates a new governed task and
records the source task rather than rewriting history.

Treat a UI status as a projection. Use task detail, `/policy`, and audit
evidence together for consequential review. See
[provenance and policy](provenance-policy.md).

