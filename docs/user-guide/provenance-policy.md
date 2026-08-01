# Provenance and policy

Every task records who dispatched it, where it was dispatched, which
registered runner and host claimed it, what policy decisions occurred, and how
it ended.

## Recorded fields

Dispatch evidence includes time, user, host, agent/client, dispatcher identity,
and public-key fingerprint. Claim evidence includes runner and host. Runtime
evidence includes claimed, started, and completed timestamps, wall and runner
CPU seconds, approval counts and ID, policy decisions, and terminal exit
reason.

These are additive sidecar fields. They do not alter the frozen canonical v2
signed payload.

## Policy surface

Authenticated `GET /policy` returns the effective hub policy and recent task
decision evidence. Dispatch, intent, approval, and completion decisions append
stage, outcome, reason, actor, and time to task provenance and audit.

The desktop Task Detail and VSIX task tooltips render the same normalized DTO.
A dashboard may read this data but may not become an alternate writer or state
authority.

For an incident, correlate task detail, `/policy`, task audit, dispatcher
registration, runner registration, and the terminal result. Missing evidence
is a defect; do not infer a successful action from UI optimism.

