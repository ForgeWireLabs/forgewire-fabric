# Troubleshooting and security

Fabric combines bearer authorization with Ed25519 identities and signed
state-changing envelopes. The bearer role answers whether an operation is
allowed; the identity and signature answer which registered actor produced the
request.

## Required boundaries

- Never place raw tokens, private keys, secret values, signing credentials, or
  history DSNs in source, audit, evidence, or UI state.
- Use TLS for non-loopback external communication. The history sink requires
  verified TLS and explicit `sslmode=require`.
- Keep dispatcher, runner, observer, approver, and reviewer credentials
  separate.
- Preserve the canonical v2 payload and protocol parity paths.
- Keep rqlite as the only Tier-1 authority.
- Treat the optional history database as export-only and absence-tolerant.
- Audit role-token lifecycle, policy decisions, secret governance, settings
  changes, egress denials, approvals, and terminal results.

Task egress is default-deny when declared and uses a per-task loopback proxy.
Child environments are cleared before a safe allowlist is applied. Secret
redaction occurs before serialization across progress, streams, results, notes,
and audit.

The desktop renderer has no raw updater or bearer capability. Native Tauri
commands hold protected values and scoped HTTP access. Unsigned silent update
is forbidden.

Report any path that bypasses these boundaries as an architecture defect, not
as a UI limitation.

## Troubleshooting

If a client shows unknown or partial data, check `/healthz` and the resource
error first. Last-good data is deliberately retained and labeled stale; an
empty panel during a transport or authorization failure is not authoritative
zero state.

For authorization failure, inspect `RolePolicyViolation`, confirm the active
hub and intended role token, and rotate a disclosed credential rather than
copying reviewer authority into a runner.

For a stuck dispatch, inspect task status, approval ID, policy decisions,
capability requirements, runner drain state, scope prefixes, base commit,
secret availability, and egress policy. Repeated redispatch without explaining
the first denial creates noise rather than recovery.

Doctor exit 2 is degraded/warning state. Read the individual JSON checks; on
the validated fleet, lack of a third physical voter is an expected honest
warning. A configured history sink that cannot connect is a failure, but the
hub and dispatch paths must remain available in thin-history mode.
