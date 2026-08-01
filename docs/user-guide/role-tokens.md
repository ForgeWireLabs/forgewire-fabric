# Role-separated tokens

Fabric separates bearer authority into dispatcher, runner, observer, approver,
and reviewer roles.

## Authority summary

- Dispatcher submits and manages tasks and dispatcher-scoped runner actions.
- Runner claims, starts, streams, handles intent, and reports results.
- Observer reads operational state, settings, history status, policy, and
  audit where authorized.
- Approver decides approval requests.
- Reviewer governs role tokens, secrets, settings mutations, and broader
  administrative operations.

The legacy token is intentionally narrow: dispatcher, runner, and observer
compatibility plus bootstrap access for migration/split. It does not inherit
reviewer, approver, secrets, or general admin authority.

## Lifecycle

Use `forgewire-fabric-cli role-tokens issue`, `migrate --split`, `list`, and
`revoke`. Raw credentials are shown once. rqlite stores only SHA-256 hashes and
public metadata. Audit events include token IDs, labels, roles, and actors but
never credentials or hashes.

Role misuse returns structured `RolePolicyViolation` data containing the
method, path, required roles, and granted roles. Rotate a disclosed token by
issuing a replacement, updating protected storage, validating the new role,
and revoking the old token.

