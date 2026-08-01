# VS Code extension

The VSIX is the reference behavioral client for Fabric. Desktop parity means
matching its information hierarchy, state meanings, refresh behavior, and
workflow results—not copying VS Code chrome pixel for pixel.

## Explorer model

The activity bar opens ForgeWire views for Hub, Hosts, Tasks, Agents,
Approvals, Cost, Audit, Secrets, and Settings. Tree nodes expose the same
entities used by desktop routes. Active tasks and terminal history include
provenance tooltips. The Settings tree includes both local VS Code preferences
and the redacted hub settings snapshot.

## Connection authority

The extension reads the active hub URL from the configured/pinned candidate
set, stores the bearer in VS Code SecretStorage, and registers a dispatcher
identity when connecting to a new hub. Candidate failover does not bypass
authorization or compatibility checks.

## Agent suite

Run `ForgeWire: Install Agent Suite` to install the packaged chatmodes and
prompt skills. Installation is conflict-safe: existing user files are not
silently overwritten. The extension package verifier checks that all declared
suite assets are present.

Use VSIX commands for actions exposed by the extension, but remember that the
hub is authoritative. A tree item or notification is not proof until the
corresponding hub read or audit evidence agrees.

Next: [Agent suite](agent-suite.md) and [provenance](provenance-policy.md).

