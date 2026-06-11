# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately** via
[GitHub Security Advisories](https://github.com/DigitalHallucinations/forgewire-fabric/security/advisories/new)
rather than opening a public issue. Include the affected component (hub,
runner, CLI, MCP server, installer), a reproduction, and the impact as you
understand it. You will get an acknowledgement, and a fix or mitigation will
be prioritized ahead of feature work — execution integrity is the product.

ForgeWire Fabric is **alpha** software. There is no bug-bounty program and no
formal SLA, but security reports are treated as release-gating.

## Scope and model

The written threat model lives at
[docs/spec/phase-2.9/THREATMODEL.md](docs/spec/phase-2.9/THREATMODEL.md).
In short: the hub is the trust anchor; dispatchers, runners, and the network
are not trusted. Things we consider in scope:

- Signature bypass or forgery on dispatch envelopes, runner claims, or stdin.
- Nonce/replay weaknesses.
- Policy-gate bypass (dispatch, runtime intent, completion).
- Secret-broker leakage: values reaching logs, audit records, or task output.
- Cross-rail claims (a command runner obtaining agent work or vice versa).
- Audit-chain tampering that is not detectable on verification.
- Installer and update-channel integrity.

Out of scope: attacks requiring possession of the hub bearer token or the
hub host itself (the token is documented as equivalent to an SSH private
key), and deployments that expose a plain-HTTP hub to untrusted networks
against the documented guidance ([docs/operations/tls.md](docs/operations/tls.md)).

## Supported versions

Alpha: only the latest `main` is supported. There are no maintained release
branches yet; fixes land on `main` and ship with the next bundle.
