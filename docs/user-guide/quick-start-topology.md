# Quick start and topology

Fabric is a Rust hub and runner control plane backed by rqlite. The VSIX and
desktop applications are clients over the same authenticated hub APIs; neither
is a second state authority.

## First connection

1. Install or start the Fabric services.
2. Confirm `GET /healthz` reports `rust_hub: true`, protocol 4, and an rqlite
   backend.
3. Install the cluster-issued bearer token in protected client storage.
4. Load a dispatcher identity whose purpose is `dispatcher`.
5. Refresh the client and confirm Hosts, Runners, Tasks, Approvals, Audit, and
   Settings return current data.
6. Dispatch a narrow task and inspect its provenance before considering the
   connection proven.

Do not create a local token independently of the cluster. Role credentials are
issued or migrated through the hub and stored as SHA-256 hashes in rqlite.

## Proven two-machine layout

The tested Windows layout uses the OptiPlex as the active rqlite leader/voter
and the Precision as a reachable non-voter standby and runner host. Both
machines advertise real host and runner identities. Multiple rqlite processes
on one machine do not count as multiple physical voters.

Use `scripts/dr/third_voter_readiness.py` to distinguish:

- ready: three distinct reachable voter hostnames;
- hardware-blocked: the current two physical hosts are healthy but cannot
  tolerate voter loss;
- unhealthy: rqlite membership or reachability is degraded.

Next: [Desktop](desktop.md), [VSIX](vsix.md), and
[HA readiness](ha-third-voter.md).

