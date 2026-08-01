# Local CI

ForgeWire Fabric uses repository-owned local validation as its primary merge gate.
Hosted CI availability is not required.

## Fast mode

```powershell
pwsh -NoProfile -File scripts/ci/local-ci.ps1 -Mode Fast
```

Runs syntax, formatting, installer, version, and local-CI contract checks.
Fast mode never authorizes access to shared rqlite state.

## Full mode

```powershell
pwsh -NoProfile -File scripts/ci/local-ci.ps1 -Mode Full
```

Runs Fast mode, deterministic Python tests selected with
`-m "not live_cluster"`, and the complete Rust workspace test suite.

Full mode is the normal local merge gate.

## Live mode

```powershell
pwsh -NoProfile -File scripts/ci/local-ci.ps1 -Mode Live -AllowLiveCluster
```

Live mode sets `FORGEWIRE_TEST_ALLOW_LIVE_CLUSTER=1` for the test process.
These tests may inspect, mutate, clean, or depend on shared rqlite state.

Live mode refuses to run unless `-AllowLiveCluster` is explicitly supplied.

## Safety boundary

Fast and Full remove live-cluster authorization before running pytest.
Live tests are operational evidence checks, not deterministic CI.
