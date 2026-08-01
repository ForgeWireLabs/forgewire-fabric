# HA and third-voter readiness

rqlite voter-loss tolerance requires an odd quorum distributed across distinct
physical hosts. Two reachable machines can provide service continuity paths,
but they cannot prove survival of one voter loss if both are voters.

## Current evidence

The validated fleet contains exactly two physical Windows hosts. The OptiPlex
is the voter/leader and the Precision is a non-voter. This avoids the
two-voter write-quorum trap while preserving a reachable standby and runner.
It does not satisfy three-voter HA.

Run:

```text
python scripts/dr/third_voter_readiness.py --rqlite-url http://HOST:4001
```

The read-only probe groups processes by hostname, requires reachable voter
members on three distinct hostname identities, rejects URL-embedded
credentials, and reports the static third-host install command without
executing it.

Exit 0 means ready, 2 means healthy but hardware-blocked, and 1 means
unhealthy. An IP address alone is not physical-host identity evidence. Never
start extra local rqlite processes to manufacture a third voter.

After acquiring a third host, install it as a voter, verify `/nodes?nonvoters`,
then run a controlled leader-loss drill before claiming voter-loss HA.

