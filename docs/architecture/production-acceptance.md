# Production acceptance

Source/release evidence reviewed October 11, 2026. This is an acceptance ledger,
not a claim that a particular cloud deployment or memory budget is supported.

| Gate | Current evidence | Remaining acceptance |
| --- | --- | --- |
| SDK licensing | PR #33 pins MIT-licensed dnapi `1d274612a81a`; main-client release inventory passes in CI | Retain the exact dependency notices in every distributed artifact |
| Portable core | Race suite, rootless encrypted proofs, finite SOCKS/peer/launcher lifecycle checks pass on main `4bd48c8` | Real consumer dependencies and platform termination behavior |
| TCP recovery | PR #35 adds RACK flight-accounting regressions, 100 race iterations and unchanged encrypted transfer deadlines; PR #39 repairs diagnostics | [Rootless periodic loss/reordering regression](packet-fault-proof.md) supplements the transfer proof; representative soak and peer/router restart evidence remain |
| Dynamic enrollment | Grant validation, durable store interface and private same-UID agent client | A concrete consumer agent and host-specific durable backend; paused/restarted owners must not overlap |
| Resources | Isolated CLI RSS and 10/100/500 encrypted sessions are measured; PR #41 adds CLI CPU ticks during sustained transfer with three retained samples | Provider acquisition/checkpoint/reconnect latency, long-running leak checks and actual 64/128/256 MiB budgets |
| Publication | Exact verified-main/CI/license gates; protected private OCI publishers, keyless signature/statement checks and synthetic tamper rejection are implemented in source | Environment and private destination setup, actual keyless producer/consumer receipt, authorized/unauthorized platform fetch and rollout/rollback admission under #38 |
| Architecture | ARM64 compilation passes | ARM64 execution before claiming runtime support |

Current validation: [main run 37977837457](https://github.com/MTG-Thomas/vojeto/actions/runs/37977837457).
Current main-client publication: [run 37978484989](https://github.com/MTG-Thomas/vojeto/actions/runs/37978484989).
These producer receipts do not establish a deployment's identity ownership,
application behavior or artifact admission policy.
The historical publication preceded the [private signed release contract](release-security.md)
and is not retrospectively certified by it. Future publication must pass that
contract; no private artifact was published by the source change.

## Required consumer proof

Use the consumer repository's protected release and rollback lane. Record exact
source, producer run/attempt, immutable artifact digest, configuration, platform
budget and target before testing. Pooled identities and fresh broker enrollment
are different acceptance paths; evidence for one does not qualify the other.

Prove cold start and required dependency readiness using the original application
TLS hostnames. Exercise credential rotation, classified control-plane outage and
recovery, rejected credentials, uncertain mutation/checkpoint, and independent
lease loss while sessions are active. Lease loss must close admission and active
traffic without waiting for an uncooperative provider call.

Prove completion and signal shutdown with real work in flight: stop admission,
bounded drain, final checkpoint, transport stop, then ownership release. Restart
and overlap tests must include a paused old process and an expired lease; expiry
or a new boot nonce is not evidence that the previous transport stopped.

Run a representative soak with recorded duration, traffic, loss/latency, platform
limits and provider activity. Track RSS, sustained CPU, reconnect latency, FDs,
goroutines and active sessions returning to baseline. Retain failures and their
diagnosis; do not change deadlines or add retries merely to obtain green.

Verify artifact authorization, signatures/provenance and a deliberately tampered
artifact at the actual consumer boundary. Rehearse rollback to the retained
published prototype digest after owned drain. Preserve quarantined identities;
rollback must not break a lease or clear an uncertain marker to make startup work.

Generic software remains here. Real membership, broker authorization, routes,
queues, scaling, deployment budgets and rollout receipts remain in the consumer
repositories. QUIC and other optional transport spikes are not cutover gates.
