# Production acceptance

Source/release evidence reviewed October 10, 2026. This is an acceptance ledger,
not a claim that a particular cloud deployment or memory budget is supported.

| Gate | Current evidence | Remaining acceptance |
| --- | --- | --- |
| SDK licensing | PR #33 pins MIT-licensed dnapi `1d274612a81a`; main-client release inventory passes in CI | Retain the exact dependency notices in every distributed artifact |
| Portable core | Race suite, rootless encrypted proofs, finite SOCKS/peer/launcher lifecycle checks pass on main `4bd48c8` | Real consumer dependencies and platform termination behavior |
| TCP recovery | PR #35 adds RACK flight-accounting regressions, 100 race iterations and unchanged encrypted transfer deadlines; PR #39 repairs diagnostics | Representative loss/reordering soak and peer/router restart evidence; a passing short proof is not a soak |
| Dynamic enrollment | Grant validation, durable store interface and private same-UID agent client | A concrete consumer agent and host-specific durable backend; paused/restarted owners must not overlap |
| Resources | Isolated CLI RSS/CPU and 10/100/500 encrypted sessions are measured | Provider acquisition/checkpoint/reconnect latency, sustained CPU, long-running leak checks and actual 64/128/256 MiB budgets |
| Publication | PR #34 adds exact verified-main/CI/license-gated main-client publication | Artifact signatures/provenance verified by consumers, access policy, tamper rejection and revocation/rollback under #38 |
| Architecture | ARM64 compilation passes | ARM64 execution before claiming runtime support |

Current validation: [main run 37977837457](https://github.com/MTG-Thomas/vojeto/actions/runs/37977837457).
Current main-client publication: [run 37978484989](https://github.com/MTG-Thomas/vojeto/actions/runs/37978484989).
These producer receipts do not establish a deployment's identity ownership,
application behavior or artifact admission policy.

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
