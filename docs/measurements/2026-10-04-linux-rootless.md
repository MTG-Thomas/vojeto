# Linux rootless resource and packet-loss measurements

The test runs the real CLI separately from its synthetic Nebula peer. Only the
CLI's `/proc` RSS and process CPU times enter the reported client metrics. It uses
fresh disposable certificates and a static identity. It verifies 500 encrypted
round trips, holds those connections open, then transfers 160 MiB bidirectionally
across ten streams and forces bounded shutdown.

Run from the repository root:

```sh
docker build --target measurements -t vojeto-measurements .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 512m --cpus 1 --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  vojeto-measurements -test.run '^TestResourceProfile$' -test.v -test.count=3 -test.timeout 3m
```

The container's 512 MiB allowance covers the CLI, peer, and test driver together.
It does not declare a 512 MiB Vojeto requirement. One shared CPU also covers all
three processes. Measurements below came from x86_64 Linux 6.12.107, with the CLI
and peer under UID 65532, a read-only root, and zero capabilities.

## Initial failure and partial correction

Before TCP selective acknowledgements, repeated transfers sometimes exceeded
60 seconds. Increasing the test container to 512 MiB and two CPUs did not resolve
that failure. Failure snapshots showed no OOM events and 14,000 to 19,000 UDP
receive-buffer drops per run. Both processes remained alive. Raising host socket
limits or adding privileges is outside the portable networking contract.

Nebula's userspace service enables TCP SACK. Our outbound stack inherited the
prototype's omission and used gVisor's disabled default. Enabling SACK matches
upstream behavior and permits selective recovery of lost TCP segments. With that
change, three repeated runs completed the same workload and original deadlines.
Transfers took 20.47 to 25.97 seconds, and active-session drain took 1.02 seconds.
No host route, firewall, DNS, capability, or buffer-limit change was made.

Without a Go memory limit, CLI peak RSS reached 127 to 136 MiB despite idle RSS
near 26 to 32 MiB and 500-connection steady RSS near 60 MiB. That exceeds the
intended 128 MiB container budget. The standard image now defaults to
`GOMEMLIMIT=96MiB`, which is a soft Go runtime limit and can be overridden through
the environment. It leaves room for code and other memory outside Go's accounting.
With that setting, three repeated runs passed under the same one-CPU allowance.

| Measurement | Observed range |
| --- | --- |
| Idle CLI RSS | 25.8 to 34.0 MiB |
| 10 connections | 26.5 to 34.2 MiB |
| 100 connections | 32.1 to 39.8 MiB |
| 500 connections | 55.6 to 59.7 MiB |
| Peak CLI RSS | 97.2 to 99.8 MiB |
| Startup to ready | 0.021 to 0.070 seconds |
| 160 MiB bidirectional transfer | 24.63 to 54.25 seconds |
| Active drain | 1.03 to 1.12 seconds |
| Whole-run CLI CPU | 8.82 to 12.41 seconds |

The first corrected measurements used the same container settings with locally rebuilt
CLI and test executables mounted read-only for the SACK change. Final public CI builds
both with the pinned Go 1.26.8 image and repeats the rootless tests. Six corrected
local stress runs passed, including three with the memory limit. This sample does
not establish tail latency or a guaranteed maximum.

## Limits of this proof

These are local static-identity measurements, not a claim of cloud support or a
supported 128 MiB maximum workload. Azure acquisition/checkpoint time, reconnect
latency, cloud latency/loss, long-running memory behavior, and platform-native
worker shutdown remain acceptance work. Total CLI CPU time covers startup, all
round trips, sustained transfer, and shutdown. It does not isolate transfer CPU.
The test reports peak RSS before shutdown, not a continuously sampled per-stage
peak. Deployment budgets must include their chosen concurrency and provider.

The opt-in measurement test preserves its 60-second transfer deadline and logs
bounded process/cgroup/UDP counters on failure. Public CI exercises it with the
same rootless restrictions. Do not replace a failing measurement with a claimed
budget or relax its deadline to conceal packet-loss recovery failures.

## Subsequent failures, 2026-10-04

The earlier passing sample did not resolve intermittent transfer stalls. Follow-up
runs reproduced the original 60-second failure with SACK enabled. Linux Nebula
socket-buffer setters used privileged FORCE options; the rootless fallback now
requests ordinary buffers within the host's limits. That fixes an independently
reproduced EPERM error, but another five-run sample still failed once.

A temporary diagnostic build then failed once in ten runs under the same encrypted
workload and deadline. Nine streams finished within 19 seconds; one had written
8 MiB and received only 850,400 bytes at timeout. The snapshot recorded UDP
receive drops, no OOM, and no recorded Nebula decrypt/firewall drop categories.
TCP queues and retransmission recovery remained active. These observations do
not identify the root cause. The diagnostic hooks were removed after inspection.
At this stage, issue #14 still blocked production replacement.

Permanent tests exercise periodic loss, a finite burst, response-tail loss, and
packet reordering in both directions using the production TCP stack configuration.
They compare every returned byte and join connection writers, echo handlers, and
packet pumps. Passing these isolated regressions does not replace the encrypted
load test or prove the deployed concurrency budget.

## Zero-pipe tail-probe timer correction

A bounded controlled tail-loss trace reproduced a sender with 3,600 unacknowledged
bytes and zero packets in its pipe estimate. After its tail probe, retransmission
was not armed. The checksum-verified gVisor patch described in
[the TCP recovery design](../architecture/tcp-recovery.md) corrects that timer gate
without changing retransmission durations or congestion control. A direct
regression fails on the pinned original and passes with the patch. Ten
instrumented tail-loss race runs and ten uninstrumented race runs of all four
fault modes passed after the correction. The full race suite and standard
container race/vet gates also passed; temporary probes were removed.

Twenty further encrypted load runs with the same workload, deadlines, one CPU,
512 MiB shared allowance and rootless restrictions passed nineteen times. One
stream still stalled at 1,620,032 of 8,388,608 echoed bytes while the other nine
completed. No OOM was recorded. This establishes an independent timer correction,
not a complete fix for encrypted load recovery. At this stage, issue #14 remained open and
production replacement remained gated. A passing CI sample cannot supersede that
failed acceptance run.

## Completed TCP recovery regressions

PRs #18 and #19 correct smaller-window retransmission and pure ACK sequence
selection at a closed peer window. See [the recovery design](../architecture/tcp-recovery.md).
Both production-stack regressions fail before their respective corrections and
passed 100 times with the race detector afterward. Full race tests, vet, standard
container checks and CI passed, including encrypted proof and ARM64 compilation.

Ten instrumented encrypted runs passed, followed by twenty clean runs without
diagnostic hooks. The clean batch kept the original 500 open connections, ten
8 MiB bidirectional streams, 60-second transfer deadline, one CPU, 512 MiB shared
allowance, UID 65532, no capabilities and read-only filesystem. All twenty passed.
The source correction is merged at `0e9c83138f4096e2e6b632ba32edc686cfbb4e9e`.

| Measurement | Observed range across twenty clean runs |
| --- | --- |
| Idle CLI RSS | 30.2 MiB to 34.1 MiB |
| 10 connections | 32.2 MiB to 34.3 MiB |
| 100 connections | 39.5 MiB to 43.7 MiB |
| 500 connections | 60.7 MiB to 79.0 MiB |
| Peak CLI RSS | 101.4 MiB to 120.4 MiB |
| Startup to ready | 0.021 seconds to 0.425 seconds |
| 160 MiB bidirectional transfer | 16.41 seconds to 38.30 seconds |
| Active drain | 1.016 seconds to 1.074 seconds |
| Whole-run CLI CPU | 6.39 seconds to 13.68 seconds |

Issue #14 is closed for these reproduced defects. These samples do not establish
an upper latency bound, cloud support, live Defined behavior or a production
memory budget. No image was published and no deployment changed. SDK licensing,
dynamic-grant integration and deployment-specific acceptance remain separate
replacement gates.
