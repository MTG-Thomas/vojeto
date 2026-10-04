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

## Initial failure and correction

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
