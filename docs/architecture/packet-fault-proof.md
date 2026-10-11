# Rootless encrypted TCP recovery proof

`TestResourceProfile` runs the real CLI and a Nebula peer as separate processes.
Set `VOJETO_PROFILE_FAULTS=1` to route their encrypted UDP traffic through a
loopback test relay. Every 200th received datagram is dropped; every 97th eligible
datagram is held until another packet in the same direction can overtake it, or
five milliseconds pass. The relay holds at most one datagram, never decrypts
traffic, and joins its worker when closed. No root, capabilities, TUN, firewall
rules, host routes or system DNS changes are involved.

The workload and existing limits stay the same: 500 TCP sessions, ten concurrent
streams transferring 8 MiB each in both directions, a 60-second stream deadline,
and a one-second forced drain with a ten-second exit bound. Both transfer
directions must account for at least 80 MiB forwarded through the relay, and
actual drops and reordering must occur. This guards against accidentally testing
a direct path after peer discovery. The periodic schedule is reproducible; the
exact packets and elapsed time depend on scheduling and retransmissions.

Run the same CI fixture locally:

```sh
docker build --target measurements --tag vojeto-measurements .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 512m --cpus 1 --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -e VOJETO_PROFILE_FAULTS=1 vojeto-measurements \
  -test.run '^TestResourceProfile$' -test.v -test.timeout 3m
```

Retain the exact source, image digest, run/attempt, counters and result. CLI RSS
and CPU exclude the relay, peer and driver. The container limit covers all of
them. Unit tests verify actual datagram ordering, a dropped datagram, reverse
traffic, bounded hold and joined shutdown on real unprivileged UDP sockets.

This is a short deterministic recovery regression, not a representative network
soak. It uses static credentials and loopback latency. It does not prove router
or peer restart, credential rotation, broker ownership, cloud TLS, long-running
FD/goroutine stability, or the proposed 64/128/256 MiB deployment budgets. Those
remain production acceptance gates.
