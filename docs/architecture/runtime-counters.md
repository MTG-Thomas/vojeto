# Runtime counters for resource acceptance

`GET /status` includes aggregate counters alongside the existing lifecycle and
readiness fields. `active_connections` counts sessions admitted by the CLI's
shared forwarding/SOCKS limit, including sessions still dialing. It excludes
health/control requests and internal dependency probes. Zero is reported
explicitly; an omitted count means the caller did not supply this counter.

`process.goroutines` counts Go goroutines in the serving process, including the
current status request. On Linux, `process.open_fds` counts entries under
`/proc/self/fd`, including the temporary enumeration descriptor. The FD field is
omitted if procfs is unavailable or the platform has no implemented accounting.
Unsupported accounting is not zero. Userspace overlay TCP endpoints are not
necessarily OS descriptors, so use all counters together.

Sampling does not read descriptor symlink targets or serialize connections,
providers or identities. There are no addresses, file paths, tokens, keys,
enrollment codes, certificate bodies or per-tenant labels in these counters.
The status response has an explicit field allowlist test. Public health remains
an explicit bind option, and completion stays on the private control surface.
Readiness/liveness do not enumerate descriptors.

The encrypted resource fixture records the actual CLI status at 0, 10, 100 and
500 admitted sessions and verifies that the admission count matches the workload.
RSS and CPU remain measurements of that separate CLI process. The peer, driver
and packet-fault relay are excluded from those process counters.

For a representative soak, retain timestamped status samples plus OS RSS/CPU,
exact source/image, platform limits, traffic and fault schedule. Compare idle
baseline, steady load, repeated failures, and return to idle after drained
sessions. Counts are observational and can change immediately; a single delta is
not a leak diagnosis. Neither this instrumentation nor the short resource
fixture establishes long-running stability, reconnect behavior or a cloud memory
budget. Those still need retained acceptance evidence.
