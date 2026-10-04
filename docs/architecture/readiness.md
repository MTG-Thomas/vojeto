# Readiness and application drain

Readiness is evidence of current identity ownership plus successful configured
probes through the userspace overlay. It is never inferred from process startup.
The CLI accepts `-readiness /private/readiness.json`:

```json
{
  "hosts": {"database.example.internal": ["192.0.2.10"]},
  "overlay": [{"target": "192.0.2.10:5432", "protocol": "tcp"}],
  "dependencies": [{"target": "database.example.internal:5432", "protocol": "postgres-tls", "server_name": "database.example.internal"}]
}
```

All example addresses are documentation fixtures. At least one explicit overlay
probe is required. Dependencies may be empty. Configuration rejects unknown
fields, trailing documents, over 64 KiB, or more than 32 probes. Supported probe
protocols are `tcp`, `tls`, and `postgres-tls`. TLS probes require the original
server name, system CA trust, and TLS 1.2 or newer. PostgreSQL probes first send
SSLRequest and require the server's `S` response. Application traffic remains an
opaque TCP stream; Vojeto does not terminate database TLS. Applications must
still configure their original TLS hostname independently of the loopback dial
address.

Host mappings are immutable per run, case-insensitive, IPv4 only. Names outside
that mapping fail closed. No system DNS changes or host resolver fallback occurs.
Dynamic overlay DNS remains a separate future resolver implementation.

Each probe has a five-second deadline. Startup retries failed probes every five
seconds within `-acquire-timeout`; listeners open only after all required probes
succeed. After admission, probes run every five seconds after the previous pass.
Failure withdraws readiness; recovery restores it. Existing application sessions
remain available during a dependency outage while identity ownership remains
valid. Lease loss closes admission and sessions immediately regardless of health.
No readiness configuration means readiness remains unverified and false.

`-health-listen 127.0.0.1:8081` exposes read-only `/live`, `/ready`, and `/status`.
A platform that probes the container IP may explicitly configure a numeric public
bind with `-allow-public-health`. That listener has no lifecycle mutation endpoint.
Status contains no targets, certificate material, or provider errors. Completion
is available only on the optional permission-0600 Unix control socket.

SIGTERM/SIGINT normally stop admission and begin bounded drain immediately.
`-signal-grace 150s`, for example, withdraws readiness while keeping the transport,
identity ownership watcher, rotation, and listeners available to applications
performing native shutdown work, including new database connections. The allowance
is bounded to five minutes and defaults to zero. Explicit completion interrupts
that allowance and stops accepting sessions immediately. Identity loss interrupts
it and quarantines ownership. Deployment-specific grace choices and native worker
completion wiring belong in the infrastructure repository.

Acceptance: tests verify deferred startup admission, degraded/recovered health,
TLS name mismatch rejection, plaintext PostgreSQL refusal, probe cancellation,
absence of host DNS fallback, separation of public health from completion, and
ownership loss during signal grace. These are local source proofs. Published-image,
cloud TLS and coordinated application shutdown proofs are still release gates.

The public validation workflow compiles AMD64/native and ARM64 images, runs the
full race suite and checksum-verified upstream packet-cache regression, and
executes encrypted overlay proof with zero capabilities and a read-only root.
ARM64 compilation alone does not establish ARM64 runtime support. No publication
step is enabled while the linked SDK license and dependency inventory remain
unresolved (#10).
