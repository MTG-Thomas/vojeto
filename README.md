# Vojeto

**Vojeto** is a portable, rootless userspace networking companion for connecting unprivileged applications to Nebula-compatible overlays.

The name comes from Esperanto: _vojeto_ means **a little path**. Vojeto's job is similarly small and deliberate: give an application a path into an existing private mesh without requiring a kernel TUN device, `NET_ADMIN`, or control of the host network stack.

> [!IMPORTANT]
> Vojeto is an independent project. It is not affiliated with or endorsed by Defined Networking or the Nebula project.

## Why

Some environments deliberately do not allow privileged networking: managed container platforms, rootless containers, CI workers, restricted Kubernetes workloads, and finite job runners.

Vojeto is intended to make those environments ordinary consumers of an existing Nebula deployment by running entirely in userspace alongside the workload.

The implementation is being extracted from a working prototype originally developed for BiFrost. That prototype already proves:

- Nebula encrypted transport with a gVisor userspace network stack;
- private IPv4 routing through an existing Nebula/Defined router;
- loopback TCP forwarding for PostgreSQL and Redis;
- Managed Defined enrollment;
- exclusively leased identity pools with rotation/checkpointing.

Vojeto additionally implements finite, loopback-only SOCKS5 TCP CONNECT with
explicit allowlists, bounded connections, and cancellation; that behavior is
covered by Vojeto tests rather than evidence from the current infra prototype.

The extraction will preserve those behaviors while separating portable client functionality from BiFrost-, Azure-, and Defined-specific policy.

## Architecture direction

```text
application
    |
    | loopback TCP / optional SOCKS
    v
  Vojeto
    |
    | userspace netstack
    v
  Nebula
    |
    v
private overlay
```

### Portable core

The core should own:

- Nebula encrypted transport;
- userspace networking;
- configurable fixed TCP forwarding;
- optional, tightly bounded SOCKS5 TCP CONNECT;
- common lifecycle for long-running services and finite jobs;
- readiness, reconnect, drain, and shutdown behavior;
- health, diagnostics, metrics, and resource limits;
- provider interfaces for identity acquisition, renewal, and release.

### Adapters

Cloud and control-plane behavior stays outside the core:

- Defined Networking enrollment and identity management;
- Azure Managed Identity and Storage-backed identity leasing;
- Azure Container Apps replica/job lifecycle integration;
- static or custom identity providers.

Vojeto should remain useful outside Azure and outside containers.

## Security posture

Vojeto defaults to the narrowest useful behavior:

- no root requirement;
- no `NET_ADMIN`;
- no TUN device;
- listeners require explicit loopback addresses;
- SOCKS is opt-in;
- SOCKS destinations are explicitly allowlisted;
- TCP CONNECT only initially;
- bounded connection counts and timeouts;
- secret-safe diagnostics and logs;
- lease loss must fail closed for new traffic.

## Status

An initial runnable extraction is available. Build with `make build`, verify with
`make test` (race detector), or build the non-root container with `docker build .`.
The build applies checksum-verified Nebula v1.11.2 patches for packet-cache
concurrency and rootless socket-buffer configuration, plus a gVisor retransmission
timer patch, in isolated dependency copies. Plain `go test ./...` does not apply
those patches. Linux buffer requests
respect the host limits; Vojeto defaults `listen.read_buffer` to 256 KiB when
omitted. The encrypted load-test stall in [#14](https://github.com/MTG-Thomas/vojeto/issues/14)
remains a production replacement blocker.

Run `./vojeto -config /private/nebula.yaml -forwards /private/forwards.json`.
Configuration contains credentials and must remain private. Forward JSON is an array:

```json
[{"Name":"database","Listen":"127.0.0.1:15432","Target":"192.0.2.10:5432","MaxConnections":32,"DialTimeout":15000000000}]
```

Durations are currently JSON nanoseconds. Global connections default to 128;
`-drain-timeout` defaults to 30 seconds. SIGTERM/SIGINT stop admission and drain by default. An explicit `-signal-grace`
withdraws readiness while allowing native applications to finish before admission
stops; exclusive ownership remains monitored throughout. Explicit completion skips
that allowance and starts bounded drain immediately.
An optional `-control-socket /private/control.sock` enables permission-0600 Unix
control: `POST /v1/lifecycle/complete` performs the same bounded shutdown.
Use a private parent directory to prevent cross-user socket replacement.

The CLI accepts static Nebula configuration or a pre-enrolled Defined/Azure Blob
identity pool. Forwarding targets may use numeric IPv4 or names explicitly
mapped in the readiness configuration. Unmapped names fail closed. It never falls back to host dialing or modifies system DNS.
The allowlisted finite SOCKS library is opt-in and is not enabled by the CLI.
Defined checkpoint/rotation and Azure lease ownership now run through the portable
runtime. Lease loss closes admission and active sessions; uncertain credential
updates leave the identity quarantined. No automatic takeover or reacquisition
is attempted. Pool provisioning and recovery remain operator responsibilities.
See [leased identity configuration and shutdown](docs/architecture/leased-runtime.md).

`/live`, `/ready`, and `/status` are available through the control socket. Readiness
requires successful configured overlay and dependency probes; process startup
is not proof of overlay connectivity. Status contains only bounded health fields.
See [readiness and native drain configuration](docs/architecture/readiness.md).

Container runtime: UID 65532, `--cap-drop ALL --read-only --security-opt
no-new-privileges`, no TUN device. Mount secret config read-only; mount a small
private writable directory only if using a control socket. No platform-specific
support or 64/128/256 MiB memory target is claimed yet.

See [extraction boundaries and compatibility](docs/architecture/extraction.md).

## License

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).

Repeatable local resource measurements and their limits are documented in
[Linux rootless measurements](docs/measurements/2026-10-04-linux-rootless.md).
The image defaults to `GOMEMLIMIT=96MiB`; this soft runtime limit does not guarantee
RSS or prove a platform memory budget. Production publication waits for the
Defined SDK license clarification in [dnapi#52](https://github.com/DefinedNet/dnapi/issues/52).

Defined identity requests use a [bounded HTTP adapter](docs/architecture/defined-client.md)
with redirect rejection, a 30-second request ceiling and a 2 MiB response limit.
Polling failures remain fail-closed. SDK licensing and live deployment acceptance
remain release blockers; this project is not yet a production replacement.
