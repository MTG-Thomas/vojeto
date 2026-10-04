# NetBird-derived design constraints

Vojeto is intentionally narrower than a full VPN client. It is a portable, rootless userspace overlay dialer and forwarder with lifecycle semantics for applications that cannot or should not own host networking.

NetBird's official rootless/netstack work provides useful prior art, especially around what changes when a client has no TUN device and cannot manipulate the host network namespace. This note records the parts worth adopting, the areas where Vojeto should deliberately differ, and the failure modes we should treat as design constraints.

## Product boundary

Vojeto is **not** a general-purpose VPN client.

It should provide a small application-facing path into an existing Nebula-compatible overlay:

```text
application
    |
    | loopback TCP / optional SOCKS / local control
    v
  Vojeto
    |
    | userspace network abstraction
    v
 gVisor netstack
    |
    | Nebula encrypted transport
    v
private overlay
```

The useful primitive is:

> TCP connectivity from an unprivileged application into an existing overlay, with lifecycle and identity semantics suitable for both long-running and ephemeral compute.

This boundary intentionally excludes host route management, transparent system networking, firewall management, device posture, SSH, exit-node behavior, and system-wide DNS ownership.

## Lesson 1: netstack is a distinct datapath, not a degraded TUN mode

NetBird treats kernel, TUN-backed userspace, and no-TUN netstack operation as meaningfully different networking modes. Vojeto should take that idea further: **netstack is the primary product model**.

Features must therefore be designed around userspace semantics from the beginning rather than implemented as if a host TUN exists and then adapted later.

Consequences:

- local application listeners are explicit;
- overlay dials are explicit;
- inbound overlay listeners, if ever supported, are explicit;
- DNS must be solved without assuming control of the host resolver;
- UDP cannot be assumed to behave like host-routed UDP;
- observability must distinguish host-local and overlay-side failures.

## Lesson 2: make the userspace network an internal API

NetBird services can operate directly against its userspace networking stack instead of requiring traffic to enter through a host TUN device.

Vojeto should expose the same concept internally through a small interface rather than allowing gVisor details to leak into every forwarding feature.

A target shape:

```go
type Network interface {
    DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
    ListenTCP(addr netip.AddrPort) (net.Listener, error)
    Resolve(ctx context.Context, name string) ([]netip.Addr, error)
}
```

The exact interface may evolve, but the boundary matters.

Expected package direction:

```text
internal/network/
    interface.go

internal/network/netstack/
    network.go
    tcp.go
    resolver.go

internal/forward/
    listener.go
    relay.go
    limits.go

internal/proxy/socks5/
    server.go
    policy.go

internal/control/
    server.go

internal/lifecycle/
    state.go
```

Fixed forwards, SOCKS, health checks, and future consumers should depend on the portable network interface rather than on gVisor directly.

## Lesson 3: separate local forwarding from overlay-facing services

In no-TUN operation there is an important difference between:

1. a host/application connection entering Vojeto on loopback and being dialed into the overlay; and
2. an overlay connection being accepted by Vojeto and forwarded toward a local application.

The first is Vojeto's primary workload.

The second should be a separate feature with its own policy and threat model if it is ever added.

Do not blur these together under a generic "port forwarding" abstraction.

## Lesson 4: DNS needs its own design

Rootless clients cannot assume they can replace `/etc/resolv.conf`, install a system resolver, or manipulate platform DNS.

Vojeto should therefore avoid making host DNS mutation a prerequisite.

The core should instead have a resolver abstraction usable by:

- fixed forwards;
- SOCKS;
- dependency probes;
- future local DNS service.

Preferred progression:

1. resolve overlay destinations internally;
2. allow configured forwards to target overlay DNS names;
3. preserve application-facing database TLS hostnames;
4. optionally expose a loopback DNS listener for runtimes that can explicitly use it.

System-wide DNS interception is not a v1 requirement.

### Database TLS identity

A local forward must not accidentally force applications to validate certificates against `localhost`.

Where libraries allow it, documentation and configuration should preserve the original database hostname for TLS verification/SNI while the transport is dialed through a local Vojeto endpoint.

Vojeto should not terminate database TLS merely to solve this problem unless a future feature explicitly requires it.

## Lesson 5: TCP is the first-class transport

TCP maps cleanly onto the current application workloads:

- PostgreSQL;
- Redis;
- service-to-service connections;
- SOCKS5 CONNECT.

UDP in a no-TUN userspace stack introduces substantially harder flow and return-path semantics. Host-originated UDP does not automatically enter the userspace stack, and transparent behavior becomes difficult quickly.

Therefore:

- TCP is a first-class supported transport;
- UDP forwarding is not implied by the word "networking";
- SOCKS5 UDP ASSOCIATE is out of initial scope;
- arbitrary UDP support requires a concrete workload before implementation.

## Lesson 6: connection lifecycle is a P0 correctness issue

Rootless relay software can leak substantial memory, file descriptors, or goroutines when half-closed and cancelled TCP sessions are not handled precisely.

Vojeto should make connection ownership explicit from the start.

Every relay should have:

- a parent context;
- bounded dial time;
- bounded idle time where appropriate;
- deterministic cancellation;
- correct TCP half-close handling;
- symmetric cleanup;
- a hard global connection ceiling;
- optional per-forward ceilings;
- observable active connection counts.

Tests should cover at least:

- client closes first;
- overlay target closes first;
- one side half-closes;
- context cancellation;
- dial timeout;
- idle timeout;
- shutdown/drain during an active session;
- repeated failed connection attempts;
- connection-limit rejection.

Operational metrics should include:

```text
active connections
connections opened/closed
connection failures by bounded reason
goroutine count
process RSS
open file descriptors where available
drain duration
```

Resource leaks are a release-blocking correctness bug, not a later optimization.

## Lesson 7: local control needs a small threat surface

A local daemon control interface can become privilege escalation or cross-user control if exposed too broadly.

Vojeto's control API should remain intentionally small.

Expected operations:

- status;
- readiness detail;
- finite-worker completion;
- graceful drain;
- diagnostics.

Avoid a broad runtime mutation API unless a concrete requirement appears.

Preferred transports:

1. Unix-domain socket with restrictive filesystem permissions where practical;
2. loopback TCP as a compatibility fallback for environments where containers share networking more easily than filesystems.

The control interface should never expose secrets or private identity material.

## Lesson 8: SOCKS is an escape hatch, not the default datapath

An ambient SOCKS proxy attached to a private overlay is an extremely effective pivot if accidentally exposed.

Vojeto's existing SOCKS posture should be treated as an invariant:

- disabled by default;
- loopback-only;
- explicit destination allowlists;
- TCP CONNECT only;
- bounded concurrent connections;
- cancellation and deadlines;
- no BIND;
- no UDP;
- no arbitrary external listen address in the initial design.

Tests should ensure configuration cannot silently widen those guarantees.

Fixed named forwards remain the preferred application interface.

## Lesson 9: rootless should be the normal artifact

NetBird ships a distinct rootless image because rootless operation is one of several client modes.

For Vojeto, rootless is the default product.

The standard container image should therefore be:

- non-root;
- no Linux capabilities;
- no `NET_ADMIN`;
- no TUN device;
- compatible with a read-only root filesystem;
- writable only where explicitly required for provider state;
- multi-architecture where dependencies permit;
- explicit about CPU/memory expectations.

If Vojeto ever grows privileged features, the privileged artifact should be the exceptional variant.

## Lesson 10: one lifecycle, multiple runtime shapes

The client core should not have an "ACA mode" and a separate generic mode.

A single state model should support both services and finite jobs:

```text
STARTING
  -> ACQUIRING_IDENTITY
  -> CONNECTING
  -> READY

READY
  -> RECONNECTING -> READY
  -> ROTATING -> READY
  -> DRAINING
  -> RELEASING_IDENTITY
  -> STOPPED

LEASE_LOST
  -> NOT_READY
  -> bounded recovery or STOPPED
```

Finite jobs add an explicit worker-completion event rather than a separate network implementation.

On completion:

1. stop accepting new sessions;
2. drain active sessions up to a configured deadline;
3. checkpoint current identity state;
4. release exclusive identity ownership;
5. flush final diagnostics/metrics;
6. exit successfully.

Platform termination remains semantically distinct from worker-completion.

## Lesson 11: identity lease loss must fail closed

When exclusive identity ownership is uncertain or lost:

- readiness becomes false;
- new forwarded connections stop;
- active sessions may drain for a short, bounded interval;
- the client must not silently continue under ambiguous ownership;
- reacquiring a different identity must be explicit in lifecycle behavior.

A temporary control-plane outage is different from a lost lease. If an already-valid identity and datapath remain safe to use, connectivity may continue according to provider policy.

## Lesson 12: keep provider and platform axes independent

These are separate questions:

> How does Vojeto obtain and maintain an overlay identity?

and:

> Where is Vojeto running?

Do not couple them.

Example identity providers:

```text
static files
Defined Networking
custom provider
```

Example platform adapters:

```text
generic process/container
Azure Container Apps
Kubernetes
Nomad
CI/job environment
```

Valid combinations should not require core changes.

Azure Storage-backed identity leasing and ACA job lifecycle behavior belong in adapters even though they motivated the original prototype.

## What to copy, improve, and avoid

### Copy

- treat netstack as an explicit networking mode;
- expose a netstack-native dial/listen abstraction;
- keep local forwarding semantics explicit;
- allow services to consume the userspace networking object directly;
- acknowledge DNS limitations instead of pretending host DNS works normally.

### Improve for Vojeto

- make rootless the primary model;
- make finite-job lifecycle first-class;
- make overlay resolution a core abstraction;
- preserve TLS hostnames deliberately;
- define TCP half-close/cancellation behavior up front;
- instrument connection/resource lifecycle from the first release;
- make lease-loss behavior explicit;
- keep platform and identity-provider abstractions independent.

### Avoid

- ambient SOCKS listeners;
- broad local daemon control;
- transparent-routing ambitions;
- early arbitrary UDP support;
- system DNS ownership;
- OS firewall/route configuration;
- treating userspace netstack as if it behaved like a host TUN;
- growing into a full VPN management client without a concrete workload.

## Initial architectural acceptance criteria

The prototype extraction should not be considered complete until:

- forwarding and SOCKS depend on a portable network interface;
- gVisor implementation details are isolated under the netstack package;
- portable packages contain no BiFrost or Azure resource names;
- Defined enrollment is behind a provider boundary;
- Azure identity leasing/checkpointing is behind a provider boundary;
- ACA lifecycle behavior is outside the core state machine;
- connection limits and cancellation are tested;
- half-close and drain behavior are tested;
- SOCKS remains opt-in, loopback-only, allowlisted, and TCP-only;
- readiness distinguishes process liveness, overlay connectivity, identity validity, and required dependency health;
- secret-safe diagnostics exist;
- rootless/non-root operation is the standard deployment path.

## Scope test

When evaluating a proposed feature, ask:

> Does this help an unprivileged application explicitly dial, accept, resolve, or manage the lifecycle of connections through its existing overlay?

If not, the feature probably belongs in a provider, platform adapter, or another project.
