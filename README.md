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
- exclusively leased identity pools with rotation/checkpointing;
- finite, loopback-only SOCKS5 TCP CONNECT with explicit destination allowlists, bounded connections, and cancellation.

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
- listeners bind to loopback unless deliberately configured otherwise;
- SOCKS is opt-in;
- SOCKS destinations are explicitly allowlisted;
- TCP CONNECT only initially;
- bounded connection counts and timeouts;
- secret-safe diagnostics and logs;
- lease loss must fail closed for new traffic.

## Status

Early extraction and generalization.

The current implementation lives in the BiFrost infrastructure repository under `tools/nebula-userspace-proof`. Vojeto will absorb that proven code in small, reviewable steps rather than rewriting the prototype from scratch.

## License

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
