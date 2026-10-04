# Initial extraction boundary

Source: bifrost-infra commit 971618addb8a2f0ed09f59668dc25f10ad3a1965,
`tools/nebula-userspace-proof`. Target: portable Linux software; no deployment changes.
Engineering procedure: mtg-engineering-flow 2026-09-30.1.

Extracted packet plumbing retains the Nebula MIT notice and dependency licensing.
gVisor remains a module dependency, with its upstream license obligations intact.
No vendored gVisor code is relicensed. The AGPL license applies to Vojeto's code.

The encrypted round-trip/firewall/route tests, rotated credential checkpoints,
checkpoint-before-reload tests, stale lease rejection, independent watchdog,
exclusive restart and unclean-owner quarantine tests are ported. Generic fixtures
replace deployment names, addresses and identifiers. Pool location, owner and host
list are supplied by callers; no resources are provisioned. Azure requests reject
redirects. Expired ownership never permits continued transport use.

The network interface exposes outbound TCP and explicit resolution. Overlay-side
listeners remain deferred to avoid silently widening the inbound policy boundary.
Fixed forwarding accepts only explicit loopback listeners, bounded sessions and
bounded dialing. Relay preserves half-close and cancellation closes both ends.
SOCKS accepts only numeric IPv4 TCP CONNECT to exact address/port allowlists,
with finite lifetime and no host DNS, BIND, UDP or external binding. No SOCKS source
was present in this source revision: it is a new implementation, not a port.

Infra retains Bicep, resource names, identity pool membership, broker contracts,
actual routes and network IDs, Key Vault wiring, scaling, queues, replica policy,
health targets, deployment workflows and migration sequencing. Wake-gate tests
remain there because the gate is a deployment-specific queue contract.

## Compatibility path

Existing infra consumers continue using their pinned prototype image and flags.
Do not replace that image directly: the Vojeto CLI is not flag-compatible.
A later infra-only change should translate fixed listeners into named forward
configuration, inject deployment-selected provider settings, preserve worker drain
ordering, and pin a published Vojeto digest after provider integration is proven.
There is no production migration or runtime evidence from this extraction.

Applications retain database TLS responsibility. For libpq, use the original
hostname as `host`, loopback as `hostaddr`, and the local forward port with
`sslmode=verify-full`. Other clients must explicitly configure their TLS server
name while dialing loopback. Redis clients likewise retain the original TLS
server name. Vojeto relays opaque bytes and never terminates database TLS.

## Outstanding acceptance

Provider adapters are library primitives, not yet a complete acquired/renewed
identity runtime. The static CLI performs no ownership release/checkpoint because
it does not acquire exclusive ownership. Lifecycle hooks enforce checkpoint and
transport-stop before provider release, but leased-runtime orchestration remains
required. Recovery is fail-stop; automatic reacquisition is not implemented.

Required dependency probes, resolver implementations, configurable CLI SOCKS,
metrics, multi-architecture validation, FD/goroutine stress testing, platform deployment tests remain release gates.

Resource targets are unmeasured. A repeatable benchmark must record idle RSS,
startup/identity timing, 10/100/500 sessions, sustained transfer CPU, reconnect
latency and drain duration before documenting supported budgets. No platform
named in the project intent is certified by these loopback Linux tests alone.
