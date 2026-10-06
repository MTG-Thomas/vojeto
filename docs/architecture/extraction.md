# Initial extraction boundary

Source: bifrost-infra commit 971618addb8a2f0ed09f59668dc25f10ad3a1965,
`tools/nebula-userspace-proof`. Target: portable Linux software; no deployment changes.
Procedure package: mtg-codex-skills 2026-10-03.6.
The engineering-flow component retains metadata version 2026-09-30.1.

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

Static and leased Defined/Azure Blob identities now share the portable runtime.
The static provider performs no exclusive lease mutation. The leased provider
monitors ownership independently of SDK polling and keeps renewals running through
bounded session drain. Checkpoint, synchronous transport stop, monitor join and
release ordering are covered by cross-package tests. See [runtime semantics](leased-runtime.md).
Recovery is fail-stop; automatic reacquisition is not implemented.

Required dependency probes and explicit name mappings are implemented; overlay
DNS remains deferred. The finite SOCKS CLI is documented in [finite jobs](finite-socks.md).
Metrics, runtime architecture validation, extended FD/goroutine stress testing and
platform deployment tests remain release gates.

[Repeatable Linux measurements](../measurements/2026-10-04-linux-rootless.md)
record idle RSS, static startup, 10/100/500 sessions, sustained transfer CPU and
drain. Real provider acquisition, reconnect latency and platform budgets still
need measurement before documenting supported budgets. No platform
named in the project intent is certified by these loopback Linux tests alone.

## Read-only consumer preflight

`vojeto -check-config` validates the provider settings, poll schedule, session
policy, readiness configuration, runtime bounds and health bind policy using the
same loaders as normal startup. Supply the usual configuration paths and flags.
It exits before identity acquisition, network probes, listener binding, checkpoint
writes or control socket creation. The public result sets `runtimeVerified:false`.
It does not establish live pool membership, credential/certificate validity,
reachability, available listening ports or platform acceptance. Static identity
state is still read and verified during actual startup. External-agent socket
permissions are checked by its constructor; the agent receives no operation.

Fixed-forward parsing is bounded to 64 KiB/128 entries and rejects unknown fields,
trailing JSON, invalid loopback binds, invalid ports/durations, duplicate names
and duplicate canonical listeners before acquiring an identity. Go durations in
forward JSON remain integer nanoseconds, not strings. This preflight prevents a
bad deployment configuration from consuming and quarantining a valid pool slot.
