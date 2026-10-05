# Ephemeral operator and target sessions

## Scope and acceptance

`vojeto-peer` and the public `github.com/MTG-Thomas/vojeto/peer` package provide
both ends of a finite TCP troubleshooting session. They use Nebula 1.11.2 and
the repository's checksum-verified patches, without TUN, administrator rights,
route changes, DNS, Managed Defined enrollment, or the Defined SDK.

The operator binds loopback TCP. The target accepts the encrypted overlay
connection and dials exactly one signed numeric IPv4 host:port on its own host
network. That destination can be localhost or an authorized service on the
remote LAN. A separate session is needed for each destination. This is suitable
for testing a service or accessing an existing remote administration endpoint;
it does not supply a shell, subnet routing, discovery, or arbitrary SOCKS access.

Acceptance tests send actual encrypted traffic through two endpoints, discover
peers through a third lighthouse, and force relay traffic by blocking discovered
direct addresses. They also check signed-policy tampering, wrong keys/roles,
invalid destinations, expiry, active-connection cancellation, and denial of an
unapproved overlay port with a real listener. CI runs the peer tests in a
read-only container with all Linux capabilities dropped. Windows AMD64 is
cross-compiled; Windows runtime is a separate canary gate.

## Identity and lifecycle

Each endpoint runs `keygen` locally and sends only `public.json` through an
already authenticated operator/device channel. The authorized issuer calls
`Issue` or `issue`, signing those public keys, the exact destination, IPv4 underlay
endpoints, roles, and expiry. The session Ed25519 CA signing key exists only in issuer
memory and is not returned or saved. Endpoint X25519 private keys stay local.

A grant includes its CA and therefore must arrive over the trusted broker
channel. A valid self-contained grant does **not** authenticate the broker.
The consumer must authorize the actor, device, destination, lifetime and optional
lighthouse before issuing or accepting grants. Possession of a peer grant does
not authenticate a user to SSH, RDP, WinRM, or the destination application.
Those credentials remain separately required.

The target firewall admits only this session's operator certificate name on
TCP 19001. The operator firewall admits outbound TCP only to that target and
port. Neither side enables unsafe routes. A lighthouse exposes no application
listener. Reusing the reserved 192.0.2.0/24 userspace addresses is safe only
because each session has a separate CA and Nebula instance; these addresses
must never be connected to a shared existing overlay.

`Run` sets an absolute deadline from the signed grant; neither role renews.
Context cancellation or CLI SIGINT/SIGTERM closes listeners and active traffic
and joins cleanup. Connections and target dials are bounded. A process crash
cannot leave a kernel overlay or route behind. Private key files persist until
the caller deletes its private session directory; a broker/launcher must own
that cleanup, including abnormal termination. The library accepts key bytes
in memory and needs no key or configuration files.

## CLI example: known reachable target UDP port

Build with `make build-peer`. Run the executable on each endpoint:

```sh
# Operator machine:
vojeto-peer keygen --out operator-key
# Target machine:
vojeto-peer keygen --out target-key
```

Transfer only the two public.json files to the authorized issuer. For example,
a target able to reach LAN service 10.20.30.40:443 and publicly reachable on UDP
203.0.113.10:4243 uses the following issuer command (documentation addresses
must be replaced):

```sh
vojeto-peer issue --operator-key operator-public.json \
  --target-key target-public.json --destination 10.20.30.40:443 \
  --target-endpoint 203.0.113.10:4243 --ttl 5m --out grants
```

Deliver target.json and operator.json over the authenticated broker. Then:

```sh
# Target machine:
vojeto-peer target --grant target.json --key target-key/private.json \
  --udp-listen 0.0.0.0:4243
# Operator machine:
vojeto-peer operator --grant operator.json --key operator-key/private.json \
  --listen 127.0.0.1:14443
```

Connect the local application to 127.0.0.1:14443. Its TLS/server identity must
still be checked correctly for the actual destination. Without `--listen`, the
OS assigns a loopback port. Startup emits a JSON `listening` event with that
local address; it reports local listener startup, not peer reachability.

Inputs reject unknown fields, extra JSON, oversized files, existing output
directories and overwriting keys. Unix key directories use mode 0700 and files
0600. Windows key directories get a protected NTFS DACL granting the invoking
account and SYSTEM full access, inherited by children. Failures securing the
directory abort before writing keys. Moving/copying keys requires preserving
that access restriction. Keys and config are never printed in errors.

## Lighthouse and relay

A known reachable endpoint can use static discovery with only two machines.
When both machines are behind NAT, a stable reachable lighthouse helps discover
observed UDP endpoints and coordinate punching. Difficult NAT combinations may
also require a relay. This implementation's optional third role combines both:

```sh
# On the infrastructure host, generate a fresh session-specific key:
vojeto-peer keygen --out lighthouse-key
# Issuer: target endpoint can be omitted when using lighthouse discovery.
vojeto-peer issue --operator-key operator-public.json \
  --target-key target-public.json --lighthouse-key lighthouse-public.json \
  --destination 10.20.30.40:443 --lighthouse-endpoint 203.0.113.20:4243 \
  --ttl 5m --out grants
# Infrastructure host:
vojeto-peer lighthouse --grant lighthouse.json \
  --key lighthouse-key/private.json --udp-listen 0.0.0.0:4243
```

The lighthouse grant shares the session CA and expires with the endpoints.
The target may bind an ephemeral UDP port in this mode. Clients advertise the
lighthouse as a relay and prefer direct connectivity when available. All three
machines still require working UDP. Nebula relay is not a TCP/HTTPS fallback
for networks that block UDP entirely. No relay-only production option is
exposed; the test forces relay by filtering direct candidate addresses.

References: [lighthouse configuration](https://nebula.defined.net/docs/config/lighthouse/),
[relay configuration](https://nebula.defined.net/docs/config/relay/).

## Azure infrastructure decision

Read-only Azure evidence on 2026-10-05: vm-mtg-bifrost-poc-app-01 in
RG-MTG-BIFROST-POC-CORE-CENTRALUS is running, with public IP 20.9.81.122. The
resource group's nsg-mtg-bifrost-poc-app has an allow UDP 4242 rule. Infra source
records an existing Managed Nebula lighthouse/relay there. These observations
are not a verification of its running Nebula process, firewall attachment,
certificate trust, or endpoint health.

A per-session CA cannot directly reuse that Managed Nebula lighthouse. The
smallest initial hosting option is an isolated `vojeto-peer lighthouse` process
on a stable public Azure host, using a distinct, reserved UDP port, its own
session grant, an unprivileged account, a process deadline and launcher cleanup.
Several sessions require distinct ports and processes, bounded concurrency,
a port allocator and narrowly scoped NSG/host-firewall rules. Verify capacity,
public-IP stability, rule attachment and actual UDP reachability before reuse.
Do not replace the existing Managed Nebula identity or occupy UDP 4242.

A long-lived shared lighthouse is a different trust design: stable infrastructure
certificates, trusted shared CA or carefully managed multiple CAs, globally
unique overlay addresses, lease/revocation rules and session firewall isolation.
That design is not silently enabled here. No Azure resources or live Nebula
services were changed by this implementation.

## Sopdet/BiFrost integration contract

The portable API is the implementation boundary. An integration should:

1. Authenticate the invoking actor and authorize the exact target device and LAN
   service; use an existing authenticated Sopdet channel for bootstrap.
2. Generate endpoint keys on their respective machines, return only public keys,
   then issue grants once both identities and destination are authorized.
3. Allocate/start an optional session lighthouse before starting operator traffic.
4. Deliver role grants, launch finite processes with owned directories and retain
   process/session IDs for revocation. Report local startup separately from an
   encrypted end-to-end connectivity probe.
5. On cancel, expiry or bootstrap failure, stop all roles, remove private files,
   release the infrastructure UDP lease and verify cleanup.

There is no new unauthenticated credential issuance HTTP service. The public
API does not bypass Sopdet authorization or make the installed BiFrost workflow
select its direct transport. A production broker adapter and a Windows laptop
canary are additional integration work; these tests do not claim either is live.
