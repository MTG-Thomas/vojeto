# Router session launcher

`vojeto-launcher` is a Linux-only privileged session issuer hosted as an
unprivileged service. It supervises a distinct `vojeto-peer lighthouse` process
per active session. Both executables and their dependency notices ship in
`docker build --target launcher-release .`. No Managed Defined SDK is linked.
`make build-launcher` builds the executable; `make test` builds the child peer
binary and runs the repository's patched race suite.

## Protocol and trust

The launcher accepts only TLS 1.3, a verified client chain and the exact pinned
broker leaf certificate SHA-256 fingerprint. The HTTP handler also refuses
plaintext. The broker owns operator, device and destination authorization.
Clients and their private keys never connect directly to the issuer API.

POST /v1/sessions accepts `id` (32 lowercase hex characters), `operatorKey` and
`targetKey` (32-byte base64 public keys), `destination` (numeric IPv4 TCP
host:port), and timezone-aware `expires` (absolute deadline at most 30 minutes
away). There is no caller-selected infrastructure endpoint, port, executable,
CA, private key, or shell command. The response is `id`, `operator` and `target`
public signed grants. A response means local lighthouse startup only.

GET /v1/sessions/{id} returns an active session's grants; DELETE revokes it and
joins child termination and private-file cleanup. Identical retries return the
same grants while active. Changed policy conflicts. A stopped, expired or
restarted session cannot be reissued under the same ID. Revoke-before-create
records a barrier to reject a delayed create RPC. Revocation barriers expire
after 30 minutes; create intents with those old deadlines are then invalid.

The CA signing key exists only during issuance. Lighthouse private keys are
written into a private runtime directory (tmpfs in deployment), then removed
after the child exits. Persistent state stores only SHA-256 request fingerprints
and expiry tombstones. An exclusive process lock fences two supervisors sharing
that state directory. Restart removes owned abandoned runtime directories and
refuses prior request IDs rather than resurrecting sessions. Every child also
enforces signed expiry independently of the broker and launcher.

Limits: at most 128 configured ports, bounded active sessions, 1,024 unexpired
tombstones, 16 KiB HTTP request, three-second child startup, five-second cleanup
wait, two-second hard kill after SIGTERM, and bounded HTTP timeouts. Deployment
starts with four ports/sessions. Capacity or persistence failure rejects work.
Failed private-file cleanup fails subsequent admissions closed. Client errors
and child stderr are not logged; neither private keys nor grants are printed.

## Configuration

The sole CLI argument is a local JSON configuration file:

```json
{
  "listen": "0.0.0.0:9443",
  "publicIP": "203.0.113.20",
  "bindIP": "0.0.0.0",
  "firstPort": 42000,
  "lastPort": 42003,
  "maxSessions": 4,
  "peerBinary": "/vojeto-peer",
  "stateDir": "/state",
  "runDir": "/run/vojeto-launcher",
  "certificate": "/secrets/server.crt",
  "key": "/secrets/server.key",
  "clientCA": "/secrets/client-ca.crt",
  "brokerFingerprint": "REPLACE_WITH_SHA256_OF_BROKER_LEAF_DER"
}
```

Use real addresses and enrolled certificates, not documentation addresses or
placeholder fingerprints. Both directories must be absolute, private mode
0700; the child executable must be a regular absolute path with executable
permission and no group/other write access. The HTTPS server identity must
match the broker URL; use a dedicated client CA and keep its signing key off
the router. Fingerprint rotation requires a supervised restart and terminates
active sessions. No hot identity rotation is promised.

Publication is manual from reviewed main, after its exact commit is Verified
and push CI succeeded. The publisher's `expected_sha` must match that exact
main head. Deployment must pin the resulting image digest; no VM-local build.
Infrastructure activation, NSG preview, Key Vault credential enrollment and
Windows canary evidence are owned by bifrost-infra's router launcher runbook.

## Acceptance

Tests exercise real child processes, encrypted operator-to-target TCP through
launcher-issued lighthouse grants, mTLS denial for missing and other trusted
client certificates, plaintext denial, immutable/idempotent requests, capacity,
expiry, revocation, revoke-before-create, exclusive supervisor state, restart
fencing and port reuse. CI repeats the child lifecycle in a read-only,
capability-free rootless container with private runtime tmpfs and inventories
all linked notices. These are source/proof tests, not deployed-router evidence.
