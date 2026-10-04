# Local identity agent protocol

The Linux CLI accepts a caller-owned identity agent for fresh Defined enrollment:

```json
{
  "type": "defined-external-agent",
  "agentSocket": "/private/identity/agent.sock",
  "hostname": "example-worker",
  "networkID": "network-EXAMPLE"
}
```

Pass this file with `-identity-provider`. `definedAPI` and `pollOutageGrace` have
 the same meanings as in the pooled provider. Pool storage, owner, claimant and
host-list settings cannot be combined with this mode. The agent is a separate
consumer-supplied process; Vojeto does not ship a broker or silently use a pool.

## Trust and ownership

The socket path must be absolute and clean. Its immediate parent must be a real
private directory, and the socket a real Unix socket, both owned by the CLI UID
with no group or other permissions. Vojeto rechecks these permissions on every
connection and checks Linux peer credentials for the same UID. Mount the private
socket directory into both processes; protect its ancestors from replacement.
Same-UID processes share the trust boundary. This does not authenticate the
agent's cloud identity or prove its backend fencing. No TCP fallback, root,
capability or system DNS change is used. Other operating systems fail closed
until their peer-credential implementation is tested.

The agent must implement the durable `EnrollmentStore` contract in
[external enrollment](external-enrollment.md). In particular it must reject
unclean restart, durably consume an attempt, and exclude active or uncertain
prior owners of the **actual host** before acknowledging bind. A local token,
new boot ID or unrelated database/blob lease alone cannot prove that exclusion.
The agent owns host reconciliation, backend authentication and deployment policy.

## Wire contract, version 1

Every operation is one HTTP POST to `/v1/identity/<operation>` over the socket,
with a JSON body and a single HTTP 200 JSON response. Other status codes,
redirects, malformed or unknown response fields and bodies over 4 MiB fail closed.
Requests have a 10-second ceiling plus caller cancellation. Vojeto never retries
an operation, follows a redirect or includes remote text or secret material in
errors. The server must bound requests, keep response fields secret and never
log request bodies. Checkpoint state is JSON base64 bytes, not a filename.

Every successful response contains `"ok":true` and a nonempty opaque `token`
(maximum 4096 bytes). Acquire returns a new token; all later responses must echo
exactly that token. All later requests contain that token. The agent must reject
stale tokens and never transfer one token to another owner or host.

| Operation | Request fields besides token | Response fields besides ok/token | Required server behavior |
| --- | --- | --- | --- |
| acquire | `attempt`: random 64-character hex nonce; no token | `leaseMilliseconds`, optional `state` | Durably acquire a fresh exclusive allocation. Existing state is refused by this enrollment mode. Never interpret a new nonce as permission to reuse uncertain ownership. |
| begin | none | none | Durably mark enrollment attempted before returning. Never store an enrollment code in this marker. |
| grant | none | `grant` | Supply the one-time code and approved host/network/address/route constraints for this allocation. |
| bind | `hostID`, `networkID` | none | Durably bind and prove host-specific exclusion before code submission. |
| checkpoint | `state`: base64 bytes | none | Durably persist the approved identity or rotated credentials before acknowledging. |
| renew | none | `leaseMilliseconds` | Confirm the same ownership remains exclusive. This is independent of Defined credential polling. |
| release | none | none | Mark reusable only after the caller has stopped transport. Reject uncertain or stale ownership. |

A grant contains `code`, `hostID`, `networkID`, `routePolicy` (a Nebula YAML
string, such as `{}` to approve no unsafe routes), and `addresses` (IP strings)
or `addressRanges` (CIDR strings). At least one address constraint is required;
when both are present both apply. Vojeto verifies the returned identity against
these constraints before persisting it or opening transport. See the enrollment
document for certificate verification and rotation rules.

Lease duration is 100–60000 milliseconds, measured conservatively from the start
of the successful request. Only acquire and renew establish a deadline. Other
responses cannot extend it. Watch renews after one third of the confirmed lease
and bounds the request by its remaining lifetime. Expiry, token mismatch or an
uncertain ownership/mutation response permanently revokes that client. It cannot
retry acquisition or release the uncertain allocation. Even without a watcher,
`Valid` reports expiry immediately. A late response cannot revive an expired lease.

The ownership watcher starts after provider acquisition, so the initial lease
must cover begin, grant, bind, enrollment, checkpoint and startup authentication.
Choose a duration and startup bounds that fit this window; slow acquisition fails
closed and requires reconciliation. No lease is silently extended during startup.
During normal runtime the watcher remains active through drain and checkpoint.
Transport stops before watcher cancellation and release. Cancelling only the
watcher for normal shutdown does not revoke otherwise valid ownership; cleanup
still must complete before its last confirmed deadline.

## Acceptance evidence and limits

Socket fixtures cover permissions, token propagation, code/constraint transfer,
checkpoint ordering, bounded blocked renewal, expiry without a watcher,
uncertain mutation quarantine, no replay, and cancellation during a pending renew
followed by clean checkpoint/release. CLI tests reject mixed provider settings.
These prove the client boundary, not a production agent's durable store, prior
owner exclusion, or platform behavior. A consumer must prove those independently
before replacing its existing enrollment path.
