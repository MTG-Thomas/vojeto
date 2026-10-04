# Externally supplied enrollment

The bounded Defined HTTP client can consume a caller-supplied one-time enrollment
code in memory. It sends both supported public-key pairs to the configured HTTPS
API and selects the private keys for the returned network curve. Requests reject
redirects, have a finite timeout, cap responses at 2 MiB, and never retry. Errors
contain no server text, URL, enrollment code or credentials.

`Client.Enroll` returns an unapproved candidate. It checks required wire metadata,
host ID consistency, curve and trust material; it cannot establish the caller's
expected host, network or route policy. It does not start transport, acquire or
release ownership, or persist a grant.

`NewEnrollmentProvider` combines this client with caller-supplied `GrantSource`
and `EnrollmentStore` implementations. The store acquires a fresh exclusive
allocation and durably marks the attempt before the source supplies a grant.
The provider validates the expected host, network and addresses, verifies inline
certificates against their CA and the expected addresses, checks the approved
unsafe-route fragment, and checkpoints the accepted identity before startup
authentication. It then uses the existing provider for strict rotation and shutdown.
The grant source transfers ownership of its returned grant; the provider clears
the code field after submission. This does not guarantee erasure of string copies.

Existing checkpoints are refused on this fresh-grant path. A caller must explicitly
choose the pooled provider for identity reuse. There is no dynamic-grant CLI mode
or private broker adapter yet; deployment integration remains issue #15.

## Ownership contract for the next slice

A grant source must establish exclusive ownership before enrollment. The provider
must monitor that ownership independently of HTTP operations and stop transport
synchronously on loss. Expected host and network constraints come from the grant
source or caller configuration. Neither a grant's successful HTTP delivery nor a
Defined enrollment response proves that a different process cannot use it.

An enrollment attempt consumes the local attempt even when the response times
out, is rejected, or cannot be decoded. Remote acceptance can precede any of those
outcomes. `ErrUncertainEnrollment` requires reconciliation by the grant owner;
it never permits an automatic retry or a clean reusable release.

The candidate must pass host, network, address, certificate and route checks before
it can become a ready identity. Where persistence is configured, an approved
checkpoint must be durable before transport starts. An enrollment that fails
validation or checkpointing must remain quarantined. An unapproved candidate
must not be stored as an ordinary resumable identity: that would bypass validation
on the next acquisition. The persistence adapter must represent this distinction
explicitly: `BeginEnrollment` must durably prevent retry after an uncertain attempt,
and `Acquire` must reject unclean or uncertain allocations after restart. An
adapter that cannot provide that fencing must not implement `EnrollmentStore`.

Once accepted, the existing strict rotation, credential-before-configuration
checkpoint ordering, ownership watcher, bounded drain and transport-before-release
semantics apply. Dynamic enrollment cannot silently substitute a pre-enrolled
pool; the caller owns capacity and reconciliation policy.

Broker endpoints, cloud identity audiences, authorization, replica membership,
host deletion, wake queues and deployment policy remain in the consumer's
infrastructure repository. The public client owns only Defined protocol handling.

## Evidence

Synthetic HTTPS fixtures cover both curves and correspondence between requested
public signing keys and returned private keys, response limits, missing metadata,
redirect rejection, request timeout, cancellation, one-attempt behavior and safe
errors. Provider fixtures cover durable fencing, required policy, wrong host/network/
address/route/certificate rejection, checkpoint failure, ownership loss, strict
rotation and no retry of uncertain attempts. The portable runtime tests prove
checkpoint-before-transport, transport-before-release on completion, and closure
of an active TCP forward without release on ownership loss. No live Defined
enrollment or worker acceptance is claimed by these tests.
