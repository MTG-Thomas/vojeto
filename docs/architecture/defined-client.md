# Bounded Defined client

Target: portable Linux process/container. No infrastructure or live provider
mutations. Issue #12. Procedure package: mtg-codex-skills 2026-10-03.6.

The pinned SDK builds a private HTTP client and reads response bodies without a
size limit. Vojeto owns a small adapter for CheckForUpdate and DoUpdate using the
SDK's exported signing, key and wire-type APIs. No SDK source is copied or patched;
its unresolved license remains a release blocker tracked in #10 and upstream #52.

The adapter copies an injected HTTP client, imposes a maximum 30-second timeout,
rejects redirects and accepts only an explicit HTTPS origin. Responses are limited
to 2 MiB before JSON decoding, including chunked responses. Non-200 responses are
rejected without reading their bodies. Errors contain no URLs, response text,
credentials or crypto material. Request contexts can impose shorter deadlines.
Injected transports must honor those contexts.

Polling requires a present boolean updateAvailable field; missing or malformed
responses cannot silently authorize continued use. Rotation generates fresh keys
for the existing curve, verifies the response with the existing trusted keys,
checks its version, nonce and increasing counter, and requires trusted keys.
Even an empty config reaches the provider after a verified rotation, so new
credentials are checkpointed with the old safe config before config rejection.
Provider-level host, network, address, route and checkpoint checks remain
unchanged. There are no automatic retries of DoUpdate: a failed response may follow
a committed remote rotation and must quarantine the identity.

All poll errors still stop the runtime. A finite outage grace policy is deferred:
it must distinguish read-only transient failures from authorization rejection,
cap continued use by both an outage budget and certificate validity, and retain
independent lease-loss shutdown. This adapter deliberately supplies no temporary
error classification yet. Availability behavior is unchanged by this batch.

Acceptance tests cover both credential curves, signed requests, valid rotation,
invalid signature/nonce/counter/trusted keys/config, malformed or missing polling
fields, redirect rejection, error-body redaction, chunked body limits, deadlines,
cancellation and quarantine after uncertain rotation. Tests use synthetic HTTPS
servers; they do not establish live Defined service compatibility.
