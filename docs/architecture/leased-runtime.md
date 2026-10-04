# Leased identity runtime

Target: portable Linux process/container. No infrastructure or live provider mutations.
Issue: #5. Package procedure: mtg-codex-skills 2026-10-03.6.

The runtime uses the same acquire/connect/complete sequence for static and leased
identities. Defined uses a pre-enrolled secret checkpoint store. Azure Blob is one
store implementation; storage base URL, owner, claimant, host membership and
expected Defined network are caller configuration. Provisioning and pool recovery
remain outside Vojeto. Existing checkpoint schema is preserved.

Ownership monitoring starts before transport initialization and is independent of
SDK polling. Loss immediately rejects admission, cancels sessions, synchronously
stops transport and invalidates readiness. A transport finishing initialization
after loss is closed before listeners start. Recovery is fail-stop: no automatic
reacquisition, lease break or quarantine clearing.

Polling/rotation remains serialized. Credentials are checkpointed before route,
network or identity checks; accepted config is checkpointed before transport reload.
Any uncertain update or reload stops the runtime and leaves an active tombstone.
The initial policy also stops on a failed SDK poll; future transient-outage policy
needs specific authenticated evidence rather than treating all failures as safe.

Completion stops admission and cancels/joins SDK work while the lease watchdog
continues. Existing sessions drain within one shared bound; timeout forces session
cancellation. Final checkpoint uses a separate bounded cleanup context, so a drain
timeout does not skip cleanup. Transport always stops, including checkpoint failure.
Only confirmed checkpoint plus synchronous transport shutdown and retained ownership
permit marking the slot available and releasing it. Monitor/renewal work is joined
before release. Other exits leave the identity quarantined; lease expiry is never
proof that its prior transport stopped.

Acceptance: tests exercise acquisition, update/checkpoint/reload ordering, clean
completion/reuse, active-session ownership loss, loss during startup/drain, failed
checkpoint/reload, stalled polling, bounded forced drain, and cancellation/join of
independent renewal. Existing prototype safety tests remain passing. Container proof
must still run non-root with zero capabilities and read-only root. Overlay and
required dependency health remain unconfirmed until #6; liveness is independent.

## Configuration

Static mode retains `-config /private/nebula.yaml`. Pool mode replaces that flag
with `-identity-provider /private/provider.json` and uses the same `-forwards` file.
Configure exactly one provider. An illustrative file (all IDs are synthetic):

```json
{
  "type": "defined-azure-pool",
  "storageBaseURL": "https://storage.example.invalid/identities",
  "owner": "example-worker",
  "claimant": "example-worker--unique-boot-id",
  "hostIDs": ["host-FIXTURE"],
  "networkID": "network-FIXTURE",
  "definedAPI": "https://api.defined.net"
}
```

`storageBaseURL` names the explicit container path; each host checkpoint is
`<base>/<hostID>.json`. Claimants must be unique per process and start with
`<owner>--`, followed by lowercase letters, digits or hyphens. Owners are
lowercase names; host membership remains an operator declaration. The trusted
initial checkpoint must be seeded for the intended network. Subsequent updates
reject network/host/address/route changes. The runtime never enrolls a new host.

The Storage token comes only from the existing loopback `IDENTITY_ENDPOINT`,
`IDENTITY_HEADER`, and optional `AZURE_CLIENT_ID`. Its audience is fixed to
`https://storage.azure.com/`. Storage and token clients reject redirects. The
Defined endpoint defaults to its official API and must use HTTPS without user
info, query, fragment or a custom path. Do not provide administrator tokens,
Storage keys, SAS URLs or enrollment codes to this configuration.

`-acquire-timeout` bounds acquisition/startup (default 30s); `-renew-interval`
(default 60s) and `-renew-timeout` (default 30s) bound SDK polling. Blob leases
retain the prototype's 60s lease, 15s conservative margin, 10s renewal interval
and independent 1s watchdog. `-drain-timeout` (default 30s) bounds sessions;
`-cleanup-timeout` (default 15s) bounds final checkpoint/release separately.

`POST /v1/lifecycle/complete` on the permission-0600 Unix socket and SIGTERM/SIGINT
both run bounded shutdown. Read-only poll cancellation can complete cleanly;
uncertain remote rotation during cancellation cannot. Expected drain timeout
forces session cancellation and still permits release after all safety gates.

Tests use synthetic in-process Storage/Defined fixtures and actual local TCP
sessions. They establish software behavior, not live Azure deployment support.
Independent overlay/dependency readiness, measurements and platform validation
remain #6/#7. Infra consumers remain on their existing pinned image until a
separate reviewed deployment translation and runtime proof is authorized.
