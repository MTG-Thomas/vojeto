# Bounded read-only Defined outage grace

Grace is opt-in. The default remains fail-closed on every poll error. A configured
`pollOutageGrace` bounds control-plane freshness from the start of the last
successful read-only poll, not from each failure. Failed polls do not extend it.
The usable deadline is also capped fifteen seconds before the earliest validated
host/issuer certificate expiry. Grace requires inline host certificates in the checkpoint. Missing, file-based,
or invalid certificate bounds reject startup when grace is enabled. Startup always requires a successful authenticated
poll; grace cannot authorize cached state on a cold start.

Only read-only HTTP 429, 502, 503, 504 and positively identified transport timeouts
are eligible. Cancellation, TLS rejection, unknown errors, authentication errors,
redirects, malformed or oversized responses are not. Any update/rotation error
remains unsafe and quarantines the identity. Response bodies and underlying
transport error text never enter logs or status.

An independent watcher enforces the freshness/certificate deadline even while a
poll is blocked. Lease ownership remains independently watched and must always
be valid. Deadline expiry or lease loss closes transport and active sessions;
neither a late HTTP success nor a later poll can restore that owner. Clean
explicit completion inside the valid bound can still checkpoint and release.
A successful read-only poll restores the configured freshness window without
changing transport identity. A successful verified rotation still checkpoints
credentials and accepted configuration before reload.

The public provider owns these software bounds. Deployments choose whether to
opt in, the grace duration, and compatible poll interval/request budgets. The
CLI rejects grace shorter than the poll interval plus request timeout. Platform
resource names, pool membership, enrollment policy, and rollout remain in infra.
Grace must be positive and at most 24 hours when enabled; it never overrides
certificate expiry or ownership validity. These are source-level acceptance
rules, not proof of a live cloud deployment.
