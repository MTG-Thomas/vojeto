# Finite workloads

Environment: portable client source; intended consumer is isolated DMARC ACA
staging. This feature does not change any deployed consumer.

A multi-container job needs both the application and its network companion to
finish. Rather than a writable cross-container completion socket, Linux Vojeto
can supervise a trusted finite executable in the same container:

```sh
/vojeto -identity-provider /private/provider.json \
  -forwards /private/forwards.json -readiness /private/readiness.json \
  -acquire-timeout 420s -workload-timeout 15m -workload-grace 30s \
  -exec -- /usr/share/dotnet/dotnet /app/DmarcAnalyzer.Api.dll
```

The consumer image must contain both licensed, published artifacts, pinned by
digest. Set `APP_MODE=worker-once` for this example. No shell is inserted and the
executable path must be absolute. Arguments are operator-owned configuration;
do not pass credentials in them. Child output goes to normal application logs;
Vojeto errors contain only closed failure codes, never command text.

The lifetime includes identity acquisition and dependency readiness. Configure
required database probes; readiness must prove the original hostname and TLS
route before starting work. The job's platform timeout must exceed lifetime,
child termination grace, network drain and cleanup budgets. `-exec` rejects
SOCKS lifetime mode, the external completion socket and service signal grace,
which otherwise introduce competing completion authorities.

The child starts only after the normal identity/overlay/dependency readiness
status becomes ready. Successful child exit requests the existing runtime's
ordered drain, checkpoint, transport close and identity release, then joins it.
Child failure still allows clean network release but returns nonzero. Failed or
uncertain cleanup returns nonzero and retains the provider's quarantine rules.
A failed overlay cancels and joins the child; it never restarts or reacquires an
identity automatically.

SIGTERM/SIGINT and lifetime expiry cancel the child first. Its process group
receives SIGTERM, then SIGKILL after the bounded grace if necessary. Vojeto joins
the direct child, closes lingering group descendants, and requests normal
network completion. Cancellation returns nonzero. Use trusted workloads that do
not daemonize or escape their process group; this is supervision, not a sandbox.
The HTTP API and other long-running consumers retain their existing lifecycle.

Focused tests cover delayed readiness, startup cancellation, worker failure,
cleanup failure, ownership loss, timeout ordering, private error suppression and
forced process-group shutdown. Existing runtime tests prove checkpoint/transport
stop/release ordering. Actual ACA execution completion, exclusive live identity
ownership and reuse still require the separately reviewed infra consumer and
protected runtime proof. No scale-to-zero or cost claim follows from these tests.
