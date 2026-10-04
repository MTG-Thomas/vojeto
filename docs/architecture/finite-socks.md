# Finite SOCKS jobs

The CLI's `-socks /private/socks.json` mode exposes the existing allowlisted
SOCKS5 library to finite workloads. It is disabled unless that flag is supplied,
and is an alternative to `-forwards`. A single job has one admission mode;
this does not create an ambient overlay proxy.

```json
{
  "listen": "127.0.0.1:1080",
  "allow": ["192.0.2.10:5432", "192.0.2.11:6379"],
  "maxConnections": 16,
  "dialTimeout": "15s",
  "lifetime": "10m"
}
```

Use either static `-config` or an `-identity-provider` configuration. The loopback
bind, explicit nonempty IPv4 address/port allowlist, positive connection limit,
positive dial timeout and finite lifetime are mandatory. Unknown configuration
fields are rejected. The policy file is capped at 64 KiB and 1024 destinations.
Hostnames and IPv6 destinations are currently rejected. SOCKS never resolves
through host DNS, invokes host TCP dialing, accepts BIND or UDP ASSOCIATE, or
allows a public bind override. The no-authentication handshake is available only
inside this loopback trust boundary; untrusted processes sharing it are not
isolated from an allowed destination.

`-max-connections` remains the global ceiling; `maxConnections` applies to this
listener as well. Admission reserves both ceilings before even reading a SOCKS
handshake. Handshakes and overlay dials are bounded separately by `dialTimeout`.
Established sessions use the same TCP relay and half-close handling as fixed
forwards. No TLS is terminated or altered.

Lifetime starts when the listener opens after identity acquisition. At expiry,
admission and active sessions close, the CLI invokes portable completion,
checkpoints state, stops transport and releases clean exclusive ownership.
Explicit `POST /v1/lifecycle/complete` on the private control socket stops new
admission and lets existing sessions drain up to `-drain-timeout`; it does not
wait for the configured lifetime. SIGTERM/SIGINT use the existing runtime drain
and optional signal grace. Identity loss closes active sessions and never marks
uncertain ownership reusable. A timeout bound does not guarantee a successful
checkpoint or release; those failures remain unclean shutdowns.

The blocking `socks5.Serve` library API remains available. `socks5.Open` supplies
runtime-managed admission, active counts, lifetime notification and bounded drain.
Tests retain the original protocol, allowlist, limit, cancellation and repeated
dial-timeout behavior, and add shared global admission, graceful active-session
drain, pending-handshake/dial cancellation and lifetime cleanup. Platform-specific
worker completion and deployment wrappers belong to the consumer repository.
