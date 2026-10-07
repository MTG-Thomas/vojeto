# RACK loss accounting regression

Scope: portable Vojeto transport release readiness; no deployed acceptance.

The merged dnapi license update's push validation failed in `TestResourceProfile`
(run 37548124738, source 88223d8). Nine encrypted streams completed; one stopped
at 3,383,136 of 8,388,608 received bytes and hit the unchanged 60-second deadline.
The job reported UDP receive-buffer drops and CPU throttling, with zero OOM events.
A later passing candidate did not resolve or waive that intermittent failure.

A focused native one-CPU run completed the transfer in 57.98 seconds. An isolated
instrumented dependency copy reproduced timeout and captured active recovery:
one remaining sender had Outstanding=134, SndCwnd=5 and queued data. Instrumentation
was limited to synthetic test connections and is not part of the release patch.

The pinned gVisor implementation marks RACK loss on `segment.lost`, while SetPipe
uses SACK scoreboard heuristics and HighRxt accounting. RACK-lost packets were
therefore still counted against the congestion window; retransmissions could be
counted twice. RACK's recovery loop also used stale pipe after marking loss.
This prevents timely retransmission even with an open receive window.

The new patch gives RACK its own pipe calculation: count each transmitted,
unsacked, non-lost packet once. Non-RACK SACK accounting is preserved. Refresh
pipe after loss detection and before checking the retransmission congestion
window. Sending a segment clears its lost flag, restoring its in-flight count.
The dependency version, existing SACK/RACK configuration, retry budgets, transfer
deadline, memory/CPU limits and application lifecycle are unchanged.

Two upstream-package regressions prove the bug deterministically. The original
code counts two lost packets as pipe=2 instead of zero, doubles retransmission
accounting, and retains stale pipe=40 at recovery. Tests cover lost, mixed,
in-flight, retransmitted and unchanged non-RACK SACK cases. Both regressions,
plus the existing timer regression, pass 100 times with race detection.

The refined patch completed three synthetic one-CPU encrypted 160 MiB transfers
in 10.276, 9.660 and 10.377 seconds, with approximately 98–100 MB peak CLI RSS
and about one second of shutdown drain. These are local diagnostic measurements,
not ACA resource or workload acceptance. The complete portable container gate
must pass on the exact release source before publication. Preserve the original
failure as evidence; never rerun the old source until green or relax its deadline.

The patch includes Apache-2.0 regression notices. Its file checksum and pinned
upstream rack.go checksum are verified before applying to an isolated module
copy; cached upstream dependencies are never edited.

Procedure package: MTG 2026-10-06.3.
