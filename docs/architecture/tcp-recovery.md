# Retransmission after a tail-loss probe

Vojeto pins gVisor at `9d7a357edefe` through Nebula v1.11.2. Builds apply
`patches/gvisor-9d7a357edefe-retransmission-timer.patch` in a private dependency
copy. The preparation script verifies the version, original source checksum,
and patch checksum. The module cache is never edited.

## Failure and correction

A controlled test drops at most three response-tail packets per flow. Failure
snapshots showed 3,600 unacknowledged sequence bytes, zero packets in the sender's
pipe estimate, an open peer window, and no retransmission after a tail-loss probe.
The receiver had an out-of-order tail packet and waited for the preceding gap.

`sender.postXmit` only armed the resend timer when `Outstanding > 0`. That count
can be zero while `SndUna != SndNxt`. After the probe, the missing timer left the
connection stuck even though its retransmission timeout was 200 milliseconds.

The patch arms retransmission whenever sequence data remains unacknowledged and
neither a probe nor resend timer is already scheduled. It removes the redundant
packet-count gate inside the existing `SndUna != SndNxt` branch. It preserves
RACK, SACK, congestion control, timeout values, zero-window handling, and the
existing full-ack timer cleanup. It does not repair every possible pipe-accounting
or congestion-control defect.

## Verification

The patch includes `TestVojetoTailProbeArmsRetransmissionWithZeroPipe` in the
private dependency copy. It fails on the pinned original source and passes with
the patch. `make test` and the container build run it 100 times with the race
detector before the Vojeto suite.

Vojeto's controlled tests exercise periodic loss, finite bursts, tail loss, and
reordering in both directions. They check all returned bytes and join writers,
echo handlers, and packet pumps. The finite tail fault accounts for retransmission
resegmentation and cannot keep dropping newly split packets indefinitely.

This isolated regression is necessary but does not replace the encrypted
500-connection load test. Keep the original 60-second encrypted transfer deadline,
30-second controlled-test cancellation, and rootless restrictions. Production
acceptance also requires the deployment's own concurrency, latency, identity
rotation, ownership-loss, and drain evidence. Resource and outage limits remain
separate from this timer correction.
