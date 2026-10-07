# Third-party notices

Vojeto is AGPL-3.0. Dependency licenses remain their upstream licenses.

- Nebula v1.11.2: MIT; copied packet plumbing and the modified packet-cache
  and rootless socket-buffer patches retain the notice in NEBULA_LICENSE. Source: github.com/slackhq/nebula.
- gVisor: Apache-2.0; the checksum-verified retransmission timer, small-window, zero-window ACK and RACK pipe-accounting patches and their
  regression preserve that license. See GVISOR_LICENSE. The module is patched
  in an isolated build copy, not relicensed.
  Source and license: https://github.com/google/gvisor/blob/master/LICENSE.
- Defined Networking dnapi: MIT. Pinned at
  `v0.0.0-20261006193934-1d274612a81a`, which includes the upstream license
  added on 2026-10-06. The release dependency bundle retains its LICENSE.
  Source: https://github.com/DefinedNet/dnapi/blob/1d274612a81a2e6b4b097ba7535264ebb4200f96/LICENSE.

The complete dependency inventory and versions are recorded in go.mod/go.sum.
`docker build --target release .` collects the complete linked-module notice
bundle and Go runtime license into `/licenses/dependencies`, with its versioned
inventory. It fails if any linked module has no discoverable license. The runtime
also retains the system CA package copyright notice. The default `runtime` target
is a local development artifact and must not be selected for publication.
Reviewing license compatibility and retaining required notices remain release
requirements; no registry publication is performed by this build.

`scripts/dependency-notices.py` collects license, notice, and patent files for the
modules linked into `cmd/vojeto`, plus the Go runtime license. Supply the JSON
stream from `go list -deps -json ./cmd/vojeto` and an explicit output directory and
GOROOT. It exits nonzero for missing licenses. The previously missing dnapi
license is present in the pinned upstream revision. The main-client `release`
target is checked in CI. This mechanical inventory does not replace review of
license compatibility or required notices.
