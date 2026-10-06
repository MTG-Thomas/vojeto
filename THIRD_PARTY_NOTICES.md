# Third-party notices

Vojeto is AGPL-3.0. Dependency licenses remain their upstream licenses.

- Nebula v1.11.2: MIT; copied packet plumbing and the modified packet-cache
  and rootless socket-buffer patches retain the notice in NEBULA_LICENSE. Source: github.com/slackhq/nebula.
- gVisor: Apache-2.0; the checksum-verified retransmission timer, small-window and zero-window ACK patches and their
  regression preserve that license. See GVISOR_LICENSE. The module is patched
  in an isolated build copy, not relicensed.
  Source and license: https://github.com/google/gvisor/blob/master/LICENSE.
- The Defined enrollment/update protocol is implemented in Vojeto's own
  `internal/definedwire` package using Go crypto and Nebula's MIT PEM helpers.
  `github.com/DefinedNet/dnapi` is no longer a linked dependency. See
  `docs/defined-protocol-replacement.md` for implementation provenance and checks.

The complete dependency inventory and versions are recorded in go.mod/go.sum.
`docker build --target release .` collects the complete linked-module notice
bundle and Go runtime license into `/licenses/dependencies`, with its versioned
inventory. It fails if any linked module has no discoverable license. The runtime
also retains the system CA package copyright notice. The default `runtime` target
is a local development artifact and must not be selected for publication.
Reviewing the replacement and license compatibility remains required before
publishing a release; no registry publication is performed by this build.

`scripts/dependency-notices.py` collects license, notice, and patent files for the
modules linked into `cmd/vojeto`, plus the Go runtime license. Supply the JSON
stream from `go list -deps -json ./cmd/vojeto` and an explicit output directory and
GOROOT. It exits nonzero for missing licenses. The SDK replacement's native
linked-module inventory passes this gate. The historical upstream clarification
is tracked at https://github.com/DefinedNet/dnapi/issues/52; no upstream license
resolution is claimed. This mechanical inventory does not replace review of
license compatibility or required notices.
