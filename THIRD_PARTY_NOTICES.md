# Third-party notices

Vojeto is AGPL-3.0. Dependency licenses remain their upstream licenses.

- Nebula v1.11.2: MIT; copied packet plumbing and the modified packet-cache
  patch retain the notice in NEBULA_LICENSE. Source: github.com/slackhq/nebula.
- gVisor: Apache-2.0; used as a Go module, not vendored or relicensed.
  Source and license: https://github.com/google/gvisor/blob/master/LICENSE.
- Defined Networking dnapi: redistribution license unresolved. As inspected on
  2026-10-04, upstream has no discoverable root license and GitHub reports no
  license. The SDK is linked into the CLI. Production binary/image publication
  must wait for an applicable grant or a reviewed replacement; linking does not
  remove license obligations. See issue #10.

The complete dependency inventory and versions are recorded in go.mod/go.sum.
A release artifact still needs a complete dependency-license inventory before
publication beyond the initial development container.

`scripts/dependency-notices.py` collects license, notice, and patent files for the
modules linked into `cmd/vojeto`, plus the Go runtime license. Supply the JSON
stream from `go list -deps -json ./cmd/vojeto` and an explicit output directory and
GOROOT. It exits nonzero for missing licenses. Current inspection identifies dnapi
as the sole missing module license; upstream clarification is tracked at
https://github.com/DefinedNet/dnapi/issues/52. This mechanical inventory does not
replace review of license compatibility or required notices.
