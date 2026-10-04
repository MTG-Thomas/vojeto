# Third-party notices

Vojeto is AGPL-3.0. Dependency licenses remain their upstream licenses.

- Nebula v1.11.2: MIT; copied packet plumbing and the modified packet-cache
  patch retain the notice in NEBULA_LICENSE. Source: github.com/slackhq/nebula.
- gVisor: Apache-2.0; used as a Go module, not vendored or relicensed.
  Source and license: https://github.com/google/gvisor/blob/master/LICENSE.
- Defined Networking dnapi: retain its upstream module license; the SDK is
  linked as a dependency, not copied into Vojeto's source.

The complete dependency inventory and versions are recorded in go.mod/go.sum.
A release artifact still needs a complete dependency-license inventory before
publication beyond the initial development container.
