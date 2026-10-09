//go:build windows

package netstack

// debugSignals is a no-op on Windows: the platform has no SIGUSR1, and
// VOJETO_DEBUG_TCP is a Linux diagnostic used by the peer measurement harness.
// The probe helpers in debug_tmp.go still compile here so the package stays
// portable across the cross-build.
func debugSignals(_ *Network) {}
