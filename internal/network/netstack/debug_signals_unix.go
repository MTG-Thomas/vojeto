//go:build !windows

package netstack

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// debugSignals collects endpoint state through the gvisor probe and dumps it to
// stderr on SIGUSR1, which is how the peer measurement harness captures
// [DEBUG-tcp-loss] lines on demand.
//
// It lives behind a build tag because syscall.SIGUSR1 does not exist on Windows,
// where the package must still compile: the Dockerfile cross-builds the peer for
// GOOS=windows.
func debugSignals(n *Network) {
	attachTCPProbe(n.ipstack)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(signals)
		for {
			select {
			case <-n.control.Context().Done():
				return
			case <-signals:
				fmt.Fprint(os.Stderr, debugTCPStack(n.ipstack))
			}
		}
	}()
}
