package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/MTG-Thomas/vojeto/internal/control"
	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/lifecycle"
	"github.com/MTG-Thomas/vojeto/internal/network/netstack"
	"github.com/MTG-Thomas/vojeto/internal/providers/static"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func run() error {
	config := flag.String("config", "", "secret Nebula configuration file")
	forwards := flag.String("forwards", "", "JSON array of named forwards")
	maximum := flag.Int("max-connections", 128, "global session ceiling")
	drain := flag.Duration("drain-timeout", 30*time.Second, "shutdown drain bound")
	socket := flag.String("control-socket", "", "optional Unix control socket in a private writable directory")
	flag.Parse()
	if *maximum < 1 || *drain <= 0 {
		return errors.New("invalid limits")
	}
	provider := static.Provider{Path: *config}
	current, e := provider.Acquire(context.Background())
	if e != nil {
		return errors.New("configuration unavailable")
	}
	var entries []forward.Config
	dataForwards, e := os.ReadFile(*forwards)
	if e != nil || json.Unmarshal(dataForwards, &entries) != nil || len(entries) == 0 {
		return errors.New("invalid forwards")
	}
	n, e := netstack.Open(current.Config)
	if e != nil {
		return e
	}
	var closeOnce sync.Once
	closeNetwork := func() { closeOnce.Do(func() { n.Close() }) }
	defer closeNetwork()
	manager := lifecycle.New()
	manager.Transition(lifecycle.AcquiringIdentity)
	manager.Transition(lifecycle.Connecting)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	limit := forward.NewLimit(*maximum)
	var listeners []*forward.Listener
	defer func() {
		for _, l := range listeners {
			d, c := context.WithTimeout(context.Background(), *drain)
			l.Drain(d)
			c()
		}
	}()
	for _, c := range entries {
		l, e := forward.Open(context.Background(), n, c, limit)
		if e != nil {
			return errors.New("forward initialization failed")
		}
		listeners = append(listeners, l)
	}
	completed := make(chan struct{})
	var completeOnce sync.Once
	if *socket != "" {
		ln, e := net.Listen("unix", *socket)
		if e != nil {
			return errors.New("control socket unavailable")
		}
		defer ln.Close()
		defer os.Remove(*socket)
		if os.Chmod(*socket, 0600) != nil {
			return errors.New("control permissions unavailable")
		}
		srv := &http.Server{Handler: control.Handler(func() control.Status { return control.Status{State: string(manager.State()), IdentityValid: true} }, func() { completeOnce.Do(func() { close(completed) }) }), ReadHeaderTimeout: time.Second}
		defer srv.Close()
		go srv.Serve(ln)
	}
	// Overlay health is intentionally unconfirmed until independent dependency probes exist.
	select {
	case <-ctx.Done():
	case <-completed:
	}
	noOp := func(context.Context) error { return nil }
	finish, cancel := context.WithTimeout(context.Background(), *drain)
	defer cancel()
	return manager.Complete(finish, lifecycle.Hooks{StopAccepting: func() {
		for _, l := range listeners {
			l.StopAccepting()
		}
	}, Drain: func(ctx context.Context) error {
		var result error
		for _, l := range listeners {
			if e := l.Drain(ctx); e != nil {
				result = e
			}
		}
		return result
	}, Checkpoint: func(ctx context.Context) error { return provider.Checkpoint(ctx, current) }, StopTransport: func(context.Context) error { closeNetwork(); return nil }, Release: func(ctx context.Context) error { return provider.Release(ctx, current) }, Flush: noOp})
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "vojeto failed; inspect configuration privately")
		os.Exit(1)
	}
}
