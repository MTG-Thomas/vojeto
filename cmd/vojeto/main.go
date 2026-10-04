package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/MTG-Thomas/vojeto/internal/control"
	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"github.com/MTG-Thomas/vojeto/internal/network/netstack"
	"github.com/MTG-Thomas/vojeto/internal/runtime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func run() error {
	config := flag.String("config", "", "secret static Nebula configuration file")
	providerConfig := flag.String("identity-provider", "", "JSON identity-provider settings (alternative to -config)")
	forwards := flag.String("forwards", "", "JSON array of named forwards")
	maximum := flag.Int("max-connections", 128, "global session ceiling")
	cfg := runtime.DefaultConfig()
	flag.DurationVar(&cfg.DrainTimeout, "drain-timeout", cfg.DrainTimeout, "shutdown drain bound")
	flag.DurationVar(&cfg.AcquireTimeout, "acquire-timeout", cfg.AcquireTimeout, "identity/startup bound")
	flag.DurationVar(&cfg.RenewInterval, "renew-interval", cfg.RenewInterval, "credential poll interval")
	flag.DurationVar(&cfg.RenewTimeout, "renew-timeout", cfg.RenewTimeout, "credential update bound")
	flag.DurationVar(&cfg.CleanupTimeout, "cleanup-timeout", cfg.CleanupTimeout, "checkpoint/release cleanup bound")
	socket := flag.String("control-socket", "", "optional Unix control socket in a private writable directory")
	flag.Parse()
	if *maximum < 1 {
		return errors.New("invalid connection limit")
	}
	provider, e := selectProvider(*config, *providerConfig)
	if e != nil {
		return e
	}
	var entries []forward.Config
	data, e := os.ReadFile(*forwards)
	if e != nil || json.Unmarshal(data, &entries) != nil || len(entries) == 0 {
		return errors.New("invalid forwards")
	}
	limit := forward.NewLimit(*maximum)
	runner, e := runtime.New(provider, func(ctx context.Context, data []byte) (runtime.Transport, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		return netstack.Open(data)
	}, func(ctx context.Context, n network.Network) ([]runtime.Session, error) {
		var sessions []runtime.Session
		for _, c := range entries {
			l, e := forward.Open(ctx, n, c, limit)
			if e != nil {
				return sessions, e
			}
			sessions = append(sessions, l)
		}
		return sessions, nil
	}, cfg)
	if e != nil {
		return e
	}
	completed := make(chan struct{})
	var once sync.Once
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
		server := &http.Server{Handler: control.Handler(runner.Status, func() { once.Do(func() { close(completed) }) }), ReadHeaderTimeout: time.Second}
		defer server.Close()
		go server.Serve(ln)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runner.Run(ctx, completed)
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "vojeto failed; inspect configuration privately")
		os.Exit(1)
	}
}
