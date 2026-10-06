package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/MTG-Thomas/vojeto/internal/control"
	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/health"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"github.com/MTG-Thomas/vojeto/internal/network/netstack"
	"github.com/MTG-Thomas/vojeto/internal/runtime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func run() error {
	checkConfig := flag.Bool("check-config", false, "validate configuration without acquiring identity, binding sockets or network traffic")
	config := flag.String("config", "", "secret static Nebula configuration file")
	providerConfig := flag.String("identity-provider", "", "JSON identity-provider settings (alternative to -config)")
	forwards := flag.String("forwards", "", "JSON array of named forwards")
	socks := flag.String("socks", "", "opt-in finite SOCKS JSON policy (alternative to forwards)")
	readinessFile := flag.String("readiness", "", "JSON overlay mappings and required dependency probes")
	healthListen := flag.String("health-listen", "", "optional read-only health HTTP listener (loopback by default)")
	publicHealth := flag.Bool("allow-public-health", false, "explicitly allow non-loopback read-only health listener")
	maximum := flag.Int("max-connections", 128, "global session ceiling")
	cfg := runtime.DefaultConfig()
	flag.DurationVar(&cfg.DrainTimeout, "drain-timeout", cfg.DrainTimeout, "shutdown drain bound")
	flag.DurationVar(&cfg.AcquireTimeout, "acquire-timeout", cfg.AcquireTimeout, "identity/startup bound")
	flag.DurationVar(&cfg.RenewInterval, "renew-interval", cfg.RenewInterval, "credential poll interval")
	flag.DurationVar(&cfg.RenewTimeout, "renew-timeout", cfg.RenewTimeout, "credential update bound")
	flag.DurationVar(&cfg.CleanupTimeout, "cleanup-timeout", cfg.CleanupTimeout, "checkpoint/release cleanup bound")
	signalGrace := flag.Duration("signal-grace", 0, "native application drain allowance before stopping admission (0 disables)")
	socket := flag.String("control-socket", "", "optional Unix control socket in a private writable directory")
	flag.Parse()
	if err := validateAdmission(*maximum, *signalGrace); err != nil {
		return err
	}
	provider, e := selectProvider(*config, *providerConfig)
	if e != nil {
		return e
	}
	if bounded, ok := provider.(interface {
		ValidatePollSchedule(time.Duration, time.Duration) error
	}); ok {
		if e = bounded.ValidatePollSchedule(cfg.RenewInterval, cfg.RenewTimeout); e != nil {
			return e
		}
	}
	entries, socksConfig, e := loadSessions(*forwards, *socks)
	if e != nil {
		return e
	}
	settings, resolver, e := loadReadiness(*readinessFile)
	if e != nil {
		return e
	}
	if *healthListen != "" {
		a, err := netip.ParseAddrPort(*healthListen)
		if err != nil || (!a.Addr().IsLoopback() && !*publicHealth) {
			return errors.New("explicit health bind required")
		}
	}
	if cfg.AcquireTimeout <= 0 || cfg.RenewInterval <= 0 || cfg.RenewTimeout <= 0 || cfg.DrainTimeout <= 0 || cfg.CleanupTimeout <= 0 {
		return errors.New("invalid runtime configuration")
	}
	if *checkConfig {
		fmt.Println(`{"configuration":"valid","runtimeVerified":false}`)
		return nil
	}
	completed := make(chan struct{})
	var once sync.Once
	complete := func() { once.Do(func() { close(completed) }) }
	limit := forward.NewLimit(*maximum)
	runner, e := runtime.New(provider, func(ctx context.Context, data []byte) (runtime.Transport, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		n, err := netstack.Open(data)
		if err != nil {
			return nil, err
		}
		if resolver != nil {
			return &resolvedTransport{Transport: n, resolver: resolver}, nil
		}
		return n, nil
	}, func(ctx context.Context, n network.Network) ([]runtime.Session, error) {
		if socksConfig != nil {
			server, err := openSocksSession(ctx, n, *socksConfig, limit, complete)
			if err != nil {
				return nil, err
			}
			return []runtime.Session{server}, nil
		}
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
	runner.SignalGrace = *signalGrace
	if settings != nil {
		runner.CheckHealth = func(ctx context.Context, n network.Network) (bool, bool) {
			overlay := health.CheckAll(ctx, n, settings.Overlay, 5*time.Second)
			dependencies := health.CheckAll(ctx, n, settings.Dependencies, 5*time.Second)
			return overlay, dependencies
		}
	}
	if *healthListen != "" {
		a, err := netip.ParseAddrPort(*healthListen)
		if err != nil || (!a.Addr().IsLoopback() && !*publicHealth) {
			return errors.New("explicit health bind required")
		}
		ln, err := net.Listen("tcp", a.String())
		if err != nil {
			return errors.New("health listener unavailable")
		}
		server := &http.Server{Handler: control.HealthHandler(runner.Status), ReadHeaderTimeout: time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		defer server.Close()
		go server.Serve(ln)
	}
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
		server := &http.Server{Handler: control.Handler(runner.Status, complete), ReadHeaderTimeout: time.Second}
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
