// Package runtime owns the portable identity/transport/session lifecycle.
package runtime

import (
	"bytes"
	"context"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/control"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"github.com/MTG-Thomas/vojeto/internal/lifecycle"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"sync"
	"time"
)

// Transport.Close must synchronously stop packet transport, or return an error.
type Transport interface {
	network.Network
	Reload([]byte) error
	Close() error
}

// Session.Drain must cancel and join all sessions on every return, including timeout.
type Session interface {
	StopAccepting()
	Drain(context.Context) error
}
type Config struct{ AcquireTimeout, RenewInterval, RenewTimeout, DrainTimeout, CleanupTimeout time.Duration }

func DefaultConfig() Config {
	return Config{30 * time.Second, 60 * time.Second, 30 * time.Second, 30 * time.Second, 15 * time.Second}
}

type Runner struct {
	// SignalGrace keeps the overlay available for native application drain after
	// platform cancellation. Explicit completion skips this grace.
	SignalGrace   time.Duration
	quiescing     bool
	Provider      identity.Provider
	Open          func(context.Context, []byte) (Transport, error)
	StartSessions func(context.Context, network.Network) ([]Session, error)
	Config        Config
	// CheckHealth must honor cancellation. Nil means readiness is unverified.
	CheckHealth                     func(context.Context, network.Network) (overlay, dependencies bool)
	HealthInterval                  time.Duration
	overlayReady, dependenciesReady bool
	state                           *lifecycle.Manager
	mu                              sync.Mutex
	current                         *identity.Identity
	transport                       *managedTransport
	sessions                        []Session
	cancelSessions                  context.CancelFunc
	cancelStartup                   context.CancelFunc
	failed                          bool
	failure                         chan struct{}
	failureOnce                     sync.Once
	running                         bool
}

func New(p identity.Provider, open func(context.Context, []byte) (Transport, error), sessions func(context.Context, network.Network) ([]Session, error), cfg Config) (*Runner, error) {
	if p == nil || open == nil || sessions == nil || cfg.AcquireTimeout <= 0 || cfg.RenewInterval <= 0 || cfg.RenewTimeout <= 0 || cfg.DrainTimeout <= 0 || cfg.CleanupTimeout <= 0 {
		return nil, errors.New("invalid runtime configuration")
	}
	return &Runner{Provider: p, Open: open, StartSessions: sessions, Config: cfg, state: lifecycle.New(), failure: make(chan struct{})}, nil
}
func (r *Runner) Status() control.Status {
	r.mu.Lock()
	valid := r.current != nil && !r.failed
	overlay, dependencies := r.overlayReady, r.dependenciesReady
	quiescing := r.quiescing
	r.mu.Unlock()
	if v, ok := r.Provider.(identity.Validity); ok && valid {
		valid = v.Valid()
	}
	s := r.state.State()
	if quiescing && (s == lifecycle.Ready || s == lifecycle.Rotating) {
		s = lifecycle.Draining
	}
	return control.Status{State: string(s), IdentityValid: valid && s != lifecycle.Stopped && s != lifecycle.ReleasingIdentity, OverlayReady: valid && overlay && s == lifecycle.Ready, DependenciesReady: valid && dependencies && s == lifecycle.Ready}
}
func (r *Runner) fail(ownership bool) {
	r.mu.Lock()
	r.failed = true
	r.overlayReady, r.dependenciesReady = false, false
	sessions := append([]Session(nil), r.sessions...)
	cancel := r.cancelSessions
	cancelStartup := r.cancelStartup
	transport := r.transport
	r.mu.Unlock()
	if ownership {
		_ = r.state.Transition(lifecycle.LeaseLost)
	}
	_ = r.state.Transition(lifecycle.NotReady)
	for _, s := range sessions {
		s.StopAccepting()
	}
	if cancelStartup != nil {
		cancelStartup()
	}
	if cancel != nil {
		cancel()
	}
	if transport != nil {
		_ = transport.Close()
	}
	r.failureOnce.Do(func() { close(r.failure) })
}
func (r *Runner) isFailed() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.failed }

// Run is single-use. Completion and platform cancellation both trigger clean drain;
// identity loss always takes precedence and leaves provider ownership quarantined.
func (r *Runner) Run(ctx context.Context, completion <-chan struct{}) (result error) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("runtime already started")
	}
	r.running = true
	r.mu.Unlock()
	_ = r.state.Transition(lifecycle.AcquiringIdentity)
	startup, cancelStartup := context.WithTimeout(ctx, r.Config.AcquireTimeout)
	r.mu.Lock()
	r.cancelStartup = cancelStartup
	r.mu.Unlock()
	startupDone := make(chan struct{})
	startupWatcherDone := make(chan struct{})
	go func() {
		defer close(startupWatcherDone)
		select {
		case <-completion:
			cancelStartup()
		case <-startupDone:
		}
	}()
	current, e := r.Provider.Acquire(startup)
	if e != nil || current == nil {
		cancelStartup()
		close(startupDone)
		<-startupWatcherDone
		r.fail(false)
		_ = r.state.Transition(lifecycle.Stopped)
		return errors.Join(errors.New("identity acquisition failed"), e)
	}
	r.mu.Lock()
	r.current = current
	r.mu.Unlock()
	sessionsCtx, cancelSessions := context.WithCancel(context.Background())
	r.mu.Lock()
	r.cancelSessions = cancelSessions
	r.mu.Unlock()
	monitorCtx, cancelMonitor := context.WithCancel(context.Background())
	monitorDone := make(chan struct{})
	if watcher, ok := r.Provider.(identity.Watcher); ok {
		go func() {
			defer close(monitorDone)
			_ = watcher.Watch(monitorCtx, func() { r.fail(true) })
			if monitorCtx.Err() == nil {
				r.fail(true)
			}
		}()
	} else {
		close(monitorDone)
	}
	pollCtx, cancelPoll := context.WithCancel(context.Background())
	pollDone := make(chan struct{})
	pollStarted := false
	healthCtx, cancelHealth := context.WithCancel(context.Background())
	healthDone := make(chan struct{})
	healthStarted := false
	defer func() {
		if result != nil {
			r.fail(false)
		}
		cancelStartup()
		cancelHealth()
		if healthStarted {
			<-healthDone
		}
		close(startupDone)
		<-startupWatcherDone
		drainCtx, cancelDrain := context.WithTimeout(context.Background(), r.Config.DrainTimeout)
		defer cancelDrain()
		var cleanup context.Context
		var cancelCleanup context.CancelFunc
		beginCleanup := func() {
			if cleanup == nil {
				cleanup, cancelCleanup = context.WithTimeout(context.Background(), r.Config.CleanupTimeout)
			}
		}
		defer func() {
			if cancelCleanup != nil {
				cancelCleanup()
			}
		}()
		finishErr := r.state.Complete(drainCtx, lifecycle.Hooks{
			StopAccepting: func() {
				r.mu.Lock()
				sessions := append([]Session(nil), r.sessions...)
				r.mu.Unlock()
				for _, s := range sessions {
					s.StopAccepting()
				}
			},
			Drain: func(c context.Context) error {
				cancelPoll()
				if pollStarted {
					<-pollDone
				}
				r.mu.Lock()
				sessions := append([]Session(nil), r.sessions...)
				r.mu.Unlock()
				var err error
				for _, s := range sessions {
					if e := s.Drain(c); e != nil {
						if errors.Is(e, context.DeadlineExceeded) {
							err = errors.Join(err, context.DeadlineExceeded)
						} else {
							err = errors.Join(err, errors.New("session drain failed"))
						}
					}
				}
				return err
			},
			Checkpoint: func(context.Context) error {
				beginCleanup()
				if result != nil || r.isFailed() {
					return errors.New("unclean identity shutdown")
				}
				r.mu.Lock()
				latest := r.current
				r.mu.Unlock()
				if r.Provider.Checkpoint(cleanup, latest) != nil {
					return errors.New("identity checkpoint failed")
				}
				return nil
			},
			StopTransport: func(context.Context) error {
				cancelSessions()
				r.mu.Lock()
				n := r.transport
				r.mu.Unlock()
				var err error
				if n != nil {
					if n.Close() != nil {
						err = errors.New("overlay shutdown unconfirmed")
					}
				}
				cancelMonitor()
				<-monitorDone
				if r.isFailed() {
					return errors.New("identity ownership lost")
				}
				return err
			},
			Release: func(context.Context) error {
				beginCleanup()
				r.mu.Lock()
				latest := r.current
				r.mu.Unlock()
				if r.Provider.Release(cleanup, latest) != nil {
					return errors.New("identity release unconfirmed")
				}
				return nil
			},
			Flush: func(context.Context) error { return nil },
		})
		if finishErr != nil {
			r.fail(false)
			_ = r.state.Transition(lifecycle.Stopped)
			result = errors.Join(result, finishErr)
		}
	}()
	if r.isFailed() {
		return errors.New("identity ownership lost before connecting")
	}
	if e = r.state.Transition(lifecycle.Connecting); e != nil {
		return errors.New("runtime connection rejected")
	}
	n, e := r.Open(startup, current.Config)
	if e != nil || n == nil {
		if n != nil {
			n.Close()
		}
		return errors.Join(errors.New("overlay initialization failed"), e)
	}
	wrapped := &managedTransport{Transport: n}
	r.mu.Lock()
	r.transport = wrapped
	lost := r.failed
	r.mu.Unlock()
	if lost {
		wrapped.Close()
		return errors.New("identity ownership lost during initialization")
	}
	if r.CheckHealth != nil {
		interval := r.HealthInterval
		if interval <= 0 {
			interval = 5 * time.Second
		}
		for {
			overlay, dependencies := r.CheckHealth(startup, wrapped)
			if startup.Err() != nil {
				return errors.New("startup readiness deadline exceeded")
			}
			r.mu.Lock()
			r.overlayReady, r.dependenciesReady = overlay, dependencies
			r.mu.Unlock()
			if overlay && dependencies {
				break
			}
			timer := time.NewTimer(interval)
			select {
			case <-startup.Done():
				timer.Stop()
				return errors.New("startup readiness deadline exceeded")
			case <-timer.C:
			}
		}
		healthStarted = true
		go func() {
			defer close(healthDone)
			ticks := time.NewTicker(interval)
			defer ticks.Stop()
			for {
				select {
				case <-healthCtx.Done():
					return
				case <-ticks.C:
				}
				overlay, dependencies := r.CheckHealth(healthCtx, wrapped)
				r.mu.Lock()
				r.overlayReady, r.dependenciesReady = overlay, dependencies
				r.mu.Unlock()
			}
		}()
	}
	sessions, e := r.StartSessions(sessionsCtx, wrapped)
	r.mu.Lock()
	r.sessions = sessions
	lost = r.failed
	r.mu.Unlock()
	if e != nil {
		return errors.Join(errors.New("session initialization failed"), e)
	}
	if lost {
		return errors.New("identity ownership lost before admission")
	}
	if e = r.state.Transition(lifecycle.Ready); e != nil {
		return errors.New("runtime admission rejected")
	}
	cancelStartup()
	pollStarted = true
	go func() { defer close(pollDone); r.poll(pollCtx) }()
	select {
	case <-ctx.Done():
		r.mu.Lock()
		r.quiescing = true
		r.mu.Unlock()
		if r.SignalGrace > 0 {
			timer := time.NewTimer(r.SignalGrace)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-completion:
			case <-r.failure:
				return errors.New("identity lost during signal grace")
			}
		}
		return nil
	case <-completion:
		return nil
	case <-r.failure:
		return errors.New("runtime stopped after identity failure")
	}
}
func (r *Runner) poll(ctx context.Context) {
	ticks := time.NewTicker(r.Config.RenewInterval)
	defer ticks.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks.C:
		}
		if r.state.Transition(lifecycle.Rotating) != nil {
			return
		}
		r.mu.Lock()
		current := r.current
		n := r.transport
		r.mu.Unlock()
		update, cancel := context.WithTimeout(ctx, r.Config.RenewTimeout)
		next, e := r.Provider.Renew(update, current)
		cancel()
		if e != nil {
			if ctx.Err() == nil || errors.Is(e, identity.ErrUnsafeRenewal) {
				r.fail(false)
			}
			return
		}
		if next == nil {
			r.fail(false)
			return
		}
		r.mu.Lock()
		r.current = next
		r.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		if r.isFailed() {
			return
		}
		if !bytes.Equal(next.Config, current.Config) {
			if n.Reload(next.Config) != nil {
				r.fail(false)
				return
			}
		}
		_ = r.state.Transition(lifecycle.Ready)
	}
}

// Serialize reload and synchronous stop. No provider HTTP operation holds this lock.
type managedTransport struct {
	Transport
	mu       sync.Mutex
	closed   bool
	closeErr error
}

func (n *managedTransport) Reload(data []byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return errors.New("transport stopped")
	}
	return n.Transport.Reload(data)
}
func (n *managedTransport) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.closed {
		n.closed = true
		n.closeErr = n.Transport.Close()
	}
	return n.closeErr
}
