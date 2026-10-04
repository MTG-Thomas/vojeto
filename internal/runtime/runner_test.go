package runtime

import (
	"context"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"github.com/MTG-Thomas/vojeto/internal/lifecycle"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type events struct {
	mu   sync.Mutex
	list []string
}

func (e *events) add(s string) { e.mu.Lock(); defer e.mu.Unlock(); e.list = append(e.list, s) }
func (e *events) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.list...)
}

type testProvider struct {
	log           *events
	loss          chan struct{}
	renew         func(context.Context, *identity.Identity) (*identity.Identity, error)
	checkpointErr error
	released      atomic.Int32
	checkpointed  atomic.Int32
}

func (p *testProvider) Acquire(context.Context) (*identity.Identity, error) {
	p.log.add("acquire")
	return &identity.Identity{Config: []byte("secret configuration")}, nil
}
func (p *testProvider) Renew(ctx context.Context, current *identity.Identity) (*identity.Identity, error) {
	if p.renew != nil {
		return p.renew(ctx, current)
	}
	return current, nil
}
func (p *testProvider) Checkpoint(ctx context.Context, _ *identity.Identity) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	p.log.add("checkpoint")
	p.checkpointed.Add(1)
	return p.checkpointErr
}
func (p *testProvider) Release(ctx context.Context, _ *identity.Identity) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	p.log.add("release")
	p.released.Add(1)
	return nil
}
func (p *testProvider) Watch(ctx context.Context, revoke func()) error {
	select {
	case <-ctx.Done():
		p.log.add("monitor joined")
		return nil
	case <-p.loss:
		revoke()
		p.log.add("revoked")
		return errors.New("ownership lost")
	}
}

type testTransport struct {
	log         *events
	mu          sync.Mutex
	closed      bool
	connections []net.Conn
	upstream    chan net.Conn
	reloadErr   error
	closeErr    error
	closedCount atomic.Int32
}

func (n *testTransport) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}
func (n *testTransport) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || ctx.Err() != nil {
		return nil, errors.New("stopped")
	}
	a, b := net.Pipe()
	n.connections = append(n.connections, a)
	n.upstream <- b
	return a, nil
}
func (n *testTransport) Reload([]byte) error { n.log.add("reload"); return n.reloadErr }
func (n *testTransport) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	n.closedCount.Add(1)
	n.log.add("transport stopped")
	for _, c := range n.connections {
		c.Close()
	}
	return n.closeErr
}
func testConfig() Config {
	return Config{time.Second, time.Hour, time.Second, 30 * time.Millisecond, time.Second}
}

type fixture struct {
	runner    *Runner
	provider  *testProvider
	transport *testTransport
	limit     *forward.Limit
	addr      chan string
	complete  chan struct{}
	done      chan error
	cancel    context.CancelFunc
}

func newFixture(t *testing.T, cfg Config, configure ...func(*testProvider, *testTransport)) *fixture {
	t.Helper()
	log := &events{}
	p := &testProvider{log: log, loss: make(chan struct{})}
	n := &testTransport{log: log, upstream: make(chan net.Conn, 10)}
	f := &fixture{provider: p, transport: n, limit: forward.NewLimit(2), addr: make(chan string, 1), complete: make(chan struct{}), done: make(chan error, 1)}
	r, e := New(p, func(context.Context, []byte) (Transport, error) { log.add("open"); return n, nil }, func(ctx context.Context, n network.Network) ([]Session, error) {
		l, e := forward.Open(ctx, n, forward.Config{Name: "test", Listen: "127.0.0.1:0", Target: "192.0.2.1:443", MaxConnections: 2, DialTimeout: time.Second}, f.limit)
		if e != nil {
			return nil, e
		}
		f.addr <- l.Addr().String()
		return []Session{l}, nil
	}, cfg)
	if e != nil {
		t.Fatal(e)
	}
	f.runner = r
	for _, setup := range configure {
		setup(p, n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	t.Cleanup(cancel)
	go func() { f.done <- r.Run(ctx, f.complete) }()
	return f
}
func awaitState(t *testing.T, r *Runner, want lifecycle.State) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticks := time.NewTicker(time.Millisecond)
	defer ticks.Stop()
	for {
		if r.state.State() == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("state %s, wanted %s", r.state.State(), want)
		case <-ticks.C:
		}
	}
}
func awaitResult(t *testing.T, f *fixture) error {
	t.Helper()
	select {
	case e := <-f.done:
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not join shutdown")
		return nil
	}
}
func connect(t *testing.T, f *fixture) (net.Conn, net.Conn) {
	t.Helper()
	awaitState(t, f.runner, lifecycle.Ready)
	address := <-f.addr
	c, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	var peer net.Conn
	select {
	case peer = <-f.transport.upstream:
	case <-time.After(time.Second):
		t.Fatal("overlay dial missing")
	}
	t.Cleanup(func() { c.Close(); peer.Close() })
	go c.Write([]byte("alive"))
	peer.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 5)
	if _, e := io.ReadFull(peer, data); e != nil || string(data) != "alive" {
		t.Fatal("session not active", e)
	}
	return c, peer
}
func TestCompletionCheckpointStopReleaseOrdering(t *testing.T) {
	f := newFixture(t, testConfig())
	awaitState(t, f.runner, lifecycle.Ready)
	s := f.runner.Status()
	if !s.IdentityValid || s.OverlayReady || s.DependenciesReady {
		t.Fatal("unproven health reported ready", s)
	}
	close(f.complete)
	if e := awaitResult(t, f); e != nil {
		t.Fatal(e)
	}
	order := strings.Join(f.provider.log.snapshot(), ",")
	if !strings.Contains(order, "checkpoint,transport stopped,monitor joined,release") {
		t.Fatal("unsafe completion ordering", order)
	}
	if f.runner.Status().IdentityValid || f.runner.state.State() != lifecycle.Stopped {
		t.Fatal("stopped runtime reports valid identity")
	}
	if f.transport.closedCount.Load() != 1 || f.provider.released.Load() != 1 {
		t.Fatal("duplicate cleanup")
	}
}
func TestLeaseLossClosesActiveSessionAndNeverReleases(t *testing.T) {
	f := newFixture(t, testConfig())
	c, _ := connect(t, f)
	close(f.provider.loss)
	c.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, e := c.Read(data[:]); e == nil {
		t.Fatal("ownership loss left session open")
	}
	if e := awaitResult(t, f); e == nil {
		t.Fatal("lease loss reported clean completion")
	}
	if f.limit.Active() != 0 || f.provider.released.Load() != 0 || f.provider.checkpointed.Load() != 0 {
		t.Fatal("ownership reused or session leaked")
	}
	if f.runner.Status().IdentityValid {
		t.Fatal("lost identity reports valid")
	}
}
func TestLeaseLossDuringStartupClosesLateTransport(t *testing.T) {
	log := &events{}
	p := &testProvider{log: log, loss: make(chan struct{})}
	n := &testTransport{log: log}
	entered := make(chan struct{})
	var admitted atomic.Bool
	r, e := New(p, func(ctx context.Context, _ []byte) (Transport, error) { close(entered); <-ctx.Done(); return n, nil }, func(context.Context, network.Network) ([]Session, error) { admitted.Store(true); return nil, nil }, testConfig())
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background(), nil) }()
	<-entered
	close(p.loss)
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("startup loss accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("startup did not stop on loss")
	}
	if admitted.Load() || n.closedCount.Load() != 1 || p.released.Load() != 0 {
		t.Fatal("late transport admitted or identity released")
	}
}
func TestLeaseLossDuringDrainQuarantinesIdentity(t *testing.T) {
	cfg := testConfig()
	cfg.DrainTimeout = time.Second
	f := newFixture(t, cfg)
	connect(t, f)
	close(f.complete)
	awaitState(t, f.runner, lifecycle.Draining)
	close(f.provider.loss)
	if awaitResult(t, f) == nil || f.provider.released.Load() != 0 || f.limit.Active() != 0 {
		t.Fatal("drain lost ownership but reused identity")
	}
}
func TestForcedDrainUsesFreshCleanupContext(t *testing.T) {
	f := newFixture(t, testConfig())
	connect(t, f)
	close(f.complete)
	if e := awaitResult(t, f); e != nil {
		t.Fatal("bounded drain prevented clean cleanup", e)
	}
	if f.provider.checkpointed.Load() != 1 || f.provider.released.Load() != 1 || f.limit.Active() != 0 {
		t.Fatal("forced drain skipped cleanup")
	}
}
func TestCheckpointFailureStillStopsTransport(t *testing.T) {
	f := newFixture(t, testConfig(), func(p *testProvider, n *testTransport) { p.checkpointErr = errors.New("private credential material") })
	awaitState(t, f.runner, lifecycle.Ready)
	close(f.complete)
	e := awaitResult(t, f)
	if e == nil || strings.Contains(e.Error(), "private credential") || f.transport.closedCount.Load() != 1 || f.provider.released.Load() != 0 {
		t.Fatal("checkpoint failure leaked secrets or released transport", e)
	}
}
func TestReloadFailureStopsAndQuarantines(t *testing.T) {
	cfg := testConfig()
	cfg.RenewInterval = 5 * time.Millisecond
	f := newFixture(t, cfg, func(p *testProvider, n *testTransport) {
		n.reloadErr = errors.New("secret failed config")
		p.renew = func(context.Context, *identity.Identity) (*identity.Identity, error) {
			return &identity.Identity{Config: []byte("next")}, nil
		}
	})
	if awaitResult(t, f) == nil || f.transport.closedCount.Load() != 1 || f.provider.released.Load() != 0 {
		t.Fatal("failed reload kept identity reusable")
	}
}
func TestCancelledRenewalQuarantinesOnlyUncertainRotation(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		t.Run(map[bool]string{false: "poll", true: "rotation"}[unsafe], func(t *testing.T) {
			cfg := testConfig()
			cfg.RenewInterval = 10 * time.Millisecond
			entered := make(chan struct{})
			f := newFixture(t, cfg, func(p *testProvider, n *testTransport) {
				p.renew = func(ctx context.Context, _ *identity.Identity) (*identity.Identity, error) {
					close(entered)
					<-ctx.Done()
					if unsafe {
						return nil, identity.ErrUnsafeRenewal
					}
					return nil, ctx.Err()
				}
			})

			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("poll missing")
			}
			close(f.complete)
			e := awaitResult(t, f)
			if unsafe {
				if e == nil || f.provider.released.Load() != 0 {
					t.Fatal("cancelled remote rotation released identity")
				}
			} else {
				if e != nil || f.provider.released.Load() != 1 {
					t.Fatal("safe poll cancellation blocked cleanup", e)
				}
			}
		})
	}
}

func TestTransportStopFailureNeverReleasesOrLeaksDetail(t *testing.T) {
	f := newFixture(t, testConfig(), func(p *testProvider, n *testTransport) { n.closeErr = errors.New("secret transport detail") })
	awaitState(t, f.runner, lifecycle.Ready)
	close(f.complete)
	e := awaitResult(t, f)
	if e == nil || strings.Contains(e.Error(), "secret") || f.provider.released.Load() != 0 {
		t.Fatal("unconfirmed stop released ownership or leaked detail", e)
	}
}
