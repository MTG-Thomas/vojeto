package defined

import (
	"context"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/definedwire"
	wirekeys "github.com/MTG-Thomas/vojeto/internal/definedwire/credentials"
	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"github.com/MTG-Thomas/vojeto/internal/runtime"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadOnlyOutageClassification(t *testing.T) {
	credentials := clientCredentials(t, false)
	for _, status := range []int{429, 502, 503, 504} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		if _, err := c.CheckForUpdate(context.Background(), credentials); !errors.Is(err, ErrTransientPoll) {
			t.Fatal(status, err)
		}
		if _, _, _, _, err := c.DoUpdate(context.Background(), credentials); errors.Is(err, ErrTransientPoll) || err == nil {
			t.Fatal("rotation error was retryable", status, err)
		}
	}
}

func TestOversizedTransientResponseDoesNotAuthorizeGrace(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2097153")
		w.WriteHeader(503)
	})
	if _, err := c.CheckForUpdate(context.Background(), clientCredentials(t, false)); err != errControlPlane {
		t.Fatal("oversized response allowed grace", err)
	}
}

func TestOutageGraceDefaultAndColdStartFailClosed(t *testing.T) {
	for _, stage := range []string{"startup", "renewal"} {
		p, _, c := providerFixture(t)
		if stage == "startup" {
			p.options.PollOutageGrace = time.Minute
			c.check = func(context.Context) (bool, error) { return false, ErrTransientPoll }
		}
		current, err := p.Acquire(context.Background())
		if stage == "startup" {
			if err == nil || current != nil {
				t.Fatal("unauthenticated cached identity started")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		c.check = func(context.Context) (bool, error) { return false, ErrTransientPoll }
		if _, err = p.Renew(context.Background(), current); err == nil {
			t.Fatal("default silently enabled grace")
		}
	}
}

func TestOutageBudgetDoesNotSlideAndRecoveryResetsIt(t *testing.T) {
	p, s, c := providerFixture(t)
	now := time.Now()
	p.now = func() time.Time { return now }
	p.options.PollOutageGrace = 100 * time.Millisecond
	current, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := *p.deadline.Load()
	c.check = func(context.Context) (bool, error) { return false, ErrTransientPoll }
	now = now.Add(40 * time.Millisecond)
	if next, err := p.Renew(context.Background(), current); err != nil || next != current {
		t.Fatal("bounded outage rejected", err)
	}
	if !p.deadline.Load().Equal(first) || len(s.saves) != 0 {
		t.Fatal("outage extended budget or wrote credentials")
	}
	c.check = func(context.Context) (bool, error) { return false, nil }
	if _, err = p.Renew(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	recovered := *p.deadline.Load()
	if !recovered.After(first) {
		t.Fatal("successful poll did not restore freshness")
	}
	c.check = func(context.Context) (bool, error) { return false, ErrTransientPoll }
	now = recovered
	if p.Valid() {
		t.Fatal("expired budget remains valid")
	}
	if _, err = p.Renew(context.Background(), current); err == nil {
		t.Fatal("exhausted budget served stale identity")
	}
	if p.Checkpoint(context.Background(), current) == nil || p.Release(context.Background(), current) == nil || s.releaseCalls != 0 {
		t.Fatal("exhausted ownership became reusable")
	}
}

func TestGraceNeverCoversUnknownErrorsRotationOrLeaseLoss(t *testing.T) {
	for _, fault := range []string{"unknown", "cancelled", "lease", "rotation"} {
		p, s, c := providerFixture(t)
		p.options.PollOutageGrace = time.Minute
		current, err := p.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		switch fault {
		case "unknown":
			c.check = func(context.Context) (bool, error) { return false, errors.New("unclassified private detail") }
		case "cancelled":
			cancel()
			c.check = func(context.Context) (bool, error) { return false, ErrTransientPoll }
		case "lease":
			s.valid.Store(false)
			c.check = func(context.Context) (bool, error) { return false, ErrTransientPoll }
		case "rotation":
			c.update = func(context.Context) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error) {
				return nil, nil, nil, nil, ErrTransientPoll
			}
		}
		_, err = p.Renew(ctx, current)
		cancel()
		if err == nil {
			t.Fatal("unsafe fault covered by grace", fault)
		}
		if fault == "unknown" && (p.Valid() || p.Release(context.Background(), current) == nil) {
			t.Fatal("unknown failure restored or released owner")
		}
		if fault == "cancelled" && p.Release(context.Background(), current) != nil {
			t.Fatal("read-only shutdown cancellation prevented clean release")
		}
		if fault == "rotation" && !errors.Is(err, identity.ErrUnsafeRenewal) {
			t.Fatal("uncertain rotation not quarantined", err)
		}
	}
}

func TestCertificateExpiryCapsGraceAndRejectsInvalidStartup(t *testing.T) {
	p, _, _ := providerFixture(t)
	p.options.PollOutageGrace = 24 * time.Hour
	now := time.Now()
	p.now = func() time.Time { return now }
	if _, err := p.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := *p.deadline.Load()
	if deadline.After(now.Add(time.Hour-certificateSafetyMargin)) || deadline.Before(now.Add(59*time.Minute)) {
		t.Fatal("certificate did not cap grace", deadline.Sub(now))
	}
	now = deadline
	if p.Valid() {
		t.Fatal("certificate safety bound ignored")
	}
	expired, _, _ := providerFixture(t)
	expired.options.PollOutageGrace = time.Minute
	expired.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := expired.Acquire(context.Background()); err == nil {
		t.Fatal("expired certificate authorized grace")
	}
}

func TestFreshnessWatcherRevokesDuringBlockedPollAndJoins(t *testing.T) {
	p, s, c := providerFixture(t)
	p.options.PollOutageGrace = 100 * time.Millisecond
	current, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	c.check = func(ctx context.Context) (bool, error) { close(entered); <-ctx.Done(); return false, ctx.Err() }
	polling, cancelPoll := context.WithCancel(context.Background())
	defer cancelPoll()
	renewed := make(chan error, 1)
	go func() { _, err := p.Renew(polling, current); renewed <- err }()
	<-entered
	watching, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()
	var calls atomic.Int32
	revoked := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- p.Watch(watching, func() { calls.Add(1); close(revoked) }) }()
	select {
	case <-revoked:
	case <-time.After(time.Second):
		t.Fatal("blocked poll hid freshness expiry")
	}
	if p.Valid() {
		t.Fatal("revoked identity remains valid")
	}
	cancelPoll()
	select {
	case err := <-renewed:
		if err == nil {
			t.Fatal("late poll restored expired owner")
		}
	case <-time.After(time.Second):
		t.Fatal("poll did not join")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unexpected clean expiry")
		}
	case <-time.After(time.Second):
		t.Fatal("ownership monitor did not join")
	}
	if calls.Load() != 1 || p.Release(context.Background(), current) == nil || s.releaseCalls != 0 {
		t.Fatal("expired owner released or revoke repeated")
	}
}

// Exercise the real lifecycle and forwarding seams with an active local TCP
// session while a deliberately stalled poll ignores its request cancellation.
func TestOutageDeadlineStopsActiveRuntimeBeforeBlockedPollReturns(t *testing.T) {
	p, s, c := providerFixture(t)
	p.options.PollOutageGrace = 300 * time.Millisecond
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }) })
	checks := 0
	c.check = func(ctx context.Context) (bool, error) {
		checks++
		if checks == 1 {
			return false, nil
		}
		close(entered)
		<-release
		return false, ctx.Err()
	}
	n := &outageTransport{peers: make(chan net.Conn, 1)}
	limit := forward.NewLimit(1)
	address := make(chan string, 1)
	cfg := runtime.DefaultConfig()
	cfg.RenewInterval = 10 * time.Millisecond
	cfg.RenewTimeout = 50 * time.Millisecond
	cfg.DrainTimeout = 50 * time.Millisecond
	cfg.CleanupTimeout = time.Second
	runner, err := runtime.New(p, func(context.Context, []byte) (runtime.Transport, error) { return n, nil }, func(ctx context.Context, n network.Network) ([]runtime.Session, error) {
		l, err := forward.Open(ctx, n, forward.Config{Name: "fixture", Listen: "127.0.0.1:0", Target: "192.0.2.1:443", MaxConnections: 1, DialTimeout: time.Second}, limit)
		if err != nil {
			return nil, err
		}
		address <- l.Addr().String()
		return []runtime.Session{l}, nil
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx, make(chan struct{})) }()
	var addr string
	select {
	case addr = <-address:
	case <-ctx.Done():
		t.Fatal("startup failed")
	}
	app, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	select {
	case peer := <-n.peers:
		defer peer.Close()
	case <-ctx.Done():
		t.Fatal("active overlay session missing")
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("poll did not start")
	}
	app.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = app.Read(b[:]); err == nil {
		t.Fatal("deadline left active session alive")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("session timed out instead of being closed")
	}
	if runner.Status().IdentityValid || p.Valid() {
		t.Fatal("expired owner remained ready")
	}
	unblock.Do(func() { close(release) })
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("freshness loss completed cleanly")
		}
	case <-ctx.Done():
		t.Fatal("runtime or blocked poll did not join")
	}
	if limit.Active() != 0 || s.releaseCalls != 0 {
		t.Fatal("freshness loss leaked a session or reused identity")
	}
}

type outageTransport struct {
	mu         sync.Mutex
	connection net.Conn
	closed     bool
	peers      chan net.Conn
}

func (n *outageTransport) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}
func (n *outageTransport) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || ctx.Err() != nil {
		return nil, errors.New("stopped")
	}
	a, b := net.Pipe()
	n.connection = a
	n.peers <- b
	return a, nil
}
func (n *outageTransport) Reload([]byte) error { return nil }
func (n *outageTransport) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	if n.connection != nil {
		n.connection.Close()
	}
	return nil
}

func TestPollScheduleCannotOutliveFreshnessBudget(t *testing.T) {
	p, _, _ := providerFixture(t)
	p.options.PollOutageGrace = time.Minute
	for _, interval := range []time.Duration{30 * time.Second, time.Minute, time.Duration(1<<63 - 1)} {
		if p.ValidatePollSchedule(interval, 30*time.Second) == nil {
			t.Fatal("invalid poll schedule accepted", interval)
		}
	}
	if p.ValidatePollSchedule(10*time.Second, 20*time.Second) != nil {
		t.Fatal("bounded schedule rejected")
	}
}
