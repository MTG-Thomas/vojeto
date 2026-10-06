package defined

import (
	"bytes"
	"context"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"github.com/MTG-Thomas/vojeto/internal/runtime"
	"net"
	"testing"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/definedwire"
	wirekeys "github.com/MTG-Thomas/vojeto/internal/definedwire/credentials"
	"go.yaml.in/yaml/v3"
)

type grantSourceFunc func(context.Context) (*EnrollmentGrant, error)

func (f grantSourceFunc) AcquireGrant(ctx context.Context) (*EnrollmentGrant, error) { return f(ctx) }

type grantTestStore struct {
	testStore
	begins                        int
	beginErr                      error
	lost                          chan struct{}
	binds                         int
	boundHost, boundNetwork       string
	expectedHost, expectedNetwork string
	bindErr                       error
	revokeOnBind                  bool
}

func (s *grantTestStore) Watch(ctx context.Context, revoke func()) error {
	if s.lost == nil {
		return s.testStore.Watch(ctx, revoke)
	}
	select {
	case <-ctx.Done():
		return nil
	case <-s.lost:
		s.valid.Store(false)
		revoke()
		return errors.New("ownership lost")
	}
}

func (s *grantTestStore) BindEnrollment(_ context.Context, host, network string) error {
	s.binds++
	if s.revokeOnBind {
		s.valid.Store(false)
	}
	if s.bindErr != nil {
		return s.bindErr
	}
	if host != s.expectedHost || network != s.expectedNetwork {
		return errors.New("allocation binding rejected")
	}
	s.boundHost, s.boundNetwork = host, network
	return nil
}

func (s *grantTestStore) BeginEnrollment(context.Context) error { s.begins++; return s.beginErr }

type grantTestClient struct {
	scriptClient
	enrollCalls int
	enroll      func(context.Context) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error)
}

func (c *grantTestClient) Enroll(ctx context.Context, code, hostname string) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error) {
	c.enrollCalls++
	if code != "fixture-code" || hostname != "fixture-worker" {
		return nil, nil, nil, nil, errors.New("bad fixture request")
	}
	return c.enroll(ctx)
}

func grantFixture(t *testing.T) (*Provider, *grantTestStore, *grantTestClient, *EnrollmentGrant) {
	t.Helper()
	state, credentials, dn := pooledRenewalFixture(t)
	var cfg map[string]any
	if yaml.Unmarshal(state.Config, &cfg) != nil {
		t.Fatal("fixture config")
	}
	key := []byte(cfg["pki"].(map[string]any)["key"].(string))
	grant := &EnrollmentGrant{Code: "fixture-code", HostID: state.HostID, NetworkID: "network-FIXTURE", Addresses: state.Addresses, RoutePolicy: []byte("{}")}
	store := &grantTestStore{expectedHost: state.HostID, expectedNetwork: "network-FIXTURE"}
	client := &grantTestClient{scriptClient: scriptClient{fakePooledDN: dn, check: func(context.Context) (bool, error) { return false, nil }}}
	client.enroll = func(context.Context) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error) {
		if store.binds != 1 || store.boundHost != state.HostID || store.boundNetwork != "network-FIXTURE" {
			t.Error("code submitted before durable host/network binding")
		}
		return state.Config, key, credentials, dn.meta, nil
	}
	source := grantSourceFunc(func(context.Context) (*EnrollmentGrant, error) {
		if store.begins != 1 || !store.Valid() {
			t.Error("grant acquisition preceded durable fencing")
		}
		return grant, nil
	})
	p, err := NewEnrollmentProvider(store, source, client, "network-FIXTURE", "fixture-worker", ProviderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return p, store, client, grant
}

func TestGrantProviderCheckpointsBeforeReadyAndUsesStrictRotation(t *testing.T) {
	p, store, client, grant := grantFixture(t)
	current, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(store.saves) != 1 || client.enrollCalls != 1 || grant.Code != "" {
		t.Fatal("enrollment not consumed and durable")
	}
	state, _, err := decodeIdentityState(store.saves[0])
	if err != nil || !bytes.Equal(state.Config, current.Config) {
		t.Fatal("ready config differs from checkpoint")
	}
	client.check = func(context.Context) (bool, error) { return true, nil }
	next, err := p.Renew(context.Background(), current)
	if err != nil || len(store.saves) != 3 || bytes.Equal(next.Config, current.Config) {
		t.Fatal("strict rotation failed", err)
	}
	if p.Checkpoint(context.Background(), next) != nil || p.Release(context.Background(), next) != nil || store.releaseCalls != 1 {
		t.Fatal("clean completion failed")
	}
}

func TestGrantProviderQuarantinesRejectedCandidate(t *testing.T) {
	for _, kind := range []string{"host", "network", "address", "route", "certificate", "certificate address", "mutated grant", "checkpoint", "ownership", "uncertain"} {
		t.Run(kind, func(t *testing.T) {
			p, store, client, grant := grantFixture(t)
			original := client.enroll
			if kind == "certificate address" {
				grant.Addresses = []string{"100.100.1.9"}
			}
			client.enroll = func(ctx context.Context) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error) {
				data, key, credentials, meta, err := original(ctx)
				switch kind {
				case "host":
					meta.Host.ID = "host-FOREIGN"
				case "network":
					meta.Network.ID = "network-FOREIGN"
				case "address":
					meta.Host.IPAddresses = []string{"192.0.2.9"}
				case "route":
					data = append(data, []byte("\ntun:\n  unsafe_routes:\n    - route: 192.0.2.0/24\n      via: 100.100.1.2\n")...)
				case "certificate":
					data = []byte("pki:\n  cert: invalid\n  ca: invalid\n")
				case "certificate address":
					meta.Host.IPAddresses = []string{"100.100.1.9"}
				case "mutated grant":
					grant.Addresses = []string{"100.100.1.9"}
					meta.Host.IPAddresses = grant.Addresses
				case "checkpoint":
					store.checkpointErr = errors.New("private checkpoint detail")
				case "ownership":
					store.valid.Store(false)
				case "uncertain":
					err = context.DeadlineExceeded
				}
				return data, key, credentials, meta, err
			}
			if current, err := p.Acquire(context.Background()); err == nil || current != nil {
				t.Fatal("rejected candidate became ready")
			}
			if len(store.saves) != 0 || store.releaseCalls != 0 {
				t.Fatal("unapproved candidate persisted or released")
			}
			if _, err := p.Acquire(context.Background()); err == nil || client.enrollCalls != 1 {
				t.Fatal("uncertain attempt retried")
			}
		})
	}
}

func TestGrantProviderFencingPrecedesCodeAndRejectsExistingState(t *testing.T) {
	for _, kind := range []string{"existing", "fence", "wrong grant network", "missing routes", "duplicate address", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			p, store, client, grant := grantFixture(t)
			ctx := context.Background()
			switch kind {
			case "existing":
				store.data = []byte("existing checkpoint")
			case "fence":
				store.beginErr = errors.New("private fence detail")
			case "wrong grant network":
				grant.NetworkID = "network-FOREIGN"
			case "missing routes":
				grant.RoutePolicy = nil
			case "duplicate address":
				grant.Addresses = append(grant.Addresses, grant.Addresses[0])
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := p.Acquire(ctx); err == nil || client.enrollCalls != 0 || store.releaseCalls != 0 || len(store.saves) != 0 {
				t.Fatal("unfenced grant submitted")
			}
		})
	}
}

func TestGrantRuntimeCompletionStopsTransportBeforeRelease(t *testing.T) {
	p, store, _, _ := grantFixture(t)
	complete := make(chan struct{})
	transport := &checkpointTransport{store: &store.testStore}
	cfg := runtime.DefaultConfig()
	cfg.RenewInterval = time.Hour
	runner, err := runtime.New(p, func(_ context.Context, data []byte) (runtime.Transport, error) {
		if len(store.saves) != 1 {
			t.Error("transport started before enrollment checkpoint")
		}
		state, _, err := decodeIdentityState(store.saves[0])
		if err != nil || !bytes.Equal(state.Config, data) {
			t.Error("transport used unapproved config")
		}
		return transport, nil
	}, func(context.Context, network.Network) ([]runtime.Session, error) { close(complete); return nil, nil }, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = runner.Run(ctx, complete); err != nil {
		t.Fatal(err)
	}
	if !transport.stopped || store.releaseCalls != 1 || len(store.saves) != 2 {
		t.Fatal("completion did not checkpoint, stop and release")
	}
}

func TestGrantOwnershipLossClosesActiveForwardWithoutRelease(t *testing.T) {
	p, store, _, _ := grantFixture(t)
	store.lost = make(chan struct{})
	n := &outageTransport{peers: make(chan net.Conn, 1)}
	limit := forward.NewLimit(1)
	address := make(chan string, 1)
	cfg := runtime.DefaultConfig()
	cfg.RenewInterval = time.Hour
	cfg.DrainTimeout = 50 * time.Millisecond
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
		t.Fatal("startup did not join")
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
		t.Fatal("session not established")
	}
	close(store.lost)
	app.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = app.Read(b[:]); err == nil {
		t.Fatal("active session remained alive")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("session timed out instead of closing")
	}
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("ownership loss released cleanly")
		}
	case <-ctx.Done():
		t.Fatal("runtime did not join")
	}
	if limit.Active() != 0 || store.releaseCalls != 0 || p.Valid() || runner.Status().IdentityValid {
		t.Fatal("lost owner leaked or became reusable")
	}
}

func TestGrantStoreBindsActualHostBeforeCodeSubmission(t *testing.T) {
	for _, kind := range []string{"foreign host", "foreign network", "uncertain binding", "ownership lost during binding"} {
		t.Run(kind, func(t *testing.T) {
			p, store, client, grant := grantFixture(t)
			switch kind {
			case "foreign host":
				grant.HostID = "host-OTHER"
			case "foreign network":
				store.expectedNetwork = "network-OTHER"
			case "uncertain binding":
				store.bindErr = context.DeadlineExceeded
			case "ownership lost during binding":
				store.revokeOnBind = true
			}
			if _, err := p.Acquire(context.Background()); err == nil || store.binds != 1 || client.enrollCalls != 0 || len(store.saves) != 0 || store.releaseCalls != 0 {
				t.Fatal("unbound or uncertain host grant submitted")
			}
			if _, err := p.Acquire(context.Background()); err == nil || store.binds != 1 || client.enrollCalls != 0 {
				t.Fatal("uncertain binding retried")
			}
		})
	}
}
