package defined

import (
	"bytes"
	"context"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/definedwire"
	wirekeys "github.com/MTG-Thomas/vojeto/internal/definedwire/credentials"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"github.com/MTG-Thomas/vojeto/internal/runtime"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type testStore struct {
	data          []byte
	saves         [][]byte
	valid         atomic.Bool
	releaseCalls  int
	checkpointErr error
}

func (s *testStore) Acquire(context.Context) ([]byte, error) {
	s.valid.Store(true)
	return append([]byte(nil), s.data...), nil
}
func (s *testStore) Checkpoint(_ context.Context, data []byte) error {
	if s.checkpointErr != nil {
		return s.checkpointErr
	}
	s.saves = append(s.saves, append([]byte(nil), data...))
	return nil
}
func (s *testStore) Release(context.Context) error {
	s.valid.Store(false)
	s.releaseCalls++
	return nil
}
func (s *testStore) Watch(ctx context.Context, stop func()) error { <-ctx.Done(); return nil }
func (s *testStore) Valid() bool                                  { return s.valid.Load() }

type scriptClient struct {
	fakePooledDN
	check  func(context.Context) (bool, error)
	update func(context.Context) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error)
}

func (c scriptClient) CheckForUpdate(ctx context.Context, _ wirekeys.Credentials) (bool, error) {
	return c.check(ctx)
}
func (c scriptClient) DoUpdate(ctx context.Context, credentials wirekeys.Credentials) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error) {
	if c.update != nil {
		return c.update(ctx)
	}
	return c.fakePooledDN.DoUpdate(ctx, credentials)
}
func providerFixture(t *testing.T) (*Provider, *testStore, *scriptClient) {
	t.Helper()
	state, credentials, dn := pooledRenewalFixture(t)
	data, e := encodeIdentityState(state.HostID, state.Addresses, state.Config, credentials)
	if e != nil {
		t.Fatal(e)
	}
	store := &testStore{data: data}
	var checks int
	client := &scriptClient{fakePooledDN: dn, check: func(context.Context) (bool, error) { checks++; return checks > 1, nil }}
	provider, e := NewProvider(store, client, "network-FIXTURE")
	if e != nil {
		t.Fatal(e)
	}
	return provider, store, client
}
func TestProviderAcquisitionRenewalAndFinalCheckpoint(t *testing.T) {
	p, s, _ := providerFixture(t)
	current, e := p.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(s.saves) != 0 {
		t.Fatal("read-only authentication wrote state")
	}
	next, e := p.Renew(context.Background(), current)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(next.Config, current.Config) || len(s.saves) != 2 {
		t.Fatal("configuration rotation not checkpointed")
	}
	first, c, e := decodeIdentityState(s.saves[0])
	if e != nil || c.Counter != 18 || !bytes.Equal(first.Config, current.Config) {
		t.Fatal("credential checkpoint did not retain safe config")
	}
	second, _, e := decodeIdentityState(s.saves[1])
	if e != nil || !bytes.Equal(second.Config, next.Config) {
		t.Fatal("accepted config not durable")
	}
	if p.Checkpoint(context.Background(), next) != nil || len(s.saves) != 3 || p.Release(context.Background(), next) != nil || s.releaseCalls != 1 {
		t.Fatal("clean provider shutdown failed")
	}
}
func TestProviderRefusedUpdateRetainsRotatedCredentialsAndQuarantines(t *testing.T) {
	p, s, c := providerFixture(t)
	current, e := p.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	c.meta.Network.ID = "network-FOREIGN"
	if _, e = p.Renew(context.Background(), current); !errors.Is(e, identity.ErrUnsafeRenewal) {
		t.Fatal("refused remote rotation classified as safe")
	}
	if p.Release(context.Background(), current) == nil || p.Checkpoint(context.Background(), current) == nil {
		t.Fatal("unsafe provider became reusable")
	}
	if len(s.saves) != 1 || s.releaseCalls != 0 {
		t.Fatal("refused update lost rotation or released identity")
	}
	state, credentials, e := decodeIdentityState(s.saves[0])
	if e != nil || credentials.Counter != 18 || !bytes.Equal(state.Config, current.Config) {
		t.Fatal("rotated credentials/safe config missing")
	}
}
func TestCancelledProviderRotationIsUnsafe(t *testing.T) {
	p, _, c := providerFixture(t)
	current, e := p.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.update = func(context.Context) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error) {
		cancel()
		return nil, nil, nil, nil, ctx.Err()
	}
	if _, e = p.Renew(ctx, current); !errors.Is(e, identity.ErrUnsafeRenewal) {
		t.Fatal("uncertain rotation not quarantined", e)
	}
}
func TestProviderRejectsForeignIdentityAndLostOwnership(t *testing.T) {
	p, s, _ := providerFixture(t)
	current, e := p.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	foreign := &identity.Identity{Config: current.Config}
	if _, e = p.Renew(context.Background(), foreign); e == nil {
		t.Fatal("foreign identity accepted")
	}
	s.valid.Store(false)
	if p.Checkpoint(context.Background(), current) == nil || p.Release(context.Background(), current) == nil {
		t.Fatal("lost ownership reauthorized")
	}
}
func TestAcquisitionNeverUsesUnauthenticatedState(t *testing.T) {
	p, s, c := providerFixture(t)
	c.check = func(context.Context) (bool, error) { return false, errors.New("private provider detail") }
	if _, e := p.Acquire(context.Background()); e == nil {
		t.Fatal("unauthenticated identity accepted")
	}
	if s.releaseCalls != 0 || len(s.saves) != 0 {
		t.Fatal("failed auth cleared quarantine")
	}
}

// Run the real provider's accepted rotation through the portable transport seam.
func TestRuntimeReloadsOnlyDurableRotatedConfiguration(t *testing.T) {
	p, s, c := providerFixture(t)
	checks := 0
	c.check = func(context.Context) (bool, error) { checks++; return checks == 2, nil }
	complete := make(chan struct{})
	transport := &checkpointTransport{store: s, completed: complete}
	cfg := runtime.DefaultConfig()
	cfg.RenewInterval = 5 * time.Millisecond
	cfg.AcquireTimeout = time.Second
	cfg.CleanupTimeout = time.Second
	runner, e := runtime.New(p, func(context.Context, []byte) (runtime.Transport, error) { return transport, nil }, func(context.Context, network.Network) ([]runtime.Session, error) { return nil, nil }, cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = runner.Run(ctx, complete); e != nil {
		t.Fatal(e)
	}
	if !transport.reloaded || len(s.saves) != 3 || s.releaseCalls != 1 || !transport.stopped {
		t.Fatal("rotation did not reload/checkpoint/release correctly")
	}
}

type checkpointTransport struct {
	store             *testStore
	completed         chan struct{}
	reloaded, stopped bool
}

func (n *checkpointTransport) Resolve(context.Context, string) ([]netip.Addr, error) {
	return nil, errors.New("unused")
}
func (n *checkpointTransport) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("unused")
}
func (n *checkpointTransport) Reload(data []byte) error {
	if len(n.store.saves) != 2 {
		return errors.New("reload preceded durable checkpoints")
	}
	saved, _, e := decodeIdentityState(n.store.saves[1])
	if e != nil || !bytes.Equal(saved.Config, data) {
		return errors.New("reload differs from restart checkpoint")
	}
	n.reloaded = true
	close(n.completed)
	return nil
}
func (n *checkpointTransport) Close() error {
	n.stopped = true
	if n.store.releaseCalls != 0 {
		return errors.New("release preceded transport stop")
	}
	return nil
}
