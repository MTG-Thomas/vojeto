package azure

import (
	"context"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/definedwire"
	wirekeys "github.com/MTG-Thomas/vojeto/internal/definedwire/credentials"
	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"github.com/MTG-Thomas/vojeto/internal/providers/defined"
	"github.com/MTG-Thomas/vojeto/internal/runtime"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type unchangedClient struct{}

func (unchangedClient) CheckForUpdate(context.Context, wirekeys.Credentials) (bool, error) {
	return false, nil
}
func (unchangedClient) DoUpdate(context.Context, wirekeys.Credentials) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error) {
	return nil, nil, nil, nil, errors.New("unexpected update")
}

type pipeTransport struct {
	mu     sync.Mutex
	peer   chan net.Conn
	local  net.Conn
	closed bool
}

func (n *pipeTransport) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}
func (n *pipeTransport) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || ctx.Err() != nil {
		return nil, errors.New("stopped")
	}
	a, b := net.Pipe()
	n.local = a
	n.peer <- b
	return a, nil
}
func (n *pipeTransport) Reload([]byte) error { return nil }
func (n *pipeTransport) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	if n.local != nil {
		n.local.Close()
	}
	return nil
}

// Cross-package proof using the real Blob lease/store and Defined provider adapters.
// All requests remain within an in-process fake Storage boundary.
func TestLeasedRuntimeCleanReuseAndActiveOwnershipLoss(t *testing.T) {
	const owner = "example-worker"
	data := fixtureState(t, "host-FIRST", 18)
	var mu sync.Mutex
	marker := "available"
	leaseID := ""
	pool := poolFixture(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Header.Get("x-ms-lease-action") {
		case "acquire":
			if leaseID != "" {
				w.Header().Set("x-ms-error-code", "LeaseAlreadyPresent")
				w.WriteHeader(409)
				return
			}
			leaseID = r.Header.Get("x-ms-proposed-lease-id")
			w.Header().Set("x-ms-lease-id", leaseID)
			w.WriteHeader(201)
			return
		case "release":
			if r.Header.Get("x-ms-lease-id") != leaseID {
				w.WriteHeader(412)
				return
			}
			leaseID = ""
			w.WriteHeader(200)
			return
		case "renew":
			w.Header().Set("x-ms-lease-id", leaseID)
			w.WriteHeader(200)
			return
		}
		if r.Header.Get("x-ms-lease-id") != leaseID || leaseID == "" {
			w.WriteHeader(412)
			return
		}
		if r.URL.RawQuery == "comp=metadata" {
			marker = r.Header.Get("x-ms-meta-state")
			w.WriteHeader(200)
			return
		}
		if r.Method == "GET" {
			w.Header().Set("x-ms-meta-owner", owner)
			w.Header().Set("x-ms-meta-state", marker)
			w.Write(data)
			return
		}
		data, _ = io.ReadAll(r.Body)
		marker = r.Header.Get("x-ms-meta-state")
		w.WriteHeader(201)
	}, owner, []string{"host-FIRST"})
	start := func(claimant string) (*Store, *runtime.Runner, chan struct{}, chan error, chan string, *pipeTransport, *forward.Limit) {
		store, e := NewStore(pool, claimant)
		if e != nil {
			t.Fatal(e)
		}
		provider, e := defined.NewProvider(store, unchangedClient{}, "network-FIXTURE")
		if e != nil {
			t.Fatal(e)
		}
		n := &pipeTransport{peer: make(chan net.Conn, 1)}
		complete := make(chan struct{})
		done := make(chan error, 1)
		address := make(chan string, 1)
		limit := forward.NewLimit(1)
		cfg := runtime.DefaultConfig()
		cfg.DrainTimeout = 20 * time.Millisecond
		cfg.CleanupTimeout = time.Second
		r, e := runtime.New(provider, func(context.Context, []byte) (runtime.Transport, error) { return n, nil }, func(ctx context.Context, n network.Network) ([]runtime.Session, error) {
			l, e := forward.Open(ctx, n, forward.Config{Name: "db", Listen: "127.0.0.1:0", Target: "192.0.2.1:443", MaxConnections: 1, DialTimeout: time.Second}, limit)
			if e != nil {
				return nil, e
			}
			address <- l.Addr().String()
			return []runtime.Session{l}, nil
		}, cfg)
		if e != nil {
			t.Fatal(e)
		}
		go func() { done <- r.Run(context.Background(), complete) }()
		return store, r, complete, done, address, n, limit
	}
	wait := func(done chan error) error {
		select {
		case e := <-done:
			return e
		case <-time.After(2 * time.Second):
			t.Fatal("leased runtime leaked")
			return nil
		}
	}
	_, _, complete, done, address, _, _ := start(owner + "--first")
	select {
	case <-address:
	case <-time.After(time.Second):
		t.Fatal("first startup failed")
	}
	close(complete)
	if e := wait(done); e != nil {
		t.Fatal(e)
	}
	mu.Lock()
	clean := marker == "available" && leaseID == ""
	mu.Unlock()
	if !clean {
		t.Fatal("clean completion did not release reusable slot")
	}
	store, r, _, done, address, n, limit := start(owner + "--second")
	var addr string
	select {
	case addr = <-address:
	case <-time.After(time.Second):
		t.Fatal("restart did not reuse identity")
	}
	app, e := net.DialTimeout("tcp", addr, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	var peer net.Conn
	select {
	case peer = <-n.peer:
	case <-time.After(time.Second):
		t.Fatal("overlay session missing")
	}
	defer peer.Close()
	// Expire the client's conservative observation while an actual TCP session exists.
	lease, _ := store.owned()
	lease.mu.Lock()
	lease.validUntil = time.Now().Add(-time.Second)
	lease.mu.Unlock()
	if r.Status().IdentityValid {
		t.Fatal("stale ownership reports valid")
	}
	app.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, e = app.Read(b[:]); e == nil {
		t.Fatal("stale ownership left session alive")
	}
	if e = wait(done); e == nil || limit.Active() != 0 {
		t.Fatal("ownership loss was clean or leaked a session", e)
	}
	mu.Lock()
	quarantined := marker == "active"
	leaseID = ""
	mu.Unlock()
	if !quarantined {
		t.Fatal("unclean shutdown cleared quarantine")
	}
	// Even simulated server expiry must not make the prior active host reusable.
	if _, _, e := pool.takeAvailable(context.Background(), owner+"--third"); !errors.Is(e, errIdentityQuarantined) {
		t.Fatal("lost identity was reused", e)
	}
}
