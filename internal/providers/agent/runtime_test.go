//go:build linux

package agent

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"github.com/MTG-Thomas/vojeto/internal/runtime"
)

// Defined validation has its own provider tests. This adapter exercises real
// Unix RPC ownership and runtime ordering without an external enrollment API.
type runtimeProvider struct{ *Client }

func (p runtimeProvider) Acquire(ctx context.Context) (*identity.Identity, error) {
	if _, err := p.Client.Acquire(ctx); err != nil {
		return nil, err
	}
	return &identity.Identity{Config: []byte("fixture")}, nil
}
func (p runtimeProvider) Renew(_ context.Context, i *identity.Identity) (*identity.Identity, error) {
	return i, nil
}
func (p runtimeProvider) Checkpoint(ctx context.Context, _ *identity.Identity) error {
	return p.Client.Checkpoint(ctx, []byte("approved fixture"))
}
func (p runtimeProvider) Release(ctx context.Context, _ *identity.Identity) error {
	return p.Client.Release(ctx)
}

type pipeTransport struct {
	client, remote net.Conn
	closed         atomic.Bool
}

func (n *pipeTransport) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return n.client, nil
}
func (n *pipeTransport) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}
func (n *pipeTransport) Reload([]byte) error { return nil }
func (n *pipeTransport) Close() error {
	n.closed.Store(true)
	n.client.Close()
	n.remote.Close()
	return nil
}
func TestRuntimeAgentLossClosesActiveForwardWithoutRelease(t *testing.T) {
	var lose atomic.Bool
	var releases atomic.Int32
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/renew") && lose.Load() {
			w.WriteHeader(409)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/release") {
			releases.Add(1)
		}
		writeReply(w, 300)
	})
	client, remote := net.Pipe()
	transport := &pipeTransport{client: client, remote: remote}
	defer transport.Close()
	limits := forward.NewLimit(1)
	listener := make(chan *forward.Listener, 1)
	cfg := runtime.DefaultConfig()
	cfg.DrainTimeout = 200 * time.Millisecond
	runner, err := runtime.New(runtimeProvider{c}, func(context.Context, []byte) (runtime.Transport, error) { return transport, nil }, func(ctx context.Context, n network.Network) ([]runtime.Session, error) {
		l, e := forward.Open(ctx, n, forward.Config{Name: "fixture", Listen: "127.0.0.1:0", Target: "192.0.2.1:5432", MaxConnections: 1, DialTimeout: time.Second}, limits)
		if e == nil {
			listener <- l
		}
		return []runtime.Session{l}, e
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx, nil) }()
	var l *forward.Listener
	select {
	case l = <-listener:
	case <-ctx.Done():
		t.Fatal("startup failed")
	}
	app, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	for limits.Active() != 1 {
		select {
		case <-ctx.Done():
			t.Fatal("session not active")
		case <-time.After(time.Millisecond):
		}
	}
	lose.Store(true)
	app.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = app.Read(b[:]); err == nil {
		t.Fatal("lost connection still open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("connection timed out instead of closing")
	}
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("ownership loss reported clean")
		}
	case <-ctx.Done():
		t.Fatal("runtime did not join")
	}
	if limits.Active() != 0 || releases.Load() != 0 || !transport.closed.Load() || runner.Status().IdentityValid {
		t.Fatal("lost owner leaked or released")
	}
}
func TestRuntimeCompletionStopsTransportBeforeAgentRelease(t *testing.T) {
	client, remote := net.Pipe()
	transport := &pipeTransport{client: client, remote: remote}
	defer transport.Close()
	var released atomic.Bool
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/release") {
			if !transport.closed.Load() {
				t.Error("release preceded transport stop")
			}
			released.Store(true)
		}
		writeReply(w, 1000)
	})
	started := make(chan struct{})
	complete := make(chan struct{})
	runner, err := runtime.New(runtimeProvider{c}, func(context.Context, []byte) (runtime.Transport, error) { return transport, nil }, func(context.Context, network.Network) ([]runtime.Session, error) { close(started); return nil, nil }, runtime.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx, complete) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("not started")
	}
	close(complete)
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("completion did not join")
	}
	if !released.Load() || c.Valid() {
		t.Fatal("clean ownership not released")
	}
}
