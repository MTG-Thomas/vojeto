package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"github.com/MTG-Thomas/vojeto/internal/proxy/socks5"
	"github.com/MTG-Thomas/vojeto/internal/runtime"
)

type socksTransport struct {
	client, remote net.Conn
	closed         atomic.Bool
	dialed         chan struct{}
}

func (n *socksTransport) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	close(n.dialed)
	return n.client, nil
}
func (n *socksTransport) Resolve(context.Context, string) ([]netip.Addr, error) {
	panic("SOCKS must not resolve DNS")
}
func (n *socksTransport) Reload([]byte) error { return nil }
func (n *socksTransport) Close() error {
	n.closed.Store(true)
	n.client.Close()
	n.remote.Close()
	return nil
}

type socksProvider struct {
	lost      chan struct{}
	released  atomic.Int32
	valid     atomic.Bool
	transport *socksTransport
}

func (p *socksProvider) Acquire(context.Context) (*identity.Identity, error) {
	p.valid.Store(true)
	return &identity.Identity{Config: []byte("fixture")}, nil
}
func (p *socksProvider) Renew(_ context.Context, i *identity.Identity) (*identity.Identity, error) {
	return i, nil
}
func (p *socksProvider) Checkpoint(context.Context, *identity.Identity) error {
	if !p.valid.Load() {
		return errors.New("lost")
	}
	return nil
}
func (p *socksProvider) Release(context.Context, *identity.Identity) error {
	if !p.transport.closed.Load() || !p.valid.Load() {
		return errors.New("unsafe release")
	}
	p.released.Add(1)
	return nil
}
func (p *socksProvider) Valid() bool { return p.valid.Load() }
func (p *socksProvider) Watch(ctx context.Context, lost func()) error {
	select {
	case <-ctx.Done():
		return nil
	case <-p.lost:
		p.valid.Store(false)
		lost()
		return errors.New("lost")
	}
}
func TestFiniteSocksCLIRuntimeCompletionAndLoss(t *testing.T) {
	for _, kind := range []string{"complete", "lifetime", "loss"} {
		t.Run(kind, func(t *testing.T) {
			client, remote := net.Pipe()
			n := &socksTransport{client: client, remote: remote, dialed: make(chan struct{})}
			defer n.Close()
			p := &socksProvider{lost: make(chan struct{}), transport: n}
			policy := socks5.Config{Listen: "127.0.0.1:0", Allow: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:443")}, MaxConnections: 1, DialTimeout: time.Second, Lifetime: time.Minute}
			if kind == "lifetime" {
				policy.Lifetime = 500 * time.Millisecond
			}
			complete := make(chan struct{})
			var once sync.Once
			finish := func() { once.Do(func() { close(complete) }) }
			global := forward.NewLimit(1)
			address := make(chan string, 1)
			cfg := runtime.DefaultConfig()
			cfg.DrainTimeout = 100 * time.Millisecond
			runner, err := runtime.New(p, func(context.Context, []byte) (runtime.Transport, error) { return n, nil }, func(ctx context.Context, n network.Network) ([]runtime.Session, error) {
				server, e := openSocksSession(ctx, n, policy, global, finish)
				if e != nil {
					return nil, e
				}
				address <- server.Addr().String()
				return []runtime.Session{server}, nil
			}, cfg)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- runner.Run(ctx, complete) }()
			var addr string
			select {
			case addr = <-address:
			case <-ctx.Done():
				t.Fatal("SOCKS did not open")
			}
			app, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			app.SetDeadline(time.Now().Add(time.Second))
			app.Write([]byte{5, 1, 0})
			var greeting [2]byte
			if _, err = io.ReadFull(app, greeting[:]); err != nil {
				t.Fatal(err)
			}
			app.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187})
			var reply [10]byte
			if _, err = io.ReadFull(app, reply[:]); err != nil || reply[1] != 0 {
				t.Fatal("CONNECT failed", err)
			}
			<-n.dialed
			if kind == "loss" {
				close(p.lost)
			}
			if kind == "complete" {
				finish()
				// Explicit completion permits an established relay to finish within drain.
				wrote := make(chan error, 1)
				go func() { _, e := remote.Write([]byte("ok")); wrote <- e }()
				var payload [2]byte
				if _, err = io.ReadFull(app, payload[:]); err != nil || string(payload[:]) != "ok" {
					t.Fatal("completion interrupted active relay", err)
				}
				if err = <-wrote; err != nil {
					t.Fatal(err)
				}
				app.Close()
				remote.Close()
			}
			select {
			case err = <-done:
				if (err != nil) != (kind == "loss") {
					t.Fatal("wrong lifecycle result", err)
				}
			case <-ctx.Done():
				t.Fatal("finite runtime did not join")
			}
			if global.Active() != 0 || !n.closed.Load() {
				t.Fatal("SOCKS runtime leaked")
			}
			want := int32(1)
			if kind == "loss" {
				want = 0
			}
			if p.released.Load() != want {
				t.Fatal("wrong release behavior")
			}
		})
	}
}
