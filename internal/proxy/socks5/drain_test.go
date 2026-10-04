package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/forward"
)

func finiteConfig() Config {
	return Config{Listen: "127.0.0.1:0", Allow: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:443")}, MaxConnections: 2, DialTimeout: time.Second, Lifetime: time.Minute}
}
func awaitActive(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for s.Active() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("session never active")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestSharedGlobalLimit(t *testing.T) {
	n := &testNetwork{peers: make(chan net.Conn, 1)}
	global := forward.NewLimit(1)
	release, ok := global.Acquire()
	if !ok {
		t.Fatal("missing global slot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := Open(ctx, n, finiteConfig(), global)
	if err != nil {
		t.Fatal(err)
	}
	excess, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	excess.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = excess.Read(b[:]); err == nil {
		t.Fatal("global ceiling bypassed")
	}
	excess.Close()
	if n.calls.Load() != 0 {
		t.Fatal("globally rejected connection dialed")
	}
	release()
	release() // reservations are idempotently released
	app, reply := connectRequest(t, s.Addr().String(), 1)
	if reply != 0 {
		t.Fatal(reply)
	}
	peer := <-n.peers
	peer.Close()
	app.Close()
	bound, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = s.Drain(bound); err != nil {
		t.Fatal(err)
	}
	if global.Active() != 0 || s.Active() != 0 {
		t.Fatal("slot leaked")
	}
}
func TestStopAdmissionDrainsExistingSession(t *testing.T) {
	n := &testNetwork{peers: make(chan net.Conn, 1)}
	global := forward.NewLimit(2)
	s, err := Open(context.Background(), n, finiteConfig(), global)
	if err != nil {
		t.Fatal(err)
	}
	app, reply := connectRequest(t, s.Addr().String(), 1)
	if reply != 0 {
		t.Fatal(reply)
	}
	defer app.Close()
	peer := <-n.peers
	defer peer.Close()
	s.StopAccepting()
	<-s.Done()
	if newcomer, err := net.DialTimeout("tcp", s.Addr().String(), time.Second); err == nil {
		newcomer.Close()
		t.Fatal("new session admitted")
	}
	wrote := make(chan error, 1)
	go func() { _, e := peer.Write([]byte("still active")); wrote <- e }()
	var data [12]byte
	if _, err = io.ReadFull(app, data[:]); err != nil || string(data[:]) != "still active" {
		t.Fatal("drain interrupted existing session", err)
	}
	if err = <-wrote; err != nil {
		t.Fatal(err)
	}
	peer.Close()
	app.Close()
	bound, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = s.Drain(bound); err != nil {
		t.Fatal(err)
	}
	if global.Active() != 0 || s.Active() != 0 {
		t.Fatal("active relay leaked")
	}
}
func TestDrainBoundClosesPendingHandshakeAndDial(t *testing.T) {
	for _, kind := range []string{"handshake", "dial"} {
		t.Run(kind, func(t *testing.T) {
			n := &testNetwork{block: true}
			global := forward.NewLimit(1)
			cfg := finiteConfig()
			cfg.DialTimeout = time.Minute
			s, err := Open(context.Background(), n, cfg, global)
			if err != nil {
				t.Fatal(err)
			}
			app, err := net.Dial("tcp", s.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			if kind == "dial" {
				app.SetDeadline(time.Now().Add(time.Second))
				app.Write([]byte{5, 1, 0})
				var hello [2]byte
				if _, err = io.ReadFull(app, hello[:]); err != nil {
					t.Fatal(err)
				}
				app.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187})
				deadline := time.Now().Add(time.Second)
				for n.calls.Load() == 0 {
					if time.Now().After(deadline) {
						t.Fatal("dial not started")
					}
					time.Sleep(time.Millisecond)
				}
			}
			awaitActive(t, s)
			bound, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err = s.Drain(bound); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("drain did not enforce bound", err)
			}
			if global.Active() != 0 || s.Active() != 0 {
				t.Fatal("pending work leaked")
			}
		})
	}
}
func TestLifetimeClosesActiveSessions(t *testing.T) {
	n := &testNetwork{peers: make(chan net.Conn, 1)}
	global := forward.NewLimit(1)
	cfg := finiteConfig()
	cfg.Lifetime = 250 * time.Millisecond
	s, err := Open(context.Background(), n, cfg, global)
	if err != nil {
		t.Fatal(err)
	}
	app, reply := connectRequest(t, s.Addr().String(), 1)
	if reply != 0 {
		t.Fatal(reply)
	}
	defer app.Close()
	peer := <-n.peers
	defer peer.Close()
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("finite listener did not expire")
	}
	bound, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = s.Drain(bound); err != nil {
		t.Fatal(err)
	}
	if global.Active() != 0 || s.Active() != 0 {
		t.Fatal("finite session leaked")
	}
	var b [1]byte
	if _, err = peer.Read(b[:]); err == nil {
		t.Fatal("remote remained open")
	}
}
