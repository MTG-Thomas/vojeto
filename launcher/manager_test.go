//go:build linux

package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/MTG-Thomas/vojeto/peer"
)

func configuration(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	u, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := u.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	u.Close()
	run := t.TempDir()
	if e := os.Chmod(run, 0700); e != nil {
		t.Fatal(e)
	}
	binary := os.Getenv("VOJETO_PEER_BINARY")
	if binary == "" {
		t.Fatal("build peer binary and set VOJETO_PEER_BINARY; use make test")
	}
	return Config{PeerBinary: binary, RunDir: run, PublicIP: netip.MustParseAddr("127.0.0.1"), BindIP: netip.MustParseAddr("127.0.0.1"), FirstPort: p, LastPort: p, MaxSessions: 1, StateDir: dir}
}
func request(t *testing.T) (StartRequest, []byte, []byte) {
	t.Helper()
	op, ok, e := peer.Keygen()
	if e != nil {
		t.Fatal(e)
	}
	tp, tk, e := peer.Keygen()
	if e != nil {
		t.Fatal(e)
	}
	id := make([]byte, 16)
	rand.Read(id)
	t.Cleanup(func() { clear(ok); clear(tk) })
	return StartRequest{ID: hex.EncodeToString(id), OperatorKey: op, TargetKey: tp, Destination: "127.0.0.1:22", Expires: time.Now().UTC().Add(20 * time.Second)}, ok, tk
}
func TestLifecycleAndRestart(t *testing.T) {
	c := configuration(t)
	m, e := Open(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	r, ok, tk := request(t)
	s, e := m.Start(r)
	if e != nil {
		t.Fatal(e)
	}
	if peer.Validate(s.Operator, ok, "operator") != nil || peer.Validate(s.Target, tk, "target") != nil {
		t.Fatal("invalid returned grants")
	}
	same, e := m.Start(r)
	if e != nil || same.Operator.ID != s.Operator.ID {
		t.Fatal("idempotent start changed session")
	}
	if _, e = Open(context.Background(), c); e == nil {
		t.Fatal("second supervisor acquired state directory")
	}
	other, _, _ := request(t)
	if _, e = m.Start(other); e != ErrCapacity {
		t.Fatalf("capacity: %v", e)
	}
	modified := r
	modified.Destination = "127.0.0.1:23"
	if _, e = m.Start(modified); e != ErrConflict {
		t.Fatalf("conflict: %v", e)
	}
	if e = m.Stop(r.ID); e != nil {
		t.Fatal(e)
	}
	if e = m.Stop(r.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Start(r); e != ErrGone {
		t.Fatal("revoked request reissued")
	}
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
	m, e = Open(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	if _, e = m.Start(r); e != ErrGone {
		t.Fatal("restart reissued session")
	}
	if _, e = m.Start(other); e != nil {
		t.Fatal("port not released")
	}
}
func TestRevokeBeforeCreate(t *testing.T) {
	m, e := Open(context.Background(), configuration(t))
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	r, _, _ := request(t)
	if e = m.Stop(r.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Start(r); e != ErrConflict {
		t.Fatal("late create escaped revocation barrier")
	}
}
func TestExpiry(t *testing.T) {
	m, e := Open(context.Background(), configuration(t))
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	r, _, _ := request(t)
	r.Expires = time.Now().UTC().Add(2 * time.Second)
	if _, e = m.Start(r); e != nil {
		t.Fatal(e)
	}
	time.Sleep(time.Until(r.Expires) + 50*time.Millisecond)
	if _, e = m.Get(r.ID); e != ErrGone {
		t.Fatal("expired role still active")
	}
	if _, e = m.Start(r); e != ErrInvalid {
		t.Fatal("expired intent replayed")
	}
}
func TestIssuedSessionCarriesEncryptedTraffic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, e := Open(ctx, configuration(t))
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	echo, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				io.Copy(c, c)
			}()
		}
	}()
	r, ok, tk := request(t)
	r.Destination = echo.Addr().String()
	s, e := m.Start(r)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 2)
	start := func(role string, g peer.Grant, k []byte) net.Addr {
		ready := make(chan net.Addr, 1)
		go func() {
			done <- peer.Run(ctx, g, k, role, peer.Options{UDPListen: "127.0.0.1:0", Listen: "127.0.0.1:0", MaxConnections: 2, DialTimeout: 5 * time.Second, OnListening: func(a net.Addr) { ready <- a }})
		}()
		select {
		case a := <-ready:
			return a
		case e := <-done:
			t.Fatal(e)
		case <-time.After(5 * time.Second):
			t.Fatal("startup timeout")
		}
		return nil
	}
	start("target", s.Target, tk)
	local := start("operator", s.Operator, ok)
	conn, e := net.Dial("tcp", local.String())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, e = io.WriteString(conn, "launcher proof"); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 14)
	if _, e = io.ReadFull(conn, buf); e != nil || string(buf) != "launcher proof" {
		t.Fatalf("echo: %v", e)
	}
	if e = m.Stop(r.ID); e != nil {
		t.Fatal(e)
	}
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("endpoint cleanup")
		}
	}
}
