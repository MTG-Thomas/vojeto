package socks5

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type testNetwork struct {
	calls atomic.Int32
	block bool
	peers chan net.Conn
}

func (n *testNetwork) Resolve(context.Context, string) ([]netip.Addr, error) {
	panic("SOCKS must not invoke DNS")
}
func (n *testNetwork) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	n.calls.Add(1)
	if n.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	a, b := net.Pipe()
	n.peers <- b
	return a, nil
}
func startServer(t *testing.T, n *testNetwork, maximum int) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	c := Config{Listen: ln.Addr().String(), Allow: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:443")}, MaxConnections: maximum, DialTimeout: 50 * time.Millisecond, Lifetime: time.Minute}
	go func() { done <- serve(ctx, n, c, func(string, string) (net.Listener, error) { return ln, nil }) }()
	t.Cleanup(cancel)
	return ln.Addr().String(), cancel, done
}
func connectRequest(t *testing.T, addr string, destination byte) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0, 1, 192, 0, 2, destination, 1, 187})
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	return c, reply[1]
}
func TestFiniteSocksAllowlistLimitAndCancellation(t *testing.T) {
	n := &testNetwork{peers: make(chan net.Conn, 1)}
	addr, cancel, done := startServer(t, n, 1)
	denied, reply := connectRequest(t, addr, 2)
	denied.Close()
	if reply == 0 || n.calls.Load() != 0 {
		t.Fatal("unlisted destination dialed")
	}
	// The denied session must leave the slot before a new CONNECT is accepted.
	deadline := time.Now().Add(time.Second)
	var c net.Conn
	for time.Now().Before(deadline) {
		candidate, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		candidate.SetDeadline(time.Now().Add(100 * time.Millisecond))
		candidate.Write([]byte{5, 1, 0})
		var hello [2]byte
		if _, err := io.ReadFull(candidate, hello[:]); err == nil {
			c = candidate
			break
		}
		candidate.Close()
		time.Sleep(time.Millisecond)
	}
	if c == nil {
		t.Fatal("rejected session never released its slot")
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187})
	var success [10]byte
	if _, err := io.ReadFull(c, success[:]); err != nil || success[1] != 0 {
		t.Fatal("CONNECT failed", err)
	}
	peer := <-n.peers
	defer peer.Close()
	excess, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	excess.SetDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := excess.Read(b[:]); err == nil {
		t.Fatal("excess connection admitted")
	}
	excess.Close()
	if n.calls.Load() != 1 {
		t.Fatal("limit bypass")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("active SOCKS session did not join")
	}
	if _, err := peer.Read(b[:]); err == nil {
		t.Fatal("remote session not closed")
	}
}
func TestSocksDialTimeoutDoesNotLeakSlot(t *testing.T) {
	n := &testNetwork{block: true}
	addr, cancel, done := startServer(t, n, 2)
	for i := 0; i < 10; i++ {
		c, reply := connectRequest(t, addr, 1)
		c.Close()
		if reply != 4 {
			t.Fatal(reply)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked dials not joined")
	}
	if n.calls.Load() != 10 {
		t.Fatal(n.calls.Load())
	}
}
