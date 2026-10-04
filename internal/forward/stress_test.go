package forward

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

type connectedNetwork struct {
	calls atomic.Int32
	peers chan net.Conn
}

func (n *connectedNetwork) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}
func (n *connectedNetwork) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	a, b := net.Pipe()
	n.calls.Add(1)
	n.peers <- b
	return a, nil
}
func waitActive(t *testing.T, l *Listener, want int) {
	t.Helper()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		if l.Active() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active=%d want=%d", l.Active(), want)
}
func TestGlobalAndPerForwardAdmission(t *testing.T) {
	n := &connectedNetwork{peers: make(chan net.Conn, 2)}
	global := NewLimit(2)
	var listeners []*Listener
	for _, name := range []string{"one", "two", "three"} {
		l, err := Open(context.Background(), n, Config{name, "127.0.0.1:0", "192.0.2.1:443", 1, time.Second}, global)
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, l)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()
			l.Drain(ctx)
		}()
	}
	c1, _ := net.Dial("tcp", listeners[0].Addr().String())
	defer c1.Close()
	p1 := <-n.peers
	defer p1.Close()
	reject := func(l *Listener) {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err := c.Read(b[:]); err == nil {
			t.Fatal("over-limit connection admitted")
		}
	}
	reject(listeners[0])
	c2, _ := net.Dial("tcp", listeners[1].Addr().String())
	defer c2.Close()
	p2 := <-n.peers
	defer p2.Close()
	reject(listeners[2])
	if n.calls.Load() != 2 {
		t.Fatal("rejected sessions reached overlay")
	}
}
func TestFiveHundredConnectionsDrainWithoutDescriptorGrowth(t *testing.T) {
	beforeFD, _ := os.ReadDir("/proc/self/fd")
	beforeG := runtime.NumGoroutine()
	n := &connectedNetwork{peers: make(chan net.Conn, 500)}
	global := NewLimit(500)
	l, err := Open(context.Background(), n, Config{"load", "127.0.0.1:0", "192.0.2.1:443", 500, time.Second}, global)
	if err != nil {
		t.Fatal(err)
	}
	var clients, peers []net.Conn
	defer func() {
		for _, c := range clients {
			c.Close()
		}
		for _, c := range peers {
			c.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		l.Drain(ctx)
	}()
	for i := 0; i < 500; i++ {
		c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		select {
		case p := <-n.peers:
			peers = append(peers, p)
		case <-time.After(time.Second):
			t.Fatal("overlay dial not established")
		}
	}
	waitActive(t, l, 500)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	l.Drain(ctx)
	if global.Active() != 0 || l.Active() != 0 {
		t.Fatal("drained sessions retained admission slots")
	}
	for _, c := range clients {
		c.Close()
	}
	for _, c := range peers {
		c.Close()
	}
	end := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > beforeG+2 && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	if runtime.NumGoroutine() > beforeG+2 {
		t.Fatal("relay goroutines survived drain")
	}
	if len(beforeFD) > 0 {
		afterFD, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		if len(afterFD) > len(beforeFD) {
			t.Fatalf("FD growth: %d -> %d", len(beforeFD), len(afterFD))
		}
	}
}
