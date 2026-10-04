package forward

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func pair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	c, e := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if e != nil {
		t.Fatal(e)
	}
	s, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	return c, s
}
func TestRelayHalfCloseBothDirections(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		app, a := pair(t)
		b, upstream := pair(t)
		if reverse {
			app, upstream = upstream, app
		}
		done := make(chan struct{})
		go func() { Relay(context.Background(), a, b); close(done) }()
		app.SetDeadline(time.Now().Add(time.Second))
		upstream.SetDeadline(time.Now().Add(time.Second))
		app.Write([]byte("request"))
		app.CloseWrite()
		got, e := io.ReadAll(upstream)
		if e != nil || string(got) != "request" {
			t.Fatalf("half close lost request: %v", e)
		}
		upstream.Write([]byte("response"))
		upstream.CloseWrite()
		got, e = io.ReadAll(app)
		if e != nil || string(got) != "response" {
			t.Fatalf("half close lost response: %v", e)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("relay leaked")
		}
		app.Close()
		upstream.Close()
	}
}

type stalledNetwork struct{}

func (stalledNetwork) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}
func (stalledNetwork) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestLimitsDialTimeoutAndDrain(t *testing.T) {
	global := NewLimit(1)
	l, e := Open(context.Background(), stalledNetwork{}, Config{"db", "127.0.0.1:0", "db.example:5432", 1, 100 * time.Millisecond}, global)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 10; i++ {
		c, e := net.Dial("tcp", l.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, e = c.Read(b[:]); e == nil {
			t.Fatal("failed dial stayed open")
		}
		c.Close()
	}
	c, _ := net.Dial("tcp", l.Addr().String())
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	l.Drain(ctx)
	if global.Active() != 0 || l.Active() != 0 {
		t.Fatal("sessions leaked")
	}
}
func TestRejectPublicBind(t *testing.T) {
	if _, e := Open(context.Background(), stalledNetwork{}, Config{"db", "0.0.0.0:0", "db:5432", 1, time.Second}, NewLimit(1)); e == nil {
		t.Fatal("public bind accepted")
	}
}
func TestGlobalAndLocalLimits(t *testing.T) {
	l := NewLimit(1)
	if !l.take() || l.take() {
		t.Fatal("limit exceeded")
	}
	l.release()
	if !l.take() {
		t.Fatal("capacity leaked")
	}
	l.release()
}

// Port of the prototype's real-time pooled-connection regression.
func TestFiniteLifetimeBeyondSixtySeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("real-time regression")
	}
	app, a := net.Pipe()
	b, upstream := net.Pipe()
	defer app.Close()
	defer upstream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 67*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { Relay(ctx, a, b); close(done) }()
	timer := time.NewTimer(61 * time.Second)
	defer timer.Stop()
	<-timer.C
	go upstream.Write([]byte("alive"))
	app.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 5)
	if _, e := io.ReadFull(app, got); e != nil || string(got) != "alive" {
		t.Fatal("connection lost after sixty seconds", e)
	}
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("finite relay leaked")
	}
}
