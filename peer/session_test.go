package peer

import (
	"context"
	"github.com/MTG-Thomas/vojeto/internal/network/netstack"
	"go.yaml.in/yaml/v3"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func udpAddress(t *testing.T) string {
	t.Helper()
	c, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := c.LocalAddr().String()
	c.Close()
	return a
}
func keys(t *testing.T) ([]byte, []byte) {
	t.Helper()
	p, k, e := Keygen()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(k) })
	return p, k
}
func TestGrantBinding(t *testing.T) {
	op, ok := keys(t)
	tp, tk := keys(t)
	r := Request{OperatorKey: op, TargetKey: tp, Target: "127.0.0.1:22", TargetEndpoint: "127.0.0.1:4242", Lifetime: time.Minute}
	g, e := Issue(r)
	if e != nil {
		t.Fatal(e)
	}
	if Validate(g["operator"], ok, "operator") != nil || Validate(g["target"], tk, "target") != nil {
		t.Fatal("valid grants rejected")
	}
	for name, change := range map[string]func(*Grant){"destination": func(g *Grant) { g.Target = "127.0.0.1:23" }, "endpoint": func(g *Grant) { g.TargetEndpoint = "127.0.0.1:4243" }, "expiry": func(g *Grant) { g.Expires = g.Expires.Add(time.Minute) }, "role": func(g *Grant) { g.Role = "target" }, "certificate": func(g *Grant) { g.Certificate = g.Certificate + "junk" }} {
		t.Run(name, func(t *testing.T) {
			bad := g["operator"]
			change(&bad)
			if Validate(bad, ok, "operator") == nil {
				t.Fatal("tampered grant accepted")
			}
		})
	}
	foreign, e := Issue(r)
	if e != nil {
		t.Fatal(e)
	}
	swapped := g["operator"]
	swapped.CA = foreign["operator"].CA
	if Validate(swapped, ok, "operator") == nil {
		t.Fatal("foreign CA accepted")
	}
	swapped = g["operator"]
	swapped.Certificate = foreign["operator"].Certificate
	if Validate(swapped, ok, "operator") == nil {
		t.Fatal("cross-session certificate accepted")
	}
	if Validate(g["operator"], tk, "operator") == nil || Validate(g["operator"], ok, "target") == nil {
		t.Fatal("foreign key/role accepted")
	}
	for _, dest := range []string{"0.0.0.0:22", "224.0.0.1:22", "localhost:22", "127.0.0.1:0", "[::1]:22"} {
		r.Target = dest
		if _, e := Issue(r); e == nil {
			t.Fatalf("accepted %s", dest)
		}
	}
	r.Target = "127.0.0.1:22"
	r.Lifetime = MaxLifetime + time.Second
	if _, e := Issue(r); e == nil {
		t.Fatal("unbounded lifetime")
	}
	r.Lifetime = time.Minute
	r.OperatorKey = make([]byte, 32)
	if _, e := Issue(r); e == nil {
		t.Fatal("low order key accepted")
	}
}

func TestEncryptedSession(t *testing.T) {
	for _, withLH := range []bool{false, true} {
		name := "static"
		if withLH {
			name = "lighthouse"
		}
		t.Run(name, func(t *testing.T) {
			echo, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer echo.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
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
			op, ok := keys(t)
			tp, tk := keys(t)
			targetUDP := udpAddress(t)
			req := Request{OperatorKey: op, TargetKey: tp, Target: echo.Addr().String(), TargetEndpoint: targetUDP, Lifetime: 30 * time.Second}
			var lk []byte
			if withLH {
				req.LighthouseKey, lk = keys(t)
				req.LighthouseEndpoint = udpAddress(t)
				req.TargetEndpoint = ""
			}
			grants, e := Issue(req)
			if e != nil {
				t.Fatal(e)
			}
			results := make(chan error, 3)
			start := func(role string, k []byte, udp string) net.Addr {
				ready := make(chan net.Addr, 1)
				go func() {
					results <- Run(ctx, grants[role], k, role, Options{UDPListen: udp, Listen: "127.0.0.1:0", MaxConnections: 4, DialTimeout: 10 * time.Second, OnListening: func(a net.Addr) { ready <- a }})
				}()
				select {
				case a := <-ready:
					return a
				case e := <-results:
					t.Fatalf("%s startup: %v", role, e)
				case <-time.After(10 * time.Second):
					t.Fatalf("%s startup timed out", role)
				}
				return nil
			}
			count := 2
			if withLH {
				start("lighthouse", lk, req.LighthouseEndpoint)
				count++
			}
			start("target", tk, targetUDP)
			local := start("operator", ok, "127.0.0.1:0")
			c, e := net.DialTimeout("tcp4", local.String(), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(15 * time.Second))
			payload := strings.Repeat("encrypted peer payload\n", 1500)
			if _, e = io.WriteString(c, payload); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, len(payload))
			if _, e = io.ReadFull(c, b); e != nil {
				t.Fatal(e)
			}
			if string(b) != payload {
				t.Fatal("payload mismatch")
			}
			cancel()
			for i := 0; i < count; i++ {
				select {
				case e := <-results:
					if e != nil {
						t.Fatal(e)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("session cleanup timed out")
				}
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			if _, e = c.Read(make([]byte, 1)); e == nil {
				t.Fatal("active connection survived revocation")
			}
			if c, e = net.DialTimeout("tcp4", local.String(), time.Second); e == nil {
				c.Close()
				t.Fatal("listener survived revocation")
			}
		})
	}
}

func TestExpiry(t *testing.T) {
	op, ok := keys(t)
	tp, _ := keys(t)
	g, e := Issue(Request{OperatorKey: op, TargetKey: tp, Target: "127.0.0.1:22", TargetEndpoint: "127.0.0.1:4242", Lifetime: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	if e = Run(context.Background(), g["operator"], ok, "operator", Options{UDPListen: "127.0.0.1:0", Listen: "127.0.0.1:0", MaxConnections: 1, DialTimeout: time.Second}); e != nil {
		t.Fatal(e)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("expiry cleanup late")
	}
	if Validate(g["operator"], ok, "operator") == nil {
		t.Fatal("expired grant accepted")
	}
}

// Simulate unreachable direct peers by rejecting their discovered underlay IP.
// The lighthouse uses another loopback address, so only the relay can carry TCP.
func TestEncryptedRelayAndFirewall(t *testing.T) {
	echo, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	op, ok := keys(t)
	tp, tk := keys(t)
	lp, lk := keys(t)
	u, e := net.ListenPacket("udp4", "127.0.0.2:0")
	if e != nil {
		t.Fatal(e)
	}
	lhAddr := u.LocalAddr().String()
	u.Close()
	g, e := Issue(Request{OperatorKey: op, TargetKey: tp, LighthouseKey: lp, Target: echo.Addr().String(), LighthouseEndpoint: lhAddr, Lifetime: 30 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	open := func(role string, key []byte, udp string) *netstack.Network {
		b, e := configuration(g[role], key, netip.MustParseAddrPort(udp))
		if e != nil {
			t.Fatal(e)
		}
		defer clear(b)
		var cfg map[string]any
		if e = yaml.Unmarshal(b, &cfg); e != nil {
			t.Fatal(e)
		}
		if role != "lighthouse" {
			cfg["lighthouse"].(map[string]any)["remote_allow_list"] = map[string]bool{"127.0.0.1/32": false, "0.0.0.0/0": true}
		}
		b, e = yaml.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		defer clear(b)
		n, e := netstack.Open(b)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { n.Close() })
		return n
	}
	open("lighthouse", lk, lhAddr)
	target := open("target", tk, "127.0.0.1:0")
	operator := open("operator", ok, "127.0.0.1:0")
	ln, e := target.ListenTCP(netip.AddrPortFrom(address("target"), servicePort))
	if e != nil {
		t.Fatal(e)
	}
	done := serveGateway(ctx, ln, echo.Addr().String(), 2, time.Second)
	dialCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	c, e := operator.DialContext(dialCtx, "tcp", netip.AddrPortFrom(address("target"), servicePort).String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e = io.WriteString(c, "relay proof"); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 11)
	if _, e = io.ReadFull(c, b); e != nil {
		t.Fatal(e)
	}
	if string(b) != "relay proof" {
		t.Fatal("relay payload mismatch")
	}
	// A real second listener cannot be reached through the production firewall.
	denied, e := target.ListenTCP(netip.AddrPortFrom(address("target"), servicePort+1))
	if e != nil {
		t.Fatal(e)
	}
	defer denied.Close()
	blockedCtx, stopBlocked := context.WithTimeout(ctx, 300*time.Millisecond)
	defer stopBlocked()
	bad, e := operator.DialContext(blockedCtx, "tcp", netip.AddrPortFrom(address("target"), servicePort+1).String())
	if e == nil {
		bad.Close()
		t.Fatal("unsigned port accepted")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway cleanup")
	}
}

func TestAbsoluteDeadline(t *testing.T) {
	op, _, _ := Keygen()
	tp, _, _ := Keygen()
	deadline := time.Now().UTC().Add(20 * time.Second)
	request := Request{OperatorKey: op, TargetKey: tp, Target: "127.0.0.1:22", TargetEndpoint: "127.0.0.1:4242", Deadline: deadline}
	grants, err := Issue(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		if !grant.Expires.Equal(deadline.Truncate(time.Second)) {
			t.Fatal("grant extended or replaced absolute deadline")
		}
	}
	request.Lifetime = time.Minute
	if _, err = Issue(request); err == nil {
		t.Fatal("accepted conflicting deadline and lifetime")
	}
	request.Lifetime = 0
	request.Deadline = time.Now().Add(-time.Second)
	if _, err = Issue(request); err == nil {
		t.Fatal("accepted expired deadline")
	}
	request.Deadline = time.Now().Add(MaxLifetime + time.Minute)
	if _, err = Issue(request); err == nil {
		t.Fatal("accepted excessive deadline")
	}
}
