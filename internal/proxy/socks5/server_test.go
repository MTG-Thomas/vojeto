package socks5

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRejectUnsafePolicy(t *testing.T) {
	base := Config{Listen: "127.0.0.1:0", Allow: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:443")}, MaxConnections: 1, DialTimeout: time.Second, Lifetime: time.Second}
	for _, change := range []string{"public", "empty", "unbounded", "infinite"} {
		c := base
		switch change {
		case "public":
			c.Listen = "0.0.0.0:1080"
		case "empty":
			c.Allow = nil
		case "unbounded":
			c.MaxConnections = 0
		case "infinite":
			c.Lifetime = 0
		}
		if Serve(context.Background(), nil, c) == nil {
			t.Fatal("unsafe policy accepted", change)
		}
	}
}
func TestConnectOnly(t *testing.T) {
	for _, command := range []byte{1, 2, 3} {
		a, b := net.Pipe()
		done := make(chan error, 1)
		go func() { _, e := request(b); b.Close(); done <- e }()
		a.SetDeadline(time.Now().Add(time.Second))
		a.Write([]byte{5, 1, 0})
		reply := make([]byte, 2)
		io.ReadFull(a, reply)
		a.Write([]byte{5, command, 0, 1})
		if command == 1 {
			a.Write([]byte{192, 0, 2, 1, 1, 187})
		}
		e := <-done
		if (e == nil) != (command == 1) {
			t.Fatal("invalid command handling", command, e)
		}
		a.Close()
	}
}
