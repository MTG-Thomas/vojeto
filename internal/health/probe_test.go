package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

type pipeNetwork struct{ serve func(net.Conn) }

func (n pipeNetwork) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}
func (n pipeNetwork) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	a, b := net.Pipe()
	go func() { defer b.Close(); n.serve(b) }()
	return a, nil
}
func TestTLSHostnameAndTrust(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	defer fixture.Close()
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	for _, protocol := range []string{"tls", "postgres-tls"} {
		for _, name := range []string{"example.com", "wrong.example"} {
			done := make(chan struct{})
			n := pipeNetwork{serve: func(c net.Conn) {
				defer close(done)
				if protocol == "postgres-tls" {
					var request [8]byte
					if _, err := io.ReadFull(c, request[:]); err != nil {
						return
					}
					if binary.BigEndian.Uint32(request[4:]) != 80877103 {
						t.Error("incorrect SSL request")
					}
					c.Write([]byte{'S'})
				}
				s := tls.Server(c, fixture.TLS)
				s.Handshake()
			}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := (Probe{Target: "database.example:5432", Protocol: protocol, ServerName: name, RootCAs: roots}).Check(ctx, n)
			cancel()
			<-done
			if (err == nil) != (name == "example.com") {
				t.Fatalf("%s %s: %v", protocol, name, err)
			}
		}
	}
}
func TestPostgresRejectsPlaintextAndCancelsBlockedResponse(t *testing.T) {
	for _, block := range []bool{false, true} {
		done := make(chan struct{})
		n := pipeNetwork{serve: func(c net.Conn) {
			defer close(done)
			var b [8]byte
			io.ReadFull(c, b[:])
			if !block {
				c.Write([]byte{'N'})
			}
			io.Copy(io.Discard, c)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		err := (Probe{Target: "192.0.2.1:5432", Protocol: "postgres-tls", ServerName: "database.example"}).Check(ctx, n)
		cancel()
		<-done
		if err == nil {
			t.Fatal("unsafe TLS probe succeeded")
		}
	}
}
