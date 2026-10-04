package netstack

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/MTG-Thomas/vojeto/internal/forward"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/service"
	"go.yaml.in/yaml/v3"
	"log/slog"
)

func TestUserspaceOverlayWithoutKernelTunnel(t *testing.T) {
	// Private disposable certificates expire in minutes. No real DN identity.
	ca, _, key, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute), nil, nil, nil)
	caPEM, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	socket.Close()
	configFor := func(ip string, peer bool) []byte {
		_, _, private, crt := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, key, ip, time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(ip), 24)}, nil, nil)
		listenPort := 0
		hosts := []string{"192.0.2.1"}
		if peer {
			listenPort = port
			hosts = nil
		}
		cfg := map[string]any{"pki": map[string]any{"ca": string(caPEM), "cert": string(crt), "key": string(private)}, "listen": map[string]any{"host": "127.0.0.1", "port": listenPort}, "lighthouse": map[string]any{"am_lighthouse": peer, "hosts": hosts}, "static_host_map": map[string]any{"192.0.2.1": []string{fmt.Sprintf("127.0.0.1:%d", port)}}, "firewall": map[string]any{"outbound": []map[string]any{{"port": 19001, "proto": "tcp", "host": "any"}}, "inbound": []map[string]any{{"port": 19001, "proto": "tcp", "host": "any"}}}, "handshakes": map[string]any{"try_interval": "100ms"}}
		out, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	peer, err := startPeer(configFor("192.0.2.1", true))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	client, err := Open(configFor("192.0.2.2", false))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Renew the actual embedded Nebula identity before the encrypted round trip.
	if err := client.Reload(configFor("192.0.2.2", false)); err != nil {
		t.Fatal(err)
	}
	if client.Reload([]byte("pki: {cert: invalid}")) == nil {
		t.Fatal("invalid certificate update accepted")
	}
	ln, err := peer.Listen("tcp", ":19001")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat(nonce, 1024)
	done := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		got := make([]byte, len(payload))
		_, e = io.ReadFull(c, got)
		if e == nil && !bytes.Equal(got, payload) {
			e = fmt.Errorf("payload mismatch")
		}
		if e == nil {
			_, e = c.Write(got)
		}
		done <- e
	}()
	// Localhost represents an unmodified application's connection to its sidecar.
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	go func() {
		c, e := local.Accept()
		if e != nil {
			return
		}
		bridge(c, func(ctx context.Context) (net.Conn, error) { return client.DialContext(ctx, "tcp", "192.0.2.1:19001") }, time.Now().Add(2*time.Minute))
	}()
	app, err := net.DialTimeout("tcp", local.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	_ = app.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err = app.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(app, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("nonce did not survive encrypted overlay round trip")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	// Prove there is no ambient kernel route to the peer's overlay TCP port.
	direct, err := net.DialTimeout("tcp", "192.0.2.1:19001", 300*time.Millisecond)
	if err == nil {
		direct.Close()
		t.Fatal("ambient kernel connectivity invalidates the proof")
	}
	deniedListener, err := peer.Listen("tcp", ":19002")
	if err != nil {
		t.Fatal(err)
	}
	defer deniedListener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	denied, err := client.DialContext(ctx, "tcp", "192.0.2.1:19002")
	if err == nil {
		denied.Close()
		t.Fatal("firewall denied destination became reachable")
	}
	if client.Close() != nil || client.Close() != nil {
		t.Fatal("transport close not idempotent")
	}
	if client.Reload(configFor("192.0.2.2", false)) == nil {
		t.Fatal("stopped transport reloaded identity")
	}
	status, _ := os.ReadFile("/proc/self/status")
	var capEff string
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			capEff = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	if os.Getenv("REQUIRE_ZERO_CAPABILITIES") == "1" && (os.Getuid() == 0 || capEff != "0000000000000000") {
		t.Fatal("container proof requires nonroot and zero effective capabilities")
	}
	t.Logf(`{"overlayRoundTrip":"passed","payloadBytes":%d,"challengePrefix":"%s","directKernelConnection":"rejected","deniedPort":"rejected","uid":%d,"effectiveCapabilities":"%s"}`, len(payload), hex.EncodeToString(nonce[:4]), os.Getuid(), capEff)
}

func startPeer(data []byte) (*service.Service, error) {
	var c config.C
	if e := c.LoadString(string(data)); e != nil {
		return nil, e
	}
	ctrl, e := nebula.Main(&c, false, "test-peer", slog.New(slog.NewTextHandler(io.Discard, nil)), overlay.NewUserDeviceFromConfig)
	if e != nil {
		return nil, e
	}
	return service.New(ctrl)
}

func TestPrivateRoutesFailClosed(t *testing.T) {
	var c config.C
	if e := c.LoadString("tun:\n  unsafe_routes:\n    - route: 198.51.100.0/24\n      via: 192.0.2.1\n    - route: 198.51.100.128/27\n      via: 192.0.2.3\n"); e != nil {
		t.Fatal(e)
	}
	d, e := newRoutedDevice(&c, []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")})
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	for _, v := range []struct{ ip, via string }{{"198.51.100.132", "192.0.2.3"}, {"198.51.100.4", "192.0.2.1"}, {"192.0.2.9", "192.0.2.9"}} {
		g := d.RoutesFor(netip.MustParseAddr(v.ip))
		if len(g) != 1 || g[0].Addr().String() != v.via {
			t.Fatal("incorrect route", v.ip)
		}
	}
	if len(d.RoutesFor(netip.MustParseAddr("10.99.0.1"))) != 0 {
		t.Fatal("undeclared route allowed")
	}
	var invalid config.C
	_ = invalid.LoadString("tun:\n  unsafe_routes:\n    - route: 198.51.100.0/24\n      via: 10.99.0.1\n")
	if _, e := newRoutedDevice(&invalid, []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}); e == nil {
		t.Fatal("gateway outside overlay allowed")
	}
}

func bridge(local net.Conn, dial func(context.Context) (net.Conn, error), deadline time.Time) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	remote, e := dial(ctx)
	if e != nil {
		local.Close()
		return
	}
	forward.Relay(ctx, local, remote)
}
