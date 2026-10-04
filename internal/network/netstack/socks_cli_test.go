package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"go.yaml.in/yaml/v3"
)

// This runs the shipped CLI, encrypted peer and driver in the same rootless,
// read-only measurement container. No broker or host network fallback is used.
func TestFiniteSocksCLI(t *testing.T) {
	binaryPath := os.Getenv("VOJETO_BINARY")
	if binaryPath == "" {
		t.Skip("requires compiled CLI in rootless proof container")
	}
	directory := t.TempDir()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil, nil, nil)
	caPEM, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpAddress := udp.LocalAddr().String()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	configuration := func(ip string, peer bool) []byte {
		_, _, key, crt := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, ip, time.Now().Add(-time.Minute), time.Now().Add(30*time.Minute), []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(ip), 24)}, nil, nil)
		listenPort := 0
		hosts := []string{"192.0.2.1"}
		if peer {
			listenPort = port
			hosts = nil
		}
		rule := []map[string]any{{"port": 19001, "proto": "tcp", "host": "any"}}
		data, err := yaml.Marshal(map[string]any{"pki": map[string]any{"ca": string(caPEM), "cert": string(crt), "key": string(key)}, "listen": map[string]any{"host": "127.0.0.1", "port": listenPort}, "lighthouse": map[string]any{"am_lighthouse": peer, "hosts": hosts}, "static_host_map": map[string]any{"192.0.2.1": []string{udpAddress}}, "firewall": map[string]any{"outbound": rule, "inbound": rule}, "handshakes": map[string]any{"try_interval": "100ms"}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	peerPath := write("peer.yaml", configuration("192.0.2.1", true))
	clientPath := write("client.yaml", configuration("192.0.2.2", false))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	peer := exec.Command(executable, "-test.run=^TestFiniteSocksPeer$")
	peer.Env = append(os.Environ(), "VOJETO_SOCKS_PEER=1", "VOJETO_PEER_CONFIG="+peerPath)
	if err = peer.Start(); err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan error, 1)
	go func() { peerDone <- peer.Wait() }()
	defer func() {
		peer.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-peerDone:
			if err != nil {
				t.Error("SOCKS proof peer exited uncleanly")
			}
		case <-time.After(3 * time.Second):
			peer.Process.Kill()
			<-peerDone
			t.Error("SOCKS proof peer failed to stop")
		}
	}()

	reserve := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		return addr
	}
	socksAddress, healthAddress := reserve(), reserve()
	policy, _ := json.Marshal(map[string]any{"listen": socksAddress, "allow": []string{"192.0.2.1:19001"}, "maxConnections": 2, "dialTimeout": "2s", "lifetime": "10s"})
	ready := []byte(`{"overlay":[{"target":"192.0.2.1:19001","protocol":"tcp"}]}`)
	cli := exec.Command(binaryPath, "-config", clientPath, "-socks", write("socks.json", policy), "-readiness", write("readiness.json", ready), "-health-listen", healthAddress, "-drain-timeout", "1s")
	started := time.Now()
	if err = cli.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cli.Wait() }()
	finished := false
	defer func() {
		if !finished {
			cli.Process.Kill()
			<-done
		}
	}()
	httpClient := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := httpClient.Get("http://" + healthAddress + "/ready")
		ready := err == nil && response.StatusCode == 200
		if response != nil {
			response.Body.Close()
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("finite SOCKS CLI never ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	connect := func(ip byte) (net.Conn, byte) {
		c, err := net.DialTimeout("tcp", socksAddress, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte{5, 1, 0})
		var hello [2]byte
		if _, err = io.ReadFull(c, hello[:]); err != nil {
			c.Close()
			t.Fatal(err)
		}
		request := []byte{5, 1, 0, 1, 192, 0, 2, ip, 0, 0}
		binary.BigEndian.PutUint16(request[8:], 19001)
		c.Write(request)
		var reply [10]byte
		if _, err = io.ReadFull(c, reply[:]); err != nil {
			c.Close()
			t.Fatal(err)
		}
		return c, reply[1]
	}
	denied, status := connect(2)
	denied.Close()
	if status != 2 {
		t.Fatal("unlisted destination accepted", status)
	}
	app, status := connect(1)
	defer app.Close()
	if status != 0 {
		t.Fatal("allowed encrypted dial failed", status)
	}
	payload := bytes.Repeat([]byte("finite encrypted SOCKS"), 100)
	wrote := make(chan error, 1)
	go func() { _, e := app.Write(payload); wrote <- e }()
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(app, received); err != nil {
		t.Fatal(err)
	}
	if err = <-wrote; err != nil || !bytes.Equal(payload, received) {
		t.Fatal("encrypted payload mismatch", err)
	}
	// Leave the session active: lifetime must close it and exit without a signal.
	app.SetDeadline(time.Now().Add(15 * time.Second))
	var one [1]byte
	if _, err = app.Read(one[:]); err == nil {
		t.Fatal("expired SOCKS session stayed open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("lifetime failed to close active session")
	}
	if time.Since(started) < 9*time.Second {
		t.Fatal("active SOCKS session closed before its lifetime")
	}
	select {
	case err = <-done:
		finished = true
		if err != nil {
			t.Fatal("finite CLI exited uncleanly", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal(fmt.Errorf("finite CLI did not complete"))
	}
}

// The SOCKS proof peer uses the production TCP stack's listening endpoint.
// Keep the existing resource profile and its original peer unchanged.
func TestFiniteSocksPeer(t *testing.T) {
	if os.Getenv("VOJETO_SOCKS_PEER") != "1" {
		t.Skip("finite SOCKS helper")
	}
	data, err := os.ReadFile(os.Getenv("VOJETO_PEER_CONFIG"))
	if err != nil {
		t.Fatal("peer config unavailable")
	}
	peer, err := Open(data)
	if err != nil {
		t.Fatal("peer startup failed")
	}
	defer peer.Close()
	ln, err := gonet.ListenTCP(peer.ipstack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 19001}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal("peer listener failed")
	}
	defer ln.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	var sessions sync.WaitGroup
	defer sessions.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			io.Copy(c, c)
		}()
	}
}
