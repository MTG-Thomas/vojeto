package netstack

// Opt-in Linux measurements run the real CLI in a separate process. The peer
// and measurement harness are excluded from the measured CLI RSS and CPU.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"go.yaml.in/yaml/v3"
)

func TestResourcePeer(t *testing.T) {
	if os.Getenv("VOJETO_RESOURCE_PEER") != "1" {
		t.Skip("measurement helper")
	}
	data, err := os.ReadFile(os.Getenv("VOJETO_PEER_CONFIG"))
	if err != nil {
		t.Fatal("peer config unavailable")
	}
	peer, err := startPeer(data)
	if err != nil {
		t.Fatal("peer startup failed")
	}
	defer peer.Close()
	if os.Getenv("VOJETO_DEBUG_TCP") == "1" {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGUSR1)
		defer signal.Stop(signals)
		go func() {
			for range signals {
				fmt.Fprint(os.Stderr, peerDebugTCP())
			}
		}()
	}
	ln, err := peer.Listen("tcp", ":19001")
	if err != nil {
		t.Fatal(err)
	}
	// Nebula service's listener closes its accept channel unconditionally.
	// Cancellation and deferred cleanup must not close that channel twice.
	var listenerStop sync.Once
	closeListener := func() { listenerStop.Do(func() { ln.Close() }) }
	defer closeListener()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	stop := context.AfterFunc(ctx, closeListener)
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn := trackPeerConn(c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer peerConnDone()
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			io.Copy(conn, conn)
		}()
	}
}

func TestResourceProfile(t *testing.T) {
	if os.Getenv("VOJETO_PROFILE") != "1" {
		t.Skip("opt-in real CLI resource profile")
	}
	binary := os.Getenv("VOJETO_BINARY")
	if binary == "" {
		t.Fatal("VOJETO_BINARY required")
	}
	directory := t.TempDir()
	ca, _, key, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil, nil, nil)
	caPEM, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpPort := socket.LocalAddr().(*net.UDPAddr).Port
	socket.Close()
	configFor := func(ip string, peer bool) []byte {
		_, _, private, crt := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, key, ip, time.Now().Add(-time.Minute), time.Now().Add(30*time.Minute), []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(ip), 24)}, nil, nil)
		port := 0
		hosts := []string{"192.0.2.1"}
		if peer {
			port = udpPort
			hosts = nil
		}
		cfg := map[string]any{"pki": map[string]any{"ca": string(caPEM), "cert": string(crt), "key": string(private)}, "listen": map[string]any{"host": "127.0.0.1", "port": port}, "lighthouse": map[string]any{"am_lighthouse": peer, "hosts": hosts}, "static_host_map": map[string]any{"192.0.2.1": []string{fmt.Sprintf("127.0.0.1:%d", udpPort)}}, "firewall": map[string]any{"outbound": []map[string]any{{"port": 19001, "proto": "tcp", "host": "any"}}, "inbound": []map[string]any{{"port": 19001, "proto": "tcp", "host": "any"}}}, "handshakes": map[string]any{"try_interval": "100ms"}}
		data, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	peerPath := write("peer.yaml", configFor("192.0.2.1", true))
	clientPath := write("client.yaml", configFor("192.0.2.2", false))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	peer := exec.Command(executable, "-test.run=^TestResourcePeer$")
	peer.Env = append(os.Environ(), "VOJETO_RESOURCE_PEER=1", "VOJETO_PEER_CONFIG="+peerPath)
	logpeer, _ := os.Create(filepath.Join(directory, "peer-debug.log"))
	defer logpeer.Close()
	peer.Stderr = logpeer
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan error, 1)
	go func() { peerDone <- peer.Wait() }()
	defer func() {
		peer.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-peerDone:
			if err != nil {
				t.Error("measurement peer exited uncleanly")
			}
		case <-time.After(5 * time.Second):
			peer.Process.Kill()
			<-peerDone
			t.Error("measurement peer failed to stop within cleanup bound")
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
	forwardAddress, healthAddress := reserve(), reserve()
	forwards, _ := json.Marshal([]map[string]any{{"Name": "load", "Listen": forwardAddress, "Target": "peer.example:19001", "MaxConnections": 512, "DialTimeout": 15_000_000_000}})
	readiness := []byte(`{"hosts":{"peer.example":["192.0.2.1"]},"overlay":[{"target":"peer.example:19001","protocol":"tcp"}]}`)
	client := exec.Command(binary, "-config", clientPath, "-forwards", write("forwards.json", forwards), "-readiness", write("readiness.json", readiness), "-health-listen", healthAddress, "-max-connections", "512", "-drain-timeout", "1s")
	started := time.Now()
	logclient, _ := os.Create(filepath.Join(directory, "client-debug.log"))
	defer logclient.Close()
	client.Stderr = logclient
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	finished := false
	defer func() {
		if !finished {
			client.Process.Kill()
			client.Wait()
		}
	}()
	httpClient := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := httpClient.Get("http://" + healthAddress + "/ready")
		ready := err == nil && resp.StatusCode == 200
		if resp != nil {
			resp.Body.Close()
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("startup never became ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	startup := time.Since(started)
	memory := func(field string) int64 {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", client.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, field+":") {
				fields := strings.Fields(line)
				kib, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return kib * 1024
			}
		}
		t.Fatal("Linux RSS unavailable")
		return 0
	}
	rss := func() int64 { return memory("VmRSS") }
	measurements := map[int]int64{0: rss()}
	var connections []net.Conn
	defer func() {
		for _, c := range connections {
			c.Close()
		}
	}()
	payload := bytes.Repeat([]byte("vojeto-resource-proof"), 200)
	for _, count := range []int{10, 100, 500} {
		for len(connections) < count {
			c, err := net.DialTimeout("tcp", forwardAddress, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			connections = append(connections, c)
			c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err = c.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatal("encrypted round trip failed", err)
			}
			c.SetDeadline(time.Time{})
		}
		measurements[count] = rss()
	}
	// Ten streams each move 8 MiB in both directions through encrypted transport.
	transferStart := time.Now()
	debugTimer := time.AfterFunc(45*time.Second, func() { client.Process.Signal(syscall.SIGUSR1); peer.Process.Signal(syscall.SIGUSR1) })
	defer debugTimer.Stop()
	var wg sync.WaitGroup
	type streamResult struct {
		Index                   int
		ReadBytes, WrittenBytes int64
		Seconds                 float64
		ReadError, WriteError   string
	}
	results := make(chan streamResult, 10)
	failures := make(chan error, 10)
	for index, c := range connections[:10] {
		wg.Add(1)
		go func(index int, c net.Conn) {
			defer wg.Done()
			started := time.Now()
			c.SetDeadline(time.Now().Add(60 * time.Second))
			written := make(chan streamResult, 1)
			go func() {
				n, err := io.CopyN(c, repeatReader{}, 8<<20)
				result := streamResult{WrittenBytes: n}
				if err != nil {
					result.WriteError = err.Error()
				}
				written <- result
			}()
			n, err := io.CopyN(io.Discard, c, 8<<20)
			if err != nil {
				c.Close()
			}
			result := <-written
			result.Index, result.ReadBytes, result.Seconds = index, n, time.Since(started).Seconds()
			if err != nil {
				result.ReadError = err.Error()
			}
			results <- result
			if err != nil {
				failures <- err
			} else if result.WriteError != "" {
				failures <- fmt.Errorf("stream %d write failed", index)
			}
		}(index, c)
	}
	wg.Wait()
	close(failures)
	close(results)
	var progress []streamResult
	for result := range results {
		progress = append(progress, result)
	}
	for err := range failures {
		for _, name := range []string{"client", "peer"} {
			data, _ := os.ReadFile(filepath.Join(directory, name+"-debug.log"))
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "[DEBUG-tcp-loss]") {
					t.Log(name + " " + line)
				}
			}
		}
		encoded, _ := json.Marshal(progress)
		t.Logf("resource failure stream progress: %s", encoded)
		for _, path := range []string{"/sys/fs/cgroup/memory.events", "/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/cpu.stat", "/proc/net/snmp"} {
			data, _ := os.ReadFile(path)
			if path == "/proc/net/snmp" {
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(line, "Udp:") {
						t.Logf("resource failure %s", line)
					}
				}
				continue
			}
			t.Logf("resource failure %s: %s", path, data)
		}
		for _, pid := range []int{client.Process.Pid, peer.Process.Pid} {
			data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "State:") || strings.HasPrefix(line, "VmRSS:") || strings.HasPrefix(line, "VmHWM:") {
					t.Logf("resource failure pid %d %s", pid, line)
				}
			}
		}
		t.Fatal("sustained transfer failed", err)
	}
	transfer := time.Since(transferStart)
	// Retain all 500 sessions to exercise forced, bounded cleanup.
	peakRSS := memory("VmHWM")
	drainStart := time.Now()
	client.Process.Signal(syscall.SIGTERM)
	wait := make(chan error, 1)
	go func() { wait <- client.Wait() }()
	select {
	case err := <-wait:
		finished = true
		if err != nil {
			t.Fatal("CLI drain failed", err)
		}
	case <-time.After(10 * time.Second):
		client.Process.Kill()
		<-wait
		finished = true
		t.Fatal("CLI shutdown exceeded bound")
	}
	result := struct {
		Source   string        `json:"source"`
		RSS      map[int]int64 `json:"rss_bytes_by_connections"`
		Startup  float64       `json:"startup_to_ready_seconds"`
		Transfer float64       `json:"bidirectional_160_mib_seconds"`
		Drain    float64       `json:"drain_seconds"`
		PeakRSS  int64         `json:"peak_cli_rss_bytes"`
		CPU      float64       `json:"cli_total_cpu_seconds"`
	}{"static identity; loopback encrypted Nebula; separate CLI process", measurements, startup.Seconds(), transfer.Seconds(), time.Since(drainStart).Seconds(), peakRSS, (client.ProcessState.UserTime() + client.ProcessState.SystemTime()).Seconds()}
	data, _ := json.Marshal(result)
	t.Log(string(data))
}

type repeatReader struct{}

func (repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i)
	}
	return len(p), nil
}
