//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, handler http.HandlerFunc) (*Client, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "vojeto-agent-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(ln)
	t.Cleanup(func() { server.Close(); os.Remove(socket); os.Remove(dir) })
	c, err := New(socket)
	if err != nil {
		t.Fatal(err)
	}
	return c, socket
}
func writeReply(w http.ResponseWriter, ttl int64) {
	json.NewEncoder(w).Encode(reply{OK: true, Token: "fixture-owner", LeaseMilliseconds: ttl})
}
func TestOrderedProtocolAndCleanWatcherStop(t *testing.T) {
	var mu sync.Mutex
	var operations []string
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		var req request
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("bad request")
		}
		op := strings.TrimPrefix(r.URL.Path, "/v1/identity/")
		if op == "acquire" {
			if len(req.Attempt) != 64 || req.Token != "" {
				t.Error("missing unique attempt")
			}
		} else if req.Token != "fixture-owner" {
			t.Error("missing fence")
		}
		mu.Lock()
		operations = append(operations, op)
		mu.Unlock()
		res := reply{OK: true, Token: "fixture-owner", LeaseMilliseconds: 1000}
		if op == "grant" {
			res.Grant = &grant{Code: "fixture-secret", HostID: "host-FIXTURE", NetworkID: "network-FIXTURE", AddressRanges: []string{"100.100.0.0/16"}, RoutePolicy: "{}"}
		}
		if op == "bind" && (req.HostID != "host-FIXTURE" || req.NetworkID != "network-FIXTURE") {
			t.Error("binding lost")
		}
		if op == "checkpoint" && string(req.State) != "fixture-checkpoint" {
			t.Error("checkpoint lost")
		}
		json.NewEncoder(w).Encode(res)
	})
	ctx := context.Background()
	if _, err := c.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.BeginEnrollment(ctx); err != nil {
		t.Fatal(err)
	}
	g, err := c.AcquireGrant(ctx)
	if err != nil || g.Code != "fixture-secret" || len(g.AddressRanges) != 1 {
		t.Fatal(err)
	}
	if err = c.BindEnrollment(ctx, g.HostID, g.NetworkID); err != nil {
		t.Fatal(err)
	}
	watchCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.Watch(watchCtx, func() { t.Error("clean cancellation reported loss") }) }()
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if !c.Valid() {
		t.Fatal("clean watcher stop revoked owner")
	}
	if err = c.Checkpoint(ctx, []byte("fixture-checkpoint")); err != nil {
		t.Fatal(err)
	}
	if err = c.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if c.Valid() {
		t.Fatal("released owner remains valid")
	}
	if err = c.Checkpoint(ctx, nil); err == nil {
		t.Fatal("released token reused")
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(operations, ",") != "acquire,begin,grant,bind,checkpoint,release" {
		t.Fatal(operations)
	}
}
func TestLeaseExpiresWithoutWatcher(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { writeReply(w, 100) })
	if _, err := c.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(110 * time.Millisecond)
	if c.Valid() {
		t.Fatal("unwatched expired lease valid")
	}
	if err := c.Release(context.Background()); err == nil {
		t.Fatal("expired ownership released")
	}
}
func TestBlockedRenewalCannotExtendOwnership(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{})
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/renew") {
			close(entered)
			<-release
		}
		writeReply(w, 150)
	})
	ctx := context.Background()
	if _, err := c.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	lost := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- c.Watch(ctx, func() { close(lost) }) }()
	<-entered
	select {
	case <-lost:
	case <-time.After(time.Second):
		t.Fatal("blocked agent did not revoke")
	}
	if err := <-done; err == nil || c.Valid() {
		t.Fatal("uncertain owner restored")
	}
	if err := c.Release(ctx); err == nil {
		t.Fatal("uncertain owner released")
	}
}
func TestWatcherCancellationDuringRequestPermitsCleanup(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/renew") {
			close(entered)
			<-release
		}
		writeReply(w, 1000)
	})
	if _, err := c.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Watch(ctx, func() { t.Error("normal stop lost ownership") }) }()
	<-entered
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !c.Valid() {
		t.Fatal("watch cancellation revoked clean owner")
	}
	if err := c.Checkpoint(context.Background(), []byte("approved")); err != nil {
		t.Fatal(err)
	}
	if err := c.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestUncertainMutationNeverRetriesOrReleases(t *testing.T) {
	for _, failure := range []string{"status", "token", "malformed", "oversize", "redirect"} {
		t.Run(failure, func(t *testing.T) {
			var calls atomic.Int32
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if strings.HasSuffix(r.URL.Path, "/acquire") {
					writeReply(w, 1000)
					return
				}
				switch failure {
				case "status":
					http.Error(w, "secret-server-body", 503)
				case "token":
					json.NewEncoder(w).Encode(reply{OK: true, Token: "stale-owner"})
				case "malformed":
					w.Write([]byte("secret malformed"))
				case "oversize":
					w.Write([]byte(strings.Repeat("X", maxBody+1)))
				case "redirect":
					w.Header().Set("Location", "http://public.example.invalid/secret")
					w.WriteHeader(307)
				}
			})
			if _, err := c.Acquire(context.Background()); err != nil {
				t.Fatal(err)
			}
			err := c.BeginEnrollment(context.Background())
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatal("unsafe response accepted/exposed", err)
			}
			if c.Valid() {
				t.Fatal("uncertain mutation retained ownership")
			}
			if err = c.Release(context.Background()); err == nil {
				t.Fatal("uncertain release allowed")
			}
			if _, err = c.Acquire(context.Background()); err == nil {
				t.Fatal("acquisition retried")
			}
			if calls.Load() != 2 {
				t.Fatal("request replayed", calls.Load())
			}
		})
	}
}
func TestSocketPermissions(t *testing.T) {
	c, path := fixture(t, func(w http.ResponseWriter, r *http.Request) { writeReply(w, 1000) })
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Fatal("public socket accepted")
	}
	if _, err := c.Acquire(context.Background()); err == nil {
		t.Fatal("permissions not rechecked")
	}
	os.Chmod(path, 0600)
	os.Chmod(filepath.Dir(path), 0755)
	if _, err := New(path); err == nil {
		t.Fatal("public directory accepted")
	}
	os.Chmod(filepath.Dir(path), 0700)
	if _, err := New("relative.sock"); err == nil {
		t.Fatal("relative socket accepted")
	}
	link := filepath.Join(filepath.Dir(path), "link.sock")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(link)
	if _, err := New(link); err == nil {
		t.Fatal("symlink socket accepted")
	}
}
