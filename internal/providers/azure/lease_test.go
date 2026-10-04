package azure

import (
	"context"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/providers/defined"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DefinedNet/dnapi/keys"
)

type poolRoundTrip func(*http.Request) (*http.Response, error)

func (f poolRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func poolFixture(t *testing.T, handler http.HandlerFunc, app string, hosts []string) *identityPool {
	t.Helper()
	client := &http.Client{Transport: poolRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "state.example.invalid" ||
			!strings.HasPrefix(r.URL.Path, "/"+"identities"+"/host-") ||
			r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("storage request escaped its boundary")
		}
		recorder := httptest.NewRecorder()
		handler(recorder, r)
		return recorder.Result(), nil
	}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pool, err := newIdentityPool(client, func(context.Context) (string, error) { return "fixture-token", nil }, app, hosts, "https://state.example.invalid/identities")
	if err != nil {
		t.Fatal("pool fixture failed")
	}
	return pool
}

func fixtureState(t *testing.T, host string, counter uint) []byte {
	t.Helper()
	generated, err := keys.New()
	if err != nil {
		t.Fatal("key generation failed")
	}
	trust, err := keys.NewTrustedKey(generated.HostP256PrivateKey.Public().Unwrap())
	if err != nil {
		t.Fatal("trust generation failed")
	}
	data, err := defined.EncodeState(host, []string{"100.100.1.1"}, []byte("fixture config"), &keys.Credentials{
		HostID: host, Counter: counter, PrivateKey: generated.HostP256PrivateKey, TrustedKeys: []keys.TrustedKey{trust}})
	if err != nil {
		t.Fatal("state fixture failed")
	}
	return data
}

func TestIdentityPoolExclusiveLeaseCheckpointAndRestart(t *testing.T) {
	const app = "example-core"
	var mu sync.Mutex
	leases := map[string]string{}
	markers := map[string]string{"host-FIRST": "available", "host-SECOND": "available"}
	states := map[string][]byte{"host-FIRST": fixtureState(t, "host-FIRST", 1), "host-SECOND": fixtureState(t, "host-SECOND", 1)}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"+"identities"+"/"), ".json")
		action := r.Header.Get("x-ms-lease-action")
		if action != "" {
			if r.Method != "PUT" || r.URL.RawQuery != "comp=lease" {
				t.Error("wrong lease operation")
			}
			switch action {
			case "acquire":
				if leases[path] != "" {
					w.Header().Set("x-ms-error-code", "LeaseAlreadyPresent")
					w.WriteHeader(409)
					return
				}
				if r.Header.Get("x-ms-lease-duration") != "60" {
					t.Error("lease not bounded")
				}
				leases[path] = r.Header.Get("x-ms-proposed-lease-id")
				w.Header().Set("x-ms-lease-id", leases[path])
				w.WriteHeader(201)
			case "renew":
				if r.Header.Get("x-ms-lease-id") != leases[path] {
					w.WriteHeader(412)
					return
				}
				w.Header().Set("x-ms-lease-id", leases[path])
				w.WriteHeader(200)
			case "release":
				if r.Header.Get("x-ms-lease-id") != leases[path] {
					w.WriteHeader(412)
					return
				}
				delete(leases, path)
				w.WriteHeader(200)
			default:
				t.Error("unexpected lease action")
			}
			return
		}
		if r.Header.Get("x-ms-lease-id") != leases[path] || leases[path] == "" {
			w.WriteHeader(412)
			return
		}
		if r.URL.RawQuery == "comp=metadata" {
			markers[path] = r.Header.Get("x-ms-meta-state")
			w.WriteHeader(200)
			return
		}
		if r.Method == "GET" {
			w.Header().Set("x-ms-meta-state", markers[path])
			w.Header().Set("x-ms-meta-owner", app)
			w.Write(states[path])
			return
		}
		if r.Header.Get("x-ms-blob-type") != "BlockBlob" || r.Header.Get("x-ms-meta-owner") != app {
			t.Error("checkpoint metadata missing")
		}
		markers[path] = r.Header.Get("x-ms-meta-state")
		states[path], _ = io.ReadAll(r.Body)
		w.WriteHeader(201)
	})
	pool := poolFixture(t, handler, app, []string{"host-FIRST", "host-SECOND"})
	first, _, err := pool.takeAvailable(context.Background(), app+"--rev-pod-a")
	if err != nil {
		t.Fatal("first lease failed")
	}
	second, _, err := pool.takeAvailable(context.Background(), app+"--rev-pod-b")
	if err != nil || second.slot == first.slot {
		t.Fatal("replicas shared an identity")
	}
	if _, _, err := pool.takeAvailable(context.Background(), app+"--rev-pod-c"); err == nil {
		t.Fatal("pool exceeded declared capacity")
	}
	if err := first.write(context.Background(), fixtureState(t, "host-FIRST", 18)); err != nil {
		t.Fatal("rotation checkpoint failed")
	}
	if err := first.renew(context.Background()); err != nil {
		t.Fatal("valid renewal failed")
	}
	if err := first.mark(context.Background(), "available"); err != nil {
		t.Fatal("clean shutdown marker failed")
	}
	if err := first.release(context.Background()); err != nil {
		t.Fatal("release failed")
	}
	restarted, data, err := pool.takeAvailable(context.Background(), app+"--rev-pod-c")
	if err != nil || restarted.slot != first.slot {
		t.Fatal("restart failed to reuse its available slot")
	}
	_, credentials, err := defined.DecodeState(data)
	if err != nil || credentials.Counter != 18 {
		t.Fatal("restart replayed initial credentials")
	}
	// Simulate server lease expiry after a crash; the active tombstone remains.
	mu.Lock()
	delete(leases, "host-FIRST")
	mu.Unlock()
	restarted.mu.Lock()
	restarted.validUntil = time.Time{}
	restarted.mu.Unlock()
	if _, _, err := pool.takeAvailable(context.Background(), app+"--rev-pod-d"); !errors.Is(err, errIdentityPoolFull) {
		t.Fatal("expired active host was automatically reused")
	}
	mu.Lock()
	if markers["host-FIRST"] != "active" {
		t.Error("quarantined owner marker was cleared")
	}
	mu.Unlock()
}

func TestIdentityLeaseRejectsStaleOrDelayedRenewal(t *testing.T) {
	var requests atomic.Int32
	var lease *identityLease
	pool := poolFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		lease.mu.Lock()
		lease.validUntil = time.Now().Add(-time.Second)
		lease.mu.Unlock()
		w.Header().Set("x-ms-lease-id", lease.id)
		w.WriteHeader(200)
	}, "example-core", []string{"host-FIRST"})
	lease = &identityLease{pool: pool, slot: 1, id: "fixture-id", validUntil: time.Now().Add(-time.Second)}
	if lease.renew(context.Background()) == nil || requests.Load() != 0 {
		t.Fatal("stale lease was renewed")
	}
	lease.validUntil = time.Now().Add(time.Minute)
	if lease.renew(context.Background()) == nil || lease.remaining() > 0 {
		t.Fatal("late renewal reauthorized stale identity")
	}
}

func TestIdentityLeaseWatchdogClosesTransportWithoutSuccessfulObservation(t *testing.T) {
	lease := &identityLease{validUntil: time.Now().Add(5 * time.Millisecond)}
	var closed atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if lease.maintain(ctx, func() { closed.Add(1) }) == nil || closed.Load() != 1 {
		t.Fatal("expired identity transport survived")
	}
}

func TestIdentityPoolRefusesForeignStatePathsAndConflicts(t *testing.T) {
	for _, entry := range []struct {
		app   string
		hosts []string
	}{
		{"../foreign", []string{"host-FIRST"}},
		{"example-core", []string{"host-FIRST", "host-FIRST"}},
		{"example-core", []string{"../host-FIRST"}},
		{"example-core", nil},
	} {
		if _, err := newIdentityPool(&http.Client{}, func(context.Context) (string, error) { return "fixture", nil }, entry.app, entry.hosts, "https://state.example.invalid/identities"); err == nil {
			t.Fatal("foreign or duplicate pool accepted")
		}
	}
	pool := poolFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-ms-error-code", "UnexpectedConflict")
		w.WriteHeader(409)
	}, "example-core", []string{"host-FIRST"})
	if _, err := pool.acquire(context.Background(), 1); err == nil || errors.Is(err, errIdentitySlotBusy) {
		t.Fatal("unknown conflict treated as healthy capacity")
	}
	lease := &identityLease{pool: pool, slot: 1, id: "id", validUntil: time.Now().Add(time.Minute)}
	if lease.write(context.Background(), fixtureState(t, "host-FOREIGN", 1)) == nil {
		t.Fatal("foreign credentials checkpointed under another identity")
	}
	pool = poolFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-ms-meta-owner", "example-dmarc")
		w.Write(fixtureState(t, "host-FIRST", 1))
	}, "example-core", []string{"host-FIRST"})
	lease.pool = pool
	if _, err := lease.read(context.Background()); err == nil {
		t.Fatal("foreign app state accepted")
	}
}

func TestStorageIdentityUsesFixedAudienceAndLocalEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "https://storage.azure.com/" || r.Header.Get("X-IDENTITY-HEADER") != "fixture-header" {
			t.Error("identity boundary escaped")
		}
		w.Write([]byte(`{"access_token":"fixture-token"}`))
	}))
	defer server.Close()
	t.Setenv("IDENTITY_ENDPOINT", server.URL+"/msi/token")
	t.Setenv("IDENTITY_HEADER", "fixture-header")
	token, err := storageIdentityToken(context.Background(), server.Client())
	if err != nil || token != "fixture-token" {
		t.Fatal("storage token request failed")
	}
	for _, endpoint := range []string{"https://127.0.0.1/msi/token", "http://example.com/msi/token", "http://user@127.0.0.1/msi/token"} {
		t.Setenv("IDENTITY_ENDPOINT", endpoint)
		if _, err := storageIdentityToken(context.Background(), server.Client()); err == nil {
			t.Fatal("foreign identity endpoint accepted")
		}
	}
}

func TestIdentityPoolAllQuarantinedFailsWithoutReauthorizingHost(t *testing.T) {
	var releases atomic.Int32
	pool := poolFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-ms-lease-action") {
		case "acquire":
			w.Header().Set("x-ms-lease-id", r.Header.Get("x-ms-proposed-lease-id"))
			w.WriteHeader(201)
		case "release":
			releases.Add(1)
			w.WriteHeader(200)
		default:
			w.Header().Set("x-ms-meta-owner", "example-core")
			w.Header().Set("x-ms-meta-state", "active")
			w.WriteHeader(200)
		}
	}, "example-core", []string{"host-FIRST"})
	if _, _, err := pool.takeAvailable(context.Background(), "example-core--rev-new"); !errors.Is(err, errIdentityQuarantined) || releases.Load() != 1 {
		t.Fatal("unclean expired owner was reused or treated as temporary capacity")
	}
}
