package defined

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/definedwire"
	wirekeys "github.com/MTG-Thomas/vojeto/internal/definedwire/credentials"
)

func TestEnrollmentBothCurves(t *testing.T) {
	for _, curve := range []definedwire.NetworkCurve{definedwire.NetworkCurve25519, definedwire.NetworkCurveP256} {
		t.Run(string(curve), func(t *testing.T) {
			trusted, _ := wirekeys.TrustedKeysToPEM(clientCredentials(t, false).TrustedKeys)
			var request definedwire.EnrollRequest
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != definedwire.EnrollEndpoint || r.Method != http.MethodPost || strings.Contains(r.URL.String(), "fixture-code") {
					t.Error("unsafe enrollment endpoint")
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil || request.Code != "fixture-code" || request.Hostname != "fixture-worker" || time.Since(request.Timestamp) > time.Second {
					t.Error("invalid grant request")
				}
				if len(request.HostPubkeyEd25519) == 0 || len(request.HostPubkeyP256) == 0 || len(request.NebulaPubkeyX25519) == 0 || len(request.NebulaPubkeyP256) == 0 {
					t.Error("missing generated keys")
				}
				json.NewEncoder(w).Encode(map[string]any{"data": definedwire.EnrollResponseData{HostID: "host-FIXTURE", Host: definedwire.HostHostMetadata{ID: "host-FIXTURE", IPAddress: "192.0.2.1"}, Network: definedwire.HostNetworkMetadata{ID: "network-FIXTURE", Curve: curve}, Counter: 1, Config: []byte("fixture-config"), TrustedKeys: trusted}})
			})
			data, key, credentials, meta, err := c.Enroll(context.Background(), "fixture-code", "fixture-worker")
			if err != nil || string(data) != "fixture-config" || len(key) == 0 || credentials.HostID != "host-FIXTURE" || credentials.Counter != 1 || meta.Network.ID != "network-FIXTURE" || !reflect.DeepEqual(meta.Host.IPAddresses, []string{"192.0.2.1"}) {
				t.Fatal("enrollment result rejected", err)
			}
			switch private := credentials.PrivateKey.Unwrap().(type) {
			case ed25519.PrivateKey:
				public, _, err := wirekeys.UnmarshalHostEd25519PublicKey(request.HostPubkeyEd25519)
				if curve != definedwire.NetworkCurve25519 || err != nil || !reflect.DeepEqual(public, private.Public()) {
					t.Fatal("wrong signing key")
				}
			case *ecdsa.PrivateKey:
				public, _, err := wirekeys.UnmarshalHostP256PublicKey(request.HostPubkeyP256)
				if curve != definedwire.NetworkCurveP256 || err != nil || !public.Equal(&private.PublicKey) {
					t.Fatal("wrong signing key")
				}
			default:
				t.Fatal("unsupported signing key")
			}
		})
	}
}

func TestEnrollmentNeverRetriesOrLeaksRejectedResponse(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308, 401, 403, 429, 500, 502, 503, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int64
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/secret-redirect")
				w.WriteHeader(status)
				io.WriteString(w, "fixture-code private-key fixture-secret")
			})
			data, key, credentials, meta, err := c.Enroll(context.Background(), "fixture-code", "fixture-worker")
			if !errors.Is(err, ErrUncertainEnrollment) || strings.Contains(err.Error(), "fixture") || data != nil || key != nil || credentials != nil || meta != nil || calls.Load() != 1 {
				t.Fatal("unsafe enrollment rejection", err, calls.Load())
			}
		})
	}
	for _, body := range []string{"", `{}`, `{"data":null}`, `{"data":{}}`, `{"data":{"network":{"curve":"bad"}}}`, strings.Repeat("x", responseLimit+1)} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
		_, _, _, _, err := c.Enroll(context.Background(), "fixture-code", "")
		if !errors.Is(err, ErrUncertainEnrollment) {
			t.Fatal("malformed response accepted")
		}
	}
}

func TestEnrollmentCancellationAndInputBounds(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	defer close(release)
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	c.http.Timeout = 200 * time.Millisecond
	_, _, _, _, err := c.Enroll(context.Background(), "fixture-code", "")
	if !errors.Is(err, ErrUncertainEnrollment) || calls.Load() != 1 {
		t.Fatal("timeout not bounded", err)
	}
	for _, code := range []string{"", strings.Repeat("x", 8193)} {
		_, _, _, _, err = c.Enroll(context.Background(), code, "")
		if !errors.Is(err, ErrUncertainEnrollment) || calls.Load() != 1 {
			t.Fatal("invalid input reached enrollment")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, _, err = c.Enroll(ctx, "fixture-code", "")
	if !errors.Is(err, ErrUncertainEnrollment) || calls.Load() != 1 {
		t.Fatal("canceled enrollment reached server")
	}
}

func TestEnrollmentRejectsIncompleteIdentityMetadata(t *testing.T) {
	trusted, _ := wirekeys.TrustedKeysToPEM(clientCredentials(t, false).TrustedKeys)
	for _, change := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing counter", func(m map[string]any) { delete(m, "counter") }},
		{"null counter", func(m map[string]any) { m["counter"] = nil }},
		{"host mismatch", func(m map[string]any) { m["hostID"] = "host-OTHER" }},
		{"missing network", func(m map[string]any) { m["network"] = map[string]any{"curve": "25519"} }},
		{"unknown curve", func(m map[string]any) { m["network"] = map[string]any{"id": "network-FIXTURE", "curve": "unknown"} }},
		{"missing address", func(m map[string]any) { m["host"] = map[string]any{"id": "host-FIXTURE"} }},
		{"empty config", func(m map[string]any) { m["config"] = nil }},
		{"bad trust", func(m map[string]any) { m["trustedKeys"] = []byte("invalid") }},
	} {
		t.Run(change.name, func(t *testing.T) {
			m := map[string]any{"hostID": "host-FIXTURE", "counter": 1, "config": []byte("fixture-config"), "trustedKeys": trusted, "host": map[string]any{"id": "host-FIXTURE", "ipAddress": "192.0.2.1"}, "network": map[string]any{"id": "network-FIXTURE", "curve": "25519"}}
			change.mutate(m)
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(map[string]any{"data": m}) })
			_, _, _, _, err := c.Enroll(context.Background(), "fixture-code", "")
			if !errors.Is(err, ErrUncertainEnrollment) {
				t.Fatal("incomplete identity accepted")
			}
		})
	}
}

func TestEnrollmentWithP256OnlyKeys(t *testing.T) {
	if os.Getenv("VOJETO_ENROLLMENT_FIPS_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestEnrollmentWithP256OnlyKeys$")
		command.Env = append(os.Environ(), "GODEBUG=fips140=only", "VOJETO_ENROLLMENT_FIPS_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("P256-only enrollment failed: %v\n%s", err, output)
		}
		return
	}
	trusted, _ := wirekeys.TrustedKeysToPEM(clientCredentials(t, true).TrustedKeys)
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		var request definedwire.EnrollRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.HostPubkeyEd25519) != 0 || len(request.NebulaPubkeyX25519) != 0 || len(request.HostPubkeyP256) == 0 || len(request.NebulaPubkeyP256) == 0 {
			t.Error("P256-only request incorrect")
		}
		json.NewEncoder(w).Encode(map[string]any{"data": definedwire.EnrollResponseData{HostID: "host-FIXTURE", Host: definedwire.HostHostMetadata{ID: "host-FIXTURE", IPAddress: "192.0.2.1"}, Network: definedwire.HostNetworkMetadata{ID: "network-FIXTURE", Curve: definedwire.NetworkCurveP256}, Counter: 1, Config: []byte("fixture-config"), TrustedKeys: trusted}})
	})
	_, key, credentials, _, err := c.Enroll(context.Background(), "fixture-code", "")
	if err != nil || len(key) == 0 || credentials == nil {
		t.Fatal("P256-only enrollment refused", err)
	}
	if _, ok := credentials.PrivateKey.Unwrap().(*ecdsa.PrivateKey); !ok {
		t.Fatal("wrong key curve")
	}
}
