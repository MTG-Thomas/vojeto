package defined

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DefinedNet/dnapi/keys"
	"github.com/DefinedNet/dnapi/message"
)

func clientCredentials(t *testing.T, p256 bool) keys.Credentials {
	t.Helper()
	k, e := keys.New()
	if e != nil {
		t.Fatal(e)
	}
	private := k.HostEd25519PrivateKey
	public := k.HostEd25519PublicKey
	if p256 {
		private, public = k.HostP256PrivateKey, k.HostP256PublicKey
	}
	trusted, e := keys.NewTrustedKey(public.Unwrap())
	if e != nil {
		t.Fatal(e)
	}
	return keys.Credentials{HostID: "host-FIXTURE", Counter: 17, PrivateKey: private, TrustedKeys: []keys.TrustedKey{trusted}}
}
func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	c, e := NewClient(s.URL, s.Client())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func decodeRequest(t *testing.T, r *http.Request, credentials keys.Credentials) message.RequestWrapper {
	t.Helper()
	var signed message.RequestV1
	if json.NewDecoder(r.Body).Decode(&signed) != nil {
		t.Error("bad request")
	}
	if r.URL.Path != message.EndpointV1 || r.Method != http.MethodPost || signed.Counter != credentials.Counter || signed.HostID != credentials.HostID {
		t.Error("request metadata")
	}
	if !credentials.TrustedKeys[0].Verify([]byte(signed.Message), signed.Signature) {
		t.Error("request signature")
	}
	raw, e := base64.StdEncoding.DecodeString(signed.Message)
	if e != nil {
		t.Error(e)
	}
	var wrapper message.RequestWrapper
	if json.Unmarshal(raw, &wrapper) != nil {
		t.Error("request wrapper")
	}
	return wrapper
}
func TestClientPolling(t *testing.T) {
	credentials := clientCredentials(t, false)
	for _, available := range []bool{false, true} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			request := decodeRequest(t, r, credentials)
			if request.Type != message.CheckForUpdate {
				t.Error("wrong operation")
			}
			json.NewEncoder(w).Encode(message.CheckForUpdateResponseWrapper{Data: message.CheckForUpdateResponse{UpdateAvailable: available}})
		})
		got, e := c.CheckForUpdate(context.Background(), credentials)
		if e != nil || got != available {
			t.Fatal(got, e)
		}
	}
}
func TestClientRejectsUnsafePollResponses(t *testing.T) {
	credentials := clientCredentials(t, false)
	for _, body := range []string{"", `{}`, `{"data":{}}`, `{"data":null}`, `{"data":{"updateAvailable":null}}`, `{"data":{"updateAvailable":false}} secret`, strings.Repeat("x", responseLimit+1)} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
		_, e := c.CheckForUpdate(context.Background(), credentials)
		if e != errControlPlane {
			t.Fatalf("unexpected error: %v", e)
		}
	}
	for _, status := range []int{301, 302, 307, 308, 401, 403, 429, 500, 503} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); io.WriteString(w, "secret") })
		_, e := c.CheckForUpdate(context.Background(), credentials)
		if e != errControlPlane {
			t.Fatal(e)
		}
	}
}
func TestClientDoesNotFollowRedirect(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer target.Close()
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	_, e := c.CheckForUpdate(context.Background(), clientCredentials(t, false))
	if e != errControlPlane || reached.Load() != 0 {
		t.Fatal("redirect followed", e)
	}
}
func TestClientTimeoutAndCancellation(t *testing.T) {
	entered := make(chan struct{}, 1)
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-time.After(250 * time.Millisecond):
		}
	})
	c.http.Timeout = 25 * time.Millisecond
	start := time.Now()
	_, e := c.CheckForUpdate(context.Background(), clientCredentials(t, false))
	if e != errControlPlane || time.Since(start) > time.Second {
		t.Fatal("timeout not bounded", e)
	}
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = c.CheckForUpdate(ctx, clientCredentials(t, false))
	if e != errControlPlane {
		t.Fatal(e)
	}
}
func TestClientRotationVerification(t *testing.T) {
	for _, p256 := range []bool{false, true} {
		for _, fault := range []string{"", "signature", "nonce", "counter", "trusted", "missing-config", "malformed", "version"} {
			t.Run(strings.Join([]string{map[bool]string{false: "25519", true: "p256"}[p256], fault}, "/"), func(t *testing.T) {
				credentials := clientCredentials(t, p256)
				c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
					wrapped := decodeRequest(t, r, credentials)
					if wrapped.Type != message.DoUpdate {
						t.Error("wrong operation")
					}
					var request message.DoUpdateRequest
					if json.Unmarshal(wrapped.Value, &request) != nil {
						t.Error("invalid update")
					}
					if len(request.Nonce) != 16 {
						t.Error("nonce size")
					}
					if p256 && (len(request.HostPubkeyP256) == 0 || len(request.NebulaPubkeyP256) == 0) {
						t.Error("missing p256 keys")
					}
					if !p256 && (len(request.HostPubkeyEd25519) == 0 || len(request.NebulaPubkeyX25519) == 0) {
						t.Error("missing 25519 keys")
					}
					trusted, _ := keys.TrustedKeysToPEM(credentials.TrustedKeys)
					result := message.DoUpdateResponse{Config: []byte("fixture-config"), Counter: 18, Nonce: request.Nonce, TrustedKeys: trusted, Host: message.HostHostMetadata{ID: credentials.HostID, IPAddress: "192.0.2.1"}, Network: message.HostNetworkMetadata{ID: "network-FIXTURE", Curve: message.NetworkCurve25519}}
					switch fault {
					case "nonce":
						result.Nonce = []byte("wrong")
					case "counter":
						result.Counter = 17
					case "trusted":
						result.TrustedKeys = nil
					case "missing-config":
						result.Config = nil
					}
					data, _ := json.Marshal(result)
					if fault == "malformed" {
						data = []byte("malformed-secret")
					}
					signature, _ := credentials.PrivateKey.Sign(data)
					if fault == "signature" {
						signature[0] ^= 1
					}
					version := 1
					if fault == "version" {
						version = 2
					}
					json.NewEncoder(w).Encode(message.SignedResponseWrapper{Data: message.SignedResponse{Version: version, Message: data, Signature: signature}})
				})
				config, nebula, next, meta, e := c.DoUpdate(context.Background(), credentials)
				if fault != "" {
					if e != errControlPlane || next != nil {
						t.Fatal("accepted invalid rotation", e)
					}
					return
				}
				if e != nil || !bytes.Equal(config, []byte("fixture-config")) || len(nebula) == 0 || next.Counter != 18 || next.HostID != credentials.HostID || meta.Network.ID != "network-FIXTURE" || meta.Host.IPAddresses[0] != "192.0.2.1" {
					t.Fatal("rotation result", e)
				}
				switch next.PrivateKey.Unwrap().(type) {
				case ed25519.PrivateKey:
					if p256 {
						t.Fatal("wrong curve")
					}
				case *ecdsa.PrivateKey:
					if !p256 {
						t.Fatal("wrong curve")
					}
				default:
					t.Fatal("unknown curve")
				}
			})
		}
	}
}
func TestClientConfiguration(t *testing.T) {
	for _, base := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com/path", "https://example.com?secret=x", "https://example.com#secret"} {
		if _, e := NewClient(base, nil); e == nil {
			t.Fatal("accepted", base)
		}
	}
	supplied := &http.Client{Timeout: time.Minute}
	c, e := NewClient("https://example.com", supplied)
	if e != nil || c.http.Timeout != 30*time.Second || supplied.Timeout != time.Minute || supplied.CheckRedirect != nil {
		t.Fatal("client copy", e)
	}
}

// Unknown length responses must be capped while streaming, rather than trusting
// Content-Length or allocating the entire body before validating its size.
func TestClientBoundsStreamingBody(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		chunk := strings.Repeat("x", 4096)
		for i := 0; i < responseLimit/4096+2; i++ {
			if _, e := io.WriteString(w, chunk); e != nil {
				return
			}
		}
	})
	_, e := c.CheckForUpdate(context.Background(), clientCredentials(t, false))
	if e != errControlPlane {
		t.Fatal("unbounded body accepted", e)
	}
}
func TestClientUncertainRotationNeverRetries(t *testing.T) {
	p, s, _ := providerFixture(t)
	var updates atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		var request message.RequestV1
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("request decode")
		}
		data, _ := base64.StdEncoding.DecodeString(request.Message)
		var wrapper message.RequestWrapper
		json.Unmarshal(data, &wrapper)
		if wrapper.Type == message.CheckForUpdate {
			io.WriteString(w, `{"data":{"updateAvailable":true}}`)
			return
		}
		updates.Add(1)
		// Remote rotation may have committed before this response was lost.
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	current, e := p.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	p.client = c
	if _, e = p.Renew(context.Background(), current); !errors.Is(e, identity.ErrUnsafeRenewal) {
		t.Fatal("uncertain update not quarantined", e)
	}
	if _, e = p.Renew(context.Background(), current); e == nil {
		t.Fatal("repeated unsafe rotation")
	}
	if e = p.Release(context.Background(), current); e == nil || s.releaseCalls != 0 || updates.Load() != 1 {
		t.Fatal("unsafe identity reused")
	}
}
