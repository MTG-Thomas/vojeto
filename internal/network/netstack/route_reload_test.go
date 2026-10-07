package netstack

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"go.yaml.in/yaml/v3"
)

func TestReloadAllowsOnlyRoutePermutation(t *testing.T) {
	ca, _, signer, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil, nil, nil)
	caPEM, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal("fixture CA failed")
	}
	_, _, key, certificate := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, signer, "fixture", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []netip.Prefix{netip.MustParsePrefix("100.100.0.66/22")}, nil, nil)
	a := map[string]any{"route": "10.30.0.0/26", "via": "100.100.0.30", "install": true}
	b := map[string]any{"route": "10.30.0.128/27", "via": "100.100.0.30", "install": true}
	encode := func(routes []any) []byte {
		data, err := yaml.Marshal(map[string]any{"pki": map[string]any{"ca": string(caPEM), "cert": string(certificate), "key": string(key)}, "tun": map[string]any{"unsafe_routes": routes}})
		if err != nil {
			t.Fatal("fixture configuration failed")
		}
		return data
	}
	var current config.C
	if current.LoadString(string(encode([]any{a, b}))) != nil {
		t.Fatal("fixture configuration rejected")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if reloadManagedConfig(&current, encode([]any{b, a}), logger) != nil {
		t.Fatal("unchanged route membership rejected")
	}
	changed := map[string]any{"route": "10.30.0.128/27", "via": "100.100.0.31", "install": true}
	if reloadManagedConfig(&current, encode([]any{changed, a}), logger) == nil {
		t.Fatal("changed gateway applied without review")
	}
}
