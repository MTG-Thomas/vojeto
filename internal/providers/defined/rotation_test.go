package defined

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/DefinedNet/dnapi"
	"github.com/DefinedNet/dnapi/keys"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"go.yaml.in/yaml/v3"
)

type fakePooledDN struct {
	data, key []byte
	next      *keys.Credentials
	meta      *dnapi.ConfigMeta
}

func (f fakePooledDN) CheckForUpdate(context.Context, keys.Credentials) (bool, error) {
	return true, nil
}
func (f fakePooledDN) DoUpdate(context.Context, keys.Credentials) ([]byte, []byte, *keys.Credentials, *dnapi.ConfigMeta, error) {
	return f.data, f.key, f.next, f.meta, nil
}

func pooledRenewalFixture(t *testing.T) (*identityState, *keys.Credentials, fakePooledDN) {
	t.Helper()
	ca, _, signing, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now().Add(-time.Minute), time.Now().Add(2*time.Hour), nil, nil, nil)
	caPEM, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal("CA fixture failed")
	}
	configFor := func() ([]byte, []byte) {
		_, _, private, certificate := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, signing, "fixture", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []netip.Prefix{netip.MustParsePrefix("100.100.1.1/22")}, nil, nil)
		data, err := yaml.Marshal(map[string]any{"pki": map[string]any{"ca": string(caPEM), "cert": string(certificate), "key": string(private)}})
		if err != nil {
			t.Fatal("config fixture failed")
		}
		return data, private
	}
	oldConfig, _ := configFor()
	nextConfig, nextKey := configFor()
	oldBlob := fixtureState(t, "host-EXPECTED", 17)
	state, old, err := decodeIdentityState(oldBlob)
	if err != nil {
		t.Fatal("identity fixture failed")
	}
	state.Config = oldConfig
	_, next, err := decodeIdentityState(fixtureState(t, "host-EXPECTED", 18))
	if err != nil {
		t.Fatal("rotated fixture failed")
	}
	meta := &dnapi.ConfigMeta{Host: dnapi.ConfigHost{ID: state.HostID, IPAddresses: state.Addresses}, Network: dnapi.ConfigNetwork{ID: "network-FIXTURE"}}
	return state, old, fakePooledDN{nextConfig, nextKey, next, meta}
}

func TestPooledRenewalCheckpointsCredentialsAndConfigBeforeReload(t *testing.T) {
	state, credentials, dn := pooledRenewalFixture(t)
	var checkpoints [][]byte
	applied := false
	checkpoint := func(data []byte) error { checkpoints = append(checkpoints, append([]byte(nil), data...)); return nil }
	apply := func(data []byte) error {
		if len(checkpoints) != 2 {
			t.Error("reload preceded durable rotation/config")
		}
		stored, _, err := decodeIdentityState(checkpoints[1])
		if err != nil || !bytes.Equal(stored.Config, data) {
			t.Error("reload differs from restart checkpoint")
		}
		applied = true
		return nil
	}
	if err := refreshPooledIdentity(context.Background(), dn, state, &credentials, "network-FIXTURE", checkpoint, apply); err != nil {
		t.Fatal("valid renewal failed")
	}
	first, firstCredentials, err := decodeIdentityState(checkpoints[0])
	if err != nil || firstCredentials.Counter != 18 || bytes.Equal(first.Config, state.Config) {
		t.Fatal("rotation credentials were not saved before changing config")
	}
	if !applied || credentials.Counter != 18 || state.Counter != 18 {
		t.Fatal("rotated state not retained")
	}
}

func TestPooledRenewalRetainsCredentialsButRefusesRouteAndIdentityChange(t *testing.T) {
	for _, change := range []string{"route", "address", "network"} {
		t.Run(change, func(t *testing.T) {
			state, credentials, dn := pooledRenewalFixture(t)
			original := append([]byte(nil), state.Config...)
			switch change {
			case "route":
				dn.data = append(dn.data, []byte("\ntun:\n  unsafe_routes:\n    - route: 203.0.113.0/24\n      via: 100.100.1.2\n")...)
			case "address":
				dn.meta.Host.IPAddresses = []string{"100.100.1.2"}
			case "network":
				dn.meta.Network.ID = "network-FOREIGN"
			}
			checkpoints := 0
			save := func(data []byte) error {
				checkpoints++
				saved, c, err := decodeIdentityState(data)
				if err != nil || c.Counter != 18 || !bytes.Equal(saved.Config, original) {
					t.Error("old safe config/new credentials checkpoint missing")
				}
				return nil
			}
			applied := false
			if refreshPooledIdentity(context.Background(), dn, state, &credentials, "network-FIXTURE", save, func([]byte) error { applied = true; return nil }) == nil || applied || checkpoints != 1 {
				t.Fatal("unreviewed update applied or credentials lost")
			}
		})
	}
}

func TestPooledRenewalRefusesReloadAfterCheckpointFailure(t *testing.T) {
	for _, failedCheckpoint := range []int{1, 2} {
		state, credentials, dn := pooledRenewalFixture(t)
		saves := 0
		applied := false
		save := func([]byte) error {
			saves++
			if saves == failedCheckpoint {
				return errors.New("fixture write outage")
			}
			return nil
		}
		if refreshPooledIdentity(context.Background(), dn, state, &credentials, "network-FIXTURE", save, func([]byte) error { applied = true; return nil }) == nil || applied || credentials.Counter != 18 {
			t.Fatal("uncheckpointed update applied or next credentials discarded")
		}
	}
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
	data, err := encodeIdentityState(host, []string{"100.100.1.1"}, []byte("fixture config"), &keys.Credentials{
		HostID: host, Counter: counter, PrivateKey: generated.HostP256PrivateKey, TrustedKeys: []keys.TrustedKey{trust}})
	if err != nil {
		t.Fatal("state fixture failed")
	}
	return data
}

func TestPooledRenewalAllowsRouteOrderOnlyChange(t *testing.T) {
	state, credentials, dn := pooledRenewalFixture(t)
	first := "    - route: 10.30.0.0/26\n      via: 100.100.0.30\n      install: true\n"
	second := "    - route: 10.30.0.128/27\n      via: 100.100.0.30\n      install: true\n"
	state.Config = append(state.Config, []byte("\ntun:\n  unsafe_routes:\n"+first+second)...)
	dn.data = append(dn.data, []byte("\ntun:\n  unsafe_routes:\n"+second+first)...)
	checkpoints := 0
	applied := false
	err := refreshPooledIdentity(context.Background(), dn, state, &credentials, "network-FIXTURE",
		func([]byte) error { checkpoints++; return nil }, func([]byte) error { applied = true; return nil })
	if err != nil || !applied || checkpoints != 2 || credentials.Counter != 18 {
		t.Fatalf("unchanged route membership quarantined: checkpoints=%d applied=%v error=%v", checkpoints, applied, err)
	}
}
