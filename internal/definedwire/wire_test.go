package definedwire

import (
	"encoding/base64"
	"encoding/json"
	"github.com/MTG-Thomas/vojeto/internal/definedwire/credentials"
	"go.yaml.in/yaml/v3"
	"testing"
)

func TestSignedRequestCoversEncodedMessage(t *testing.T) {
	keys, err := credentials.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []credentials.PrivateKey{keys.HostEd25519PrivateKey, keys.HostP256PrivateKey} {
		if key == nil {
			continue
		}
		data, err := SignRequestV1(DoUpdate, []byte("payload"), "host-test", 9, key)
		if err != nil {
			t.Fatal(err)
		}
		var outer RequestV1
		if json.Unmarshal(data, &outer) != nil {
			t.Fatal("invalid envelope")
		}
		raw, err := base64.StdEncoding.DecodeString(outer.Message)
		if err != nil {
			t.Fatal(err)
		}
		trust, _ := credentials.NewTrustedKey(key.Public().Unwrap())
		if !trust.Verify([]byte(outer.Message), outer.Signature) || trust.Verify(raw, outer.Signature) {
			t.Fatal("wrong signed representation")
		}
		var inner RequestWrapper
		if json.Unmarshal(raw, &inner) != nil || inner.Type != DoUpdate || string(inner.Value) != "payload" || inner.Timestamp.IsZero() || outer.Version != 1 || outer.HostID != "host-test" || outer.Counter != 9 {
			t.Fatal("wire fields")
		}
	}
}
func TestPrivateKeyInsertion(t *testing.T) {
	result, err := InsertConfigPrivateKey([]byte("pki:\n  cert: fixture\n  key: old\nstatic_host_map:\n  192.0.2.1: [example:4242]\n"), []byte("private\nkey\n"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if yaml.Unmarshal(result, &parsed) != nil {
		t.Fatal("invalid YAML")
	}
	pki := parsed["pki"].(map[string]any)
	if pki["cert"] != "fixture" || pki["key"] != "private\nkey\n" || parsed["static_host_map"] == nil {
		t.Fatal("lost configuration")
	}
	for _, bad := range []string{"[]", "pki: []", "pki: {}\npki: {}", "pki:\n  key: a\n  key: b", "pki: {}\n---\npki: {}"} {
		if _, err := InsertConfigPrivateKey([]byte(bad), nil); err == nil {
			t.Fatal("accepted invalid document", bad)
		}
	}
}
