package defined

import (
	"bytes"
	"github.com/DefinedNet/dnapi/keys"
	"testing"
)

func TestIdentityCheckpointPreservesRotatedSDKCredentials(t *testing.T) {
	generated, err := keys.New()
	if err != nil {
		t.Fatal("key generation failed")
	}
	for _, private := range []keys.PrivateKey{generated.HostEd25519PrivateKey, generated.HostP256PrivateKey} {
		if private == nil {
			continue
		} // SDK omits Ed25519 in FIPS-only mode.
		trusted, err := keys.NewTrustedKey(private.Public().Unwrap())
		if err != nil {
			t.Fatal("trust fixture failed")
		}
		original := &keys.Credentials{HostID: "host-IDENTITYTEST", Counter: 17, PrivateKey: private, TrustedKeys: []keys.TrustedKey{trusted}}
		encoded, err := encodeIdentityState(original.HostID, []string{"100.100.1.1"}, []byte("fixture config"), original)
		if err != nil {
			t.Fatal("identity checkpoint failed")
		}
		state, restored, err := decodeIdentityState(encoded)
		if err != nil || restored.Counter != 17 || restored.HostID != original.HostID || !bytes.Equal(state.Config, []byte("fixture config")) {
			t.Fatal("checkpoint lost config or SDK identity/counter")
		}
		message := []byte("post-restart SDK authentication")
		signature, err := restored.PrivateKey.Sign(message)
		if err != nil || !restored.TrustedKeys[0].Verify(message, signature) {
			t.Fatal("restored credentials cannot authenticate")
		}
		if restored.TrustedKeys[0].Verify([]byte("wrong request"), signature) {
			t.Fatal("restored trust accepted another request")
		}
	}
}

func TestIdentityCheckpointRejectsAmbiguousAndForeignState(t *testing.T) {
	for _, payload := range [][]byte{nil, bytes.Repeat([]byte("x"), maximumIdentityStateBytes+1), []byte(`{"version":2}`), []byte(`{"version":1,"unexpected":"secret"}`), []byte(`{"version":1} {"version":1}`), []byte(`{"version":1,"hostId":"host-OTHER","addresses":["100.100.1.1"],"config":"YQ=="}`)} {
		if _, _, err := decodeIdentityState(payload); err == nil {
			t.Fatal("invalid identity state accepted")
		}
	}
	generated, err := keys.New()
	if err != nil {
		t.Fatal("key generation failed")
	}
	if _, err := encodeIdentityState("host-EXPECTED", []string{"100.100.1.1"}, []byte("config"), &keys.Credentials{HostID: "host-FOREIGN", PrivateKey: generated.HostP256PrivateKey}); err == nil {
		t.Fatal("foreign SDK identity accepted")
	}
}
