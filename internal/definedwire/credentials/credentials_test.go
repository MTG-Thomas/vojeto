package credentials

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// RFC 8032 section 7.1, test 1 is an independent known-answer signature.
func TestRFC8032(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	expected, _ := hex.DecodeString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	key := private{ed25519.NewKeyFromSeed(seed)}
	signature, err := key.Sign(nil)
	if err != nil || hex.EncodeToString(signature) != hex.EncodeToString(expected) {
		t.Fatal("known answer mismatch")
	}
	trust, err := NewTrustedKey(key.Public().Unwrap())
	if err != nil || !trust.Verify(nil, expected) || trust.Verify([]byte("changed"), expected) {
		t.Fatal("verification mismatch")
	}
}
func TestPEMRoundtripAndTampering(t *testing.T) {
	generated, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []PrivateKey{generated.HostEd25519PrivateKey, generated.HostP256PrivateKey} {
		if key == nil {
			continue
		}
		encoded, err := key.MarshalPEM()
		if err != nil {
			t.Fatal(err)
		}
		decoded, rest, err := UnmarshalHostPrivateKey(encoded)
		if err != nil || len(rest) != 0 {
			t.Fatal("private checkpoint decode")
		}
		trust, _ := NewTrustedKey(key.Public().Unwrap())
		bundle, _ := TrustedKeysToPEM([]TrustedKey{trust})
		trusted, err := TrustedKeysFromPEM(bundle)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := decoded.Sign([]byte("wire bytes"))
		if err != nil || !trusted[0].Verify([]byte("wire bytes"), signature) || trusted[0].Verify([]byte("wrong bytes"), signature) {
			t.Fatal("signature verification")
		}
		if _, err := TrustedKeysFromPEM(append([]byte("junk"), bundle...)); err == nil {
			t.Fatal("accepted prefixed junk")
		}
	}
	if _, err := TrustedKeysFromPEM(nil); err == nil {
		t.Fatal("empty trust set")
	}
	if _, _, err := UnmarshalHostPrivateKey([]byte("invalid")); err == nil {
		t.Fatal("invalid private key")
	}
}
