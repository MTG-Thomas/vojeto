// Package credentials implements Vojeto's checkpoint and signature codecs with
// Go crypto primitives and Nebula's licensed PEM codec. It contains no SDK code.
package credentials

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/slackhq/nebula/cert"
)

var invalidKey = errors.New("invalid Defined protocol key")

// Host signing keys use X.509 DER; Nebula identity and trusted keys use raw PEM.
const edPublic = "DEFINED HOST ED25519 PUBLIC KEY"
const edPrivate = "DEFINED HOST ED25519 PRIVATE KEY"
const ecPublic = "DEFINED HOST P256 PUBLIC KEY"
const ecPrivate = "DEFINED HOST P256 PRIVATE KEY"

type PublicKey interface {
	Unwrap() any
	MarshalPEM() ([]byte, error)
}
type PrivateKey interface {
	Public() PublicKey
	Unwrap() any
	MarshalPEM() ([]byte, error)
	Sign([]byte) ([]byte, error)
}
type TrustedKey interface {
	Verify([]byte, []byte) bool
	MarshalPEM() ([]byte, error)
}
type Credentials struct {
	HostID      string
	Counter     uint
	PrivateKey  PrivateKey
	TrustedKeys []TrustedKey
}

type private struct{ value any }
type public struct{ value any }
type trusted struct{ value any }

func validPublic(value any) bool {
	switch k := value.(type) {
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize
	case *ecdsa.PublicKey:
		return k != nil && k.Curve == elliptic.P256() && k.X != nil && k.Y != nil && k.Curve.IsOnCurve(k.X, k.Y)
	}
	return false
}
func (p public) Unwrap() any  { return p.value }
func (p private) Unwrap() any { return p.value }
func (p private) Public() PublicKey {
	switch k := p.value.(type) {
	case ed25519.PrivateKey:
		return public{k.Public()}
	case *ecdsa.PrivateKey:
		return public{k.Public()}
	}
	return nil
}
func (p public) MarshalPEM() ([]byte, error) {
	if !validPublic(p.value) {
		return nil, invalidKey
	}
	der, err := x509.MarshalPKIXPublicKey(p.value)
	if err != nil {
		return nil, invalidKey
	}
	banner := edPublic
	if _, ok := p.value.(*ecdsa.PublicKey); ok {
		banner = ecPublic
	}
	return pem.EncodeToMemory(&pem.Block{Type: banner, Bytes: der}), nil
}
func (p private) MarshalPEM() ([]byte, error) {
	var der []byte
	var err error
	var banner string
	switch k := p.value.(type) {
	case ed25519.PrivateKey:
		der, err = x509.MarshalPKCS8PrivateKey(k)
		banner = edPrivate
	case *ecdsa.PrivateKey:
		der, err = x509.MarshalECPrivateKey(k)
		banner = ecPrivate
	default:
		return nil, invalidKey
	}
	if err != nil {
		return nil, invalidKey
	}
	return pem.EncodeToMemory(&pem.Block{Type: banner, Bytes: der}), nil
}
func (p private) Sign(data []byte) ([]byte, error) {
	switch k := p.value.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, invalidKey
		}
		return ed25519.Sign(k, data), nil
	case *ecdsa.PrivateKey:
		hash := sha256.Sum256(data)
		signature, err := ecdsa.SignASN1(rand.Reader, k, hash[:])
		if err != nil {
			return nil, invalidKey
		}
		return signature, nil
	}
	return nil, invalidKey
}
func NewTrustedKey(value any) (TrustedKey, error) {
	if !validPublic(value) {
		return nil, invalidKey
	}
	return trusted{value}, nil
}
func (t trusted) Verify(data, signature []byte) bool {
	switch k := t.value.(type) {
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize && ed25519.Verify(k, data, signature)
	case *ecdsa.PublicKey:
		hash := sha256.Sum256(data)
		return validPublic(k) && ecdsa.VerifyASN1(k, hash[:], signature)
	}
	return false
}
func (t trusted) MarshalPEM() ([]byte, error) {
	if !validPublic(t.value) {
		return nil, invalidKey
	}
	switch k := t.value.(type) {
	case ed25519.PublicKey:
		return cert.MarshalSigningPublicKeyToPEM(cert.Curve_CURVE25519, k), nil
	case *ecdsa.PublicKey:
		dh, err := k.ECDH()
		if err != nil {
			return nil, invalidKey
		}
		return cert.MarshalSigningPublicKeyToPEM(cert.Curve_P256, dh.Bytes()), nil
	}
	return nil, invalidKey
}
func TrustedKeysToPEM(keys []TrustedKey) ([]byte, error) {
	var out bytes.Buffer
	for _, key := range keys {
		if key == nil {
			return nil, invalidKey
		}
		data, err := key.MarshalPEM()
		if err != nil {
			return nil, invalidKey
		}
		out.Write(data)
	}
	return out.Bytes(), nil
}
func TrustedKeysFromPEM(data []byte) ([]TrustedKey, error) {
	var out []TrustedKey
	for len(bytes.TrimSpace(data)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
			return nil, invalidKey
		}
		raw, rest, curve, err := cert.UnmarshalSigningPublicKeyFromPEM(data)
		if err != nil {
			return nil, invalidKey
		}
		var value any
		switch curve {
		case cert.Curve_CURVE25519:
			value = ed25519.PublicKey(raw)
		case cert.Curve_P256:
			dh, err := ecdh.P256().NewPublicKey(raw)
			if err != nil {
				return nil, invalidKey
			}
			x, y := elliptic.Unmarshal(elliptic.P256(), dh.Bytes())
			if x == nil {
				return nil, invalidKey
			}
			value = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		default:
			return nil, invalidKey
		}
		key, err := NewTrustedKey(value)
		if err != nil {
			return nil, invalidKey
		}
		out = append(out, key)
		data = rest
	}
	if len(out) == 0 {
		return nil, invalidKey
	}
	return out, nil
}
func decodeHost(data []byte) (*pem.Block, []byte, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
		return nil, nil, invalidKey
	}
	block, rest := pem.Decode(data)
	if block == nil || len(block.Headers) != 0 {
		return nil, nil, invalidKey
	}
	return block, rest, nil
}
func UnmarshalHostPrivateKey(data []byte) (PrivateKey, []byte, error) {
	block, rest, err := decodeHost(data)
	if err != nil {
		return nil, nil, err
	}
	var value any
	switch block.Type {
	case edPrivate:
		value, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, ok := value.(ed25519.PrivateKey)
		if !ok || len(key) != ed25519.PrivateKeySize {
			return nil, nil, invalidKey
		}
	case ecPrivate:
		value, err = x509.ParseECPrivateKey(block.Bytes)
		key, ok := value.(*ecdsa.PrivateKey)
		if !ok || key == nil || !validPublic(&key.PublicKey) {
			return nil, nil, invalidKey
		}
	default:
		return nil, nil, invalidKey
	}
	if err != nil {
		return nil, nil, invalidKey
	}
	return private{value}, rest, nil
}
func parsePublic(data []byte, banner string) (any, []byte, error) {
	block, rest, err := decodeHost(data)
	if err != nil || block.Type != banner {
		return nil, nil, invalidKey
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil || !validPublic(value) {
		return nil, nil, invalidKey
	}
	return value, rest, nil
}
func UnmarshalHostEd25519PublicKey(data []byte) (ed25519.PublicKey, []byte, error) {
	value, rest, err := parsePublic(data, edPublic)
	key, ok := value.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, nil, invalidKey
	}
	return key, rest, nil
}
func UnmarshalHostP256PublicKey(data []byte) (*ecdsa.PublicKey, []byte, error) {
	value, rest, err := parsePublic(data, ecPublic)
	key, ok := value.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return nil, nil, invalidKey
	}
	return key, rest, nil
}

type Generated struct {
	HostEd25519PrivateKey, HostP256PrivateKey                                                            PrivateKey
	HostEd25519PublicKey, HostP256PublicKey                                                              PublicKey
	NebulaX25519PrivateKeyPEM, NebulaX25519PublicKeyPEM, NebulaP256PrivateKeyPEM, NebulaP256PublicKeyPEM []byte
}

func New() (*Generated, error) {
	result := &Generated{}
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, invalidKey
	}
	dh, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, invalidKey
	}
	result.HostP256PrivateKey = private{signing}
	result.HostP256PublicKey = result.HostP256PrivateKey.Public()
	result.NebulaP256PrivateKeyPEM = cert.MarshalPrivateKeyToPEM(cert.Curve_P256, dh.Bytes())
	result.NebulaP256PublicKeyPEM = cert.MarshalPublicKeyToPEM(cert.Curve_P256, dh.PublicKey().Bytes())
	if !fips140.Enabled() {
		_, signing, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, invalidKey
		}
		dh, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, invalidKey
		}
		result.HostEd25519PrivateKey = private{signing}
		result.HostEd25519PublicKey = result.HostEd25519PrivateKey.Public()
		result.NebulaX25519PrivateKeyPEM = cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, dh.Bytes())
		result.NebulaX25519PublicKeyPEM = cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, dh.PublicKey().Bytes())
	}
	return result, nil
}
