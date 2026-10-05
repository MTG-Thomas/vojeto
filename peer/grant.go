// Package peer supplies isolated, finite Nebula sessions to authenticated callers.
// Issuing a grant is a privileged operation; callers own operator/device authorization.
package peer

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
)

const MaxLifetime = 30 * time.Minute
const servicePort = 19001

var ErrRejected = errors.New("peer session rejected")

// Grant contains public certificates and signed policy, never endpoint private keys.
// Deliver it through an authenticated broker channel. Its self-contained CA is
// not a substitute for authenticating that channel or approving its destination.
type Grant struct {
	Version            int       `json:"version"`
	ID                 string    `json:"id"`
	Role               string    `json:"role"`
	Issued             time.Time `json:"issued"`
	Expires            time.Time `json:"expires"`
	CA                 string    `json:"ca"`
	Certificate        string    `json:"certificate"`
	Target             string    `json:"target"`
	TargetEndpoint     string    `json:"targetEndpoint,omitempty"`
	LighthouseEndpoint string    `json:"lighthouseEndpoint,omitempty"`
	Signature          []byte    `json:"signature"`
}

// Request is already-authorized policy supplied by the consumer, not a remote
// unauthenticated request. Keys are fresh X25519 public keys from each endpoint.
type Request struct {
	OperatorKey, TargetKey, LighthouseKey      []byte
	Target, TargetEndpoint, LighthouseEndpoint string
	Lifetime                                   time.Duration
	// Deadline is an alternative to Lifetime for an immutable broker lease.
	Deadline time.Time
}

// Keygen returns public bytes to send to the issuer and private PEM to retain locally.
func Keygen() (public, private []byte, err error) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, ErrRejected
	}
	return k.PublicKey().Bytes(), cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, k.Bytes()), nil
}

func endpoint(s string) bool {
	a, e := netip.ParseAddrPort(s)
	return e == nil && a.Addr().Is4() && a.Port() != 0 && !a.Addr().IsUnspecified() && !a.Addr().IsMulticast()
}
func target(s string) bool {
	a, e := netip.ParseAddrPort(s)
	return e == nil && a.Addr().Is4() && endpoint(s)
}
func signingBytes(g Grant) []byte { g.Signature = nil; b, _ := json.Marshal(g); return b }

// Issue creates a new per-session CA in memory. The signing key is not returned
// or persisted, so this session cannot silently acquire additional peers.
func Issue(r Request) (map[string]Grant, error) {
	if !r.Deadline.IsZero() {
		if r.Lifetime != 0 {
			return nil, ErrRejected
		}
		r.Lifetime = time.Until(r.Deadline)
	}
	if r.Lifetime < time.Second || r.Lifetime > MaxLifetime || !target(r.Target) || len(r.OperatorKey) != 32 || len(r.TargetKey) != 32 || bytes.Equal(r.OperatorKey, r.TargetKey) {
		return nil, ErrRejected
	}
	if r.TargetEndpoint != "" && !endpoint(r.TargetEndpoint) {
		return nil, ErrRejected
	}
	if r.LighthouseEndpoint != "" && (!endpoint(r.LighthouseEndpoint) || len(r.LighthouseKey) != 32 || bytes.Equal(r.LighthouseKey, r.OperatorKey) || bytes.Equal(r.LighthouseKey, r.TargetKey)) {
		return nil, ErrRejected
	}
	if r.TargetEndpoint == "" && r.LighthouseEndpoint == "" || r.LighthouseEndpoint == "" && len(r.LighthouseKey) != 0 {
		return nil, ErrRejected
	}
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return nil, ErrRejected
	}
	id := hex.EncodeToString(nonce)
	now := time.Now().UTC().Truncate(time.Second)
	expiry := now.Add(r.Lifetime).Truncate(time.Second)
	if !r.Deadline.IsZero() {
		expiry = r.Deadline.UTC().Truncate(time.Second)
		if !expiry.After(now) {
			return nil, ErrRejected
		}
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, ErrRejected
	}
	defer clear(priv)
	ca, e := (&cert.TBSCertificate{Version: cert.Version2, Curve: cert.Curve_CURVE25519, Name: "vojeto-session-" + id, IsCA: true, NotBefore: now.Add(-time.Second), NotAfter: expiry, PublicKey: pub}).Sign(nil, cert.Curve_CURVE25519, priv)
	if e != nil {
		return nil, ErrRejected
	}
	pem, e := ca.MarshalPEM()
	if e != nil {
		return nil, ErrRejected
	}
	keys := map[string][]byte{"operator": r.OperatorKey, "target": r.TargetKey}
	if r.LighthouseEndpoint != "" {
		keys["lighthouse"] = r.LighthouseKey
	}
	grants := make(map[string]Grant)
	for role, key := range keys {
		// Reject malformed/low-order X25519 public keys before signing them.
		parsed, e := ecdh.X25519().NewPublicKey(key)
		if e != nil {
			return nil, ErrRejected
		}
		probe, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return nil, ErrRejected
		}
		if _, e = probe.ECDH(parsed); e != nil {
			return nil, ErrRejected
		}
		c, e := (&cert.TBSCertificate{Version: cert.Version2, Curve: cert.Curve_CURVE25519, Name: id + "/" + role, NotBefore: now.Add(-time.Second), NotAfter: expiry, PublicKey: key, Networks: []netip.Prefix{netip.PrefixFrom(address(role), 24)}}).Sign(ca, cert.Curve_CURVE25519, priv)
		if e != nil {
			return nil, ErrRejected
		}
		cPEM, e := c.MarshalPEM()
		if e != nil {
			return nil, ErrRejected
		}
		g := Grant{Version: 1, ID: id, Role: role, Issued: now, Expires: expiry, CA: string(pem), Certificate: string(cPEM), Target: r.Target, TargetEndpoint: r.TargetEndpoint, LighthouseEndpoint: r.LighthouseEndpoint}
		g.Signature = ed25519.Sign(priv, signingBytes(g))
		grants[role] = g
	}
	return grants, nil
}
func address(role string) netip.Addr {
	switch role {
	case "target":
		return netip.MustParseAddr("192.0.2.1")
	case "operator":
		return netip.MustParseAddr("192.0.2.2")
	case "lighthouse":
		return netip.MustParseAddr("192.0.2.3")
	}
	return netip.Addr{}
}

// Validate binds the signed policy to the local key and role, including expiry.
func Validate(g Grant, private []byte, role string) error {
	now := time.Now()
	id, e := hex.DecodeString(g.ID)
	if e != nil || len(id) != 16 || g.Version != 1 || g.Role != role || !address(role).IsValid() || !target(g.Target) || g.Expires.Sub(g.Issued) > MaxLifetime || !g.Expires.After(g.Issued) || g.Issued.After(now.Add(time.Second)) || !g.Expires.After(now) {
		return ErrRejected
	}
	if g.TargetEndpoint != "" && !endpoint(g.TargetEndpoint) || g.LighthouseEndpoint != "" && !endpoint(g.LighthouseEndpoint) || g.TargetEndpoint == "" && g.LighthouseEndpoint == "" || role == "lighthouse" && g.LighthouseEndpoint == "" {
		return ErrRejected
	}
	ca, rest, e := cert.UnmarshalCertificateFromPEM([]byte(g.CA))
	if e != nil || len(bytes.TrimSpace(rest)) != 0 || !ca.IsCA() || ca.Curve() != cert.Curve_CURVE25519 || ca.Name() != "vojeto-session-"+g.ID || len(ca.PublicKey()) != ed25519.PublicKeySize || !ca.NotAfter().Equal(g.Expires) {
		return ErrRejected
	}
	if !ed25519.Verify(ca.PublicKey(), signingBytes(g), g.Signature) {
		return ErrRejected
	}
	cp, e := cert.NewCAPoolFromPEM([]byte(g.CA))
	if e != nil {
		return ErrRejected
	}
	leaf, rest, e := cert.UnmarshalCertificateFromPEM([]byte(g.Certificate))
	if e != nil || len(bytes.TrimSpace(rest)) != 0 {
		return ErrRejected
	}
	if _, e = cp.VerifyCertificate(now, leaf); e != nil {
		return ErrRejected
	}
	if leaf.IsCA() || leaf.Curve() != cert.Curve_CURVE25519 || leaf.Name() != g.ID+"/"+role || !leaf.NotAfter().Equal(g.Expires) || len(leaf.Networks()) != 1 || leaf.Networks()[0] != netip.PrefixFrom(address(role), 24) || len(leaf.UnsafeNetworks()) != 0 || len(leaf.Groups()) != 0 {
		return ErrRejected
	}
	raw, rest, curve, e := cert.UnmarshalPrivateKeyFromPEM(private)
	if e != nil || len(bytes.TrimSpace(rest)) != 0 || curve != cert.Curve_CURVE25519 {
		return ErrRejected
	}
	defer clear(raw)
	key, e := ecdh.X25519().NewPrivateKey(raw)
	if e != nil || !bytes.Equal(key.PublicKey().Bytes(), leaf.PublicKey()) {
		return ErrRejected
	}
	return nil
}
