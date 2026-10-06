package defined

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/definedwire"
	wirekeys "github.com/MTG-Thomas/vojeto/internal/definedwire/credentials"
)

// ErrUncertainEnrollment requires reconciliation by the exclusive grant owner.
// Enrollment is never retried: a failed response may follow remote acceptance.
var ErrUncertainEnrollment = errors.New("Defined enrollment requires reconciliation")

// Enroll consumes an externally supplied one-time code in memory. The caller
// must fence the grant, validate returned identity/network/route policy, and
// checkpoint accepted credentials before starting transport. This method does
// not acquire ownership or make an identity ready for transport.
func (c *Client) Enroll(ctx context.Context, code, hostname string) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error) {
	reject := func() ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error) {
		return nil, nil, nil, nil, ErrUncertainEnrollment
	}
	if len(code) == 0 || len(code) > 8192 || len(hostname) > 253 || ctx.Err() != nil {
		return reject()
	}
	generated, err := wirekeys.New()
	if err != nil {
		return reject()
	}
	var ed []byte
	if generated.HostEd25519PublicKey != nil {
		ed, err = generated.HostEd25519PublicKey.MarshalPEM()
		if err != nil {
			return reject()
		}
	}
	p256, err := generated.HostP256PublicKey.MarshalPEM()
	if err != nil {
		return reject()
	}
	value, err := json.Marshal(definedwire.EnrollRequest{Code: code, Hostname: hostname, Timestamp: time.Now().UTC(), HostPubkeyEd25519: ed, HostPubkeyP256: p256, NebulaPubkeyX25519: generated.NebulaX25519PublicKeyPEM, NebulaPubkeyP256: generated.NebulaP256PublicKeyPEM})
	if err != nil {
		return reject()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.enrollmentEndpoint, bytes.NewReader(value))
	if err != nil {
		return reject()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vojeto/initial")
	resp, err := c.http.Do(req)
	if err != nil {
		return reject()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > responseLimit {
		return reject()
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if err != nil || len(data) > responseLimit {
		return reject()
	}
	var result struct {
		Data *struct {
			definedwire.EnrollResponseData
			Counter *uint `json:"counter"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &result) != nil || result.Data == nil || result.Data.Counter == nil {
		return reject()
	}
	enrolled := result.Data.EnrollResponseData
	enrolled.Counter = *result.Data.Counter
	if enrolled.HostID == "" || enrolled.HostID != enrolled.Host.ID || enrolled.Network.ID == "" || len(enrolled.Config) == 0 {
		return reject()
	}
	trusted, err := wirekeys.TrustedKeysFromPEM(enrolled.TrustedKeys)
	if err != nil || len(trusted) == 0 {
		return reject()
	}
	var host wirekeys.PrivateKey
	var nebula []byte
	switch enrolled.Network.Curve {
	case definedwire.NetworkCurve25519:
		if generated.HostEd25519PrivateKey == nil || len(generated.NebulaX25519PrivateKeyPEM) == 0 {
			return reject()
		}
		host, nebula = generated.HostEd25519PrivateKey, generated.NebulaX25519PrivateKeyPEM
	case definedwire.NetworkCurveP256:
		host, nebula = generated.HostP256PrivateKey, generated.NebulaP256PrivateKeyPEM
	default:
		return reject()
	}
	addresses := enrolled.Host.IPAddresses
	if len(addresses) == 0 && enrolled.Host.IPAddress != "" {
		addresses = []string{enrolled.Host.IPAddress}
	}
	if len(addresses) == 0 {
		return reject()
	}
	credentials := &wirekeys.Credentials{HostID: enrolled.HostID, Counter: enrolled.Counter, PrivateKey: host, TrustedKeys: trusted}
	meta := &definedwire.ConfigMeta{Org: definedwire.ConfigOrg{ID: enrolled.Organization.ID, Name: enrolled.Organization.Name}, Network: definedwire.ConfigNetwork{ID: enrolled.Network.ID, Name: enrolled.Network.Name}, Host: definedwire.ConfigHost{ID: enrolled.Host.ID, Name: enrolled.Host.Name, IPAddresses: addresses}}
	if enrolled.EndpointOIDCMeta != nil {
		meta.EndpointOIDC = &definedwire.ConfigEndpointOIDC{Email: enrolled.EndpointOIDCMeta.Email, ExpiresAt: enrolled.EndpointOIDCMeta.ExpiresAt}
	}
	return enrolled.Config, nebula, credentials, meta, nil
}
