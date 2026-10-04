package defined

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/DefinedNet/dnapi"
	"github.com/DefinedNet/dnapi/keys"
	"github.com/DefinedNet/dnapi/message"
)

const responseLimit = 2 << 20

var errControlPlane = errors.New("Defined control-plane request rejected")

// ErrTransientPoll classifies only positively identified read-only outages.
// It contains no response body, URL, credentials, or underlying error text.
var ErrTransientPoll = errors.New("Defined read-only poll temporarily unavailable")

// Client implements only the two DNClient operations needed by leased identities.
// It uses SDK public signing, key and wire types; it does not use its HTTP client.
type Client struct {
	http     http.Client
	endpoint string
}

// NewClient copies the supplied HTTP client and imposes a finite request timeout
// and redirect rejection. The transport must honor request cancellation.
func NewClient(base string, client *http.Client) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid Defined API URL")
	}
	c := http.Client{}
	if client != nil {
		c = *client
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		c.Timeout = 30 * time.Second
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	u.Path = message.EndpointV1
	return &Client{http: c, endpoint: u.String()}, nil
}

func (c *Client) request(ctx context.Context, operation string, value []byte, credentials keys.Credentials) ([]byte, error) {
	if credentials.PrivateKey == nil {
		return nil, errControlPlane
	}
	body, err := dnapi.SignRequestV1(operation, value, credentials.HostID, credentials.Counter, credentials.PrivateKey)
	if err != nil {
		return nil, errControlPlane
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errControlPlane
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vojeto/initial")
	resp, err := c.http.Do(req)
	if err != nil {
		var networkError net.Error
		if operation == message.CheckForUpdate && !errors.Is(ctx.Err(), context.Canceled) && errors.As(err, &networkError) && networkError.Timeout() {
			return nil, ErrTransientPoll
		}
		return nil, errControlPlane
	}
	defer resp.Body.Close()
	if resp.ContentLength > responseLimit {
		return nil, errControlPlane
	}
	// Error bodies can contain credentials or operator-controlled text. Never
	// read or include them in errors, and never retry a possibly accepted update.
	if operation == message.CheckForUpdate {
		switch resp.StatusCode {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return nil, ErrTransientPoll
		}
	}
	if resp.StatusCode != http.StatusOK || resp.ContentLength > responseLimit {
		return nil, errControlPlane
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if err != nil || len(data) > responseLimit {
		return nil, errControlPlane
	}
	return data, nil
}

func (c *Client) CheckForUpdate(ctx context.Context, credentials keys.Credentials) (bool, error) {
	data, err := c.request(ctx, message.CheckForUpdate, nil, credentials)
	if err != nil {
		return false, err
	}
	// Missing/null fields must not silently mean "no update".
	var result struct {
		Data *struct {
			Available *bool `json:"updateAvailable"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &result) != nil || result.Data == nil || result.Data.Available == nil {
		return false, errControlPlane
	}
	return *result.Data.Available, nil
}

func (c *Client) DoUpdate(ctx context.Context, credentials keys.Credentials) ([]byte, []byte, *keys.Credentials, *dnapi.ConfigMeta, error) {
	reject := func() ([]byte, []byte, *keys.Credentials, *dnapi.ConfigMeta, error) {
		return nil, nil, nil, nil, errControlPlane
	}
	if credentials.PrivateKey == nil {
		return reject()
	}
	generated, err := keys.New()
	if err != nil {
		return reject()
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return reject()
	}
	request := message.DoUpdateRequest{Nonce: nonce}
	var host keys.PrivateKey
	var nebula []byte
	switch credentials.PrivateKey.Unwrap().(type) {
	case ed25519.PrivateKey:
		if generated.HostEd25519PublicKey == nil {
			return reject()
		}
		request.HostPubkeyEd25519, err = generated.HostEd25519PublicKey.MarshalPEM()
		request.NebulaPubkeyX25519 = generated.NebulaX25519PublicKeyPEM
		host, nebula = generated.HostEd25519PrivateKey, generated.NebulaX25519PrivateKeyPEM
	case *ecdsa.PrivateKey:
		request.HostPubkeyP256, err = generated.HostP256PublicKey.MarshalPEM()
		request.NebulaPubkeyP256 = generated.NebulaP256PublicKeyPEM
		host, nebula = generated.HostP256PrivateKey, generated.NebulaP256PrivateKeyPEM
	default:
		return reject()
	}
	if err != nil {
		return reject()
	}
	value, err := json.Marshal(request)
	if err != nil {
		return reject()
	}
	data, err := c.request(ctx, message.DoUpdate, value, credentials)
	if err != nil {
		return reject()
	}
	var signed message.SignedResponseWrapper
	if json.Unmarshal(data, &signed) != nil || signed.Data.Version != 1 {
		return reject()
	}
	verified := false
	for _, key := range credentials.TrustedKeys {
		if key != nil && key.Verify(signed.Data.Message, signed.Data.Signature) {
			verified = true
			break
		}
	}
	if !verified {
		return reject()
	}
	var result message.DoUpdateResponse
	if json.Unmarshal(signed.Data.Message, &result) != nil || !bytes.Equal(result.Nonce, nonce) || result.Counter <= credentials.Counter {
		return reject()
	}
	trusted, err := keys.TrustedKeysFromPEM(result.TrustedKeys)
	if err != nil || len(trusted) == 0 {
		return reject()
	}
	next := &keys.Credentials{HostID: credentials.HostID, Counter: result.Counter, PrivateKey: host, TrustedKeys: trusted}
	addresses := result.Host.IPAddresses
	if len(addresses) == 0 && result.Host.IPAddress != "" {
		addresses = []string{result.Host.IPAddress}
	}
	meta := &dnapi.ConfigMeta{
		Org:     dnapi.ConfigOrg{ID: result.Organization.ID, Name: result.Organization.Name},
		Network: dnapi.ConfigNetwork{ID: result.Network.ID, Name: result.Network.Name},
		Host:    dnapi.ConfigHost{ID: result.Host.ID, Name: result.Host.Name, IPAddresses: addresses},
	}
	if result.EndpointOIDCMeta != nil {
		meta.EndpointOIDC = &dnapi.ConfigEndpointOIDC{Email: result.EndpointOIDCMeta.Email, ExpiresAt: result.EndpointOIDCMeta.ExpiresAt}
	}
	return result.Config, nebula, next, meta, nil
}

var _ pooledDNClient = (*Client)(nil)
