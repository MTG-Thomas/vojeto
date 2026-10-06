// Package definedwire implements the enrollment and signed update wire contract.
// Its codecs are independently written; the Defined SDK is not a dependency.
package definedwire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/definedwire/credentials"
	"go.yaml.in/yaml/v3"
	"io"
	"time"
)

const (
	EndpointV1     = "/v1/dnclient"
	EnrollEndpoint = "/v2/enroll"
	CheckForUpdate = "CheckForUpdate"
	DoUpdate       = "DoUpdate"
)

type NetworkCurve string

const (
	NetworkCurve25519 NetworkCurve = "25519"
	NetworkCurveP256  NetworkCurve = "P256"
)

type RequestWrapper struct {
	Type      string    `json:"type"`
	Value     []byte    `json:"value"`
	Timestamp time.Time `json:"timestamp"`
}
type RequestV1 struct {
	Version   int    `json:"version"`
	HostID    string `json:"hostID"`
	Counter   uint   `json:"counter"`
	Message   string `json:"message"`
	Signature []byte `json:"signature"`
}

func SignRequestV1(operation string, value []byte, host string, counter uint, key credentials.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("missing request signing key")
	}
	inner, err := json.Marshal(RequestWrapper{Type: operation, Value: value, Timestamp: time.Now().UTC()})
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(inner)
	signature, err := key.Sign([]byte(encoded))
	if err != nil {
		return nil, err
	}
	return json.Marshal(RequestV1{Version: 1, HostID: host, Counter: counter, Message: encoded, Signature: signature})
}

type SignedResponse struct {
	Version   int    `json:"version"`
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}
type SignedResponseWrapper struct {
	Data SignedResponse `json:"data"`
}
type CheckForUpdateResponse struct {
	UpdateAvailable bool `json:"updateAvailable"`
}
type CheckForUpdateResponseWrapper struct {
	Data CheckForUpdateResponse `json:"data"`
}
type DoUpdateRequest struct {
	HostPubkeyEd25519  []byte `json:"edPubkeyPEM"`
	NebulaPubkeyX25519 []byte `json:"dhPubkeyPEM"`
	HostPubkeyP256     []byte `json:"p256HostPubkeyPEM"`
	NebulaPubkeyP256   []byte `json:"p256NebulaPubkeyPEM"`
	Nonce              []byte `json:"nonce"`
}
type HostOrganizationMetadata struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type HostNetworkMetadata struct {
	ID    string       `json:"id"`
	Name  string       `json:"name"`
	Curve NetworkCurve `json:"curve"`
	CIDR  string       `json:"cidr"`
	CIDRs []string     `json:"cidrs"`
}
type HostHostMetadata struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	IPAddress   string   `json:"ipAddress"`
	IPAddresses []string `json:"ipAddresses"`
}
type EndpointOIDCMetadata struct {
	Email     string     `json:"email"`
	ExpiresAt *time.Time `json:"expiresAt"`
}
type DoUpdateResponse struct {
	Config           []byte                   `json:"config"`
	Counter          uint                     `json:"counter"`
	Nonce            []byte                   `json:"nonce"`
	TrustedKeys      []byte                   `json:"trustedKeys"`
	Organization     HostOrganizationMetadata `json:"organization"`
	Network          HostNetworkMetadata      `json:"network"`
	Host             HostHostMetadata         `json:"host"`
	EndpointOIDCMeta *EndpointOIDCMetadata    `json:"endpointOIDC"`
}
type EnrollRequest struct {
	Code               string    `json:"code"`
	NebulaPubkeyX25519 []byte    `json:"dhPubkey"`
	HostPubkeyEd25519  []byte    `json:"edPubkey"`
	NebulaPubkeyP256   []byte    `json:"nebulaPubkeyP256"`
	HostPubkeyP256     []byte    `json:"hostPubkeyP256"`
	Timestamp          time.Time `json:"timestamp"`
	Hostname           string    `json:"hostname,omitempty"`
}
type EnrollResponseData struct {
	HostID           string                   `json:"hostID"`
	Config           []byte                   `json:"config"`
	Counter          uint                     `json:"counter"`
	TrustedKeys      []byte                   `json:"trustedKeys"`
	Organization     HostOrganizationMetadata `json:"organization"`
	Network          HostNetworkMetadata      `json:"network"`
	Host             HostHostMetadata         `json:"host"`
	EndpointOIDCMeta *EndpointOIDCMetadata    `json:"endpointOIDC"`
}
type ConfigOrg struct{ ID, Name string }
type ConfigNetwork struct{ ID, Name string }
type ConfigHost struct {
	ID, Name    string
	IPAddresses []string
}
type ConfigEndpointOIDC struct {
	Email     string
	ExpiresAt *time.Time
}
type ConfigMeta struct {
	Org          ConfigOrg
	Network      ConfigNetwork
	Host         ConfigHost
	EndpointOIDC *ConfigEndpointOIDC
}

// InsertConfigPrivateKey preserves the document while replacing only pki.key.
func InsertConfigPrivateKey(config, key []byte) ([]byte, error) {
	rejected := errors.New("invalid Nebula configuration")
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(config))
	if decoder.Decode(&document) != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, rejected
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return nil, rejected
	}
	root := document.Content[0]
	var pki *yaml.Node
	seen := map[string]bool{}
	for i := 0; i < len(root.Content); i += 2 {
		name := root.Content[i].Value
		if seen[name] {
			return nil, rejected
		}
		seen[name] = true
		if name == "pki" {
			pki = root.Content[i+1]
		}
	}
	if pki == nil || pki.Kind != yaml.MappingNode {
		return nil, rejected
	}
	seen = map[string]bool{}
	found := false
	for i := 0; i < len(pki.Content); i += 2 {
		name := pki.Content[i].Value
		if seen[name] {
			return nil, rejected
		}
		seen[name] = true
		if name == "key" {
			pki.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(key)}
			found = true
		}
	}
	if !found {
		pki.Content = append(pki.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "key"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(key)})
	}
	return yaml.Marshal(&document)
}
