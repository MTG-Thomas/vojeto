package defined

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/DefinedNet/dnapi/keys"
	"io"
	"regexp"
)

// Secret state for an exclusively leased Blob, never a receipt or log record.
// Persist SDK credentials as well as Nebula config: DoUpdate rotates the former.
type identityState struct {
	Version     int      `json:"version"`
	HostID      string   `json:"hostId"`
	Addresses   []string `json:"addresses"`
	Config      []byte   `json:"config"`
	Counter     uint     `json:"counter"`
	PrivateKey  []byte   `json:"privateKey"`
	TrustedKeys []byte   `json:"trustedKeys"`
}

const maximumIdentityStateBytes = 1024 * 1024

func encodeIdentityState(hostID string, addresses []string, config []byte, credentials *keys.Credentials) ([]byte, error) {
	if credentials == nil || credentials.HostID != hostID || credentials.PrivateKey == nil || len(credentials.TrustedKeys) == 0 {
		return nil, errors.New("invalid identity credentials")
	}
	private, err := credentials.PrivateKey.MarshalPEM()
	if err != nil {
		return nil, errors.New("identity private key encoding failed")
	}
	trusted, err := keys.TrustedKeysToPEM(credentials.TrustedKeys)
	if err != nil {
		return nil, errors.New("identity trust encoding failed")
	}
	state := identityState{1, hostID, addresses, config, credentials.Counter, private, trusted}
	encoded, err := json.Marshal(state)
	if err != nil {
		return nil, errors.New("identity encoding failed")
	}
	if _, _, err := decodeIdentityState(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func decodeIdentityState(encoded []byte) (*identityState, *keys.Credentials, error) {
	if len(encoded) == 0 || len(encoded) > maximumIdentityStateBytes {
		return nil, nil, errors.New("identity state size rejected")
	}
	var state identityState
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, nil, errors.New("identity state encoding rejected")
	}
	if state.Version != 1 || !regexp.MustCompile(`^host-[A-Z0-9]+$`).MatchString(state.HostID) || len(state.Config) == 0 || len(state.Addresses) == 0 {
		return nil, nil, errors.New("identity state metadata rejected")
	}
	private, remainder, err := keys.UnmarshalHostPrivateKey(state.PrivateKey)
	if err != nil || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, nil, errors.New("identity private key rejected")
	}
	trusted, err := keys.TrustedKeysFromPEM(state.TrustedKeys)
	if err != nil || len(trusted) == 0 {
		return nil, nil, errors.New("identity trust rejected")
	}
	return &state, &keys.Credentials{HostID: state.HostID, PrivateKey: private, Counter: state.Counter, TrustedKeys: trusted}, nil
}

// EncodeState serializes secret SDK credentials for an exclusive state store.
func EncodeState(host string, addresses []string, config []byte, c *keys.Credentials) ([]byte, error) {
	return encodeIdentityState(host, addresses, config, c)
}

// DecodeState validates a bounded secret checkpoint.
func DecodeState(data []byte) (*identityState, *keys.Credentials, error) {
	return decodeIdentityState(data)
}
