package defined

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/definedwire"
	wirekeys "github.com/MTG-Thomas/vojeto/internal/definedwire/credentials"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
)

// EnrollmentGrant contains a secret one-time code and caller-approved constraints.
// RoutePolicy is a Nebula YAML fragment containing the approved tun.unsafe_routes;
// {} explicitly approves no unsafe routes. Addresses pins a known allocation;
// AddressRanges approves an allocation whose address is not known until enrollment.
// At least one is required; when both are supplied, both must match.
// Never render a grant in diagnostics.
type EnrollmentGrant struct {
	Code, HostID, NetworkID string
	Addresses               []string
	AddressRanges           []netip.Prefix
	RoutePolicy             []byte
}

// GrantSource runs only after exclusive state acquisition. It must honor context
// cancellation. Broker authentication and allocation policy belong to the caller.
type GrantSource interface {
	AcquireGrant(context.Context) (*EnrollmentGrant, error)
}

// EnrollmentStore must durably fence the attempt before a code is submitted.
// Acquire returns empty state only for a fresh exclusive allocation; an uncertain
// or unclean attempt must be rejected on subsequent acquisitions. BeginEnrollment
// must never persist the code. Checkpoint accepts only approved identity state.
type EnrollmentStore interface {
	StateStore
	BeginEnrollment(context.Context) error
	// BindEnrollment must durably associate this owner with the exact host/network
	// and refuse a host whose prior owner is active or uncertain. No code is passed.
	BindEnrollment(context.Context, string, string) error
}

type EnrollmentClient interface {
	pooledDNClient
	Enroll(context.Context, string, string) ([]byte, []byte, *wirekeys.Credentials, *definedwire.ConfigMeta, error)
}

// NewEnrollmentProvider initializes a fresh fenced grant, then delegates polling,
// strict rotation, checkpointing, ownership monitoring and release to Provider.
// Existing checkpoints are refused; this path does not silently reuse a pool.
func NewEnrollmentProvider(store EnrollmentStore, source GrantSource, client EnrollmentClient, networkID, hostname string, options ProviderOptions) (*Provider, error) {
	if store == nil || source == nil || client == nil {
		return nil, errors.New("invalid enrollment provider configuration")
	}
	initializer := &grantStore{EnrollmentStore: store, source: source, client: client, networkID: networkID, hostname: hostname}
	return NewProviderWithOptions(initializer, client, networkID, options)
}

type grantStore struct {
	EnrollmentStore
	source              GrantSource
	client              EnrollmentClient
	networkID, hostname string
	attempted           atomic.Bool
}

func (s *grantStore) Acquire(ctx context.Context) ([]byte, error) {
	reject := func() ([]byte, error) { return nil, ErrUncertainEnrollment }
	if !s.attempted.CompareAndSwap(false, true) {
		return reject()
	}
	existing, err := s.EnrollmentStore.Acquire(ctx)
	if err != nil || len(existing) != 0 || !s.Valid() || ctx.Err() != nil {
		return reject()
	}
	if s.BeginEnrollment(ctx) != nil || !s.Valid() || ctx.Err() != nil {
		return reject()
	}
	supplied, err := s.source.AcquireGrant(ctx)
	var grant *EnrollmentGrant
	if supplied != nil {
		snapshot := *supplied
		snapshot.Addresses = append([]string(nil), supplied.Addresses...)
		snapshot.RoutePolicy = bytes.Clone(supplied.RoutePolicy)
		snapshot.AddressRanges = append([]netip.Prefix(nil), supplied.AddressRanges...)
		grant = &snapshot
		supplied.Code = ""
	}
	if err != nil || grant == nil || grant.HostID == "" || grant.NetworkID != s.networkID || (len(grant.Addresses) == 0 && len(grant.AddressRanges) == 0) || len(grant.RoutePolicy) == 0 || !s.Valid() || ctx.Err() != nil {
		return reject()
	}
	var policy config.C
	if policy.LoadString(string(grant.RoutePolicy)) != nil {
		return reject()
	}
	approved := make(map[netip.Addr]bool, len(grant.Addresses))
	for _, raw := range grant.Addresses {
		ip, err := netip.ParseAddr(raw)
		if err != nil || approved[ip] {
			return reject()
		}
		approved[ip] = true
	}
	for _, prefix := range grant.AddressRanges {
		if !prefix.IsValid() {
			return reject()
		}
	}
	if s.BindEnrollment(ctx, grant.HostID, grant.NetworkID) != nil || !s.Valid() || ctx.Err() != nil {
		return reject()
	}
	data, key, credentials, meta, err := s.client.Enroll(ctx, grant.Code, s.hostname)
	grant.Code = ""
	if err != nil || credentials == nil || meta == nil || credentials.HostID != grant.HostID || meta.Host.ID != grant.HostID || meta.Network.ID != s.networkID || (len(grant.Addresses) > 0 && !reflect.DeepEqual(meta.Host.IPAddresses, grant.Addresses)) || !s.Valid() || ctx.Err() != nil {
		return reject()
	}
	addresses := append([]string(nil), meta.Host.IPAddresses...)
	if len(addresses) == 0 {
		return reject()
	}
	expected := make(map[netip.Addr]bool, len(addresses))
	for _, raw := range addresses {
		ip, err := netip.ParseAddr(raw)
		if err != nil || expected[ip] {
			return reject()
		}
		if len(grant.AddressRanges) > 0 {
			permitted := false
			for _, prefix := range grant.AddressRanges {
				if prefix.Contains(ip) {
					permitted = true
					break
				}
			}
			if !permitted {
				return reject()
			}
		}
		expected[ip] = true
	}
	data, err = definedwire.InsertConfigPrivateKey(data, key)
	if err != nil {
		return reject()
	}
	var cfg config.C
	if cfg.LoadString(string(data)) != nil || !reflect.DeepEqual(cfg.Get("tun.unsafe_routes"), policy.Get("tun.unsafe_routes")) {
		return reject()
	}
	pki, err := nebula.NewPKIFromConfig(slog.New(slog.NewTextHandler(io.Discard, nil)), &cfg)
	if err != nil {
		return reject()
	}
	certificates := []byte(cfg.GetString("pki.cert", ""))
	count := 0
	for len(bytes.TrimSpace(certificates)) > 0 {
		leaf, rest, err := cert.UnmarshalCertificateFromPEM(certificates)
		if err != nil || leaf.IsCA() {
			return reject()
		}
		if _, err = pki.GetCAPool().VerifyCertificate(time.Now(), leaf); err != nil {
			return reject()
		}
		ips := make(map[netip.Addr]bool)
		for _, network := range leaf.Networks() {
			ips[network.Addr()] = true
		}
		if !reflect.DeepEqual(ips, expected) {
			return reject()
		}
		certificates = rest
		count++
	}
	if count == 0 || !s.Valid() || ctx.Err() != nil {
		return reject()
	}
	encoded, err := encodeIdentityState(grant.HostID, addresses, data, credentials)
	if err != nil || s.Checkpoint(ctx, encoded) != nil || !s.Valid() || ctx.Err() != nil {
		return reject()
	}
	return encoded, nil
}
