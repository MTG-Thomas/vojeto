package defined

import (
	"context"
	"errors"
	wirekeys "github.com/MTG-Thomas/vojeto/internal/definedwire/credentials"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"sync"
	"sync/atomic"
	"time"
)

// StateStore holds an exclusively owned, pre-enrolled SDK checkpoint.
// Release marks a slot reusable, so it is only called after transport has stopped.
type StateStore interface {
	Acquire(context.Context) ([]byte, error)
	Checkpoint(context.Context, []byte) error
	Release(context.Context) error
	Watch(context.Context, func()) error
	Valid() bool
}

// Provider combines Defined credentials with an independently monitored store.
// Configuration, host membership and expected network are supplied by the caller.
type Provider struct {
	mu              sync.Mutex
	store           StateStore
	client          pooledDNClient
	network         string
	state           *identityState
	credentials     *wirekeys.Credentials
	current         *identity.Identity
	unsafe          bool
	options         ProviderOptions
	now             func() time.Time
	deadline        atomic.Pointer[time.Time]
	revoked         atomic.Bool
	deadlineChanged chan struct{}
}

func NewProvider(store StateStore, client pooledDNClient, expectedNetwork string) (*Provider, error) {
	return NewProviderWithOptions(store, client, expectedNetwork, ProviderOptions{})
}

// ProviderOptions preserves default fail-closed behavior unless grace is enabled.
type ProviderOptions struct{ PollOutageGrace time.Duration }

func NewProviderWithOptions(store StateStore, client pooledDNClient, expectedNetwork string, options ProviderOptions) (*Provider, error) {
	if store == nil || client == nil || expectedNetwork == "" || options.PollOutageGrace < 0 || options.PollOutageGrace > 24*time.Hour {
		return nil, errors.New("invalid leased identity configuration")
	}
	return &Provider{store: store, client: client, network: expectedNetwork, options: options, now: time.Now, deadlineChanged: make(chan struct{}, 1)}, nil
}

var _ identity.Provider = (*Provider)(nil)
var _ identity.Watcher = (*Provider)(nil)

func (p *Provider) Acquire(ctx context.Context) (*identity.Identity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != nil {
		return nil, errors.New("identity already acquired")
	}
	encoded, e := p.store.Acquire(ctx)
	if e != nil {
		return nil, errors.New("identity acquisition failed")
	}
	state, credentials, e := decodeIdentityState(encoded)
	if e != nil {
		return nil, e
	}
	p.state, p.credentials = state, credentials
	// Authenticate against Defined before using the stored transport identity.
	started := p.now()
	available, e := p.client.CheckForUpdate(ctx, *p.credentials)
	if e != nil {
		return nil, errors.New("identity startup authentication failed")
	}
	if available {
		if e = p.refresh(ctx); e != nil {
			return nil, e
		}
	}
	if !p.Valid() || ctx.Err() != nil {
		return nil, errors.New("identity ownership unconfirmed during acquisition")
	}
	if e = p.confirmFreshness(started); e != nil {
		return nil, e
	}
	p.current = &identity.Identity{Config: append([]byte(nil), p.state.Config...)}
	return p.current, nil
}
func (p *Provider) refresh(ctx context.Context) error {
	return refreshPooledIdentity(ctx, p.client, p.state, &p.credentials, p.network, func(data []byte) error { return p.store.Checkpoint(ctx, data) }, func([]byte) error { return nil })
}
func (p *Provider) Renew(ctx context.Context, current *identity.Identity) (*identity.Identity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unsafe || current == nil || current != p.current || !p.Valid() {
		return nil, errors.New("identity renewal ownership rejected")
	}
	started := p.now()
	available, e := p.client.CheckForUpdate(ctx, *p.credentials)
	if e != nil {
		if p.options.PollOutageGrace > 0 && errors.Is(e, ErrTransientPoll) && !errors.Is(ctx.Err(), context.Canceled) && p.Valid() {
			return p.current, nil
		}
		// Read-only cancellation during explicit shutdown can release cleanly.
		// Unknown/authentication failures cannot restore or reuse this owner.
		if !errors.Is(ctx.Err(), context.Canceled) {
			p.revoked.Store(true)
		}
		return nil, errors.New("identity update poll failed")
	}
	if !p.Valid() {
		return nil, errors.New("identity freshness or ownership lost during poll")
	}
	if !available {
		if e = p.confirmFreshness(started); e != nil {
			return nil, e
		}
		return p.current, nil
	}
	if e = p.refresh(ctx); e != nil {
		p.unsafe = true
		return nil, errors.Join(identity.ErrUnsafeRenewal, e)
	}
	if !p.Valid() {
		p.unsafe = true
		return nil, errors.Join(identity.ErrUnsafeRenewal, errors.New("identity ownership lost during rotation"))
	}
	if e = p.confirmFreshness(started); e != nil {
		p.unsafe = true
		return nil, errors.Join(identity.ErrUnsafeRenewal, e)
	}
	p.current = &identity.Identity{Config: append([]byte(nil), p.state.Config...)}
	return p.current, nil
}
func (p *Provider) Checkpoint(ctx context.Context, current *identity.Identity) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unsafe || current == nil || current != p.current || !p.Valid() {
		return errors.New("identity checkpoint ownership rejected")
	}
	data, e := encodeIdentityState(p.state.HostID, p.state.Addresses, p.state.Config, p.credentials)
	if e != nil {
		return e
	}
	return p.store.Checkpoint(ctx, data)
}
func (p *Provider) Release(ctx context.Context, current *identity.Identity) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unsafe || current == nil || current != p.current || !p.Valid() {
		return errors.New("identity release ownership rejected")
	}
	if e := p.store.Release(ctx); e != nil {
		return e
	}
	p.current = nil
	return nil
}

// Valid reports conservative lease validity without blocking on SDK polling.
func (p *Provider) Valid() bool {
	if p.revoked.Load() || !p.store.Valid() {
		return false
	}
	deadline := p.deadline.Load()
	return deadline == nil || p.now().Before(*deadline)
}
