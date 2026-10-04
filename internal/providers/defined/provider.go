package defined

import (
	"context"
	"errors"
	"github.com/DefinedNet/dnapi/keys"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"sync"
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
	mu          sync.Mutex
	store       StateStore
	client      pooledDNClient
	network     string
	state       *identityState
	credentials *keys.Credentials
	current     *identity.Identity
	unsafe      bool
}

func NewProvider(store StateStore, client pooledDNClient, expectedNetwork string) (*Provider, error) {
	if store == nil || client == nil || expectedNetwork == "" {
		return nil, errors.New("invalid leased identity configuration")
	}
	return &Provider{store: store, client: client, network: expectedNetwork}, nil
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
	available, e := p.client.CheckForUpdate(ctx, *p.credentials)
	if e != nil {
		return nil, errors.New("identity startup authentication failed")
	}
	if available {
		if e = p.refresh(ctx); e != nil {
			return nil, e
		}
	}
	if !p.store.Valid() || ctx.Err() != nil {
		return nil, errors.New("identity ownership unconfirmed during acquisition")
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
	if p.unsafe || current == nil || current != p.current || !p.store.Valid() {
		return nil, errors.New("identity renewal ownership rejected")
	}
	available, e := p.client.CheckForUpdate(ctx, *p.credentials)
	if e != nil {
		return nil, errors.New("identity update poll failed")
	}
	if !available {
		return p.current, nil
	}
	if e = p.refresh(ctx); e != nil {
		p.unsafe = true
		return nil, errors.Join(identity.ErrUnsafeRenewal, e)
	}
	if !p.store.Valid() {
		p.unsafe = true
		return nil, errors.Join(identity.ErrUnsafeRenewal, errors.New("identity ownership lost during rotation"))
	}
	p.current = &identity.Identity{Config: append([]byte(nil), p.state.Config...)}
	return p.current, nil
}
func (p *Provider) Checkpoint(ctx context.Context, current *identity.Identity) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unsafe || current == nil || current != p.current || !p.store.Valid() {
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
	if p.unsafe || current == nil || current != p.current || !p.store.Valid() {
		return errors.New("identity release ownership rejected")
	}
	if e := p.store.Release(ctx); e != nil {
		return e
	}
	p.current = nil
	return nil
}
func (p *Provider) Watch(ctx context.Context, revoke func()) error { return p.store.Watch(ctx, revoke) }

// Valid reports conservative lease validity without blocking on SDK polling.
func (p *Provider) Valid() bool { return p.store.Valid() }
