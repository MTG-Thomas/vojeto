package azure

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Store adapts a configured Blob pool to Defined's secret-state store boundary.
// It is single-use; no implicit takeover, lease break or resource provisioning occurs.
type Store struct {
	mu        sync.Mutex
	pool      *identityPool
	claimant  string
	lease     *identityLease
	attempted bool
}

func NewStore(pool *identityPool, claimant string) (*Store, error) {
	if pool == nil || !stringsReplicaOf(pool.app, claimant) {
		return nil, errors.New("invalid pool claimant")
	}
	return &Store{pool: pool, claimant: claimant}, nil
}
func (s *Store) Acquire(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attempted {
		return nil, errors.New("store acquisition already attempted")
	}
	s.attempted = true
	lease, data, e := acquireAvailable(ctx, time.Second, func() (*identityLease, []byte, error) { return s.pool.takeAvailable(ctx, s.claimant) })
	if e != nil {
		return nil, e
	}
	s.lease = lease
	return data, nil
}
func (s *Store) owned() (*identityLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lease == nil {
		return nil, errors.New("no acquired identity lease")
	}
	return s.lease, nil
}
func (s *Store) Valid() bool { l, e := s.owned(); return e == nil && l.remaining() > 0 }
func (s *Store) Checkpoint(ctx context.Context, data []byte) error {
	l, e := s.owned()
	if e != nil {
		return e
	}
	return l.write(ctx, data)
}
func (s *Store) Watch(ctx context.Context, revoke func()) error {
	l, e := s.owned()
	if e != nil {
		revoke()
		return e
	}
	return l.maintain(ctx, revoke)
}
func (s *Store) Release(ctx context.Context) error {
	l, e := s.owned()
	if e != nil {
		return e
	}
	return l.ReleaseClean(ctx)
}

// StorageToken uses the platform's existing local managed-identity endpoint.
// It neither provisions credentials nor permits a remote token endpoint.
func StorageToken(ctx context.Context, client *http.Client) (string, error) {
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return storageIdentityToken(ctx, &copyClient)
}

// Only confirmed lease contention is retryable. Quarantine, authentication and
// unknown provider failures never become capacity or trigger implicit takeover.
func acquireAvailable(ctx context.Context, interval time.Duration, take func() (*identityLease, []byte, error)) (*identityLease, []byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		lease, data, err := take()
		if !errors.Is(err, errIdentityPoolFull) {
			return lease, data, err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, ctx.Err()
		case <-timer.C:
		}
	}
}
