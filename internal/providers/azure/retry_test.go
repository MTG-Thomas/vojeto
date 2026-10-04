package azure

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCapacityRetryOnlyConfirmedContention(t *testing.T) {
	calls := 0
	lease := &identityLease{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, _, err := acquireAvailable(ctx, time.Millisecond, func() (*identityLease, []byte, error) {
		calls++
		if calls < 3 {
			return nil, nil, errIdentityPoolFull
		}
		return lease, []byte("synthetic"), nil
	})
	if err != nil || got != lease || calls != 3 {
		t.Fatal(calls, err)
	}
	for _, failure := range []error{errIdentityQuarantined, errors.New("authentication rejected"), errors.New("unknown conflict")} {
		calls = 0
		_, _, err := acquireAvailable(ctx, time.Millisecond, func() (*identityLease, []byte, error) { calls++; return nil, nil, failure })
		if !errors.Is(err, failure) || calls != 1 {
			t.Fatal("non-capacity failure retried")
		}
	}
}
func TestCapacityWaitHonorsStartupBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	calls := 0
	_, _, err := acquireAvailable(ctx, time.Hour, func() (*identityLease, []byte, error) { calls++; return nil, nil, errIdentityPoolFull })
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatal(calls, err)
	}
}
