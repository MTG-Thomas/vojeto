package defined

import (
	"context"
	"errors"
	"github.com/DefinedNet/dnapi"
	"github.com/DefinedNet/dnapi/keys"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"io"
	"log/slog"
	"reflect"
)

type pooledDNClient interface {
	CheckForUpdate(context.Context, keys.Credentials) (bool, error)
	DoUpdate(context.Context, keys.Credentials) ([]byte, []byte, *keys.Credentials, *dnapi.ConfigMeta, error)
}

// A successful SDK update rotates credentials remotely. Checkpoint them first,
// even when the accompanying route/config is refused. Never persist/apply a new
// route or host identity implicitly, and never apply an uncheckpointed config.
func refreshPooledIdentity(ctx context.Context, dn pooledDNClient, state *identityState, credentials **keys.Credentials,
	expectedNetwork string, checkpoint func([]byte) error, apply func([]byte) error) error {
	data, key, next, meta, err := dn.DoUpdate(ctx, **credentials)
	if err != nil || next == nil || next.HostID != state.HostID || next.Counter <= (*credentials).Counter {
		return errors.New("pooled identity update rejected; operator reconciliation required")
	}
	*credentials = next
	durable, err := encodeIdentityState(state.HostID, state.Addresses, state.Config, next)
	if err != nil || checkpoint(durable) != nil {
		return errors.New("rotated identity checkpoint failed; operator reconciliation required")
	}
	if meta == nil || meta.Host.ID != state.HostID || meta.Network.ID != expectedNetwork || !reflect.DeepEqual(meta.Host.IPAddresses, state.Addresses) {
		return errors.New("pooled identity changed")
	}
	data, err = dnapi.InsertConfigPrivateKey(data, key)
	if err != nil {
		return errors.New("pooled private key insertion failed")
	}
	var oldConfig, newConfig config.C
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if oldConfig.LoadString(string(state.Config)) != nil || newConfig.LoadString(string(data)) != nil ||
		!reflect.DeepEqual(oldConfig.Get("tun.unsafe_routes"), newConfig.Get("tun.unsafe_routes")) {
		return errors.New("pooled route change requires review")
	}
	if _, err := nebula.NewPKIFromConfig(logger, &newConfig); err != nil {
		return errors.New("pooled identity certificate rejected")
	}
	durable, err = encodeIdentityState(state.HostID, state.Addresses, data, next)
	if err != nil || checkpoint(durable) != nil {
		return errors.New("pooled configuration checkpoint failed")
	}
	if apply(data) != nil {
		return errors.New("pooled configuration reload failed")
	}
	state.Config = append([]byte(nil), data...)
	state.Counter = next.Counter
	return nil
}
