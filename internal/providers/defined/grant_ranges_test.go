package defined

import (
	"context"
	"net/netip"
	"testing"

	"github.com/DefinedNet/dnapi"
	"github.com/DefinedNet/dnapi/keys"
)

func TestGrantApprovesAllocatedAddressWithinCallerRangesAndPinsIt(t *testing.T) {
	p, store, client, grant := grantFixture(t)
	grant.Addresses = nil
	grant.AddressRanges = []netip.Prefix{netip.MustParsePrefix("100.100.0.0/16")}
	current, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := decodeIdentityState(store.saves[0])
	if err != nil || len(state.Addresses) != 1 || state.Addresses[0] != "100.100.1.1" {
		t.Fatal("allocated address not pinned")
	}
	client.check = func(context.Context) (bool, error) { return true, nil }
	client.fakePooledDN.meta.Host.IPAddresses = []string{"100.100.1.2"}
	if _, err = p.Renew(context.Background(), current); err == nil {
		t.Fatal("range policy allowed rotation to change identity")
	}
	if store.releaseCalls != 0 || p.Release(context.Background(), current) == nil {
		t.Fatal("changed identity became reusable")
	}
}

func TestGrantRangeConstraintsRejectUnapprovedAllocation(t *testing.T) {
	for _, kind := range []string{"missing", "invalid range", "foreign allocation", "exact plus foreign range", "malformed allocation", "duplicate allocation", "mutated range"} {
		t.Run(kind, func(t *testing.T) {
			p, store, client, grant := grantFixture(t)
			grant.Addresses = nil
			grant.AddressRanges = []netip.Prefix{netip.MustParsePrefix("100.100.0.0/16")}
			switch kind {
			case "missing":
				grant.AddressRanges = nil
			case "invalid range":
				grant.AddressRanges = []netip.Prefix{{}}
			case "foreign allocation", "exact plus foreign range", "mutated range":
				grant.AddressRanges = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
			}
			if kind == "exact plus foreign range" {
				grant.Addresses = []string{"100.100.1.1"}
			}
			original := client.enroll
			client.enroll = func(ctx context.Context) ([]byte, []byte, *keys.Credentials, *dnapi.ConfigMeta, error) {
				data, key, credentials, meta, err := original(ctx)
				switch kind {
				case "malformed allocation":
					meta.Host.IPAddresses = []string{"invalid"}
				case "duplicate allocation":
					meta.Host.IPAddresses = []string{"100.100.1.1", "100.100.1.1"}
				case "mutated range":
					grant.AddressRanges[0] = netip.MustParsePrefix("100.100.0.0/16")
				}
				return data, key, credentials, meta, err
			}
			if _, err := p.Acquire(context.Background()); err == nil || len(store.saves) != 0 || store.releaseCalls != 0 {
				t.Fatal("unapproved allocation accepted")
			}
			if (kind == "missing" || kind == "invalid range") && client.enrollCalls != 0 {
				t.Fatal("invalid caller policy consumed grant")
			}
		})
	}
}
