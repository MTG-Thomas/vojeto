package network

import (
	"context"
	"errors"
	"net/netip"
	"strings"
)

// Resolver uses only explicitly configured overlay destinations. It never invokes
// the host resolver, changes system DNS, or falls back to host networking.
type Resolver struct{ hosts map[string][]netip.Addr }

func NewResolver(hosts map[string][]string) (*Resolver, error) {
	r := &Resolver{hosts: make(map[string][]netip.Addr)}
	for name, values := range hosts {
		key := strings.ToLower(strings.TrimSuffix(name, "."))
		if key == "" || strings.ContainsAny(key, " /:\t\n") || len(values) == 0 {
			return nil, errors.New("invalid overlay host mapping")
		}
		if _, exists := r.hosts[key]; exists {
			return nil, errors.New("duplicate overlay host mapping")
		}
		for _, value := range values {
			a, err := netip.ParseAddr(value)
			if err != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() {
				return nil, errors.New("invalid overlay address")
			}
			r.hosts[key] = append(r.hosts[key], a)
		}
	}
	return r, nil
}
func (r *Resolver) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a, err := netip.ParseAddr(name); err == nil && a.Is4() {
		return []netip.Addr{a}, nil
	}
	if values := r.hosts[strings.ToLower(strings.TrimSuffix(name, "."))]; len(values) != 0 {
		return append([]netip.Addr(nil), values...), nil
	}
	return nil, errors.New("overlay destination not configured")
}
