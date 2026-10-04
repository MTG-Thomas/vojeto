package network

import (
	"context"
	"testing"
)

func TestResolverIsExplicitAndReturnsCopies(t *testing.T) {
	r, err := NewResolver(map[string][]string{"Database.Example.": {"192.0.2.1"}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.Resolve(context.Background(), "database.example")
	if err != nil || a[0].String() != "192.0.2.1" {
		t.Fatal(a, err)
	}
	a[0] = a[0].Next()
	b, _ := r.Resolve(context.Background(), "DATABASE.EXAMPLE.")
	if b[0].String() != "192.0.2.1" {
		t.Fatal("mutable mapping")
	}
	if _, err = r.Resolve(context.Background(), "localhost"); err == nil {
		t.Fatal("host DNS fallback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.Resolve(ctx, "192.0.2.1"); err == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestRejectAmbiguousMappings(t *testing.T) {
	for _, m := range []map[string][]string{{"a": {"::1"}}, {"a": {"0.0.0.0"}}, {"a": {}}, {"a": {"192.0.2.1"}, "A.": {"192.0.2.2"}}} {
		if _, err := NewResolver(m); err == nil {
			t.Fatal(m)
		}
	}
}
