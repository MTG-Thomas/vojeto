package routeconfig

import (
	"reflect"
	"testing"
)

func TestPermutationPreservesEveryRouteAttributeAndMultiplicity(t *testing.T) {
	a := map[string]any{"route": "10.30.0.0/26", "via": "100.100.0.30", "install": true}
	b := map[string]any{"route": "10.30.0.128/27", "via": "100.100.0.30", "install": true}
	original := []any{a, b}
	if !Equal(original, []any{b, a}) || !reflect.DeepEqual(original, []any{a, b}) {
		t.Fatal("route permutation rejected or input changed")
	}
	for _, changed := range []any{
		[]any{a}, []any{a, b, b}, []any{a, a},
		[]any{a, map[string]any{"route": "10.30.0.128/27", "via": "100.100.0.31", "install": true}},
		[]any{a, map[string]any{"route": "10.30.0.128/27", "via": "100.100.0.30", "install": false}},
		[]any{a, map[string]any{"route": "10.30.0.128/27", "via": "100.100.0.30", "install": true, "metric": 5}},
		[]any{a, map[string]any{"route": "10.30.0.96/27", "via": "100.100.0.30", "install": true}},
	} {
		if Equal(original, changed) {
			t.Fatal("changed route policy accepted")
		}
	}
	if Equal(nil, []any{}) || Equal(original, []any{b, "invalid"}) {
		t.Fatal("different absent or malformed route policy accepted")
	}
}

func TestPermutationDoesNotNormalizeAttributeTypes(t *testing.T) {
	a := map[string]any{"route": "10.30.0.0/26", "via": "100.100.0.30", "metric": 5}
	b := map[string]any{"route": "10.30.0.128/27", "via": "100.100.0.30"}
	changed := map[string]any{"route": "10.30.0.0/26", "via": "100.100.0.30", "metric": float64(5)}
	if Equal([]any{a, b}, []any{b, changed}) {
		t.Fatal("decoded attribute type changed")
	}
}
