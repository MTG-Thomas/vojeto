// Package routeconfig compares immutable managed Nebula routes without treating
// serialization order as a policy change.
package routeconfig

import "reflect"

// Equal allows only permutation of identical route entries. Every attribute,
// its decoded type and duplicate multiplicity remain significant. Inputs are
// never changed; managed configuration size is bounded by the provider.
func Equal(a, b any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	left, ok := a.([]any)
	if !ok {
		return false
	}
	right, ok := b.([]any)
	if !ok || len(left) != len(right) {
		return false
	}
	used := make([]bool, len(right))
	for _, entry := range left {
		if _, ok := entry.(map[string]any); !ok {
			return false
		}
		matched := false
		for i, candidate := range right {
			if !used[i] && reflect.DeepEqual(entry, candidate) {
				used[i], matched = true, true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
