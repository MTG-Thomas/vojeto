// Package routeconfig compares immutable managed Nebula routes without treating
// serialization order as a policy change.
package routeconfig

import (
	"encoding/json"
	"reflect"
	"sort"
)

// Equal allows only permutation of identical route entries. Every attribute and
// the number of duplicate entries remains significant; inputs are never changed.
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
	canonical := func(entries []any) ([]string, bool) {
		values := make([]string, len(entries))
		for i, entry := range entries {
			if _, ok := entry.(map[string]any); !ok {
				return nil, false
			}
			data, err := json.Marshal(entry)
			if err != nil {
				return nil, false
			}
			values[i] = string(data)
		}
		sort.Strings(values)
		return values, true
	}
	l, ok := canonical(left)
	if !ok {
		return false
	}
	r, ok := canonical(right)
	return ok && reflect.DeepEqual(l, r)
}
