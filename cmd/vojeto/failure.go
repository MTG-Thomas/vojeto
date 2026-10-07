package main

import (
	"sort"
	"strings"
)

// Errors may contain secret configuration or upstream response text. Only
// exact, source-owned constants become diagnostic codes; raw text never escapes.
func safeFailureCodes(err error) string {
	known := map[string]string{
		"identity acquisition failed":                                          "identity-acquisition",
		"identity startup authentication failed":                               "identity-authentication",
		"pooled route change requires review":                                  "route-change",
		"pooled identity changed":                                              "identity-change",
		"pooled identity certificate rejected":                                 "identity-certificate",
		"rotated identity checkpoint failed; operator reconciliation required": "rotation-checkpoint",
		"pooled configuration checkpoint failed":                               "config-checkpoint",
		"overlay initialization failed":                                        "overlay-initialization",
		"Nebula initialization failed":                                         "nebula-initialization",
		"userspace service initialization failed":                              "netstack-initialization",
		"startup readiness deadline exceeded":                                  "startup-readiness",
		"session initialization failed":                                        "session-initialization",
		"identity ownership lost":                                              "identity-ownership",
	}
	found := map[string]bool{}
	remaining := 32
	var visit func(error, int)
	visit = func(e error, depth int) {
		if e == nil || depth > 8 || remaining == 0 {
			return
		}
		remaining--
		if code, ok := known[e.Error()]; ok {
			found[code] = true
		}
		switch wrapped := e.(type) {
		case interface{ Unwrap() []error }:
			for _, inner := range wrapped.Unwrap() {
				visit(inner, depth+1)
			}
		case interface{ Unwrap() error }:
			visit(wrapped.Unwrap(), depth+1)
		}
	}
	visit(err, 0)
	codes := make([]string, 0, len(found))
	for code := range found {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	if len(codes) == 0 {
		return "unclassified"
	}
	return strings.Join(codes, ",")
}
