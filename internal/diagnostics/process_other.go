//go:build !linux

package diagnostics

func openFDs() *int { return nil }
