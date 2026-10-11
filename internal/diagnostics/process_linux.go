//go:build linux

package diagnostics

import "os"

func openFDs() *int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}
	// Includes the temporary descriptor used to enumerate this directory. Never
	// read symlink targets: file paths and socket addresses are not diagnostics.
	count := len(entries)
	return &count
}
