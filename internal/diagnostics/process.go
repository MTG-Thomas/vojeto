// Package diagnostics exposes aggregate process counters, never object contents.
package diagnostics

import "runtime"

type Process struct {
	Goroutines int  `json:"goroutines"`
	OpenFDs    *int `json:"open_fds,omitempty"`
}

// Snapshot is observational: concurrent work can change counts immediately.
// Unsupported or inaccessible FD accounting is omitted, never reported as zero.
func Snapshot() Process { return Process{Goroutines: runtime.NumGoroutine(), OpenFDs: openFDs()} }
