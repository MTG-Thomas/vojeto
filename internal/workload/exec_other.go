//go:build !linux

package workload

import (
	"context"
	"errors"
	"time"
)

// Supported reports whether process-group supervision is available.
const Supported = false

func Execute(context.Context, []string, time.Duration) error {
	return errors.New("workload execution requires Linux")
}
