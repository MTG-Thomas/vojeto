//go:build linux

package workload

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Supported reports whether process-group supervision is available.
const Supported = true

// Execute runs an explicit executable without a shell and joins the direct
// child. Cancellation terminates its process group, then forces it closed after
// grace. Descendants must not escape the process group; use this for trusted jobs.
func Execute(ctx context.Context, args []string, grace time.Duration) error {
	if len(args) == 0 || !filepath.IsAbs(args[0]) || grace <= 0 || grace > 5*time.Minute {
		return errors.New("invalid workload command")
	}
	if ctx.Err() != nil {
		return errors.New("workload cancelled")
	}
	command := exec.Command(args[0], args[1:]...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if command.Start() != nil {
		return errors.New("workload start failed")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case e := <-done:
		// Close lingering descendants before allowing network release.
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if e != nil {
			return errors.New("workload failed")
		}
		return nil
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		return errors.New("workload cancelled")
	}
}
