//go:build linux

package workload

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestExecuteFailureHasNoCommandOrOutputInError(t *testing.T) {
	e := Execute(context.Background(), []string{"/bin/sh", "-c", "exit 23 # private-token"}, time.Second)
	if e == nil || e.Error() != "workload failed" {
		t.Fatal(e)
	}
	e = Execute(context.Background(), []string{"/private/missing-token"}, time.Second)
	if e == nil || e.Error() != "workload start failed" {
		t.Fatal(e)
	}
}
func TestExecuteRejectsRelativeCommandBeforeStart(t *testing.T) {
	if Execute(context.Background(), []string{"sh"}, time.Second) == nil {
		t.Fatal("PATH lookup accepted")
	}
}
func TestExecuteCancellationKillsUnresponsiveProcessGroup(t *testing.T) {
	path := t.TempDir() + "/ready"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Execute(ctx, []string{"/bin/sh", "-c", `trap '' TERM; touch "$1"; while :; do sleep 1; done`, "fixture", path}, 50*time.Millisecond)
	}()
	deadline := time.After(3 * time.Second)
	for {
		if _, e := os.Stat(path); e == nil {
			break
		}
		select {
		case e := <-done:
			t.Fatal("premature exit", e)
		case <-deadline:
			t.Fatal("child never started")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case e := <-done:
		if e == nil || e.Error() != "workload cancelled" {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("process group termination exceeded bound")
	}
}
