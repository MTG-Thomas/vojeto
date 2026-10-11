//go:build linux

package diagnostics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFDAccountingTracksOpenedAndClosedResources(t *testing.T) {
	before := Snapshot()
	if before.OpenFDs == nil {
		t.Skip("Linux procfs unavailable")
	}
	var files []*os.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	for range 16 {
		f, err := os.OpenFile(filepath.Join(t.TempDir(), "fixture"), os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	during := Snapshot()
	if during.OpenFDs == nil || *during.OpenFDs < *before.OpenFDs+16 {
		t.Fatal("open descriptors missing from count")
	}
	for _, f := range files {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	files = nil
	after := Snapshot()
	if after.OpenFDs == nil || *after.OpenFDs > *before.OpenFDs+2 {
		t.Fatal("closed descriptors remained in count")
	}
}
