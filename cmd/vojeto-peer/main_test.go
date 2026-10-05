package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeygenAndIssue(t *testing.T) {
	base := t.TempDir()
	op := filepath.Join(base, "operator")
	target := filepath.Join(base, "target")
	grants := filepath.Join(base, "grants")
	for _, dir := range []string{op, target} {
		if e := run([]string{"keygen", "--out", dir}); e != nil {
			t.Fatal(e)
		}
	}
	before, e := os.ReadFile(filepath.Join(op, "private.json"))
	if e != nil {
		t.Fatal(e)
	}
	if run([]string{"keygen", "--out", op}) == nil {
		t.Fatal("overwrote key directory")
	}
	after, _ := os.ReadFile(filepath.Join(op, "private.json"))
	if string(before) != string(after) {
		t.Fatal("changed existing key")
	}
	if e := run([]string{"issue", "--operator-key", filepath.Join(op, "public.json"), "--target-key", filepath.Join(target, "public.json"), "--destination", "127.0.0.1:22", "--target-endpoint", "127.0.0.1:4242", "--out", grants}); e != nil {
		t.Fatal(e)
	}
	files, e := os.ReadDir(grants)
	if e != nil || len(files) != 2 {
		t.Fatalf("grants: %v", e)
	}
}
func TestStrictRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	for _, input := range []string{`{"unexpected":1}`, `"AA==" "AA=="`, `"AA=="` + strings.Repeat(" ", 64<<10), `"unterminated`} {
		if e := os.WriteFile(path, []byte(input), 0600); e != nil {
			t.Fatal(e)
		}
		var value []byte
		if read(path, &value) == nil {
			t.Fatal("accepted malformed input")
		}
	}
}
