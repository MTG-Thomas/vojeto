package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadinessConfigurationStrict(t *testing.T) {
	for _, body := range []string{`{}`, `{"overlay":[{"target":"192.0.2.1:443","protocol":"tls"}]}`, `{"overlay":[{"target":"192.0.2.1:443","protocol":"tcp","secret":"hidden"}]}`, `{"overlay":[{"target":"192.0.2.1:443","protocol":"tcp"}]} {}`, strings.Repeat(" ", 65537)} {
		p := filepath.Join(t.TempDir(), "readiness.json")
		os.WriteFile(p, []byte(body), 0600)
		if _, _, err := loadReadiness(p); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}
func TestReadinessConfiguredNames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "readiness.json")
	os.WriteFile(p, []byte(`{"hosts":{"database.example":["192.0.2.1"]},"overlay":[{"target":"database.example:443","protocol":"tls","server_name":"database.example"}]}`), 0600)
	s, r, err := loadReadiness(p)
	if err != nil || s == nil || r == nil {
		t.Fatal(err)
	}
}
