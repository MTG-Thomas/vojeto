package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForwardPreflightRejectsBeforeIdentityAcquisition(t *testing.T) {
	valid := `{"Name":"postgres","Listen":"127.0.0.1:5432","Target":"192.0.2.10:5432","MaxConnections":128,"DialTimeout":15000000000}`
	cases := []struct {
		data  string
		valid bool
	}{
		{"[" + valid + "]", true},
		{"[" + strings.Replace(valid, `127.0.0.1`, `0.0.0.0`, 1) + "]", false},
		{"[" + strings.Replace(valid, `15000000000`, `"15s"`, 1) + "]", false},
		{"[" + valid + "," + valid + "]", false},
		{"[" + valid + "," + strings.Replace(strings.Replace(valid, `"postgres"`, `"second"`, 1), `127.0.0.1:5432`, `[::ffff:127.0.0.1]:5432`, 1) + "]", false},
		{"[" + valid + "," + strings.Replace(valid, `"postgres"`, `"second"`, 1) + "]", false},
		{"[" + valid + ", " + strings.Replace(valid, `127.0.0.1:5432`, `127.0.0.1:15432`, 1) + "]", false},
		{"[" + strings.Replace(valid, `"Name"`, `"Typo"`, 1) + "]", false},
		{"[" + valid + "] {}", false},
		{strings.Repeat(" ", 65537) + "[" + valid + "]", false},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "forwards.json")
		if err := os.WriteFile(path, []byte(c.data), 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := loadSessions(path, "")
		if (err == nil) != c.valid {
			t.Fatalf("forward policy outcome: %v", err)
		}
	}
}
