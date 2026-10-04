package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFiniteSocksCLIInvariants(t *testing.T) {
	if _, _, err := loadSessions("", ""); err == nil {
		t.Fatal("SOCKS enabled implicitly")
	}
	if _, _, err := loadSessions("forwards", "socks"); err == nil {
		t.Fatal("mixed admission modes accepted")
	}
	base := map[string]any{"listen": "127.0.0.1:1080", "allow": []string{"192.0.2.1:443"}, "maxConnections": 4, "dialTimeout": "5s", "lifetime": "10m"}
	for _, test := range []struct {
		name, field string
		value       any
		valid       bool
	}{
		{"valid", "", nil, true}, {"public", "listen", "0.0.0.0:1080", false}, {"hostname bind", "listen", "localhost:1080", false}, {"empty allow", "allow", []string{}, false}, {"hostname target", "allow", []string{"internal.example:443"}, false}, {"IPv6 target", "allow", []string{"[::1]:443"}, false}, {"zero port", "allow", []string{"192.0.2.1:0"}, false}, {"unbounded", "maxConnections", 0, false}, {"no timeout", "dialTimeout", "0s", false}, {"bad timeout", "dialTimeout", 42, false}, {"infinite", "lifetime", "0s", false}, {"negative lifetime", "lifetime", "-1s", false}, {"unknown", "public", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := map[string]any{}
			for k, v := range base {
				cfg[k] = v
			}
			if test.field != "" {
				cfg[test.field] = test.value
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "socks.json")
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			entries, settings, err := loadSessions("", path)
			if (err == nil) != test.valid {
				t.Fatal(err)
			}
			if test.valid && (len(entries) != 0 || settings == nil || len(settings.Allow) != 1) {
				t.Fatal("SOCKS policy lost")
			}
		})
	}
}
