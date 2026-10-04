package main

import (
	"encoding/json"
	"github.com/MTG-Thomas/vojeto/internal/providers/defined"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestProviderConfigurationBoundaries(t *testing.T) {
	if _, e := selectProvider("", ""); e == nil {
		t.Fatal("missing provider accepted")
	}
	if _, e := selectProvider("static", "provider"); e == nil {
		t.Fatal("mixed providers accepted")
	}
	for _, data := range []string{`{}`, `{"type":"defined-azure-pool","unknown":"value"}`, `{"type":"defined-azure-pool","definedAPI":"http://api.example.invalid"}`, `{"type":"defined-azure-pool","definedAPI":"https://user@api.example.invalid"}`, `{"type":"defined-azure-pool","definedAPI":"https://api.example.invalid/?token=value"}`, `{"type":"defined-azure-pool","storageBaseURL":"https://state.example.invalid/identities","owner":"example","claimant":"foreign--run","hostIDs":["host-FIRST"],"networkID":"network-FIXTURE"}`} {
		path := filepath.Join(t.TempDir(), "provider.json")
		if e := os.WriteFile(path, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := selectProvider("", path); e == nil {
			t.Fatal("unsafe or foreign provider accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "provider.json")
	data := `{"type":"defined-azure-pool","storageBaseURL":"https://state.example.invalid/identities","owner":"example","claimant":"example--job","hostIDs":["host-FIRST"],"networkID":"network-FIXTURE"}`
	os.WriteFile(path, []byte(data), 0600)
	if _, e := selectProvider("", path); e != nil {
		t.Fatal("configured generic provider rejected", e)
	}
}

func TestExplicitClaimantEnvironment(t *testing.T) {
	t.Setenv("TEST_VOJETO_REPLICA", "example--job")
	for _, fields := range []struct {
		body  string
		valid bool
	}{
		{`"claimantEnv":"TEST_VOJETO_REPLICA"`, true},
		{`"claimantEnv":"TEST_VOJETO_REPLICA","claimant":"example--other"`, false},
		{`"claimantEnv":"MISSING_VOJETO_REPLICA"`, false},
		{`"claimantEnv":"invalid-name"`, false},
	} {
		path := filepath.Join(t.TempDir(), "provider.json")
		body := `{"type":"defined-azure-pool","storageBaseURL":"https://state.example.invalid/identities","owner":"example","hostIDs":["host-FIRST"],"networkID":"network-FIXTURE",` + fields.body + `}`
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := selectProvider("", path)
		if (err == nil) != fields.valid {
			t.Fatal(fields.body, err)
		}
	}
}

func TestExplicitPollOutageConfiguration(t *testing.T) {
	for _, grace := range []struct {
		value string
		valid bool
	}{{"5m", true}, {"0s", true}, {"-1s", false}, {"25h", false}, {"unknown", false}} {
		path := filepath.Join(t.TempDir(), "provider.json")
		body := `{"type":"defined-azure-pool","storageBaseURL":"https://state.example.invalid/identities","owner":"example","claimant":"example--job","hostIDs":["host-FIRST"],"networkID":"network-FIXTURE","pollOutageGrace":"` + grace.value + `"}`
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := selectProvider("", path)
		if (err == nil) != grace.valid {
			t.Fatal(grace.value, err)
		}
	}
}

func TestExternalAgentConfiguration(t *testing.T) {
	dir, err := os.MkdirTemp("", "vojeto-cli-agent-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	defer os.Remove(dir)
	if err = os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	base := map[string]any{"type": "defined-external-agent", "agentSocket": socket, "networkID": "network-FIXTURE", "hostname": "fixture-worker"}
	for _, test := range []struct {
		name  string
		field string
		value any
		valid bool
	}{
		{"valid", "", nil, true}, {"missing network", "networkID", "", false}, {"missing hostname", "hostname", "", false}, {"relative socket", "agentSocket", "relative.sock", false}, {"pool storage", "storageBaseURL", "https://state.example.invalid", false}, {"pool owner", "owner", "example", false}, {"pool claimant", "claimant", "example", false}, {"pool env", "claimantEnv", "EXAMPLE_MISSING", false}, {"pool hosts", "hostIDs", []string{"host-FIXTURE"}, false}, {"unknown", "unknown", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := make(map[string]any)
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
			path := filepath.Join(t.TempDir(), "provider.json")
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			provider, err := selectProvider("", path)
			if (err == nil) != test.valid {
				t.Fatal(err)
			}
			if test.valid {
				if _, ok := provider.(*defined.Provider); !ok {
					t.Fatal("external provider not wired")
				}
			}
		})
	}
}
