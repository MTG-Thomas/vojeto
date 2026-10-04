package main

import (
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
