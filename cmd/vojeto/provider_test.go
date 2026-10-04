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
