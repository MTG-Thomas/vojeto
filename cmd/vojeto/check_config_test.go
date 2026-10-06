package main

import (
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigCheckDoesNotBindOrAcquireIdentity(t *testing.T) {
	dir := t.TempDir()
	provider := filepath.Join(dir, "provider.json")
	forwards := filepath.Join(dir, "forwards.json")
	readiness := filepath.Join(dir, "readiness.json")
	os.WriteFile(provider, []byte(`{"type":"defined-azure-pool","storageBaseURL":"https://state.example.invalid/pool","owner":"example","claimant":"example--run","hostIDs":["host-FIRST"],"networkID":"network-FIXTURE"}`), 0600)
	// Both ports are deliberately occupied: config checking must not bind either.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	os.WriteFile(forwards, []byte(`[{"Name":"database","Listen":"`+listener.Addr().String()+`","Target":"192.0.2.10:5432","MaxConnections":128,"DialTimeout":15000000000}]`), 0600)
	os.WriteFile(readiness, []byte(`{"overlay":[{"target":"192.0.2.10:5432","protocol":"tcp"}],"dependencies":[]}`), 0600)
	oldArgs, oldFlags := os.Args, flag.CommandLine
	defer func() { os.Args = oldArgs; flag.CommandLine = oldFlags }()
	flag.CommandLine = flag.NewFlagSet("vojeto-test", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{"vojeto", "-check-config", "-identity-provider", provider, "-forwards", forwards, "-readiness", readiness, "-health-listen", listener.Addr().String()}
	// No Azure identity endpoint or live Defined credentials are supplied.
	t.Setenv("IDENTITY_ENDPOINT", "")
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
