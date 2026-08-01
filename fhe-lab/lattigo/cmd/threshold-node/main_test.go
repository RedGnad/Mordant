package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseOptionsRequiresEveryTrustBoundary(t *testing.T) {
	if _, err := parseOptions(nil); err == nil {
		t.Fatal("empty threshold-node configuration accepted")
	}
	settings, err := parseOptions([]string{
		"--operator-config", "operator.bin",
		"--ledger", "ledger.db",
		"--tls-cert", "server.pem",
		"--tls-key", "server-key.pem",
		"--client-ca", "ca.pem",
		"--coordinator-key", "coordinator.pub",
	})
	if err != nil || settings.listen != "127.0.0.1:9443" {
		t.Fatalf("valid configuration rejected: %+v %v", settings, err)
	}
}

func TestReadSecretFileRejectsBroadPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "operator.bin")
	if err := os.WriteFile(path, []byte("sealed-test-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	if contents, err := readSecretFile(path, 128); err != nil || string(contents) != "sealed-test-material" {
		t.Fatalf("0600 secret rejected: %q %v", contents, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(path, 128); err == nil {
		t.Fatal("group-readable secret accepted")
	}
}
