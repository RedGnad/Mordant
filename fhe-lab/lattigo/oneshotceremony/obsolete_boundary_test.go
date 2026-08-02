package oneshotceremony

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
)

func TestObsoleteRecoverableCommandsAreBuildConstrained(t *testing.T) {
	directories := []string{
		"ceremony-client",
		"ceremony-coordinator",
		"ceremony-evaluator",
		"ceremony-lab",
		"ceremony-operator",
	}
	for _, directory := range directories {
		entries, err := os.ReadDir(filepath.Join("..", "cmd", directory))
		if err != nil {
			t.Fatalf("read obsolete command %s: %v", directory, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
				continue
			}
			path := filepath.Join("..", "cmd", directory, entry.Name())
			file, err := os.Open(path)
			if err != nil {
				t.Fatalf("open %s: %v", path, err)
			}
			scanner := bufio.NewScanner(file)
			first := ""
			if scanner.Scan() {
				first = scanner.Text()
			}
			closeErr := file.Close()
			if scanner.Err() != nil || closeErr != nil {
				t.Fatalf("read %s: scan=%v close=%v", path, scanner.Err(), closeErr)
			}
			if first != "//go:build obsolete_recoverable_ceremony" {
				t.Fatalf("obsolete command source is reachable without its historical tag: %s", path)
			}
		}
	}

	implementationFiles := []string{
		"ceremony_recovery.go",
		filepath.Join("internal", "thresholdnet", "ceremony.go"),
		filepath.Join("internal", "thresholdnet", "ceremony_ledger.go"),
	}
	for _, relative := range implementationFiles {
		path := filepath.Join("..", relative)
		file, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		scanner := bufio.NewScanner(file)
		first := ""
		if scanner.Scan() {
			first = scanner.Text()
		}
		closeErr := file.Close()
		if scanner.Err() != nil || closeErr != nil {
			t.Fatalf("read %s: scan=%v close=%v", path, scanner.Err(), closeErr)
		}
		if first != "//go:build obsolete_recoverable_ceremony" {
			t.Fatalf("recoverable implementation is reachable without its historical tag: %s", path)
		}
	}
}

func TestLegacyRecoveryAndBundleMagicIsUnconditionallyRejected(t *testing.T) {
	for _, magic := range []string{"MCR1", "MCL1"} {
		data := []byte(magic)
		if _, err := ParseContext(data); err == nil {
			t.Fatalf("legacy context magic accepted: %s", magic)
		}
		if _, err := ParsePrivateBundle(data); err == nil {
			t.Fatalf("legacy private bundle magic accepted: %s", magic)
		}
		if _, err := ParseSealedOperatorBundle(data); err == nil {
			t.Fatalf("legacy sealed bundle magic accepted: %s", magic)
		}
		if _, err := ParsePublicBundle(data); err == nil {
			t.Fatalf("legacy public bundle magic accepted: %s", magic)
		}
	}
}
