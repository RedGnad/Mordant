package governedfhe

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func retainedFixture(t *testing.T, scenario string) ([]byte, Digest, Digest) {
	t.Helper()
	manifest, caseID := DigestBytes([]byte("manifest/"+scenario)), DigestBytes([]byte("case/"+scenario))
	value := map[string]any{
		"schemaVersion":  retainedProtectionEvidenceSchema,
		"manifestDigest": manifest,
		"scenario":       scenario,
		"protectionCase": map[string]any{"fheCaseId": caseID},
		"chronology":     map[string]any{"events": []any{}},
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data, manifest, caseID
}

func TestRetainPublicEvidenceConfinesDestinationCapability(t *testing.T) {
	data, manifest, caseID := retainedFixture(t, "conflict")
	t.Run("exact create and retry", func(t *testing.T) {
		root := canonicalTempDir(t)
		reconciled, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data)
		if err != nil || reconciled {
			t.Fatalf("create: reconciled=%v err=%v", reconciled, err)
		}
		reconciled, err = RetainPublicEvidence(root, "conflict", manifest, caseID, data)
		if err != nil || !reconciled {
			t.Fatalf("retry: reconciled=%v err=%v", reconciled, err)
		}
		retained, err := os.ReadFile(filepath.Join(root, "conflict.json"))
		if err != nil || string(retained) != string(data) {
			t.Fatal("exact retained bytes changed")
		}
	})
	t.Run("destination symlink", func(t *testing.T) {
		root := canonicalTempDir(t)
		target := filepath.Join(canonicalTempDir(t), "target")
		if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "conflict.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data); err == nil {
			t.Fatal("destination symlink accepted")
		}
		if got, _ := os.ReadFile(target); string(got) != "untouched" {
			t.Fatal("symlink target changed")
		}
	})
	t.Run("root and intermediate symlinks", func(t *testing.T) {
		realRoot := canonicalTempDir(t)
		rootLink := filepath.Join(canonicalTempDir(t), "root-link")
		if err := os.Symlink(realRoot, rootLink); err != nil {
			t.Fatal(err)
		}
		if _, err := RetainPublicEvidence(rootLink, "conflict", manifest, caseID, data); err == nil {
			t.Fatal("root symlink accepted")
		}
		parent := canonicalTempDir(t)
		realParent := canonicalTempDir(t)
		if err := os.Mkdir(filepath.Join(realParent, "retained"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realParent, filepath.Join(parent, "intermediate")); err != nil {
			t.Fatal(err)
		}
		if _, err := RetainPublicEvidence(filepath.Join(parent, "intermediate", "retained"), "conflict", manifest, caseID, data); err == nil {
			t.Fatal("intermediate symlink accepted")
		}
	})
	t.Run("non-directory root and non-regular destination", func(t *testing.T) {
		rootFile := filepath.Join(canonicalTempDir(t), "root-file")
		if err := os.WriteFile(rootFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := RetainPublicEvidence(rootFile, "conflict", manifest, caseID, data); err == nil {
			t.Fatal("non-directory root accepted")
		}
		root := canonicalTempDir(t)
		if err := os.Mkdir(filepath.Join(root, "conflict.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data); err == nil {
			t.Fatal("non-regular destination accepted")
		}
	})
	t.Run("cross-case and cross-scenario", func(t *testing.T) {
		if _, err := RetainPublicEvidence(canonicalTempDir(t), "conflict", manifest, DigestBytes([]byte("other")), data); !errors.Is(err, ErrArtifact) {
			t.Fatalf("cross-case: %v", err)
		}
		if _, err := RetainPublicEvidence(canonicalTempDir(t), "no-conflict", manifest, caseID, data); !errors.Is(err, ErrArtifact) {
			t.Fatalf("cross-scenario: %v", err)
		}
	})
	t.Run("parent replacement", func(t *testing.T) {
		parent := canonicalTempDir(t)
		root := filepath.Join(parent, "retained")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		old := filepath.Join(parent, "retained-old")
		_, err := retainPublicEvidence(root, "conflict", manifest, caseID, data, func() {
			if renameErr := os.Rename(root, old); renameErr != nil {
				t.Fatal(renameErr)
			}
			if mkdirErr := os.Mkdir(root, 0o700); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
		})
		if err == nil {
			t.Fatal("parent replacement accepted")
		}
		if _, statErr := os.Stat(filepath.Join(root, "conflict.json")); !os.IsNotExist(statErr) {
			t.Fatal("replacement path received evidence")
		}
	})
}
