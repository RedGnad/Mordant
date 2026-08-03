package governedfhe

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

func assertMissing(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("expected missing path %s, got %v", path, err)
		}
	}
}

func replaceRoot(t *testing.T, root, old, replacement string) {
	t.Helper()
	if err := os.Rename(root, old); err != nil {
		t.Fatal(err)
	}
	if replacement == "" {
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.Rename(replacement, root); err != nil {
		t.Fatal(err)
	}
}

func TestRetainPublicEvidenceConfinesDestinationCapability(t *testing.T) {
	data, manifest, caseID := retainedFixture(t, "conflict")

	t.Run("exact create and byte-identical retry", func(t *testing.T) {
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

	t.Run("stable destination symlink", func(t *testing.T) {
		root := canonicalTempDir(t)
		target := filepath.Join(canonicalTempDir(t), "target")
		if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "conflict.json")); err != nil {
			t.Fatal(err)
		}
		if reconciled, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data); err == nil || reconciled {
			t.Fatalf("destination symlink accepted: reconciled=%v err=%v", reconciled, err)
		}
		if got, _ := os.ReadFile(target); string(got) != "untouched" {
			t.Fatal("symlink target changed")
		}
	})

	t.Run("stable root symlink", func(t *testing.T) {
		realRoot := canonicalTempDir(t)
		rootLink := filepath.Join(canonicalTempDir(t), "root-link")
		if err := os.Symlink(realRoot, rootLink); err != nil {
			t.Fatal(err)
		}
		if reconciled, err := RetainPublicEvidence(rootLink, "conflict", manifest, caseID, data); err == nil || reconciled {
			t.Fatalf("root symlink accepted: reconciled=%v err=%v", reconciled, err)
		}
		assertMissing(t, filepath.Join(realRoot, "conflict.json"))
	})

	t.Run("stable intermediate parent symlink", func(t *testing.T) {
		parent := canonicalTempDir(t)
		realParent := canonicalTempDir(t)
		if err := os.Mkdir(filepath.Join(realParent, "retained"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realParent, filepath.Join(parent, "intermediate")); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(parent, "intermediate", "retained")
		if reconciled, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data); err == nil || reconciled {
			t.Fatalf("intermediate symlink accepted: reconciled=%v err=%v", reconciled, err)
		}
		assertMissing(t, filepath.Join(realParent, "retained", "conflict.json"))
	})

	t.Run("deleted root is never recreated", func(t *testing.T) {
		parent := canonicalTempDir(t)
		root := filepath.Join(parent, "retained")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(root); err != nil {
			t.Fatal(err)
		}
		for attempt := 0; attempt < 2; attempt++ {
			if reconciled, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data); err == nil || reconciled {
				t.Fatalf("missing root accepted: reconciled=%v err=%v", reconciled, err)
			}
			assertMissing(t, root)
		}
	})

	t.Run("root substitution during component traversal", func(t *testing.T) {
		parent := canonicalTempDir(t)
		root := filepath.Join(parent, "retained")
		old := filepath.Join(parent, "retained-a")
		replacement := filepath.Join(parent, "retained-b")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(replacement, 0o700); err != nil {
			t.Fatal(err)
		}
		swapped := false
		hooks := retentionHooks{afterComponentSnapshot: func(_ int, component string) error {
			if component == filepath.Base(root) && !swapped {
				replaceRoot(t, root, old, replacement)
				swapped = true
			}
			return nil
		}}
		reconciled, err := retainPublicEvidenceWithHooks(root, "conflict", manifest, caseID, data, hooks)
		if err == nil || reconciled || !swapped {
			t.Fatalf("component race accepted: swapped=%v reconciled=%v err=%v", swapped, reconciled, err)
		}
		assertMissing(t, filepath.Join(old, "conflict.json"), filepath.Join(root, "conflict.json"))
	})

	t.Run("substitution after final descriptor pin", func(t *testing.T) {
		parent := canonicalTempDir(t)
		root := filepath.Join(parent, "retained")
		old := filepath.Join(parent, "retained-old")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		hooks := retentionHooks{afterPin: func() error {
			replaceRoot(t, root, old, "")
			return nil
		}}
		reconciled, err := retainPublicEvidenceWithHooks(root, "conflict", manifest, caseID, data, hooks)
		if err == nil || reconciled {
			t.Fatalf("post-pin substitution accepted: reconciled=%v err=%v", reconciled, err)
		}
		assertMissing(t, filepath.Join(old, "conflict.json"), filepath.Join(root, "conflict.json"))
	})

	t.Run("root rename and replacement before temporary creation", func(t *testing.T) {
		parent := canonicalTempDir(t)
		root := filepath.Join(parent, "retained")
		old := filepath.Join(parent, "retained-old")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		hooks := retentionHooks{beforeCreate: func() error {
			replaceRoot(t, root, old, "")
			return nil
		}}
		reconciled, err := retainPublicEvidenceWithHooks(root, "conflict", manifest, caseID, data, hooks)
		if err == nil || reconciled {
			t.Fatalf("pre-create replacement accepted: reconciled=%v err=%v", reconciled, err)
		}
		assertMissing(t, filepath.Join(old, "conflict.json"), filepath.Join(root, "conflict.json"))
	})

	t.Run("concurrent destination creation never overwrites", func(t *testing.T) {
		root := canonicalTempDir(t)
		const concurrent = "concurrent-winner"
		hooks := retentionHooks{beforePublish: func(directoryFD int, name string) error {
			fd, err := unix.Openat(directoryFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o444)
			if err != nil {
				return err
			}
			file := os.NewFile(uintptr(fd), name)
			if file == nil {
				_ = unix.Close(fd)
				return ErrStore
			}
			if _, err := file.Write([]byte(concurrent)); err != nil {
				_ = file.Close()
				return err
			}
			if err := file.Sync(); err != nil {
				_ = file.Close()
				return err
			}
			return file.Close()
		}}
		reconciled, err := retainPublicEvidenceWithHooks(root, "conflict", manifest, caseID, data, hooks)
		if err == nil || reconciled {
			t.Fatalf("concurrent destination accepted: reconciled=%v err=%v", reconciled, err)
		}
		got, readErr := os.ReadFile(filepath.Join(root, "conflict.json"))
		if readErr != nil || string(got) != concurrent {
			t.Fatalf("concurrent destination overwritten: %q err=%v", got, readErr)
		}
		entries, readDirErr := os.ReadDir(root)
		if readDirErr != nil {
			t.Fatal(readDirErr)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".mordant-create-") {
				t.Fatalf("temporary object leaked: %s", entry.Name())
			}
		}
	})

	t.Run("FIFO without writer fails without blocking", func(t *testing.T) {
		root := canonicalTempDir(t)
		fifo := filepath.Join(root, "conflict.json")
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("FIFO accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("FIFO classification blocked without a writer")
		}
	})

	t.Run("directory socket and device destinations are rejected", func(t *testing.T) {
		t.Run("directory", func(t *testing.T) {
			root := canonicalTempDir(t)
			if err := os.Mkdir(filepath.Join(root, "conflict.json"), 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data); err == nil {
				t.Fatal("directory destination accepted")
			}
		})
		t.Run("socket", func(t *testing.T) {
			shortRoot, err := os.MkdirTemp("/tmp", "mrt-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(shortRoot)
			root, err := filepath.EvalSymlinks(shortRoot)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "conflict.json")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if _, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data); err == nil {
				t.Fatal("socket destination accepted")
			}
		})
		t.Run("device", func(t *testing.T) {
			fd, stat, err := openAbsoluteDirectoryNoFollow("/dev", nil)
			if err != nil {
				t.Fatal(err)
			}
			store := &objectStore{root: "/dev", fd: fd, device: uint64(stat.Dev), inode: uint64(stat.Ino)}
			defer store.close()
			if opened, _, err := store.openRegular("null"); err == nil {
				_ = unix.Close(opened)
				t.Fatal("device accepted as regular file")
			}
		})
	})

	t.Run("pre-created temporary filename is never consumed", func(t *testing.T) {
		root := canonicalTempDir(t)
		temporary := filepath.Join(root, ".mordant-create-preexisting")
		if err := os.WriteFile(temporary, []byte("untouched"), 0o600); err != nil {
			t.Fatal(err)
		}
		if reconciled, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data); err == nil || reconciled {
			t.Fatalf("pre-created temporary object accepted: reconciled=%v err=%v", reconciled, err)
		}
		if got, _ := os.ReadFile(temporary); string(got) != "untouched" {
			t.Fatal("pre-created temporary object changed")
		}
		assertMissing(t, filepath.Join(root, "conflict.json"))
	})

	t.Run("parent replacement after publication fails closed", func(t *testing.T) {
		parent := canonicalTempDir(t)
		root := filepath.Join(parent, "retained")
		old := filepath.Join(parent, "retained-old")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		hooks := retentionHooks{afterPublication: func() error {
			replaceRoot(t, root, old, "")
			return nil
		}}
		reconciled, err := retainPublicEvidenceWithHooks(root, "conflict", manifest, caseID, data, hooks)
		if err == nil || reconciled {
			t.Fatalf("post-publication replacement accepted: reconciled=%v err=%v", reconciled, err)
		}
		retained, readErr := os.ReadFile(filepath.Join(old, "conflict.json"))
		if readErr != nil || string(retained) != string(data) {
			t.Fatalf("pinned directory did not receive exact bytes: err=%v", readErr)
		}
		assertMissing(t, filepath.Join(root, "conflict.json"))
	})

	t.Run("different CaseID at same scenario destination", func(t *testing.T) {
		root := canonicalTempDir(t)
		if _, err := RetainPublicEvidence(root, "conflict", manifest, caseID, data); err != nil {
			t.Fatal(err)
		}
		otherData, otherManifest, otherCase := retainedFixture(t, "conflict-other")
		// Preserve the destination scenario while changing the signed roots.
		var other map[string]any
		if err := json.Unmarshal(otherData, &other); err != nil {
			t.Fatal(err)
		}
		other["scenario"] = "conflict"
		otherData, _ = json.Marshal(other)
		if reconciled, err := RetainPublicEvidence(root, "conflict", otherManifest, otherCase, otherData); err == nil || reconciled {
			t.Fatalf("cross-case replacement accepted: reconciled=%v err=%v", reconciled, err)
		}
		retained, err := os.ReadFile(filepath.Join(root, "conflict.json"))
		if err != nil || string(retained) != string(data) {
			t.Fatal("original case destination was overwritten")
		}
	})

	t.Run("cross-case and cross-scenario request fields", func(t *testing.T) {
		if _, err := RetainPublicEvidence(canonicalTempDir(t), "conflict", manifest, DigestBytes([]byte("other")), data); !errors.Is(err, ErrArtifact) {
			t.Fatalf("cross-case: %v", err)
		}
		if _, err := RetainPublicEvidence(canonicalTempDir(t), "no-conflict", manifest, caseID, data); !errors.Is(err, ErrArtifact) {
			t.Fatalf("cross-scenario: %v", err)
		}
	})
}
