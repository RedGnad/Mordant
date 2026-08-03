package governedfhe

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const retainedProtectionEvidenceSchema = "mordant.protection-evidence/4"

type retainedEvidenceProjection struct {
	SchemaVersion  string `json:"schemaVersion"`
	ManifestDigest Digest `json:"manifestDigest"`
	Scenario       string `json:"scenario"`
	ProtectionCase struct {
		FHECaseID Digest `json:"fheCaseId"`
	} `json:"protectionCase"`
}

type retentionHooks struct {
	afterComponentSnapshot func(index int, component string) error
	afterPin               func() error
	beforeCreate           func() error
	beforePublish          func(directoryFD int, name string) error
	afterPublication       func() error
}

// RetainPublicEvidence publishes one verified public manifest through a pinned
// directory capability. The root must already exist in immutable local
// operator configuration; this function never creates or follows it.
func RetainPublicEvidence(root, scenario string, expectedManifest, expectedCase Digest, data []byte) (bool, error) {
	return retainPublicEvidenceWithHooks(root, scenario, expectedManifest, expectedCase, data, retentionHooks{})
}

// retainPublicEvidence preserves the original package-test hook while routing
// production and tests through the same dedicated retention opener.
func retainPublicEvidence(root, scenario string, expectedManifest, expectedCase Digest, data []byte, afterPin func()) (bool, error) {
	hooks := retentionHooks{}
	if afterPin != nil {
		hooks.afterPin = func() error {
			afterPin()
			return nil
		}
	}
	return retainPublicEvidenceWithHooks(root, scenario, expectedManifest, expectedCase, data, hooks)
}

func retentionObjectName(scenario string) (string, error) {
	switch scenario {
	case "conflict":
		return "conflict.json", nil
	case "no-conflict":
		return "no-conflict.json", nil
	default:
		return "", ErrStore
	}
}

// openAbsoluteDirectoryNoFollow pins an already-existing absolute directory by
// starting at / and traversing every component relative to the prior pinned
// descriptor. fstatat is only a race detector: the opened descriptor is the
// authority, and its identity must match the snapshot taken immediately before
// openat. No component is created and no symlink is followed.
func openAbsoluteDirectoryNoFollow(root string, afterSnapshot func(index int, component string) error) (int, unix.Stat_t, error) {
	var zero unix.Stat_t
	if !filepath.IsAbs(root) {
		return -1, zero, ErrStore
	}
	clean := filepath.Clean(root)
	currentFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, zero, ErrStore
	}
	closeCurrent := true
	defer func() {
		if closeCurrent {
			_ = unix.Close(currentFD)
		}
	}()
	var currentStat unix.Stat_t
	if unix.Fstat(currentFD, &currentStat) != nil || currentStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return -1, zero, ErrStore
	}
	trimmed := strings.TrimPrefix(clean, string(filepath.Separator))
	if trimmed != "" {
		components := strings.Split(trimmed, string(filepath.Separator))
		for index, component := range components {
			if component == "" || component == "." || component == ".." || strings.ContainsRune(component, 0) {
				return -1, zero, ErrStore
			}
			var snapshot unix.Stat_t
			if unix.Fstatat(currentFD, component, &snapshot, unix.AT_SYMLINK_NOFOLLOW) != nil || snapshot.Mode&unix.S_IFMT != unix.S_IFDIR {
				return -1, zero, ErrStore
			}
			if afterSnapshot != nil {
				if err := afterSnapshot(index, component); err != nil {
					return -1, zero, ErrStore
				}
			}
			nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if openErr != nil {
				return -1, zero, ErrStore
			}
			var nextStat unix.Stat_t
			if unix.Fstat(nextFD, &nextStat) != nil || nextStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
				uint64(nextStat.Dev) != uint64(snapshot.Dev) || uint64(nextStat.Ino) != uint64(snapshot.Ino) {
				_ = unix.Close(nextFD)
				return -1, zero, ErrStore
			}
			if unix.Close(currentFD) != nil {
				_ = unix.Close(nextFD)
				return -1, zero, ErrStore
			}
			currentFD, currentStat = nextFD, nextStat
		}
	}
	closeCurrent = false
	return currentFD, currentStat, nil
}

func openRetentionRoot(root string, hooks retentionHooks) (*objectStore, error) {
	fd, stat, err := openAbsoluteDirectoryNoFollow(root, hooks.afterComponentSnapshot)
	if err != nil {
		return nil, err
	}
	store := &objectStore{
		root: filepath.Clean(root), fd: fd, device: uint64(stat.Dev), inode: uint64(stat.Ino),
		quota: PublicCaseQuota, maxObjects: maxPublicCaseObjects, fileMode: os.FileMode(0o444), directory: os.FileMode(0o755),
	}
	if _, err := store.usedBytes(); err != nil {
		_ = store.close()
		return nil, err
	}
	return store, nil
}

// verifyConfiguredRetentionRoot is a read-only pathname identity check. All
// reads and writes continue to use the original pinned descriptor; this second
// traversal can only veto success if the configured path was replaced.
func verifyConfiguredRetentionRoot(store *objectStore) error {
	if store == nil || store.verifyPinned() != nil {
		return ErrStore
	}
	fd, stat, err := openAbsoluteDirectoryNoFollow(store.root, nil)
	if err != nil {
		return ErrStore
	}
	defer unix.Close(fd)
	if uint64(stat.Dev) != store.device || uint64(stat.Ino) != store.inode {
		return ErrStore
	}
	return nil
}

func validateRetainedProjection(data []byte, scenario string, expectedManifest, expectedCase Digest) error {
	var projection retainedEvidenceProjection
	if json.Unmarshal(data, &projection) != nil || projection.SchemaVersion != retainedProtectionEvidenceSchema ||
		projection.Scenario != scenario || projection.ManifestDigest != expectedManifest ||
		projection.ProtectionCase.FHECaseID != expectedCase || !nonzero(expectedManifest, expectedCase) {
		return ErrArtifact
	}
	return nil
}

func verifyRetainedReadback(store *objectStore, name, scenario string, expectedManifest, expectedCase Digest, expected []byte) error {
	retained, ref, err := store.readNamed(name, PublicCaseQuota)
	if err != nil || !bytes.Equal(retained, expected) || ref.Digest != DigestBytes(expected) ||
		validateRetainedProjection(retained, scenario, expectedManifest, expectedCase) != nil ||
		store.verifyPinned() != nil || verifyConfiguredRetentionRoot(store) != nil {
		return ErrStore
	}
	return nil
}

func retainPublicEvidenceWithHooks(
	root, scenario string,
	expectedManifest, expectedCase Digest,
	data []byte,
	hooks retentionHooks,
) (bool, error) {
	name, err := retentionObjectName(scenario)
	if err != nil || !filepath.IsAbs(root) || len(data) == 0 {
		return false, ErrStore
	}
	// Acquiring the already-existing component-wise no-follow capability is the
	// first authoritative filesystem validation. Manifest parsing happens only
	// after the descriptor is pinned.
	store, err := openRetentionRoot(root, hooks)
	if err != nil {
		return false, err
	}
	defer store.close()
	if hooks.afterPin != nil {
		if err := hooks.afterPin(); err != nil {
			return false, ErrStore
		}
	}
	if verifyConfiguredRetentionRoot(store) != nil {
		return false, ErrStore
	}
	if err := validateRetainedProjection(data, scenario, expectedManifest, expectedCase); err != nil {
		return false, err
	}

	existingFD, _, openErr := store.openRegular(name)
	if openErr == nil {
		_ = unix.Close(existingFD)
		if verifyRetainedReadback(store, name, scenario, expectedManifest, expectedCase, data) != nil {
			return false, ErrStore
		}
		return true, nil
	}
	if !errors.Is(openErr, unix.ENOENT) {
		return false, ErrStore
	}
	if hooks.beforeCreate != nil {
		if err := hooks.beforeCreate(); err != nil {
			return false, ErrStore
		}
	}
	if verifyConfiguredRetentionRoot(store) != nil {
		return false, ErrStore
	}
	if _, err := store.createWithHooks(name, data, objectCreateHooks{beforePublish: hooks.beforePublish}); err != nil {
		return false, err
	}
	if hooks.afterPublication != nil {
		if err := hooks.afterPublication(); err != nil {
			return false, ErrStore
		}
	}
	if verifyRetainedReadback(store, name, scenario, expectedManifest, expectedCase, data) != nil {
		return false, ErrStore
	}
	return false, nil
}
