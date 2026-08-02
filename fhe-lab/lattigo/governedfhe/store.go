package governedfhe

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	parametersObject         = "parameters.bin"
	publicKeyObject          = "public-key.bin"
	relinearizationKeyObject = "relinearization-key.bin"
	caseCryptoObject         = "case-crypto.json"
	caseBindingObject        = "case-binding.json"
	caseManifestObject       = "case-manifest.json"
	bindingSignatureAObject  = "binding-signature-a.json"
	bindingSignatureBObject  = "binding-signature-b.json"
	submissionAObject        = "submission-a.bin"
	submissionBObject        = "submission-b.bin"
	submissionAManifest      = "submission-a.json"
	submissionBManifest      = "submission-b.json"
	resultCiphertextObject   = "result-conflict.bin"
	evaluatedArtifactObject  = "evaluated-conflict.json"
	releaseAuthorityObject   = "release-authority.json"
	publicResultObject       = "governed-conflict-result.json"
	recourseRecordObject     = "recourse-record.json"
	evidenceObject           = "evidence.json"

	secretKeyObject           = "secret-key.bin"
	decryptorSigningKeyObject = "decryptor-signing-key.bin"
	privateCaseObject         = "private-case.json"
	releaseAdmissionObject    = "release-admitted.json"
	releaseConsumedObject     = "release-consumed.json"
	retainedResultObject      = "retained-governed-result.json"
)

func galoisObject(index int) string { return fmt.Sprintf("galois-key-%02d.bin", index) }

type objectStore struct {
	root      string
	quota     int64
	fileMode  os.FileMode
	directory os.FileMode
}

func openObjectStore(root string, quota int64, private bool) (*objectStore, error) {
	if !filepath.IsAbs(root) || quota <= 0 {
		return nil, ErrStore
	}
	clean := filepath.Clean(root)
	directoryMode, fileMode := os.FileMode(0o755), os.FileMode(0o644)
	if private {
		directoryMode, fileMode = 0o700, 0o600
	}
	if err := os.MkdirAll(clean, directoryMode); err != nil {
		return nil, fmt.Errorf("%w: create root: %v", ErrStore, err)
	}
	info, err := os.Lstat(clean)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrStore
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil || resolved != clean {
		return nil, ErrStore
	}
	if private {
		if err := os.Chmod(clean, directoryMode); err != nil {
			return nil, ErrStore
		}
	}
	return &objectStore{root: clean, quota: quota, fileMode: fileMode, directory: directoryMode}, nil
}

func validateObjectName(name string) error {
	if name == "" || name != filepath.Base(name) || filepath.IsAbs(name) || strings.Contains(name, "..") ||
		strings.ContainsAny(name, "/\\") || strings.ContainsRune(name, 0) {
		return ErrStore
	}
	return nil
}

func (s *objectStore) path(name string) (string, error) {
	if s == nil || validateObjectName(name) != nil {
		return "", ErrStore
	}
	return filepath.Join(s.root, name), nil
}

func (s *objectStore) usedBytes() (int64, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return 0, ErrStore
	}
	var total int64
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return 0, ErrStore
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return 0, ErrStore
		}
		total += info.Size()
		if total > s.quota {
			return 0, ErrStore
		}
	}
	return total, nil
}

func (s *objectStore) create(name string, data []byte) (ObjectRef, error) {
	var ref ObjectRef
	target, err := s.path(name)
	if err != nil || len(data) == 0 || int64(len(data)) > s.quota {
		return ref, ErrStore
	}
	used, err := s.usedBytes()
	if err != nil || used+int64(len(data)) > s.quota {
		return ref, ErrStore
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return ref, ErrStore
	}
	temp, err := os.CreateTemp(s.root, ".mordant-create-")
	if err != nil {
		return ref, ErrStore
	}
	tempName := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(s.fileMode); err != nil {
		return ref, fmt.Errorf("%w: chmod temporary object: %v", ErrStore, err)
	}
	if _, err := temp.Write(data); err != nil {
		return ref, fmt.Errorf("%w: write temporary object: %v", ErrStore, err)
	}
	if err := temp.Sync(); err != nil {
		return ref, fmt.Errorf("%w: sync temporary object: %v", ErrStore, err)
	}
	if err := temp.Close(); err != nil {
		return ref, fmt.Errorf("%w: close temporary object: %v", ErrStore, err)
	}
	// A hard-link publication is atomic and, unlike rename on Unix, refuses to
	// replace an existing target.
	if err := os.Link(tempName, target); err != nil {
		return ref, fmt.Errorf("%w: publish object: %v", ErrStore, err)
	}
	if err := os.Remove(tempName); err != nil {
		return ref, ErrStore
	}
	committed = true
	directory, err := os.Open(s.root)
	if err != nil {
		return ref, ErrStore
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return ref, ErrStore
	}
	_ = directory.Close()
	return ObjectRef{Path: name, Digest: DigestBytes(data), Length: int64(len(data))}, nil
}

func (s *objectStore) createJSON(name string, value any) (ObjectRef, []byte, error) {
	encoded, err := marshalCanonical(value)
	if err != nil {
		return ObjectRef{}, nil, err
	}
	ref, err := s.create(name, encoded)
	return ref, encoded, err
}

func (s *objectStore) read(ref ObjectRef, maximum int64) ([]byte, error) {
	if ref.validate(ref.Path, maximum) != nil {
		return nil, ErrArtifact
	}
	path, err := s.path(ref.Path)
	if err != nil {
		return nil, ErrStore
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != ref.Length {
		return nil, ErrArtifact
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) != ref.Length || DigestBytes(data) != ref.Digest {
		return nil, ErrArtifact
	}
	return data, nil
}

func (s *objectStore) readNamed(name string, maximum int64) ([]byte, ObjectRef, error) {
	path, err := s.path(name)
	if err != nil {
		return nil, ObjectRef{}, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, ObjectRef{}, ErrArtifact
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ObjectRef{}, ErrArtifact
	}
	hash := sha256.New()
	data, err := io.ReadAll(io.TeeReader(io.LimitReader(file, maximum+1), hash))
	_ = file.Close()
	if err != nil || int64(len(data)) != info.Size() || int64(len(data)) > maximum {
		return nil, ObjectRef{}, ErrArtifact
	}
	var digest Digest
	copy(digest[:], hash.Sum(nil))
	return data, ObjectRef{Path: name, Digest: digest, Length: int64(len(data))}, nil
}

func (s *objectStore) readJSON(name string, target any) ([]byte, ObjectRef, error) {
	data, ref, err := s.readNamed(name, maxManifestBytes)
	if err != nil || decodeStrict(data, target) != nil {
		return nil, ObjectRef{}, ErrArtifact
	}
	return data, ref, nil
}

func (s *objectStore) exists(name string) bool {
	path, err := s.path(name)
	if err != nil {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func (s *objectStore) names() ([]string, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, ErrStore
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || strings.HasPrefix(entry.Name(), ".mordant-create-") {
			return nil, ErrStore
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (s *objectStore) rejectUnknown(allowed map[string]bool) error {
	names, err := s.names()
	if err != nil {
		return err
	}
	for _, name := range names {
		if !allowed[name] {
			return ErrArtifact
		}
	}
	return nil
}
