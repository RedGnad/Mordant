package governedfhe

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	parametersObject           = "parameters.bin"
	publicKeyObject            = "public-key.bin"
	relinearizationKeyObject   = "relinearization-key.bin"
	caseCryptoObject           = "case-crypto.json"
	caseBindingObject          = "case-binding.json"
	caseManifestObject         = "case-manifest.json"
	bindingSignatureAObject    = "binding-signature-a.json"
	bindingSignatureBObject    = "binding-signature-b.json"
	submissionAObject          = "submission-a.bin"
	submissionBObject          = "submission-b.bin"
	submissionAManifest        = "submission-a.json"
	submissionBManifest        = "submission-b.json"
	evaluationAdmissionObject  = "evaluation-admitted.json"
	evaluationCompletedObject  = "evaluation-completed.json"
	resultCiphertextObject     = "result-conflict.bin"
	evaluatedArtifactObject    = "evaluated-conflict.json"
	releaseAuthorityObject     = "release-authority.json"
	publicResultObject         = "governed-conflict-result.json"
	recourseClockObject        = "recourse-clock-binding.json"
	recourseRecordObject       = "recourse-record.json"
	protectionBindingObject    = "protection-binding.json"
	protectionSignatureAObject = "protection-binding-signature-a.json"
	protectionSignatureBObject = "protection-binding-signature-b.json"
	productAttestationObject   = "product-recourse-attestation.json"
	evidenceObject             = "evidence.json"

	secretKeyObject                               = "secret-key.bin"
	decryptorSigningKeyObject                     = "decryptor-signing-key.bin"
	privateCaseObject                             = "private-case.json"
	recomputeAdmissionObject                      = "recompute-admitted.json"
	recomputedResultObject                        = "recomputed-conflict.bin"
	recomputeVerifiedObject                       = "recompute-verified.json"
	recomputeMismatchObject                       = "recompute-mismatch.json"
	releaseAdmissionObject                        = "release-admitted.json"
	releaseConsumedObject                         = "release-consumed.json"
	retainedResultObject                          = "retained-governed-result.json"
	maxPublicCaseObjects                          = 40
	maxPrivateCaseObjects                         = 16
	maximumTemporaryNameTries                     = 16
	maximumRecoverableParticipantTemporaryObjects = 2
)

func galoisObject(index int) string { return fmt.Sprintf("galois-key-%02d.bin", index) }

type objectStore struct {
	root       string
	fd         int
	device     uint64
	inode      uint64
	quota      int64
	maxObjects int
	fileMode   os.FileMode
	directory  os.FileMode
	private    bool
}

type objectCreateHooks struct {
	beforePublish func(directoryFD int, name string) error
	afterCommit   func(directoryFD int, name string) error
}

func openObjectStore(root string, quota int64, private bool) (*objectStore, error) {
	return openObjectStoreWithParticipantRecovery(root, quota, private, nil)
}

// openObjectStoreWithParticipantRecovery is deliberately not used by managed
// governed-FHE paths. A non-nil target map authorizes the experimental
// participant-originated path to remove at most two strictly shaped crash
// temporaries while holding the directory lock. Post-link temporaries are
// recovered only when their inode has exactly one authorized target link.
func openObjectStoreWithParticipantRecovery(root string, quota int64, private bool, recoverableTargets map[string]int64) (*objectStore, error) {
	if !filepath.IsAbs(root) || quota <= 0 {
		return nil, ErrStore
	}
	clean := filepath.Clean(root)
	directoryMode, fileMode, maxObjects := os.FileMode(0o755), os.FileMode(0o444), maxPublicCaseObjects
	if private {
		directoryMode, fileMode, maxObjects = 0o700, 0o400, maxPrivateCaseObjects
	}
	if err := os.MkdirAll(clean, directoryMode); err != nil {
		return nil, fmt.Errorf("%w: create root: %v", ErrStore, err)
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil || resolved != clean {
		return nil, ErrStore
	}
	fd, err := unix.Open(clean, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: pin root: %v", ErrStore, err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = unix.Close(fd)
		}
	}()
	var descriptorStat, pathStat unix.Stat_t
	if unix.Fstat(fd, &descriptorStat) != nil || unix.Stat(clean, &pathStat) != nil ||
		descriptorStat.Mode&unix.S_IFMT != unix.S_IFDIR || pathStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint64(descriptorStat.Dev) != uint64(pathStat.Dev) || uint64(descriptorStat.Ino) != uint64(pathStat.Ino) {
		return nil, ErrStore
	}
	if private {
		if err := unix.Fchmod(fd, uint32(directoryMode.Perm())); err != nil {
			return nil, ErrStore
		}
	}
	store := &objectStore{
		root: clean, fd: fd, device: uint64(descriptorStat.Dev), inode: uint64(descriptorStat.Ino),
		quota: quota, maxObjects: maxObjects, fileMode: fileMode, directory: directoryMode, private: private,
	}
	if recoverableTargets != nil {
		if err := store.recoverParticipantOriginatedTemporaryObjects(recoverableTargets); err != nil {
			return nil, err
		}
	}
	if _, err := store.usedBytes(); err != nil {
		return nil, err
	}
	closeOnError = false
	return store, nil
}

func validMordantTemporaryObjectName(name string) bool {
	const prefix = ".mordant-create-"
	if len(name) != len(prefix)+32 || !strings.HasPrefix(name, prefix) {
		return false
	}
	for _, value := range []byte(name[len(prefix):]) {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return false
		}
	}
	return true
}

func sameStatIdentity(left, right unix.Stat_t) bool {
	return uint64(left.Dev) == uint64(right.Dev) && uint64(left.Ino) == uint64(right.Ino)
}

func (s *objectStore) recoverParticipantOriginatedTemporaryObjects(targets map[string]int64) error {
	if s == nil || len(targets) == 0 || s.verifyPathIdentity() != nil {
		return ErrStore
	}
	maximum := int64(0)
	for name, limit := range targets {
		if validateObjectName(name) != nil || limit <= 0 || limit > s.quota {
			return ErrStore
		}
		if limit > maximum {
			maximum = limit
		}
	}
	if err := unix.Flock(s.fd, unix.LOCK_EX); err != nil {
		return ErrStore
	}
	defer func() { _ = unix.Flock(s.fd, unix.LOCK_UN) }()
	if s.verifyPathIdentity() != nil {
		return ErrStore
	}
	entries, err := s.directoryEntries()
	if err != nil {
		return err
	}
	temporaryNames := make([]string, 0, maximumRecoverableParticipantTemporaryObjects)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mordant-create-") {
			if !validMordantTemporaryObjectName(entry.Name()) || len(temporaryNames) >= maximumRecoverableParticipantTemporaryObjects {
				return ErrStore
			}
			temporaryNames = append(temporaryNames, entry.Name())
		}
	}
	if len(temporaryNames) == 0 {
		return nil
	}
	for _, temporaryName := range temporaryNames {
		var temporaryStat unix.Stat_t
		if unix.Fstatat(s.fd, temporaryName, &temporaryStat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			temporaryStat.Mode&unix.S_IFMT != unix.S_IFREG || temporaryStat.Size < 0 || temporaryStat.Size > maximum ||
			temporaryStat.Uid != uint32(os.Geteuid()) || (uint32(temporaryStat.Mode)&0o777 != 0o600 && uint32(temporaryStat.Mode)&0o777 != uint32(s.fileMode.Perm())) ||
			(temporaryStat.Nlink != 1 && temporaryStat.Nlink != 2) {
			return ErrStore
		}
		matchingTargets := 0
		for target, limit := range targets {
			var targetStat unix.Stat_t
			if err := unix.Fstatat(s.fd, target, &targetStat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
				continue
			} else if err != nil {
				return ErrStore
			}
			if targetStat.Mode&unix.S_IFMT != unix.S_IFREG {
				return ErrStore
			}
			if sameStatIdentity(temporaryStat, targetStat) {
				if targetStat.Size > limit {
					return ErrStore
				}
				matchingTargets++
			}
		}
		if (temporaryStat.Nlink == 1 && matchingTargets != 0) || (temporaryStat.Nlink == 2 && matchingTargets != 1) {
			return ErrStore
		}
		if err := unix.Unlinkat(s.fd, temporaryName, 0); err != nil {
			return ErrStore
		}
	}
	if err := unix.Fsync(s.fd); err != nil || s.verifyPathIdentity() != nil {
		return ErrStore
	}
	return nil
}

func (s *objectStore) close() error {
	if s == nil || s.fd < 0 {
		return nil
	}
	fd := s.fd
	s.fd = -1
	if err := unix.Close(fd); err != nil {
		return ErrStore
	}
	return nil
}

func (s *objectStore) verifyPinned() error {
	if s == nil || s.fd < 0 {
		return ErrStore
	}
	var stat unix.Stat_t
	if unix.Fstat(s.fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint64(stat.Dev) != s.device || uint64(stat.Ino) != s.inode {
		return ErrStore
	}
	return nil
}

func (s *objectStore) verifyPathIdentity() error {
	if s.verifyPinned() != nil {
		return ErrStore
	}
	resolved, err := filepath.EvalSymlinks(s.root)
	var stat unix.Stat_t
	if err != nil || resolved != s.root || unix.Stat(s.root, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint64(stat.Dev) != s.device || uint64(stat.Ino) != s.inode {
		return ErrStore
	}
	return nil
}

func validateObjectName(name string) error {
	if name == "" || name != filepath.Base(name) || filepath.IsAbs(name) || strings.Contains(name, "..") ||
		strings.ContainsAny(name, "/\\") || strings.ContainsRune(name, 0) {
		return ErrStore
	}
	return nil
}

func (s *objectStore) directoryEntries() ([]os.DirEntry, error) {
	if s.verifyPinned() != nil {
		return nil, ErrStore
	}
	// dup(2) would share the directory stream offset with the pinned
	// descriptor. Repeated quota checks could then observe an empty suffix and
	// undercount both objects and bytes. Opening "." relative to the capability
	// keeps the same pinned directory identity with an independent offset.
	directoryFD, err := unix.Openat(s.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrStore
	}
	var stat unix.Stat_t
	if unix.Fstat(directoryFD, &stat) != nil || uint64(stat.Dev) != s.device || uint64(stat.Ino) != s.inode {
		_ = unix.Close(directoryFD)
		return nil, ErrStore
	}
	directory := os.NewFile(uintptr(directoryFD), "mordant-pinned-store")
	if directory == nil {
		_ = unix.Close(directoryFD)
		return nil, ErrStore
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrStore
	}
	return entries, nil
}

func (s *objectStore) usedBytes() (int64, error) {
	entries, err := s.directoryEntries()
	if err != nil || len(entries) > s.maxObjects {
		return 0, ErrResourceAdmission
	}
	var total int64
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || strings.HasPrefix(entry.Name(), ".mordant-create-") {
			return 0, ErrStore
		}
		fd, stat, err := s.openRegular(entry.Name())
		if err != nil {
			return 0, err
		}
		_ = unix.Close(fd)
		total += stat.Size
		if total > s.quota {
			return 0, ErrResourceAdmission
		}
	}
	return total, nil
}

func (s *objectStore) openRegular(name string) (int, unix.Stat_t, error) {
	var before, stat unix.Stat_t
	if s.verifyPinned() != nil || validateObjectName(name) != nil {
		return -1, stat, ErrStore
	}
	if err := unix.Fstatat(s.fd, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, stat, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1, stat, ErrStore
	}
	// O_NONBLOCK prevents a type-swap race from hanging on a FIFO between the
	// no-follow classification and the descriptor open. The post-open fstat and
	// identity comparison make the classification authoritative.
	fd, err := unix.Openat(s.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, stat, err
	}
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		uint64(stat.Dev) != uint64(before.Dev) || uint64(stat.Ino) != uint64(before.Ino) ||
		(s.private && uint64(stat.Nlink) != 1) {
		_ = unix.Close(fd)
		return -1, stat, ErrStore
	}
	return fd, stat, nil
}

func temporaryObjectName() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf(".mordant-create-%x", nonce[:]), nil
}

func (s *objectStore) create(name string, data []byte) (ObjectRef, error) {
	return s.createWithHooks(name, data, objectCreateHooks{})
}

// createFromReader is the bounded streaming counterpart to create. It keeps the
// same pinned-directory, no-follow, quota, create-only, fsync and hard-link
// publication guarantees without first materializing a participant ciphertext
// in coordinator memory. The caller supplies an absolute upper bound; one byte
// beyond it is consumed solely to make truncation at the limit detectable.
func (s *objectStore) createFromReader(name string, reader io.Reader, maximum int64) (ObjectRef, error) {
	return s.createFromReaderExpected(name, reader, maximum, nil)
}

// createFromReaderExpected authenticates the exact transport digest and length
// before the temporary inode is linked under its public object name.
func (s *objectStore) createFromReaderExpected(name string, reader io.Reader, maximum int64, expected *ObjectRef) (ObjectRef, error) {
	return s.createFromReaderExpectedWithHooks(name, reader, maximum, expected, objectCreateHooks{})
}

func (s *objectStore) unlinkObjectIfIdentity(name string, expected unix.Stat_t) error {
	var actual unix.Stat_t
	if err := unix.Fstatat(s.fd, name, &actual, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil || !sameStatIdentity(actual, expected) {
		return ErrStore
	}
	if err := unix.Unlinkat(s.fd, name, 0); err != nil {
		return ErrStore
	}
	return nil
}

func (s *objectStore) createFromReaderExpectedWithHooks(name string, reader io.Reader, maximum int64, expected *ObjectRef, hooks objectCreateHooks) (result ObjectRef, returnErr error) {
	var ref ObjectRef
	if s == nil || reader == nil || validateObjectName(name) != nil || maximum <= 0 || maximum > s.quota || s.verifyPinned() != nil {
		return ref, ErrStore
	}
	if expected != nil && expected.validate(name, maximum) != nil {
		return ref, ErrStore
	}
	if err := unix.Flock(s.fd, unix.LOCK_EX); err != nil {
		return ref, ErrStore
	}
	defer func() { _ = unix.Flock(s.fd, unix.LOCK_UN) }()
	used, err := s.usedBytes()
	if err != nil || used >= s.quota {
		return ref, ErrResourceAdmission
	}
	entries, err := s.directoryEntries()
	if err != nil || len(entries) >= s.maxObjects {
		return ref, ErrResourceAdmission
	}
	if existing, _, openErr := s.openRegular(name); openErr == nil {
		_ = unix.Close(existing)
		return ref, ErrStore
	} else if !errors.Is(openErr, unix.ENOENT) {
		return ref, ErrStore
	}

	remaining := s.quota - used
	limit := maximum
	if remaining < limit {
		limit = remaining
	}
	if limit <= 0 {
		return ref, ErrResourceAdmission
	}

	var tempName string
	tempFD := -1
	for attempt := 0; attempt < maximumTemporaryNameTries; attempt++ {
		tempName, err = temporaryObjectName()
		if err != nil {
			return ref, ErrStore
		}
		tempFD, err = unix.Openat(s.fd, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EEXIST) {
			return ref, ErrStore
		}
	}
	if tempFD < 0 {
		return ref, ErrStore
	}
	var temporary *os.File
	var temporaryStat unix.Stat_t
	temporaryRemoved := false
	targetCreated := false
	completed := false
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		} else {
			_ = unix.Close(tempFD)
		}
		cleanupFailed := false
		if targetCreated && !completed {
			if s.unlinkObjectIfIdentity(name, temporaryStat) != nil {
				cleanupFailed = true
			}
		}
		if !temporaryRemoved {
			if err := unix.Unlinkat(s.fd, tempName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				cleanupFailed = true
			}
		}
		if targetCreated && !completed && unix.Fsync(s.fd) != nil {
			cleanupFailed = true
		}
		if cleanupFailed {
			result = ObjectRef{}
			returnErr = ErrStore
		}
	}()
	temporary = os.NewFile(uintptr(tempFD), tempName)
	if temporary == nil || unix.Fstat(tempFD, &temporaryStat) != nil || temporaryStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return ref, ErrStore
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(reader, limit+1))
	if copyErr != nil {
		return ref, fmt.Errorf("%w: stream temporary object: %v", ErrStore, copyErr)
	}
	if count <= 0 || count > limit {
		return ref, ErrResourceAdmission
	}
	var digest Digest
	copy(digest[:], hash.Sum(nil))
	ref = ObjectRef{Path: name, Digest: digest, Length: count}
	if expected != nil && ref != *expected {
		return ObjectRef{}, ErrArtifact
	}
	if err := temporary.Sync(); err != nil {
		return ref, fmt.Errorf("%w: sync temporary object: %v", ErrStore, err)
	}
	if err := unix.Fchmod(tempFD, uint32(s.fileMode.Perm())); err != nil {
		return ref, ErrStore
	}
	if err := temporary.Sync(); err != nil {
		return ref, ErrStore
	}
	if s.verifyPathIdentity() != nil {
		return ref, ErrStore
	}
	if hooks.beforePublish != nil {
		if err := hooks.beforePublish(s.fd, name); err != nil {
			return ref, ErrStore
		}
	}
	if s.verifyPathIdentity() != nil {
		return ref, ErrStore
	}
	if err := unix.Linkat(s.fd, tempName, s.fd, name, 0); err != nil {
		return ref, fmt.Errorf("%w: publish object: %v", ErrStore, err)
	}
	targetCreated = true
	if err := unix.Unlinkat(s.fd, tempName, 0); err != nil {
		return ref, ErrStore
	}
	temporaryRemoved = true
	if err := unix.Fsync(s.fd); err != nil {
		return ref, ErrStore
	}
	if hooks.afterCommit != nil {
		if err := hooks.afterCommit(s.fd, name); err != nil {
			return ref, ErrStore
		}
	}
	if s.verifyPathIdentity() != nil {
		return ref, ErrStore
	}
	completed = true
	return ref, nil
}

func (s *objectStore) createWithHooks(name string, data []byte, hooks objectCreateHooks) (ObjectRef, error) {
	var ref ObjectRef
	if s == nil || validateObjectName(name) != nil || len(data) == 0 || int64(len(data)) > s.quota || s.verifyPinned() != nil {
		return ref, ErrStore
	}
	if err := unix.Flock(s.fd, unix.LOCK_EX); err != nil {
		return ref, ErrStore
	}
	defer func() { _ = unix.Flock(s.fd, unix.LOCK_UN) }()
	used, err := s.usedBytes()
	if err != nil || used+int64(len(data)) > s.quota {
		return ref, ErrResourceAdmission
	}
	entries, err := s.directoryEntries()
	if err != nil || len(entries) >= s.maxObjects {
		return ref, ErrResourceAdmission
	}
	if existing, _, openErr := s.openRegular(name); openErr == nil {
		_ = unix.Close(existing)
		return ref, ErrStore
	} else if !errors.Is(openErr, unix.ENOENT) {
		return ref, ErrStore
	}

	var tempName string
	tempFD := -1
	for attempt := 0; attempt < maximumTemporaryNameTries; attempt++ {
		tempName, err = temporaryObjectName()
		if err != nil {
			return ref, ErrStore
		}
		tempFD, err = unix.Openat(s.fd, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EEXIST) {
			return ref, ErrStore
		}
	}
	if tempFD < 0 {
		return ref, ErrStore
	}
	var temporary *os.File
	committed := false
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		} else {
			_ = unix.Close(tempFD)
		}
		if !committed {
			_ = unix.Unlinkat(s.fd, tempName, 0)
		}
	}()
	temporary = os.NewFile(uintptr(tempFD), tempName)
	if temporary == nil {
		return ref, ErrStore
	}
	if _, err := temporary.Write(data); err != nil {
		return ref, fmt.Errorf("%w: write temporary object: %v", ErrStore, err)
	}
	if err := temporary.Sync(); err != nil {
		return ref, fmt.Errorf("%w: sync temporary object: %v", ErrStore, err)
	}
	if err := unix.Fchmod(tempFD, uint32(s.fileMode.Perm())); err != nil {
		return ref, ErrStore
	}
	if err := temporary.Sync(); err != nil {
		return ref, ErrStore
	}
	if hooks.beforePublish != nil {
		if err := hooks.beforePublish(s.fd, name); err != nil {
			return ref, ErrStore
		}
	}
	if err := unix.Linkat(s.fd, tempName, s.fd, name, 0); err != nil {
		return ref, fmt.Errorf("%w: publish object: %v", ErrStore, err)
	}
	if err := unix.Unlinkat(s.fd, tempName, 0); err != nil {
		return ref, ErrStore
	}
	committed = true
	if err := unix.Fsync(s.fd); err != nil {
		return ref, ErrStore
	}
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
	data, actual, err := s.readNamed(ref.Path, maximum)
	if err != nil {
		return nil, fmt.Errorf("%w: pinned read %s: %v", ErrArtifact, ref.Path, err)
	}
	if actual.Length != ref.Length {
		return nil, fmt.Errorf("%w: length mismatch for %s", ErrArtifact, ref.Path)
	}
	if actual.Digest != ref.Digest {
		return nil, fmt.Errorf("%w: digest mismatch for %s", ErrArtifact, ref.Path)
	}
	return data, nil
}

func (s *objectStore) readNamed(name string, maximum int64) ([]byte, ObjectRef, error) {
	var ref ObjectRef
	if maximum <= 0 {
		return nil, ref, ErrArtifact
	}
	fd, stat, err := s.openRegular(name)
	if err != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return nil, ref, fmt.Errorf("%w: open pinned object %s: %v", ErrArtifact, name, err)
	}
	if stat.Size <= 0 || stat.Size > maximum {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return nil, ref, fmt.Errorf("%w: size for %s", ErrArtifact, name)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ref, ErrArtifact
	}
	hash := sha256.New()
	data, readErr := io.ReadAll(io.TeeReader(io.LimitReader(file, maximum+1), hash))
	var after unix.Stat_t
	statErr := unix.Fstat(fd, &after)
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil {
		return nil, ref, fmt.Errorf("%w: read pinned object %s (read=%v stat=%v close=%v)", ErrArtifact, name, readErr, statErr, closeErr)
	}
	if int64(len(data)) != stat.Size || int64(len(data)) > maximum || after.Size != stat.Size {
		return nil, ref, fmt.Errorf("%w: unstable size for %s (%d/%d/%d)", ErrArtifact, name, len(data), stat.Size, after.Size)
	}
	if uint64(after.Dev) != uint64(stat.Dev) || uint64(after.Ino) != uint64(stat.Ino) {
		return nil, ref, fmt.Errorf("%w: unstable identity for %s", ErrArtifact, name)
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
	fd, _, err := s.openRegular(name)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

func (s *objectStore) names() ([]string, error) {
	entries, err := s.directoryEntries()
	if err != nil || len(entries) > s.maxObjects {
		return nil, ErrResourceAdmission
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || strings.HasPrefix(entry.Name(), ".mordant-create-") || validateObjectName(entry.Name()) != nil {
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
