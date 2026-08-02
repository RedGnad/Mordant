package oneshotceremony

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// OperatorLocalStorageConfig is provisioned by one operator outside the
// ceremony request path. StateRoot and StorageIdentity are immutable for that
// operator identity; a coordinator must never construct or replace this
// configuration.
type OperatorLocalStorageConfig struct {
	StateRoot       string
	StorageIdentity [32]byte
	Identity        OperatorIdentity
	ProcessInstance string
	BootSession     string
}

// OperatorStorageCapability is the only storage object accepted by a
// Participant. Its witness, monotone session registry and completed-private
// roots are derived once from the operator-local configuration rather than
// supplied by a ceremony caller.
type OperatorStorageCapability struct {
	witness       *WitnessStore
	identity      OperatorIdentity
	storageID     [32]byte
	startup       ExecutableProvenance
	process       [32]byte
	boot          [32]byte
	completedRoot string
}

func DeriveOperatorStorageBinding(stateRoot string, storageIdentity [32]byte, identity OperatorIdentity) ([32]byte, error) {
	if !filepath.IsAbs(stateRoot) || isZero32(storageIdentity) || identity.Point == 0 || identity.AdministratorID == "" ||
		identity.SigningPublicKey == ([ed25519.PublicKeySize]byte{}) || isZero32(identity.EncryptionPublicKey) ||
		isZero32(identity.TransportCertFingerprint) || isZero32(identity.RuntimeBinaryDigest) || identity.GoVersion == "" ||
		identity.OperatingSystem == "" || identity.Architecture == "" {
		return [32]byte{}, ErrBinding
	}
	root := filepath.Clean(stateRoot)
	var e encoder
	e.text("MordantOneShotOperatorStorageBinding/v3")
	e.text(root)
	e.fixed(storageIdentity[:])
	e.u64(identity.Point)
	e.text(identity.AdministratorID)
	e.fixed(identity.SigningPublicKey[:])
	e.fixed(identity.EncryptionPublicKey[:])
	e.fixed(identity.TransportCertFingerprint[:])
	e.fixed(identity.RuntimeBinaryDigest[:])
	e.text(identity.GoVersion)
	e.text(identity.OperatingSystem)
	e.text(identity.Architecture)
	return hashDomain("MordantOneShotOperatorStorageBindingDigest/v3", e.Bytes()), nil
}

func OpenOperatorStorageCapability(config OperatorLocalStorageConfig) (*OperatorStorageCapability, error) {
	if config.ProcessInstance == "" || config.BootSession == "" {
		return nil, ErrBinding
	}
	expected, err := DeriveOperatorStorageBinding(config.StateRoot, config.StorageIdentity, config.Identity)
	if err != nil || expected != config.Identity.StorageBindingDigest {
		return nil, ErrBinding
	}
	startup, err := CurrentExecutableProvenance()
	if err != nil || startup.ExecutableSHA256 != config.Identity.RuntimeBinaryDigest || startup.GoVersion != config.Identity.GoVersion ||
		startup.OperatingSystem != config.Identity.OperatingSystem || startup.Architecture != config.Identity.Architecture {
		return nil, fmt.Errorf("%w: operator startup executable", ErrBinding)
	}
	root := filepath.Clean(config.StateRoot)
	if err := openRestrictedDirectory(root); err != nil {
		return nil, err
	}
	witness, err := openWitnessStore(filepath.Join(root, "witness"), filepath.Join(root, "session-registry"))
	if err != nil {
		return nil, err
	}
	completedRoot := filepath.Join(root, "completed-private")
	if err := openRestrictedDirectory(completedRoot); err != nil {
		return nil, err
	}
	return &OperatorStorageCapability{
		witness:       witness,
		identity:      config.Identity,
		storageID:     config.StorageIdentity,
		startup:       startup,
		process:       hashDomain("MordantOneShotProcessInstance/v1", []byte(config.ProcessInstance)),
		boot:          hashDomain("MordantOneShotBootSession/v1", []byte(config.BootSession)),
		completedRoot: completedRoot,
	}, nil
}

func (c *OperatorStorageCapability) StartupProvenance() ExecutableProvenance {
	if c == nil {
		return ExecutableProvenance{}
	}
	return c.startup
}

// PublicWitnessRecords returns only the signed public witness history retained
// by this operator. It exists for the narrow network-runtime evidence boundary;
// the capability still exposes no storage path, key, share or private bundle.
func (c *OperatorStorageCapability) PublicWitnessRecords(ceremonyID [32]byte) ([]WitnessRecord, error) {
	if c == nil || c.witness == nil || isZero32(ceremonyID) {
		return nil, ErrPersistence
	}
	return c.witness.Records(ceremonyID)
}

// PublicTerminalTombstone returns the operator's public terminal usability
// decision without exposing its witness store or completed-private boundary.
func (c *OperatorStorageCapability) PublicTerminalTombstone(ceremonyID [32]byte) (TerminalTombstone, error) {
	if c == nil || c.witness == nil || isZero32(ceremonyID) {
		return TerminalTombstone{}, ErrPersistence
	}
	return c.witness.TerminalTombstone(ceremonyID)
}

func (c *OperatorStorageCapability) storeCompletedPrivate(key [32]byte, sealed SealedOperatorBundle) error {
	if c == nil || isZero32(key) || sealed.OperatorPoint != c.identity.Point || sealed.CeremonyID == ([32]byte{}) {
		return ErrPersistence
	}
	sealedBytes, err := sealed.MarshalBinary()
	if err != nil {
		return err
	}
	var e encoder
	e.text("MordantOneShotCompletedPrivateArtifact/v3")
	e.fixed(key[:])
	e.field(sealedBytes)
	name := "completed-" + hex.EncodeToString(sealed.CeremonyID[:]) + ".bin"
	return (&WitnessStore{root: c.completedRoot}).writeNoReplace(name, e.Bytes())
}

func (c *OperatorStorageCapability) readCompletedPrivate(ceremonyID [32]byte) ([32]byte, SealedOperatorBundle, error) {
	var key [32]byte
	if c == nil || isZero32(ceremonyID) {
		return key, SealedOperatorBundle{}, ErrSecretAccess
	}
	name := "completed-" + hex.EncodeToString(ceremonyID[:]) + ".bin"
	data, err := readNoSymlinkFile(filepath.Join(c.completedRoot, name))
	if err != nil {
		return key, SealedOperatorBundle{}, ErrSecretAccess
	}
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != "MordantOneShotCompletedPrivateArtifact/v3" {
		return key, SealedOperatorBundle{}, ErrSecretAccess
	}
	value, err := d.fixed(32)
	if err != nil || copy32(&key, value) != nil || isZero32(key) {
		return [32]byte{}, SealedOperatorBundle{}, ErrSecretAccess
	}
	sealedBytes, err := d.field()
	if err != nil || d.done() != nil {
		return [32]byte{}, SealedOperatorBundle{}, ErrSecretAccess
	}
	sealed, err := ParseSealedOperatorBundle(sealedBytes)
	if err != nil || sealed.CeremonyID != ceremonyID || sealed.OperatorPoint != c.identity.Point {
		return [32]byte{}, SealedOperatorBundle{}, ErrSecretAccess
	}
	return key, sealed, nil
}

// WitnessStore is the internal witness replica reached only through an
// OperatorStorageCapability.
type WitnessStore struct {
	root     string
	registry *sessionRegistry
}

func openWitnessStore(root, sessionRegistryRoot string) (*WitnessStore, error) {
	if sameOrNestedPath(root, sessionRegistryRoot) {
		return nil, fmt.Errorf("%w: witness and session registry roots must be separate", ErrPersistence)
	}
	if err := openRestrictedDirectory(root); err != nil {
		return nil, err
	}
	registry, err := openSessionRegistry(sessionRegistryRoot)
	if err != nil {
		return nil, err
	}
	return &WitnessStore{root: root, registry: registry}, nil
}

func (s *WitnessStore) Reserve(reservation AttemptReservation) error {
	if s == nil || s.registry == nil || reservation.OperatorPoint == 0 {
		return fmt.Errorf("%w: reservation", ErrPersistence)
	}
	encoded, err := reservation.MarshalBinary()
	if err != nil {
		return err
	}
	context, err := ParseContext(reservation.ContextSnapshot)
	if err != nil || context.CeremonyID() != reservation.CeremonyID || context.SessionBindingDigest() != reservation.SessionBindingDigest {
		return ErrBinding
	}
	// Participant.Reserve has already consumed the session registry marker.
	// From this point this method only persists the completed reservation and
	// its ceremony/scope markers.
	name := "used-" + hex.EncodeToString(reservation.CeremonyID[:]) + ".marker"
	if err := s.writeNoReplace(name, encoded); err != nil {
		return fmt.Errorf("%w: ceremony identifier already used", ErrReplay)
	}
	scopeName := "scope-" + hex.EncodeToString(reservation.ScopeOrdinalDigest[:]) + ".marker"
	if err := s.writeNoReplace(scopeName, encoded); err != nil {
		return fmt.Errorf("%w: scope ordinal already used", ErrReplay)
	}
	return nil
}

func (s *WitnessStore) ConsumeSession(context Context, point uint64) error {
	if s == nil || s.registry == nil {
		return ErrPersistence
	}
	return s.registry.consume(context, point)
}

func (s *WitnessStore) StoreReservation(reservation AttemptReservation) error {
	encoded, err := reservation.MarshalBinary()
	if err != nil {
		return err
	}
	name := fmt.Sprintf("reservation-%s-%020d.bin", hex.EncodeToString(reservation.CeremonyID[:]), reservation.OperatorPoint)
	if err := s.writeNoReplace(name, encoded); err != nil {
		return fmt.Errorf("%w: reservation already stored", ErrReplay)
	}
	return nil
}

func (s *WitnessStore) PublicHead() ([32]byte, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: read store", ErrPersistence)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || strings.Contains(entry.Name(), ".tmp-") {
			return [32]byte{}, fmt.Errorf("%w: unexpected store entry", ErrPersistence)
		}
		if strings.HasPrefix(entry.Name(), "record-") || strings.HasPrefix(entry.Name(), "reservation-") || strings.HasPrefix(entry.Name(), "status-") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	var e encoder
	e.text("MordantOneShotLocalWitnessHead/v1")
	for _, name := range names {
		data, readErr := os.ReadFile(filepath.Join(s.root, name))
		if readErr != nil {
			return [32]byte{}, fmt.Errorf("%w: read witness head", ErrPersistence)
		}
		digest := hashDomain("MordantOneShotLocalWitnessEntry/v1", []byte(name), data)
		e.fixed(digest[:])
	}
	return hashDomain("MordantOneShotLocalWitnessHeadDigest/v1", e.Bytes()), nil
}

func (s *WitnessStore) WriteDecision(ceremonyID [32]byte, sequence uint64, statementDigest [32]byte, signature []byte) error {
	var e encoder
	e.text("MordantOneShotSigningDecision/v1")
	e.fixed(ceremonyID[:])
	e.u64(sequence)
	e.fixed(statementDigest[:])
	e.field(signature)
	name := fmt.Sprintf("decision-%s-%020d.bin", hex.EncodeToString(ceremonyID[:]), sequence)
	if err := s.writeNoReplace(name, e.Bytes()); err != nil {
		return fmt.Errorf("%w: signing decision already exists", ErrReplay)
	}
	return nil
}

func (s *WitnessStore) MarkGeneration(context Context, label string) error {
	if s == nil || label == "" || strings.ContainsAny(label, `/\\`) {
		return ErrPersistence
	}
	ceremonyID := context.CeremonyID()
	session := context.SessionBindingDigest()
	var e encoder
	e.text("MordantOneShotGenerationMarker/v2")
	e.fixed(ceremonyID[:])
	e.fixed(session[:])
	e.text(label)
	name := fmt.Sprintf("generation-%s-%s.marker", hex.EncodeToString(ceremonyID[:]), label)
	if err := s.writeNoReplace(name, e.Bytes()); err != nil {
		return fmt.Errorf("%w: generation already marked", ErrReplay)
	}
	return nil
}

func (s *WitnessStore) WriteTerminalTombstone(tombstone TerminalTombstone) error {
	if s == nil {
		return ErrPersistence
	}
	encoded, err := tombstone.MarshalBinary()
	if err != nil {
		return err
	}
	name := "terminal-" + hex.EncodeToString(tombstone.CeremonyID[:]) + ".bin"
	if err := s.writeNoReplace(name, encoded); err != nil {
		existing, readErr := readNoSymlinkFile(filepath.Join(s.root, name))
		if readErr != nil || !slices.Equal(existing, encoded) {
			return fmt.Errorf("%w: terminal tombstone conflict", ErrReplay)
		}
	}
	return nil
}

func (s *WitnessStore) TerminalTombstone(ceremonyID [32]byte) (TerminalTombstone, error) {
	if s == nil || isZero32(ceremonyID) {
		return TerminalTombstone{}, ErrPersistence
	}
	name := "terminal-" + hex.EncodeToString(ceremonyID[:]) + ".bin"
	data, err := readNoSymlinkFile(filepath.Join(s.root, name))
	if err != nil {
		return TerminalTombstone{}, err
	}
	tombstone, err := ParseTerminalTombstone(data)
	if err != nil || tombstone.CeremonyID != ceremonyID {
		return TerminalTombstone{}, ErrPersistence
	}
	return tombstone, nil
}

func (s *WitnessStore) writeStatusDecision(keyID [32]byte, sequence uint64, statementDigest [32]byte, signature []byte) error {
	var e encoder
	e.text("MordantOneShotStatusSigningDecision/v1")
	e.fixed(keyID[:])
	e.u64(sequence)
	e.fixed(statementDigest[:])
	e.field(signature)
	name := fmt.Sprintf("status-decision-%s-%020d.bin", hex.EncodeToString(keyID[:]), sequence)
	if err := s.writeNoReplace(name, e.Bytes()); err != nil {
		return fmt.Errorf("%w: status signing decision already exists", ErrReplay)
	}
	return nil
}

func (s *WitnessStore) Append(record WitnessRecord) error {
	encoded, err := record.MarshalBinary()
	if err != nil {
		return err
	}
	records, err := s.Records(record.Statement.CeremonyID)
	if err != nil {
		return err
	}
	if record.Statement.Sequence != uint64(len(records)+1) {
		return fmt.Errorf("%w: witness sequence drift", ErrPersistence)
	}
	var expectedPrevious [32]byte
	if len(records) > 0 {
		expectedPrevious = records[len(records)-1].EventDigest()
	}
	if record.Statement.PreviousDigest != expectedPrevious {
		return fmt.Errorf("%w: witness predecessor drift", ErrPersistence)
	}
	// The stable sequence slot makes concurrent conflicting appends race for
	// the same create-only filename. At most one can become authoritative.
	name := fmt.Sprintf("record-%s-%020d.bin", hex.EncodeToString(record.Statement.CeremonyID[:]), record.Statement.Sequence)
	if err := s.writeNoReplace(name, encoded); err != nil {
		return fmt.Errorf("%w: witness record already exists", ErrReplay)
	}
	readback, err := readNoSymlinkFile(filepath.Join(s.root, name))
	if err != nil || !slices.Equal(readback, encoded) {
		return fmt.Errorf("%w: witness readback", ErrPersistence)
	}
	return nil
}

func (s *WitnessStore) Records(ceremonyID [32]byte) ([]WitnessRecord, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("%w: read store", ErrPersistence)
	}
	prefix := "record-" + hex.EncodeToString(ceremonyID[:]) + "-"
	names := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || strings.Contains(name, ".tmp-") {
			return nil, fmt.Errorf("%w: unexpected store entry", ErrPersistence)
		}
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
			continue
		}
		if !strings.HasPrefix(name, "record-") && !strings.HasPrefix(name, "used-") && !strings.HasPrefix(name, "scope-") && !strings.HasPrefix(name, "decision-") && !strings.HasPrefix(name, "reservation-") && !strings.HasPrefix(name, "status-") && !strings.HasPrefix(name, "generation-") && !strings.HasPrefix(name, "terminal-") {
			return nil, fmt.Errorf("%w: unknown store entry", ErrPersistence)
		}
	}
	sort.Strings(names)
	records := make([]WitnessRecord, 0, len(names))
	for _, name := range names {
		data, readErr := os.ReadFile(filepath.Join(s.root, name))
		if readErr != nil {
			return nil, fmt.Errorf("%w: read witness", ErrPersistence)
		}
		record, parseErr := ParseWitnessRecord(data)
		if parseErr != nil || record.Statement.CeremonyID != ceremonyID {
			return nil, fmt.Errorf("%w: corrupt witness", ErrPersistence)
		}
		records = append(records, record)
	}
	for index, record := range records {
		if record.Statement.Sequence != uint64(index+1) {
			return nil, fmt.Errorf("%w: witness sequence gap", ErrPersistence)
		}
	}
	return records, nil
}

func (s *WitnessStore) writeNoReplace(name string, data []byte) error {
	if s == nil || filepath.Base(name) != name || strings.Contains(name, string(filepath.Separator)) {
		return fmt.Errorf("%w: invalid filename", ErrPersistence)
	}
	if err := ensureNoSymlinkPath(s.root); err != nil {
		return err
	}
	temp, err := os.CreateTemp(s.root, ".tmp-oneshot-")
	if err != nil {
		return fmt.Errorf("%w: create temporary", ErrPersistence)
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("%w: temporary permissions", ErrPersistence)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("%w: write temporary", ErrPersistence)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("%w: sync temporary", ErrPersistence)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("%w: close temporary", ErrPersistence)
	}
	finalName := filepath.Join(s.root, name)
	if err := os.Link(tempName, finalName); err != nil {
		return fmt.Errorf("%w: no-replace publish", ErrPersistence)
	}
	if err := syncDirectory(s.root); err != nil {
		return err
	}
	if err := os.Remove(tempName); err != nil {
		return fmt.Errorf("%w: remove temporary", ErrPersistence)
	}
	return syncDirectory(s.root)
}

func ensureNoSymlinkPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%w: absolute path", ErrPersistence)
	}
	volume := filepath.VolumeName(abs)
	remainder := strings.TrimPrefix(abs, volume)
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(remainder, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errorsIsNotExist(statErr) {
			return nil
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlinked path", ErrPersistence)
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: open directory", ErrPersistence)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("%w: sync directory", ErrPersistence)
	}
	return nil
}

func errorsIsNotExist(err error) bool { return err != nil && errors.Is(err, fs.ErrNotExist) }
