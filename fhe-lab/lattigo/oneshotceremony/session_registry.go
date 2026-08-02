package oneshotceremony

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	sessionReservationSchema = "mordant.fhe-session-reservation/oneshot-v2"
	terminalTombstoneSchema  = "mordant.fhe-terminal-tombstone/oneshot-v2"
)

type TerminalDisposition uint8

const (
	DispositionPoisoned TerminalDisposition = iota + 1
	DispositionAborted
	DispositionCompleted
)

// TerminalTombstone is the operator-local authoritative usability decision.
// Bytes can remain after abort, but no private artifact consumer may accept
// them unless this record says COMPLETED and binds the exact public artifacts.
type TerminalTombstone struct {
	SchemaVersion            string
	CeremonyID               [32]byte
	SessionBindingDigest     [32]byte
	Disposition              TerminalDisposition
	WitnessEventDigest       [32]byte
	KeyID                    [32]byte
	PublishedBundleDigest    [32]byte
	PublicationReceiptDigest [32]byte
}

func (t TerminalTombstone) MarshalBinary() ([]byte, error) {
	if t.SchemaVersion != terminalTombstoneSchema || isZero32(t.CeremonyID) || isZero32(t.SessionBindingDigest) ||
		t.Disposition < DispositionPoisoned || t.Disposition > DispositionCompleted {
		return nil, ErrBinding
	}
	if t.Disposition == DispositionCompleted {
		if isZero32(t.WitnessEventDigest) || isZero32(t.KeyID) || isZero32(t.PublishedBundleDigest) || isZero32(t.PublicationReceiptDigest) {
			return nil, ErrBinding
		}
	} else if !isZero32(t.KeyID) || !isZero32(t.PublishedBundleDigest) || !isZero32(t.PublicationReceiptDigest) {
		return nil, ErrBinding
	}
	var e encoder
	e.text(terminalTombstoneSchema)
	e.text(t.SchemaVersion)
	e.fixed(t.CeremonyID[:])
	e.fixed(t.SessionBindingDigest[:])
	e.u8(uint8(t.Disposition))
	e.fixed(t.WitnessEventDigest[:])
	e.fixed(t.KeyID[:])
	e.fixed(t.PublishedBundleDigest[:])
	e.fixed(t.PublicationReceiptDigest[:])
	return e.Bytes(), nil
}

func ParseTerminalTombstone(data []byte) (TerminalTombstone, error) {
	var tombstone TerminalTombstone
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != terminalTombstoneSchema {
		return tombstone, errCanonical
	}
	if tombstone.SchemaVersion, err = d.text(); err != nil || tombstone.SchemaVersion != magic {
		return TerminalTombstone{}, errCanonical
	}
	for _, target := range []*[32]byte{&tombstone.CeremonyID, &tombstone.SessionBindingDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return TerminalTombstone{}, errCanonical
		}
	}
	disposition, err := d.u8()
	if err != nil {
		return TerminalTombstone{}, err
	}
	tombstone.Disposition = TerminalDisposition(disposition)
	for _, target := range []*[32]byte{&tombstone.WitnessEventDigest, &tombstone.KeyID, &tombstone.PublishedBundleDigest, &tombstone.PublicationReceiptDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return TerminalTombstone{}, errCanonical
		}
	}
	if d.done() != nil {
		return TerminalTombstone{}, errCanonical
	}
	reencoded, err := tombstone.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return TerminalTombstone{}, errCanonical
	}
	return tombstone, nil
}

type sessionRegistry struct {
	root string
}

func openSessionRegistry(root string) (*sessionRegistry, error) {
	if err := openRestrictedDirectory(root); err != nil {
		return nil, err
	}
	return &sessionRegistry{root: root}, nil
}

func (r *sessionRegistry) consume(context Context, point uint64) error {
	if r == nil || point == 0 {
		return ErrPersistence
	}
	session := context.SessionBindingDigest()
	ceremony := context.CeremonyID()
	if isZero32(session) || isZero32(ceremony) {
		return ErrBinding
	}
	var e encoder
	e.text(sessionReservationSchema)
	e.fixed(session[:])
	e.fixed(ceremony[:])
	contextDigest := context.ContextDigest()
	e.fixed(contextDigest[:])
	e.u64(point)
	store := &WitnessStore{root: r.root}
	name := "session-" + hex.EncodeToString(session[:]) + ".marker"
	if err := store.writeNoReplace(name, e.Bytes()); err != nil {
		return fmt.Errorf("%w: bilateral session already consumed", ErrReplay)
	}
	return nil
}

func openRestrictedDirectory(root string) error {
	if !filepath.IsAbs(root) {
		return fmt.Errorf("%w: store path must be absolute", ErrPersistence)
	}
	if err := ensureNoSymlinkPath(root); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if errorsIsNotExist(err) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return fmt.Errorf("%w: create store", ErrPersistence)
		}
		if err := syncDirectory(filepath.Dir(root)); err != nil {
			return err
		}
		info, err = os.Lstat(root)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: unsafe store root", ErrPersistence)
	}
	return nil
}

func readNoSymlinkFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrPersistence
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrPersistence
	}
	return data, nil
}

func sameOrNestedPath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	within := func(base, target string) bool {
		relative, err := filepath.Rel(base, target)
		return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	return within(left, right) || within(right, left)
}
