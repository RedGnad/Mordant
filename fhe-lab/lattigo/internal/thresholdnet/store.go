// Package thresholdnet contains the durable one-shot state required before a
// threshold party can be moved behind a network boundary.
package thresholdnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

const recordVersion = 1

var (
	bindingBucket = []byte("protocol-bindings-v1")
	sessionBucket = []byte("session-index-v1")

	ErrInvalidDescriptor = errors.New("invalid threshold session descriptor")
	ErrBindingConsumed   = errors.New("threshold protocol binding already consumed")
	ErrSessionExists     = errors.New("threshold session already exists")
	ErrSessionNotFound   = errors.New("threshold session not found")
	ErrInvalidTransition = errors.New("invalid threshold session transition")
	ErrTerminal          = errors.New("threshold session is terminal")
	ErrCorruptLedger     = errors.New("corrupt threshold one-shot ledger")
)

// State is the durable lifecycle of one threshold response. COMMITTED is
// written atomically before any cryptographic share generation begins.
type State string

const (
	StatePrepared        State = "PREPARED"
	StateCommitted       State = "COMMITTED"
	StateGenerated       State = "GENERATED"
	StateReleased        State = "RELEASED"
	StateAcked           State = "ACKED"
	StateAbortedPrestart State = "ABORTED_PRESTART"
	StateFailedTerminal  State = "FAILED_TERMINAL"
)

// FailureCode is a bounded, machine-readable terminal cause. It is not a free
// form error message and therefore does not persist secrets or sensitive data.
type FailureCode string

const (
	FailureAbortedBeforeCommit FailureCode = "ABORTED_BEFORE_COMMIT"
	FailureGeneration          FailureCode = "GENERATION_FAILED"
	FailureRelease             FailureCode = "RELEASE_FAILED"
	FailureRestartAfterCommit  FailureCode = "RESTART_AFTER_COMMIT"
)

// Descriptor contains audit metadata for a proposed protocol run. Binding is
// the global authority: changing SessionID or CoalitionDigest never creates a
// second generation opportunity for the same binding.
type Descriptor struct {
	SessionID       [32]byte
	Binding         [32]byte
	CoalitionDigest [32]byte
}

// Record is the persisted state for one globally unique protocol binding.
// ResponseDigest commits to generated response bytes without storing them in
// the ledger.
type Record struct {
	Version           uint8       `json:"version"`
	SessionID         [32]byte    `json:"sessionId"`
	Binding           [32]byte    `json:"binding"`
	CoalitionDigest   [32]byte    `json:"coalitionDigest"`
	State             State       `json:"state"`
	ResponseDigest    [32]byte    `json:"responseDigest"`
	FailureCode       FailureCode `json:"failureCode,omitempty"`
	CreatedAtUnixNano int64       `json:"createdAtUnixNano"`
	UpdatedAtUnixNano int64       `json:"updatedAtUnixNano"`
}

// IsTerminal reports whether no further lifecycle transition is permitted.
func (r Record) IsTerminal() bool {
	return r.State == StateAcked || r.State == StateAbortedPrestart || r.State == StateFailedTerminal
}

// Store is a durable, globally keyed one-shot ledger. bbolt's synchronous
// write transaction is the commit barrier before cryptographic generation.
type Store struct {
	db *bolt.DB
}

// Open opens or creates a one-shot ledger and performs fail-closed recovery.
// Any run found at COMMITTED, GENERATED or RELEASED is terminalized because a
// process restart cannot prove that the corresponding response was never
// generated or released.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty database path", ErrInvalidDescriptor)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create ledger directory: %w", err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open threshold ledger: %w", err)
	}
	store := &Store{db: db}
	if err := store.initializeAndRecover(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the underlying durable ledger.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Prepare reserves Binding globally and records a new PREPARED session in one
// transaction. A reservation is never deleted, including after a pre-start
// abort, so neither a new session identifier nor a new coalition can bypass it.
func (s *Store) Prepare(descriptor Descriptor) (Record, error) {
	if err := validateDescriptor(descriptor); err != nil {
		return Record{}, err
	}

	now := time.Now().UnixNano()
	record := Record{
		Version:           recordVersion,
		SessionID:         descriptor.SessionID,
		Binding:           descriptor.Binding,
		CoalitionDigest:   descriptor.CoalitionDigest,
		State:             StatePrepared,
		CreatedAtUnixNano: now,
		UpdatedAtUnixNano: now,
	}

	err := s.update(func(tx *bolt.Tx) error {
		bindings := tx.Bucket(bindingBucket)
		sessions := tx.Bucket(sessionBucket)
		if sessions.Get(descriptor.SessionID[:]) != nil {
			return ErrSessionExists
		}
		if bindings.Get(descriptor.Binding[:]) != nil {
			return ErrBindingConsumed
		}
		encoded, err := encodeRecord(record)
		if err != nil {
			return err
		}
		if err := bindings.Put(descriptor.Binding[:], encoded); err != nil {
			return err
		}
		return sessions.Put(descriptor.SessionID[:], descriptor.Binding[:])
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

// Commit atomically persists COMMITTED. The caller may begin cryptographic
// share generation only after this method returns successfully. Calling Commit
// again is never permission to retry generation.
func (s *Store) Commit(sessionID [32]byte) (Record, error) {
	return s.transition(sessionID, StatePrepared, StateCommitted, nil)
}

// MarkGenerated records the digest of the already-generated response.
func (s *Store) MarkGenerated(sessionID, responseDigest [32]byte) (Record, error) {
	if responseDigest == ([32]byte{}) {
		return Record{}, fmt.Errorf("%w: empty response digest", ErrInvalidDescriptor)
	}
	return s.transition(sessionID, StateCommitted, StateGenerated, func(record *Record) {
		record.ResponseDigest = responseDigest
	})
}

// MarkReleased records that the response left the threshold party boundary.
func (s *Store) MarkReleased(sessionID [32]byte) (Record, error) {
	return s.transition(sessionID, StateGenerated, StateReleased, nil)
}

// MarkAcked records the terminal successful acknowledgement.
func (s *Store) MarkAcked(sessionID [32]byte) (Record, error) {
	return s.transition(sessionID, StateReleased, StateAcked, nil)
}

// AbortPrepared terminalizes a run that has not crossed the commit barrier.
func (s *Store) AbortPrepared(sessionID [32]byte) (Record, error) {
	return s.transition(sessionID, StatePrepared, StateAbortedPrestart, func(record *Record) {
		record.FailureCode = FailureAbortedBeforeCommit
	})
}

// FailTerminal records a post-commit terminal failure. It cannot be used to
// reopen or overwrite a successful or already terminal run.
func (s *Store) FailTerminal(sessionID [32]byte, code FailureCode) (Record, error) {
	if !validFailureCode(code) || code == FailureAbortedBeforeCommit || code == FailureRestartAfterCommit {
		return Record{}, fmt.Errorf("%w: invalid post-commit failure code", ErrInvalidDescriptor)
	}
	return s.mutate(sessionID, func(record *Record) error {
		switch record.State {
		case StateCommitted, StateGenerated, StateReleased:
			record.State = StateFailedTerminal
			record.FailureCode = code
			return nil
		default:
			return transitionError(*record, StateFailedTerminal)
		}
	})
}

// Get returns a record by session identifier.
func (s *Store) Get(sessionID [32]byte) (Record, error) {
	if sessionID == ([32]byte{}) {
		return Record{}, fmt.Errorf("%w: empty session id", ErrInvalidDescriptor)
	}
	var record Record
	err := s.view(func(tx *bolt.Tx) error {
		var err error
		record, err = recordBySession(tx, sessionID)
		return err
	})
	return record, err
}

// GetByBinding returns the sole record reserved for a global protocol binding.
func (s *Store) GetByBinding(binding [32]byte) (Record, error) {
	if binding == ([32]byte{}) {
		return Record{}, fmt.Errorf("%w: empty binding", ErrInvalidDescriptor)
	}
	var record Record
	err := s.view(func(tx *bolt.Tx) error {
		encoded := tx.Bucket(bindingBucket).Get(binding[:])
		if encoded == nil {
			return ErrSessionNotFound
		}
		var err error
		record, err = decodeRecord(encoded)
		return err
	})
	return record, err
}

func (s *Store) initializeAndRecover() error {
	return s.update(func(tx *bolt.Tx) error {
		bindings, err := tx.CreateBucketIfNotExists(bindingBucket)
		if err != nil {
			return err
		}
		sessions, err := tx.CreateBucketIfNotExists(sessionBucket)
		if err != nil {
			return err
		}

		type recovery struct {
			key    []byte
			record Record
		}
		var recoveries []recovery
		if err := bindings.ForEach(func(key, value []byte) error {
			if value == nil || len(key) != 32 {
				return fmt.Errorf("%w: invalid binding entry", ErrCorruptLedger)
			}
			record, err := decodeRecord(value)
			if err != nil {
				return err
			}
			if !equal32Bytes(record.Binding, key) {
				return fmt.Errorf("%w: binding key mismatch", ErrCorruptLedger)
			}
			indexedBinding := sessions.Get(record.SessionID[:])
			if !equal32Bytes(record.Binding, indexedBinding) {
				return fmt.Errorf("%w: missing or mismatched session index", ErrCorruptLedger)
			}
			switch record.State {
			case StateCommitted, StateGenerated, StateReleased:
				record.State = StateFailedTerminal
				record.FailureCode = FailureRestartAfterCommit
				record.UpdatedAtUnixNano = timestampAtLeast(record.UpdatedAtUnixNano)
				keyCopy := append([]byte(nil), key...)
				recoveries = append(recoveries, recovery{key: keyCopy, record: record})
			}
			return nil
		}); err != nil {
			return err
		}

		if err := sessions.ForEach(func(sessionID, binding []byte) error {
			if binding == nil || len(sessionID) != 32 || len(binding) != 32 {
				return fmt.Errorf("%w: invalid session index entry", ErrCorruptLedger)
			}
			encoded := bindings.Get(binding)
			if encoded == nil {
				return fmt.Errorf("%w: dangling session index", ErrCorruptLedger)
			}
			record, err := decodeRecord(encoded)
			if err != nil {
				return err
			}
			if !equal32Bytes(record.SessionID, sessionID) {
				return fmt.Errorf("%w: aliased session index", ErrCorruptLedger)
			}
			return nil
		}); err != nil {
			return err
		}

		for _, item := range recoveries {
			encoded, err := encodeRecord(item.record)
			if err != nil {
				return err
			}
			if err := bindings.Put(item.key, encoded); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) transition(sessionID [32]byte, from, to State, apply func(*Record)) (Record, error) {
	return s.mutate(sessionID, func(record *Record) error {
		if record.State != from {
			return transitionError(*record, to)
		}
		record.State = to
		if apply != nil {
			apply(record)
		}
		return nil
	})
}

func (s *Store) mutate(sessionID [32]byte, mutate func(*Record) error) (Record, error) {
	if sessionID == ([32]byte{}) {
		return Record{}, fmt.Errorf("%w: empty session id", ErrInvalidDescriptor)
	}
	var record Record
	err := s.update(func(tx *bolt.Tx) error {
		var err error
		record, err = recordBySession(tx, sessionID)
		if err != nil {
			return err
		}
		if err := mutate(&record); err != nil {
			return err
		}
		record.UpdatedAtUnixNano = timestampAtLeast(record.UpdatedAtUnixNano)
		encoded, err := encodeRecord(record)
		if err != nil {
			return err
		}
		return tx.Bucket(bindingBucket).Put(record.Binding[:], encoded)
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Store) update(fn func(*bolt.Tx) error) error {
	if s == nil || s.db == nil {
		return bolt.ErrDatabaseNotOpen
	}
	return s.db.Update(fn)
}

func (s *Store) view(fn func(*bolt.Tx) error) error {
	if s == nil || s.db == nil {
		return bolt.ErrDatabaseNotOpen
	}
	return s.db.View(fn)
}

func recordBySession(tx *bolt.Tx, sessionID [32]byte) (Record, error) {
	binding := tx.Bucket(sessionBucket).Get(sessionID[:])
	if binding == nil {
		return Record{}, ErrSessionNotFound
	}
	encoded := tx.Bucket(bindingBucket).Get(binding)
	if encoded == nil {
		return Record{}, fmt.Errorf("%w: session index has no binding record", ErrCorruptLedger)
	}
	record, err := decodeRecord(encoded)
	if err != nil {
		return Record{}, err
	}
	if record.SessionID != sessionID {
		return Record{}, fmt.Errorf("%w: session id mismatch", ErrCorruptLedger)
	}
	return record, nil
}

func encodeRecord(record Record) ([]byte, error) {
	if err := validateRecord(record); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode threshold record: %w", err)
	}
	return encoded, nil
}

func decodeRecord(encoded []byte) (Record, error) {
	var record Record
	if err := json.Unmarshal(encoded, &record); err != nil {
		return Record{}, fmt.Errorf("%w: decode record: %v", ErrCorruptLedger, err)
	}
	if err := validateRecord(record); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrCorruptLedger, err)
	}
	return record, nil
}

func validateDescriptor(descriptor Descriptor) error {
	if descriptor.SessionID == ([32]byte{}) || descriptor.Binding == ([32]byte{}) || descriptor.CoalitionDigest == ([32]byte{}) {
		return fmt.Errorf("%w: session id, binding and coalition digest are required", ErrInvalidDescriptor)
	}
	return nil
}

func validateRecord(record Record) error {
	if record.Version != recordVersion {
		return fmt.Errorf("unsupported record version %d", record.Version)
	}
	if err := validateDescriptor(Descriptor{
		SessionID:       record.SessionID,
		Binding:         record.Binding,
		CoalitionDigest: record.CoalitionDigest,
	}); err != nil {
		return err
	}
	if record.CreatedAtUnixNano <= 0 || record.UpdatedAtUnixNano <= 0 || record.UpdatedAtUnixNano < record.CreatedAtUnixNano {
		return errors.New("invalid record timestamps")
	}
	switch record.State {
	case StatePrepared, StateCommitted:
		if record.ResponseDigest != ([32]byte{}) || record.FailureCode != "" {
			return errors.New("pre-generation record contains response or failure data")
		}
	case StateGenerated, StateReleased, StateAcked:
		if record.ResponseDigest == ([32]byte{}) || record.FailureCode != "" {
			return errors.New("generated record is missing response digest or has failure data")
		}
	case StateAbortedPrestart:
		if record.ResponseDigest != ([32]byte{}) || record.FailureCode != FailureAbortedBeforeCommit {
			return errors.New("invalid pre-start abort record")
		}
	case StateFailedTerminal:
		if !validFailureCode(record.FailureCode) || record.FailureCode == FailureAbortedBeforeCommit {
			return errors.New("invalid terminal failure record")
		}
	default:
		return fmt.Errorf("unknown state %q", record.State)
	}
	return nil
}

func transitionError(record Record, target State) error {
	if record.IsTerminal() || record.State == StateCommitted || record.State == StateGenerated || record.State == StateReleased {
		return fmt.Errorf("%w: %s cannot transition to %s", ErrTerminal, record.State, target)
	}
	return fmt.Errorf("%w: %s cannot transition to %s", ErrInvalidTransition, record.State, target)
}

func validFailureCode(code FailureCode) bool {
	if len(code) == 0 || len(code) > 64 {
		return false
	}
	for _, char := range code {
		if (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' {
			return false
		}
	}
	return true
}

func equal32Bytes(value [32]byte, encoded []byte) bool {
	if len(encoded) != len(value) {
		return false
	}
	for i := range value {
		if value[i] != encoded[i] {
			return false
		}
	}
	return true
}

func timestampAtLeast(previous int64) int64 {
	now := time.Now().UnixNano()
	if now < previous {
		return previous
	}
	return now
}
