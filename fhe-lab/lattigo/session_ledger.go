package lattigospike

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// External audit finding H-01, second half. The V4 evaluator recorded consumed
// nonces and enrollment ids in Go maps. A restarted evaluator forgot every
// session it had ever run, so replaying a recorded request after a restart
// re-ran the circuit and produced a second release under the same
// authorization. "One-shot" was a property of the process, not of the protocol.
//
// The ledger below is the same guarantee written to disk in one atomic
// transaction, so it survives a restart and a crash mid-session.

var (
	// ErrSessionConsumed reports a session, nullifier or enrollment that this
	// ledger has already admitted.
	ErrSessionConsumed = errors.New("session already consumed")
	// ErrSessionUnknown reports a transition on a session that was never
	// reserved.
	ErrSessionUnknown = errors.New("session not reserved")
	// ErrSessionState reports a transition that is not legal from the recorded
	// state.
	ErrSessionState = errors.New("illegal session state transition")
)

var (
	bucketSessions    = []byte("v5-sessions")
	bucketNullifiers  = []byte("v5-nullifiers")
	bucketEnrollments = []byte("v5-enrollments")
)

// SessionState is the durable lifecycle of one bilateral session.
type SessionState uint8

const (
	// SessionReserved means the pair was admitted and evaluation may proceed.
	// A crash here is terminal for the session: it is never re-admitted.
	SessionReserved SessionState = 1
	// SessionReleased means a quorum released the two bits for this session.
	SessionReleased SessionState = 2
	// SessionFailed means the session was abandoned. Also terminal.
	SessionFailed SessionState = 3
)

// SessionRecord is the durable record of one session.
type SessionRecord struct {
	State             SessionState
	SessionCommitment [32]byte
	SessionNullifier  [32]byte
	EnrollmentDigestA [32]byte
	EnrollmentDigestB [32]byte
	OutputsDigest     [32]byte
	ReservedAt        uint64
	SettledAt         uint64
}

// SessionLedger is a crash-safe one-shot ledger for V5 sessions.
type SessionLedger struct {
	db *bolt.DB
}

// OpenSessionLedger opens or creates the ledger. Writes are fsynced on commit,
// which is what makes "already consumed" outlive a power loss.
func OpenSessionLedger(path string) (*SessionLedger, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open session ledger: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketSessions, bucketNullifiers, bucketEnrollments} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize session ledger: %w", err)
	}
	return &SessionLedger{db: db}, nil
}

func (ledger *SessionLedger) Close() error {
	if ledger == nil || ledger.db == nil {
		return nil
	}
	return ledger.db.Close()
}

// Reserve admits one session exactly once.
//
// The session commitment, the salt-independent nullifier and BOTH enrollment
// digests are consumed in a single transaction. Consuming the nullifier stops a
// resalted commitment; consuming the enrollment digests stops the same signed
// enrollment being reused in a different pair.
func (ledger *SessionLedger) Reserve(paired PairedEnrollmentsV5, now time.Time) (SessionRecord, error) {
	var record SessionRecord
	if ledger == nil || ledger.db == nil {
		return record, bolt.ErrDatabaseNotOpen
	}
	zero := [32]byte{}
	if paired.SessionCommitment == zero || paired.SessionNullifier == zero ||
		paired.EnrollmentDigestA == zero || paired.EnrollmentDigestB == zero ||
		paired.EnrollmentDigestA == paired.EnrollmentDigestB {
		return record, ErrMalformedEnrollment
	}

	record = SessionRecord{
		State:             SessionReserved,
		SessionCommitment: paired.SessionCommitment,
		SessionNullifier:  paired.SessionNullifier,
		EnrollmentDigestA: paired.EnrollmentDigestA,
		EnrollmentDigestB: paired.EnrollmentDigestB,
		ReservedAt:        uint64(now.Unix()),
	}
	err := ledger.db.Update(func(tx *bolt.Tx) error {
		sessions := tx.Bucket(bucketSessions)
		nullifiers := tx.Bucket(bucketNullifiers)
		enrollments := tx.Bucket(bucketEnrollments)
		if sessions.Get(paired.SessionCommitment[:]) != nil {
			return fmt.Errorf("%w: session commitment", ErrSessionConsumed)
		}
		if nullifiers.Get(paired.SessionNullifier[:]) != nil {
			return fmt.Errorf("%w: session nullifier", ErrSessionConsumed)
		}
		for _, digest := range [][32]byte{paired.EnrollmentDigestA, paired.EnrollmentDigestB} {
			if enrollments.Get(digest[:]) != nil {
				return fmt.Errorf("%w: enrollment", ErrSessionConsumed)
			}
		}
		if err := nullifiers.Put(paired.SessionNullifier[:], paired.SessionCommitment[:]); err != nil {
			return err
		}
		for _, digest := range [][32]byte{paired.EnrollmentDigestA, paired.EnrollmentDigestB} {
			if err := enrollments.Put(digest[:], paired.SessionCommitment[:]); err != nil {
				return err
			}
		}
		return sessions.Put(paired.SessionCommitment[:], encodeSessionRecord(record))
	})
	if err != nil {
		return SessionRecord{}, err
	}
	return record, nil
}

// MarkReleased records that a quorum released this session's two bits, binding
// the recomputed output digest. Legal only from SessionReserved.
func (ledger *SessionLedger) MarkReleased(sessionCommitment, outputsDigest [32]byte, now time.Time) (SessionRecord, error) {
	return ledger.transition(sessionCommitment, SessionReserved, SessionReleased, func(record *SessionRecord) {
		record.OutputsDigest = outputsDigest
		record.SettledAt = uint64(now.Unix())
	})
}

// MarkFailed closes a session without a release. Terminal: the authorization is
// spent either way, so an abandoned session is never retried under the same
// enrollments.
func (ledger *SessionLedger) MarkFailed(sessionCommitment [32]byte, now time.Time) (SessionRecord, error) {
	return ledger.transition(sessionCommitment, SessionReserved, SessionFailed, func(record *SessionRecord) {
		record.SettledAt = uint64(now.Unix())
	})
}

// Get returns the durable record for one session.
func (ledger *SessionLedger) Get(sessionCommitment [32]byte) (SessionRecord, error) {
	var record SessionRecord
	if ledger == nil || ledger.db == nil {
		return record, bolt.ErrDatabaseNotOpen
	}
	err := ledger.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketSessions).Get(sessionCommitment[:])
		if raw == nil {
			return ErrSessionUnknown
		}
		decoded, err := decodeSessionRecord(raw)
		if err != nil {
			return err
		}
		record = decoded
		return nil
	})
	return record, err
}

func (ledger *SessionLedger) transition(sessionCommitment [32]byte, from, to SessionState, apply func(*SessionRecord)) (SessionRecord, error) {
	var record SessionRecord
	if ledger == nil || ledger.db == nil {
		return record, bolt.ErrDatabaseNotOpen
	}
	err := ledger.db.Update(func(tx *bolt.Tx) error {
		sessions := tx.Bucket(bucketSessions)
		raw := sessions.Get(sessionCommitment[:])
		if raw == nil {
			return ErrSessionUnknown
		}
		decoded, err := decodeSessionRecord(raw)
		if err != nil {
			return err
		}
		if decoded.State != from {
			return fmt.Errorf("%w: %d -> %d", ErrSessionState, decoded.State, to)
		}
		decoded.State = to
		apply(&decoded)
		record = decoded
		return sessions.Put(sessionCommitment[:], encodeSessionRecord(decoded))
	})
	if err != nil {
		return SessionRecord{}, err
	}
	return record, nil
}

// The encoding is fixed-width and positional. No JSON, no reflection, so a
// record written by one build is read identically by the next.
const sessionRecordSize = 1 + 32*5 + 8*2

func encodeSessionRecord(record SessionRecord) []byte {
	buffer := make([]byte, 0, sessionRecordSize)
	buffer = append(buffer, byte(record.State))
	buffer = append(buffer, record.SessionCommitment[:]...)
	buffer = append(buffer, record.SessionNullifier[:]...)
	buffer = append(buffer, record.EnrollmentDigestA[:]...)
	buffer = append(buffer, record.EnrollmentDigestB[:]...)
	buffer = append(buffer, record.OutputsDigest[:]...)
	var times [16]byte
	binary.BigEndian.PutUint64(times[0:8], record.ReservedAt)
	binary.BigEndian.PutUint64(times[8:16], record.SettledAt)
	return append(buffer, times[:]...)
}

func decodeSessionRecord(raw []byte) (SessionRecord, error) {
	var record SessionRecord
	if len(raw) != sessionRecordSize {
		return record, fmt.Errorf("corrupt session record: %d bytes", len(raw))
	}
	record.State = SessionState(raw[0])
	offset := 1
	for _, field := range []*[32]byte{
		&record.SessionCommitment, &record.SessionNullifier,
		&record.EnrollmentDigestA, &record.EnrollmentDigestB, &record.OutputsDigest,
	} {
		copy(field[:], raw[offset:offset+32])
		offset += 32
	}
	record.ReservedAt = binary.BigEndian.Uint64(raw[offset : offset+8])
	record.SettledAt = binary.BigEndian.Uint64(raw[offset+8 : offset+16])
	return record, nil
}
