package oneshotceremony

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

type StatusSignature struct {
	Point     uint64
	Signature [ed25519.SignatureSize]byte
}

type StatusRecord struct {
	Statement  KeyStatusStatement
	Signatures []StatusSignature
}

func NewTerminalKeyStatus(previous KeyStatusStatement, status KeyStatus, effectiveAt int64, reason [32]byte) (KeyStatusStatement, error) {
	if previous.SchemaVersion != StatusSchema || previous.Status != StatusActive ||
		(status != StatusRevoked && status != StatusExpired) || effectiveAt < previous.EffectiveAt || isZero32(reason) {
		return KeyStatusStatement{}, ErrState
	}
	return KeyStatusStatement{
		SchemaVersion:  StatusSchema,
		KeyID:          previous.KeyID,
		Sequence:       previous.Sequence + 1,
		Status:         status,
		EffectiveAt:    effectiveAt,
		ReasonDigest:   reason,
		PreviousDigest: previous.Digest(),
	}, nil
}

func SignKeyStatus(context Context, previous, statement KeyStatusStatement, point uint64, key ed25519.PrivateKey, store *WitnessStore) (StatusSignature, error) {
	identity, ok := context.Operator(point)
	digest := statement.Digest()
	if !ok || store == nil || len(key) != ed25519.PrivateKeySize || isZero32(digest) || validateStatusTransition(previous, statement) != nil ||
		!slices.Equal(key.Public().(ed25519.PublicKey), identity.SigningPublicKey[:]) {
		return StatusSignature{}, ErrSignature
	}
	signature := StatusSignature{Point: point}
	copy(signature.Signature[:], ed25519.Sign(key, digest[:]))
	if err := store.writeStatusDecision(statement.KeyID, statement.Sequence, digest, signature.Signature[:]); err != nil {
		return StatusSignature{}, err
	}
	return signature, nil
}

func AssembleStatusRecord(context Context, previous KeyStatusStatement, statement KeyStatusStatement, signatures []StatusSignature) (StatusRecord, error) {
	record := StatusRecord{Statement: statement, Signatures: slices.Clone(signatures)}
	slices.SortFunc(record.Signatures, func(a, b StatusSignature) int {
		if a.Point < b.Point {
			return -1
		}
		if a.Point > b.Point {
			return 1
		}
		return 0
	})
	if err := VerifyStatusRecord(context, previous, record); err != nil {
		return StatusRecord{}, err
	}
	return record, nil
}

func VerifyStatusRecord(context Context, previous KeyStatusStatement, record StatusRecord) error {
	statement := record.Statement
	if validateStatusTransition(previous, statement) != nil || len(record.Signatures) < Threshold || len(record.Signatures) > PartyCount {
		return ErrState
	}
	digest := statement.Digest()
	var last uint64
	for index, signature := range record.Signatures {
		identity, ok := context.Operator(signature.Point)
		if !ok || (index > 0 && signature.Point <= last) || !ed25519.Verify(identity.SigningPublicKey[:], digest[:], signature.Signature[:]) {
			return ErrSignature
		}
		last = signature.Point
	}
	return nil
}

func (r StatusRecord) MarshalBinary() ([]byte, error) {
	statement, err := r.Statement.MarshalBinary()
	if err != nil || len(r.Signatures) < Threshold || len(r.Signatures) > PartyCount {
		return nil, ErrBinding
	}
	var e encoder
	e.text("MordantOneShotStatusRecord/v1")
	e.field(statement)
	e.u32(uint32(len(r.Signatures)))
	for _, signature := range r.Signatures {
		e.u64(signature.Point)
		e.fixed(signature.Signature[:])
	}
	return e.Bytes(), nil
}

func ParseStatusRecord(data []byte) (StatusRecord, error) {
	var record StatusRecord
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != "MordantOneShotStatusRecord/v1" {
		return record, errCanonical
	}
	statement, err := d.field()
	if err != nil {
		return record, err
	}
	if record.Statement, err = ParseKeyStatusStatement(statement); err != nil {
		return record, err
	}
	count, err := d.u32()
	if err != nil || count < Threshold || count > PartyCount {
		return StatusRecord{}, errCanonical
	}
	record.Signatures = make([]StatusSignature, count)
	for index := range record.Signatures {
		if record.Signatures[index].Point, err = d.u64(); err != nil {
			return StatusRecord{}, err
		}
		value, readErr := d.fixed(ed25519.SignatureSize)
		if readErr != nil {
			return StatusRecord{}, readErr
		}
		copy(record.Signatures[index].Signature[:], value)
	}
	if d.done() != nil {
		return StatusRecord{}, errCanonical
	}
	reencoded, err := record.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return StatusRecord{}, errCanonical
	}
	return record, nil
}

func (r StatusRecord) Digest() [32]byte {
	encoded, err := r.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotStatusRecordDigest/v1", encoded)
}

func (s *WitnessStore) AppendStatus(context Context, previous KeyStatusStatement, record StatusRecord) error {
	if err := VerifyStatusRecord(context, previous, record); err != nil {
		return err
	}
	encoded, err := record.MarshalBinary()
	if err != nil {
		return err
	}
	digest := record.Digest()
	name := fmt.Sprintf("status-%s-%020d-%s.bin", hex.EncodeToString(record.Statement.KeyID[:]), record.Statement.Sequence, hex.EncodeToString(digest[:]))
	if err := s.writeNoReplace(name, encoded); err != nil {
		return fmt.Errorf("%w: status already appended", ErrReplay)
	}
	return nil
}

func (s *WitnessStore) StatusRecords(context Context, initial KeyStatusStatement) ([]StatusRecord, error) {
	if s == nil || initial.KeyID == ([32]byte{}) {
		return nil, ErrPersistence
	}
	if _, err := s.Records(context.CeremonyID()); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, ErrPersistence
	}
	prefix := "status-" + hex.EncodeToString(initial.KeyID[:]) + "-"
	names := make([]string, 0, 1)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	records := make([]StatusRecord, len(names))
	previous := initial
	for index, name := range names {
		data, readErr := os.ReadFile(filepath.Join(s.root, name))
		if readErr != nil {
			return nil, ErrPersistence
		}
		record, parseErr := ParseStatusRecord(data)
		if parseErr != nil || VerifyStatusRecord(context, previous, record) != nil {
			return nil, ErrPersistence
		}
		digest := record.Digest()
		if !strings.HasSuffix(name, hex.EncodeToString(digest[:])+".bin") {
			return nil, ErrPersistence
		}
		records[index] = record
		previous = record.Statement
	}
	return records, nil
}

func VerifyStatusReplicaAgreement(context Context, initial KeyStatusStatement, replicas ...[]StatusRecord) error {
	if len(replicas) != PartyCount || len(replicas[0]) == 0 {
		return ErrPersistence
	}
	for replicaIndex, replica := range replicas {
		previous := initial
		if len(replica) != len(replicas[0]) {
			return ErrPersistence
		}
		for recordIndex, record := range replica {
			if VerifyStatusRecord(context, previous, record) != nil ||
				(replicaIndex > 0 && record.Digest() != replicas[0][recordIndex].Digest()) {
				return ErrPersistence
			}
			previous = record.Statement
		}
	}
	return nil
}

func validateStatusTransition(previous, statement KeyStatusStatement) error {
	if previous.Digest() == ([32]byte{}) || statement.Digest() == ([32]byte{}) || statement.KeyID != previous.KeyID ||
		statement.Sequence != previous.Sequence+1 || statement.PreviousDigest != previous.Digest() ||
		previous.Status != StatusActive || (statement.Status != StatusRevoked && statement.Status != StatusExpired) ||
		statement.EffectiveAt < previous.EffectiveAt {
		return ErrState
	}
	return nil
}
