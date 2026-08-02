package oneshotceremony

import (
	"crypto/ed25519"
	"fmt"
	"slices"
)

type WitnessStatement struct {
	SchemaVersion    string
	CeremonyID       [32]byte
	ContextDigest    [32]byte
	RosterDigest     [32]byte
	Sequence         uint64
	PreviousDigest   [32]byte
	FromPhase        Phase
	ToPhase          Phase
	Step             uint32
	TranscriptDigest [32]byte
	MaterialDigest   [32]byte
	ReasonDigest     [32]byte
}

type WitnessSignature struct {
	Point     uint64
	Signature [ed25519.SignatureSize]byte
}

type WitnessRecord struct {
	Statement  WitnessStatement
	Signatures []WitnessSignature
}

// ReplicaHeadAttestation is one operator's signed statement of its own
// durable canonical event head. A generation authorization requires exactly
// one current attestation from each fixed roster point.
type ReplicaHeadAttestation struct {
	SchemaVersion string
	CeremonyID    [32]byte
	ContextDigest [32]byte
	OperatorPoint uint64
	Sequence      uint64
	EventDigest   [32]byte
	Signature     [ed25519.SignatureSize]byte
}

func (a ReplicaHeadAttestation) signingBytes() ([]byte, error) {
	if a.SchemaVersion != "mordant.fhe-replica-head/oneshot-v3" || isZero32(a.CeremonyID) || isZero32(a.ContextDigest) || a.OperatorPoint == 0 ||
		(a.Sequence == 0 && !isZero32(a.EventDigest)) || (a.Sequence > 0 && isZero32(a.EventDigest)) {
		return nil, ErrBinding
	}
	var e encoder
	e.text("MordantOneShotReplicaHeadSignature/v3")
	e.text(a.SchemaVersion)
	e.fixed(a.CeremonyID[:])
	e.fixed(a.ContextDigest[:])
	e.u64(a.OperatorPoint)
	e.u64(a.Sequence)
	e.fixed(a.EventDigest[:])
	return e.Bytes(), nil
}

func (p *Participant) AttestReplicaHead() (ReplicaHeadAttestation, error) {
	if p == nil || p.poisoned || len(p.signingKey) != ed25519.PrivateKeySize || VerifyWitnessChain(p.context, p.records) != nil {
		return ReplicaHeadAttestation{}, ErrTerminal
	}
	attestation := ReplicaHeadAttestation{
		SchemaVersion: "mordant.fhe-replica-head/oneshot-v3",
		CeremonyID:    p.context.CeremonyID(),
		ContextDigest: p.context.ContextDigest(),
		OperatorPoint: p.Point(),
		Sequence:      uint64(len(p.records)),
	}
	if len(p.records) > 0 {
		attestation.EventDigest = p.records[len(p.records)-1].EventDigest()
	}
	message, err := attestation.signingBytes()
	if err != nil {
		return ReplicaHeadAttestation{}, err
	}
	copy(attestation.Signature[:], ed25519.Sign(p.signingKey, message))
	return attestation, nil
}

func VerifyReplicaHeadAttestations(context Context, local []WitnessRecord, attestations []ReplicaHeadAttestation) error {
	if len(attestations) != PartyCount || VerifyWitnessChain(context, local) != nil {
		return fmt.Errorf("%w: three signed replica heads required", ErrPersistence)
	}
	sequence := uint64(len(local))
	var event [32]byte
	if len(local) > 0 {
		event = local[len(local)-1].EventDigest()
	}
	for index, attestation := range attestations {
		expected := context.Operators[index]
		message, err := attestation.signingBytes()
		if err != nil || attestation.CeremonyID != context.CeremonyID() || attestation.ContextDigest != context.ContextDigest() ||
			attestation.OperatorPoint != expected.Point || attestation.Sequence != sequence || attestation.EventDigest != event ||
			!ed25519.Verify(expected.SigningPublicKey[:], message, attestation.Signature[:]) {
			return fmt.Errorf("%w: missing, stale or divergent signed replica head", ErrPersistence)
		}
	}
	return nil
}

func NewWitnessStatement(context Context, records []WitnessRecord, to Phase, step uint32, transcript, material, reason [32]byte) (WitnessStatement, error) {
	if err := VerifyWitnessChain(context, records); err != nil {
		return WitnessStatement{}, err
	}
	from := PhaseNotStarted
	var previous [32]byte
	if len(records) > 0 {
		from = records[len(records)-1].Statement.ToPhase
		previous = records[len(records)-1].Digest()
	}
	statement := WitnessStatement{
		SchemaVersion:    WitnessSchema,
		CeremonyID:       context.CeremonyID(),
		ContextDigest:    context.ContextDigest(),
		RosterDigest:     context.RosterDigest(),
		Sequence:         uint64(len(records) + 1),
		PreviousDigest:   previous,
		FromPhase:        from,
		ToPhase:          to,
		Step:             step,
		TranscriptDigest: transcript,
		MaterialDigest:   material,
		ReasonDigest:     reason,
	}
	if err := validateWitnessTransition(context, records, statement); err != nil {
		return WitnessStatement{}, err
	}
	return statement, nil
}

func (s WitnessStatement) MarshalBinary() ([]byte, error) {
	if s.SchemaVersion != WitnessSchema || isZero32(s.CeremonyID) || isZero32(s.ContextDigest) || isZero32(s.RosterDigest) || s.Sequence == 0 {
		return nil, ErrBinding
	}
	var e encoder
	e.text(WitnessSchema)
	e.text(s.SchemaVersion)
	e.fixed(s.CeremonyID[:])
	e.fixed(s.ContextDigest[:])
	e.fixed(s.RosterDigest[:])
	e.u64(s.Sequence)
	e.fixed(s.PreviousDigest[:])
	e.u16(uint16(s.FromPhase))
	e.u16(uint16(s.ToPhase))
	e.u32(s.Step)
	e.fixed(s.TranscriptDigest[:])
	e.fixed(s.MaterialDigest[:])
	e.fixed(s.ReasonDigest[:])
	return e.Bytes(), nil
}

func parseWitnessStatement(d *decoder) (WitnessStatement, error) {
	var s WitnessStatement
	magic, err := d.text()
	if err != nil || magic != WitnessSchema {
		return s, errCanonical
	}
	if s.SchemaVersion, err = d.text(); err != nil {
		return s, err
	}
	for _, target := range []*[32]byte{&s.CeremonyID, &s.ContextDigest, &s.RosterDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return s, errCanonical
		}
	}
	if s.Sequence, err = d.u64(); err != nil {
		return s, err
	}
	value, err := d.fixed(32)
	if err != nil || copy32(&s.PreviousDigest, value) != nil {
		return s, errCanonical
	}
	from, err := d.u16()
	if err != nil {
		return s, err
	}
	to, err := d.u16()
	if err != nil {
		return s, err
	}
	s.FromPhase, s.ToPhase = Phase(from), Phase(to)
	if s.Step, err = d.u32(); err != nil {
		return s, err
	}
	for _, target := range []*[32]byte{&s.TranscriptDigest, &s.MaterialDigest, &s.ReasonDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return s, errCanonical
		}
	}
	return s, nil
}

func (s WitnessStatement) Digest() [32]byte {
	encoded, err := s.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotWitnessStatement/v1", encoded)
}

func SignWitnessStatement(statement WitnessStatement, point uint64, key ed25519.PrivateKey) (WitnessSignature, error) {
	digest := statement.Digest()
	if isZero32(digest) || len(key) != ed25519.PrivateKeySize {
		return WitnessSignature{}, ErrSignature
	}
	signature := WitnessSignature{Point: point}
	copy(signature.Signature[:], ed25519.Sign(key, digest[:]))
	return signature, nil
}

func AssembleWitnessRecord(context Context, statement WitnessStatement, signatures []WitnessSignature) (WitnessRecord, error) {
	record := WitnessRecord{Statement: statement, Signatures: sortedWitnessSignatures(signatures)}
	if err := VerifyWitnessRecord(context, record); err != nil {
		return WitnessRecord{}, err
	}
	return record, nil
}

func (r WitnessRecord) MarshalBinary() ([]byte, error) {
	statement, err := r.Statement.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var e encoder
	e.text("MordantOneShotWitnessRecord/v1")
	e.field(statement)
	e.u32(uint32(len(r.Signatures)))
	for _, signature := range r.Signatures {
		e.u64(signature.Point)
		e.fixed(signature.Signature[:])
	}
	return e.Bytes(), nil
}

func ParseWitnessRecord(data []byte) (WitnessRecord, error) {
	var record WitnessRecord
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != "MordantOneShotWitnessRecord/v1" {
		return record, errCanonical
	}
	statementBytes, err := d.field()
	if err != nil {
		return record, err
	}
	statementDecoder := newDecoder(statementBytes)
	if record.Statement, err = parseWitnessStatement(statementDecoder); err != nil || statementDecoder.done() != nil {
		return record, errCanonical
	}
	count, err := d.u32()
	if err != nil || count < Threshold || count > PartyCount {
		return record, errCanonical
	}
	record.Signatures = make([]WitnessSignature, count)
	for i := range record.Signatures {
		if record.Signatures[i].Point, err = d.u64(); err != nil {
			return record, err
		}
		value, readErr := d.fixed(ed25519.SignatureSize)
		if readErr != nil {
			return record, readErr
		}
		copy(record.Signatures[i].Signature[:], value)
	}
	if err := d.done(); err != nil {
		return record, err
	}
	reencoded, err := record.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return WitnessRecord{}, errCanonical
	}
	return record, nil
}

// EventDigest commits only to canonical event semantics. It is deliberately
// independent of the valid quorum subset and signature presentation order.
func (r WitnessRecord) EventDigest() [32]byte {
	return r.Statement.Digest()
}

// AttestationDigest commits to the exact canonical signature collection. It is
// an artifact digest, never a witness-chain predecessor.
func (r WitnessRecord) AttestationDigest() [32]byte {
	encoded, err := r.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return sha256Record(encoded)
}

// Digest is retained as the canonical event identity used by existing callers.
func (r WitnessRecord) Digest() [32]byte { return r.EventDigest() }

func sha256Record(encoded []byte) [32]byte {
	return hashDomain("MordantOneShotWitnessRecordDigest/v1", encoded)
}

func VerifyWitnessRecord(context Context, record WitnessRecord) error {
	statement := record.Statement
	if statement.SchemaVersion != WitnessSchema || statement.CeremonyID != context.CeremonyID() ||
		statement.ContextDigest != context.ContextDigest() || statement.RosterDigest != context.RosterDigest() {
		return ErrBinding
	}
	required := PartyCount
	if statement.ToPhase == PhaseAborted {
		required = Threshold
	}
	if len(record.Signatures) < required || len(record.Signatures) > PartyCount {
		return ErrSignature
	}
	digest := statement.Digest()
	var previous uint64
	seen := map[uint64]struct{}{}
	for index, signature := range record.Signatures {
		if signature.Point == 0 || (index > 0 && signature.Point <= previous) {
			return ErrSignature
		}
		operator, ok := context.Operator(signature.Point)
		if !ok {
			return ErrSignature
		}
		if _, duplicate := seen[signature.Point]; duplicate || !ed25519.Verify(operator.SigningPublicKey[:], digest[:], signature.Signature[:]) {
			return ErrSignature
		}
		seen[signature.Point] = struct{}{}
		previous = signature.Point
	}
	return nil
}

func VerifyWitnessChain(context Context, records []WitnessRecord) error {
	for index, record := range records {
		if err := VerifyWitnessRecord(context, record); err != nil {
			return err
		}
		if err := validateWitnessTransition(context, records[:index], record.Statement); err != nil {
			return err
		}
	}
	return nil
}

func VerifyReplicaAgreement(context Context, replicas ...[]WitnessRecord) error {
	if len(replicas) != PartyCount {
		return fmt.Errorf("%w: three witness replicas required", ErrPersistence)
	}
	for _, replica := range replicas {
		if err := VerifyWitnessChain(context, replica); err != nil {
			return err
		}
	}
	if len(replicas[0]) == 0 {
		return fmt.Errorf("%w: empty witness", ErrPersistence)
	}
	for i := 1; i < len(replicas); i++ {
		if len(replicas[i]) != len(replicas[0]) {
			return fmt.Errorf("%w: rollback or deletion", ErrPersistence)
		}
		for j := range replicas[0] {
			if replicas[i][j].EventDigest() != replicas[0][j].EventDigest() {
				return fmt.Errorf("%w: fork or equivocation", ErrPersistence)
			}
		}
	}
	return nil
}

// VerifyCompatibleReplicaHeads is required before every signing decision. It
// accepts empty chains only for the first RESERVED event and otherwise requires
// three valid replicas with identical canonical event histories. Signature
// subsets may differ without creating different event heads.
func VerifyCompatibleReplicaHeads(context Context, local []WitnessRecord, replicas ...[]WitnessRecord) error {
	if len(replicas) != PartyCount {
		return fmt.Errorf("%w: three witness replicas required", ErrPersistence)
	}
	if err := VerifyWitnessChain(context, local); err != nil {
		return err
	}
	for _, replica := range replicas {
		if err := VerifyWitnessChain(context, replica); err != nil || len(replica) != len(local) {
			return fmt.Errorf("%w: stale or invalid replica head", ErrPersistence)
		}
		for index := range local {
			if replica[index].EventDigest() != local[index].EventDigest() {
				return fmt.Errorf("%w: divergent replica head", ErrPersistence)
			}
		}
	}
	return nil
}

func validateWitnessTransition(context Context, previous []WitnessRecord, statement WitnessStatement) error {
	if statement.CeremonyID != context.CeremonyID() || statement.ContextDigest != context.ContextDigest() || statement.RosterDigest != context.RosterDigest() ||
		statement.Sequence != uint64(len(previous)+1) {
		return ErrBinding
	}
	from := PhaseNotStarted
	var previousDigest [32]byte
	var previousStep uint32
	if len(previous) > 0 {
		last := previous[len(previous)-1]
		from = last.Statement.ToPhase
		previousDigest = last.Digest()
		previousStep = last.Statement.Step
		if from.Terminal() {
			return ErrTerminal
		}
	}
	if statement.FromPhase != from || statement.PreviousDigest != previousDigest {
		return ErrState
	}
	if statement.ToPhase == PhaseAborted {
		if isZero32(statement.ReasonDigest) || statement.Step != previousStep {
			return ErrState
		}
		return nil
	}
	if !isZero32(statement.ReasonDigest) {
		return ErrState
	}
	valid := false
	switch from {
	case PhaseNotStarted:
		valid = statement.ToPhase == PhaseReserved && statement.Step == 0
	case PhaseReserved:
		valid = statement.ToPhase == PhaseRunning && statement.Step == 0
	case PhaseRunning:
		valid = statement.ToPhase == PhaseCRSCommitted && statement.Step == 0
	case PhaseCRSCommitted:
		valid = statement.ToPhase == PhaseCRSRevealed && statement.Step == 0
	case PhaseCRSRevealed:
		valid = statement.ToPhase == PhasePrivateShares && statement.Step == 0
	case PhasePrivateShares:
		valid = statement.ToPhase == PhasePublicKey && statement.Step == 0
	case PhasePublicKey:
		valid = statement.ToPhase == PhaseRelinOne && statement.Step == 0
	case PhaseRelinOne:
		valid = statement.ToPhase == PhaseRelinTwo && statement.Step == 0
	case PhaseRelinTwo:
		valid = statement.ToPhase == PhaseGalois && statement.Step == 0
	case PhaseGalois:
		if previousStep+1 < uint32(len(context.GaloisElements)) {
			valid = statement.ToPhase == PhaseGalois && statement.Step == previousStep+1
		} else {
			valid = statement.ToPhase == PhaseManifest && statement.Step == previousStep
		}
	case PhaseManifest:
		valid = statement.ToPhase == PhasePublished && statement.Step == previousStep
	case PhasePublished:
		valid = statement.ToPhase == PhaseCompleted && statement.Step == previousStep
	}
	if !valid {
		return ErrState
	}
	if statement.ToPhase >= PhaseCRSCommitted && (isZero32(statement.TranscriptDigest) || isZero32(statement.MaterialDigest)) {
		return ErrBinding
	}
	return nil
}

func sortedWitnessSignatures(signatures []WitnessSignature) []WitnessSignature {
	out := slices.Clone(signatures)
	slices.SortFunc(out, func(a, b WitnessSignature) int {
		switch {
		case a.Point < b.Point:
			return -1
		case a.Point > b.Point:
			return 1
		default:
			return 0
		}
	})
	return out
}

func cloneWitnessRecord(input WitnessRecord) WitnessRecord {
	output := input
	output.Signatures = slices.Clone(input.Signatures)
	return output
}

func cloneWitnessChain(input []WitnessRecord) []WitnessRecord {
	output := make([]WitnessRecord, len(input))
	for index := range input {
		output[index] = cloneWitnessRecord(input[index])
	}
	return output
}
