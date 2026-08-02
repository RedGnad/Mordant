package oneshotceremony

import (
	"crypto/ed25519"
	"crypto/sha256"
	"slices"
)

// AttemptReservation is created before any ceremony secret. It permanently
// binds one operator process instance to one ceremony and scope ordinal.
type AttemptReservation struct {
	SchemaVersion            string
	CeremonyID               [32]byte
	ContextDigest            [32]byte
	RosterDigest             [32]byte
	SessionBindingDigest     [32]byte
	ScopeOrdinalDigest       [32]byte
	ContextSnapshot          []byte
	OperatorPoint            uint64
	ProcessInstanceDigest    [32]byte
	BootSessionDigest        [32]byte
	PreviousLocalWitnessHead [32]byte
	StartupProvenance        ExecutableProvenance
	StorageBindingDigest     [32]byte
	Signature                [ed25519.SignatureSize]byte
}

func newAttemptReservation(context Context, point uint64, processInstance, bootSession string, previous [32]byte,
	startup ExecutableProvenance, storageBinding [32]byte, key ed25519.PrivateKey,
) (AttemptReservation, error) {
	if processInstance == "" || bootSession == "" || len(key) != ed25519.PrivateKeySize {
		return AttemptReservation{}, ErrBinding
	}
	if _, err := startup.MarshalBinary(); err != nil || isZero32(storageBinding) {
		return AttemptReservation{}, ErrBinding
	}
	contextSnapshot, err := context.MarshalBinary()
	if err != nil {
		return AttemptReservation{}, err
	}
	reservation := AttemptReservation{
		SchemaVersion:            "mordant.fhe-attempt-reservation/oneshot-v3",
		CeremonyID:               context.CeremonyID(),
		ContextDigest:            context.ContextDigest(),
		RosterDigest:             context.RosterDigest(),
		SessionBindingDigest:     context.SessionBindingDigest(),
		ScopeOrdinalDigest:       context.ScopeOrdinalDigest(),
		ContextSnapshot:          contextSnapshot,
		OperatorPoint:            point,
		ProcessInstanceDigest:    hashDomain("MordantOneShotProcessInstance/v1", []byte(processInstance)),
		BootSessionDigest:        hashDomain("MordantOneShotBootSession/v1", []byte(bootSession)),
		PreviousLocalWitnessHead: previous,
		StartupProvenance:        startup,
		StorageBindingDigest:     storageBinding,
	}
	identity, ok := context.Operator(point)
	if !ok || !slices.Equal(key.Public().(ed25519.PublicKey), identity.SigningPublicKey[:]) ||
		startup.SourceRevision != context.SourceCommit || startup.ExecutableSHA256 != identity.RuntimeBinaryDigest ||
		startup.GoVersion != identity.GoVersion || startup.OperatingSystem != identity.OperatingSystem ||
		startup.Architecture != identity.Architecture || storageBinding != identity.StorageBindingDigest {
		return AttemptReservation{}, ErrSignature
	}
	copy(reservation.Signature[:], ed25519.Sign(key, reservation.signingBytes()))
	return reservation, nil
}

func (r AttemptReservation) signingBytes() []byte {
	var e encoder
	e.text("MordantOneShotAttemptReservationSignature/v3")
	e.text(r.SchemaVersion)
	e.fixed(r.CeremonyID[:])
	e.fixed(r.ContextDigest[:])
	e.fixed(r.RosterDigest[:])
	e.fixed(r.SessionBindingDigest[:])
	e.fixed(r.ScopeOrdinalDigest[:])
	e.field(r.ContextSnapshot)
	e.u64(r.OperatorPoint)
	e.fixed(r.ProcessInstanceDigest[:])
	e.fixed(r.BootSessionDigest[:])
	e.fixed(r.PreviousLocalWitnessHead[:])
	provenance, _ := r.StartupProvenance.MarshalBinary()
	e.field(provenance)
	e.fixed(r.StorageBindingDigest[:])
	return e.Bytes()
}

func (r AttemptReservation) MarshalBinary() ([]byte, error) {
	if r.SchemaVersion != "mordant.fhe-attempt-reservation/oneshot-v3" || isZero32(r.CeremonyID) ||
		isZero32(r.ContextDigest) || isZero32(r.RosterDigest) || isZero32(r.SessionBindingDigest) || isZero32(r.ScopeOrdinalDigest) || len(r.ContextSnapshot) == 0 ||
		r.OperatorPoint == 0 || isZero32(r.ProcessInstanceDigest) || isZero32(r.BootSessionDigest) ||
		isZero32(r.StorageBindingDigest) {
		return nil, ErrBinding
	}
	if _, err := r.StartupProvenance.MarshalBinary(); err != nil {
		return nil, err
	}
	var e encoder
	e.text(r.SchemaVersion)
	e.field(r.signingBytes())
	e.fixed(r.Signature[:])
	return e.Bytes(), nil
}

func ParseAttemptReservation(data []byte) (AttemptReservation, error) {
	var reservation AttemptReservation
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != "mordant.fhe-attempt-reservation/oneshot-v3" {
		return reservation, errCanonical
	}
	body, err := d.field()
	if err != nil {
		return reservation, err
	}
	bd := newDecoder(body)
	domain, err := bd.text()
	if err != nil || domain != "MordantOneShotAttemptReservationSignature/v3" {
		return reservation, errCanonical
	}
	if reservation.SchemaVersion, err = bd.text(); err != nil || reservation.SchemaVersion != magic {
		return reservation, errCanonical
	}
	for _, target := range []*[32]byte{&reservation.CeremonyID, &reservation.ContextDigest, &reservation.RosterDigest, &reservation.SessionBindingDigest, &reservation.ScopeOrdinalDigest} {
		value, readErr := bd.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return AttemptReservation{}, errCanonical
		}
	}
	if reservation.ContextSnapshot, err = bd.field(); err != nil || len(reservation.ContextSnapshot) == 0 {
		return AttemptReservation{}, errCanonical
	}
	if reservation.OperatorPoint, err = bd.u64(); err != nil {
		return reservation, err
	}
	for _, target := range []*[32]byte{&reservation.ProcessInstanceDigest, &reservation.BootSessionDigest, &reservation.PreviousLocalWitnessHead} {
		value, readErr := bd.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return AttemptReservation{}, errCanonical
		}
	}
	provenanceBytes, err := bd.field()
	if err != nil {
		return AttemptReservation{}, errCanonical
	}
	if reservation.StartupProvenance, err = ParseExecutableProvenance(provenanceBytes); err != nil {
		return AttemptReservation{}, errCanonical
	}
	value, err := bd.fixed(32)
	if err != nil || copy32(&reservation.StorageBindingDigest, value) != nil {
		return AttemptReservation{}, errCanonical
	}
	if bd.done() != nil {
		return AttemptReservation{}, errCanonical
	}
	signature, err := d.fixed(ed25519.SignatureSize)
	if err != nil || d.done() != nil {
		return AttemptReservation{}, errCanonical
	}
	copy(reservation.Signature[:], signature)
	reencoded, err := reservation.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return AttemptReservation{}, errCanonical
	}
	return reservation, nil
}

func VerifyAttemptReservation(context Context, reservation AttemptReservation) error {
	identity, ok := context.Operator(reservation.OperatorPoint)
	parsed, parseErr := ParseContext(reservation.ContextSnapshot)
	if !ok || parseErr != nil || reservation.SchemaVersion != "mordant.fhe-attempt-reservation/oneshot-v3" ||
		reservation.CeremonyID != context.CeremonyID() || reservation.ContextDigest != context.ContextDigest() ||
		parsed.ContextDigest() != context.ContextDigest() || reservation.RosterDigest != context.RosterDigest() ||
		reservation.SessionBindingDigest != context.SessionBindingDigest() || reservation.ScopeOrdinalDigest != context.ScopeOrdinalDigest() ||
		reservation.StartupProvenance.SourceRevision != context.SourceCommit ||
		reservation.StartupProvenance.ExecutableSHA256 != identity.RuntimeBinaryDigest ||
		reservation.StartupProvenance.GoVersion != identity.GoVersion ||
		reservation.StartupProvenance.OperatingSystem != identity.OperatingSystem ||
		reservation.StartupProvenance.Architecture != identity.Architecture ||
		reservation.StorageBindingDigest != identity.StorageBindingDigest ||
		!ed25519.Verify(identity.SigningPublicKey[:], reservation.signingBytes(), reservation.Signature[:]) {
		return ErrSignature
	}
	return nil
}

func cloneAttemptReservation(input AttemptReservation) AttemptReservation {
	output := input
	output.ContextSnapshot = slices.Clone(input.ContextSnapshot)
	return output
}

func reservationSetDigest(context Context, reservations []AttemptReservation) ([32]byte, error) {
	if len(reservations) != PartyCount {
		return [32]byte{}, ErrBinding
	}
	var e encoder
	e.text("MordantOneShotReservationSet/v1")
	ceremonyID := context.CeremonyID()
	e.fixed(ceremonyID[:])
	for index, reservation := range reservations {
		if reservation.OperatorPoint != context.Operators[index].Point || VerifyAttemptReservation(context, reservation) != nil {
			return [32]byte{}, ErrBinding
		}
		encoded, err := reservation.MarshalBinary()
		if err != nil {
			return [32]byte{}, err
		}
		e.field(encoded)
	}
	return sha256.Sum256(e.Bytes()), nil
}
