package oneshotceremony

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

type PublicMaterial struct {
	PublicKeyBytes       []byte
	RelinearizationBytes []byte
	GaloisKeyBytes       [][]byte
}

type Participant struct {
	params            bgv.Parameters
	context           Context
	identity          OperatorIdentity
	signingKey        ed25519.PrivateKey
	encryptionKey     *ecdh.PrivateKey
	store             *WitnessStore
	random            io.Reader
	records           []WitnessRecord
	phase             Phase
	step              uint32
	reserved          bool
	poisoned          bool
	reservation       AttemptReservation
	reservationSet    [32]byte
	transcript        Transcript
	pendingTranscript *Transcript
	pendingPhase      Phase
	pendingStep       uint32
	pendingMaterial   [32]byte

	secretKey        *rlwe.SecretKey
	shamirPolynomial multiparty.ShamirPolynomial
	thresholdShare   multiparty.ShamirSecretShare
	hasThreshold     bool
	crsReveal        [32]byte
	crsSeed          [32]byte
	crsCommitment    [32]byte

	publicKeyBytes []byte
	relinProtocol  *multiparty.RelinearizationKeyGenProtocol
	relinEphemeral *rlwe.SecretKey
	relinOneBytes  []byte
	relinKeyBytes  []byte
	galoisKeyBytes [][]byte

	generated map[string]struct{}
}

func NewParticipant(params bgv.Parameters, context Context, point uint64, signingKey ed25519.PrivateKey, encryptionKey *ecdh.PrivateKey, store *WitnessStore, random io.Reader) (*Participant, error) {
	if err := context.Validate(); err != nil || store == nil || encryptionKey == nil || len(signingKey) != ed25519.PrivateKeySize {
		return nil, ErrBinding
	}
	if time.Now().Unix() >= context.ExpiresAtUnix {
		return nil, ErrTerminal
	}
	fingerprint, err := ParameterFingerprint(params)
	if err != nil || fingerprint != context.ParameterFingerprint {
		return nil, ErrBinding
	}
	identity, ok := context.Operator(point)
	if !ok || !slices.Equal(signingKey.Public().(ed25519.PublicKey), identity.SigningPublicKey[:]) ||
		!slices.Equal(encryptionKey.PublicKey().Bytes(), identity.EncryptionPublicKey[:]) {
		return nil, ErrSignature
	}
	records, err := store.Records(context.CeremonyID())
	if err != nil {
		return nil, err
	}
	if len(records) != 0 {
		return nil, ErrReplay
	}
	if random == nil {
		random = rand.Reader
	}
	return &Participant{
		params:        params,
		context:       context,
		identity:      identity,
		signingKey:    slices.Clone(signingKey),
		encryptionKey: encryptionKey,
		store:         store,
		random:        random,
		phase:         PhaseNotStarted,
		generated:     make(map[string]struct{}),
	}, nil
}

func (p *Participant) Point() uint64 { return p.identity.Point }
func (p *Participant) Phase() Phase  { return p.phase }

func (p *Participant) Records() []WitnessRecord { return slices.Clone(p.records) }

func (p *Participant) Reserve(processInstance, bootSession string) error {
	if p.phase != PhaseNotStarted || p.reserved || p.poisoned {
		return ErrReplay
	}
	previous, err := p.store.PublicHead()
	if err != nil {
		p.poisoned = true
		return err
	}
	reservation, err := newAttemptReservation(p.context, p.Point(), processInstance, bootSession, previous, p.signingKey)
	if err != nil {
		p.poisoned = true
		return err
	}
	if err := p.store.Reserve(reservation); err != nil {
		p.poisoned = true
		return err
	}
	p.reservation = reservation
	p.reserved = true
	return nil
}

func (p *Participant) Reservation() (AttemptReservation, error) {
	if !p.reserved {
		return AttemptReservation{}, ErrState
	}
	return p.reservation, nil
}

func (p *Participant) AcceptReservations(reservations []AttemptReservation) error {
	if p.phase != PhaseNotStarted || !p.reserved || !isZero32(p.reservationSet) {
		return ErrState
	}
	digest, err := reservationSetDigest(p.context, reservations)
	if err != nil {
		return p.poison(err)
	}
	if reservations[indexOfPoint(p.context, p.Point())].Signature != p.reservation.Signature {
		return p.poison(ErrBinding)
	}
	for _, reservation := range reservations {
		if err := p.store.StoreReservation(reservation); err != nil {
			return p.poison(err)
		}
	}
	p.reservationSet = digest
	return nil
}

func (p *Participant) ProposedTransition(to Phase, reason [32]byte) (WitnessStatement, error) {
	if p.phase.Terminal() {
		return WitnessStatement{}, ErrTerminal
	}
	if p.poisoned && to != PhaseAborted {
		return WitnessStatement{}, ErrTerminal
	}
	transcript := p.transcript.Root(p.context)
	material := p.context.ContextDigest()
	step := p.step
	if to == PhaseReserved {
		if !p.reserved || p.phase != PhaseNotStarted || isZero32(p.reservationSet) {
			return WitnessStatement{}, ErrState
		}
		material = p.reservationSet
	} else if to == PhaseRunning {
		if p.phase != PhaseReserved {
			return WitnessStatement{}, ErrState
		}
		roster := p.context.RosterDigest()
		material = hashDomain("MordantOneShotAttemptStarted/v1", roster[:], p.reservationSet[:])
	} else if to == PhaseAborted {
		if isZero32(reason) {
			return WitnessStatement{}, ErrBinding
		}
		material = hashDomain("MordantOneShotAbortMaterial/v1", transcript[:], reason[:])
	} else {
		if p.pendingTranscript == nil || p.pendingPhase != to {
			return WitnessStatement{}, ErrState
		}
		transcript = p.pendingTranscript.Root(p.context)
		material = p.pendingMaterial
		step = p.pendingStep
	}
	return NewWitnessStatement(p.context, p.records, to, step, transcript, material, reason)
}

func (p *Participant) SignTransition(statement WitnessStatement) (WitnessSignature, error) {
	proposed, err := p.ProposedTransition(statement.ToPhase, statement.ReasonDigest)
	if err != nil || proposed.Digest() != statement.Digest() {
		return WitnessSignature{}, p.poison(ErrState)
	}
	signature, err := SignWitnessStatement(statement, p.Point(), p.signingKey)
	if err != nil {
		return WitnessSignature{}, err
	}
	if err := p.store.WriteDecision(p.context.CeremonyID(), statement.Sequence, statement.Digest(), signature.Signature[:]); err != nil {
		p.poisoned = true
		return WitnessSignature{}, err
	}
	return signature, nil
}

func (p *Participant) CommitTransition(record WitnessRecord) error {
	if p.phase.Terminal() {
		return ErrTerminal
	}
	if err := VerifyWitnessRecord(p.context, record); err != nil {
		return p.poison(err)
	}
	proposed, err := p.ProposedTransition(record.Statement.ToPhase, record.Statement.ReasonDigest)
	if err != nil || proposed.Digest() != record.Statement.Digest() {
		return p.poison(ErrState)
	}
	if err := p.store.Append(record); err != nil {
		return p.poison(err)
	}
	p.records = append(p.records, record)
	p.phase = record.Statement.ToPhase
	p.step = record.Statement.Step
	if p.pendingTranscript != nil && p.pendingPhase == p.phase {
		p.transcript = *p.pendingTranscript
		p.pendingTranscript = nil
		p.pendingPhase = 0
		p.pendingMaterial = [32]byte{}
	}
	if p.phase.Terminal() {
		p.clearAttemptSecrets()
	}
	return nil
}

func (p *Participant) BeginSecrets() error {
	if p.phase != PhaseRunning || p.secretKey != nil || p.poisoned || p.wasGenerated("begin-secrets") {
		return ErrState
	}
	p.markGenerated("begin-secrets")
	if _, err := io.ReadFull(p.random, p.crsReveal[:]); err != nil || isZero32(p.crsReveal) {
		return p.poison(ErrMaterial)
	}
	p.secretKey = rlwe.NewKeyGenerator(p.params).GenSecretKeyNew()
	polynomial, err := multiparty.NewThresholdizer(p.params).GenShamirPolynomial(Threshold, p.secretKey)
	if err != nil {
		return p.poison(ErrMaterial)
	}
	p.shamirPolynomial = polynomial
	return nil
}

func (p *Participant) CRSCommitEnvelope() (SignedEnvelope, error) {
	if p.phase != PhaseRunning || p.secretKey == nil || p.poisoned || p.wasGenerated("crs-commit") {
		return SignedEnvelope{}, ErrState
	}
	commitment := crsContributionCommitment(p.context, p.Point(), p.crsReveal)
	p.markGenerated("crs-commit")
	envelope, err := NewSignedEnvelope(p.context, p.signingKey, p.Point(), 0, OperationCRSCommit, 0, 0,
		p.transcript.Root(p.context), p.context.ContextDigest(), commitment[:])
	if err != nil {
		return SignedEnvelope{}, p.poison(err)
	}
	return envelope, nil
}

func (p *Participant) AcceptCRSCommitStage(envelopes []SignedEnvelope) error {
	if p.phase != PhaseRunning {
		return ErrState
	}
	stage := TranscriptStage{Operation: OperationCRSCommit, Envelopes: envelopes}
	return p.stageTransition(stage, PhaseCRSCommitted, 0, stageMaterialDigest(stage))
}

func (p *Participant) CRSRevealEnvelope() (SignedEnvelope, error) {
	if p.phase != PhaseCRSCommitted || p.poisoned || p.wasGenerated("crs-reveal") {
		return SignedEnvelope{}, ErrState
	}
	p.markGenerated("crs-reveal")
	envelope, err := NewSignedEnvelope(p.context, p.signingKey, p.Point(), 0, OperationCRSReveal, 0, 0,
		p.transcript.Root(p.context), p.transcript.Root(p.context), p.crsReveal[:])
	if err != nil {
		return SignedEnvelope{}, p.poison(err)
	}
	return envelope, nil
}

func (p *Participant) AcceptCRSRevealStage(envelopes []SignedEnvelope) error {
	if p.phase != PhaseCRSCommitted {
		return ErrState
	}
	commits := p.transcript.Stages[0].Envelopes
	if len(commits) != PartyCount || len(envelopes) != PartyCount {
		return p.poison(ErrBinding)
	}
	var seedEncoder encoder
	seedEncoder.text("MordantOneShotCRS/v1")
	ceremonyID := p.context.CeremonyID()
	seedEncoder.fixed(ceremonyID[:])
	for index, reveal := range envelopes {
		if _, err := VerifySignedEnvelope(p.context, reveal); err != nil || len(reveal.Payload) != 32 ||
			crsContributionCommitment(p.context, reveal.Header.SenderPoint, bytes32(reveal.Payload)) != bytes32(commits[index].Payload) {
			return p.poison(ErrBinding)
		}
		seedEncoder.u64(reveal.Header.SenderPoint)
		seedEncoder.fixed(reveal.Payload)
	}
	p.crsSeed = sha256.Sum256(seedEncoder.Bytes())
	p.crsCommitment = hashDomain("MordantOneShotCRSCommitment/v1", p.crsSeed[:], ceremonyID[:])
	stage := TranscriptStage{Operation: OperationCRSReveal, Envelopes: envelopes}
	return p.stageTransition(stage, PhaseCRSRevealed, 0, p.crsCommitment)
}

func (p *Participant) PrivateMessages() ([]SealedPrivateMessage, error) {
	if p.phase != PhaseCRSRevealed || p.secretKey == nil || p.poisoned || len(p.shamirPolynomial.Value) == 0 || p.wasGenerated("private-shares") {
		return nil, ErrState
	}
	p.markGenerated("private-shares")
	thresholdizer := multiparty.NewThresholdizer(p.params)
	messages := make([]SealedPrivateMessage, 0, PartyCount)
	previous := p.transcript.Root(p.context)
	for _, recipient := range p.context.Operators {
		share := thresholdizer.AllocateThresholdSecretShare()
		thresholdizer.GenShamirSecretShare(multiparty.ShamirPublicPoint(recipient.Point), p.shamirPolynomial, &share)
		payload, err := share.MarshalBinary()
		if err != nil {
			return nil, p.poison(ErrMaterial)
		}
		envelope, err := NewSignedEnvelope(p.context, p.signingKey, p.Point(), recipient.Point,
			OperationPrivateShamirShare, 0, 0, previous, p.crsCommitment, payload)
		if err != nil {
			return nil, p.poison(err)
		}
		sealed, err := SealPrivateEnvelope(p.context, envelope, p.random)
		if err != nil {
			return nil, p.poison(err)
		}
		messages = append(messages, sealed)
	}
	p.shamirPolynomial = multiparty.ShamirPolynomial{}
	return messages, nil
}

func (p *Participant) ReceivePrivateMessages(all []SealedPrivateMessage) ([]SignedEnvelope, error) {
	if p.phase != PhaseCRSRevealed || p.poisoned || p.wasGenerated("private-receipts") || len(all) != PartyCount*PartyCount {
		return nil, ErrState
	}
	p.markGenerated("private-receipts")
	thresholdizer := multiparty.NewThresholdizer(p.params)
	aggregate := thresholdizer.AllocateThresholdSecretShare()
	receipts := make([]SignedEnvelope, 0, PartyCount)
	previous := p.transcript.Root(p.context)
	for _, message := range all {
		if message.RecipientPoint != p.Point() {
			continue
		}
		envelope, err := OpenPrivateEnvelope(p.context, message, p.encryptionKey)
		if err != nil || envelope.Header.PreviousTranscriptDigest != previous || envelope.Header.InputDigest != p.crsCommitment {
			return nil, p.poison(ErrBinding)
		}
		share := thresholdizer.AllocateThresholdSecretShare()
		if err := share.UnmarshalBinary(envelope.Payload); err != nil {
			return nil, p.poison(ErrMaterial)
		}
		if err := thresholdizer.AggregateShares(aggregate, share, &aggregate); err != nil {
			return nil, p.poison(ErrMaterial)
		}
		receipt, err := NewSignedEnvelope(p.context, p.signingKey, p.Point(), 0, OperationPrivateShareReceipt, 0, 0,
			previous, p.crsCommitment, privateReceiptPayload(message.SenderPoint, message.RecipientPoint, message.Digest()))
		if err != nil {
			return nil, p.poison(err)
		}
		receipts = append(receipts, receipt)
	}
	if len(receipts) != PartyCount {
		return nil, p.poison(ErrBinding)
	}
	p.thresholdShare = aggregate
	p.hasThreshold = true
	return receipts, nil
}

func (p *Participant) AcceptPrivateStage(messages []SealedPrivateMessage, receipts []SignedEnvelope) error {
	if p.phase != PhaseCRSRevealed || !p.hasThreshold {
		return ErrState
	}
	stage := TranscriptStage{Operation: OperationPrivateShareReceipt, PrivateMessages: messages, Envelopes: receipts}
	return p.stageTransition(stage, PhasePrivateShares, 0, stageMaterialDigest(stage))
}

func (p *Participant) PublicKeyShareEnvelope() (SignedEnvelope, error) {
	if p.phase != PhasePrivateShares || p.secretKey == nil || p.poisoned || p.wasGenerated("public-key") {
		return SignedEnvelope{}, ErrState
	}
	p.markGenerated("public-key")
	protocol := multiparty.NewPublicKeyGenProtocol(p.params)
	crs, digest, err := p.stageCRS("public-key", 0)
	if err != nil {
		return SignedEnvelope{}, p.poison(err)
	}
	share := protocol.AllocateShare()
	protocol.GenShare(p.secretKey, protocol.SampleCRP(crs), &share)
	payload, err := share.MarshalBinary()
	if err != nil {
		return SignedEnvelope{}, p.poison(ErrMaterial)
	}
	envelope, err := NewSignedEnvelope(p.context, p.signingKey, p.Point(), 0, OperationPublicKeyShare, 0, 0,
		p.transcript.Root(p.context), digest, payload)
	if err != nil {
		return SignedEnvelope{}, p.poison(err)
	}
	return envelope, nil
}

func (p *Participant) AcceptPublicKeyStage(envelopes []SignedEnvelope) error {
	if p.phase != PhasePrivateShares {
		return ErrState
	}
	stage := TranscriptStage{Operation: OperationPublicKeyShare, Envelopes: envelopes}
	transcript, err := p.withStage(stage)
	if err != nil {
		return err
	}
	publicKey, err := reconstructPublicKey(p.params, p.context, p.crsSeed, stage)
	if err != nil {
		return p.poison(err)
	}
	p.publicKeyBytes, err = publicKey.MarshalBinary()
	if err != nil {
		return p.poison(ErrMaterial)
	}
	p.setPending(transcript, PhasePublicKey, 0, sha256.Sum256(p.publicKeyBytes))
	return nil
}

func (p *Participant) RelinRoundOneEnvelope() (SignedEnvelope, error) {
	if p.phase != PhasePublicKey || p.secretKey == nil || p.poisoned || p.wasGenerated("relin-1") {
		return SignedEnvelope{}, ErrState
	}
	p.markGenerated("relin-1")
	protocol := multiparty.NewRelinearizationKeyGenProtocol(p.params)
	crs, digest, err := p.stageCRS("relin", 0)
	if err != nil {
		return SignedEnvelope{}, p.poison(err)
	}
	eph, share, _ := protocol.AllocateShare()
	protocol.GenShareRoundOne(p.secretKey, protocol.SampleCRP(crs), eph, &share)
	payload, err := share.MarshalBinary()
	if err != nil {
		return SignedEnvelope{}, p.poison(ErrMaterial)
	}
	p.relinProtocol, p.relinEphemeral = &protocol, eph
	envelope, err := NewSignedEnvelope(p.context, p.signingKey, p.Point(), 0, OperationRelinShare, 1, 0,
		p.transcript.Root(p.context), digest, payload)
	if err != nil {
		return SignedEnvelope{}, p.poison(err)
	}
	return envelope, nil
}

func (p *Participant) AcceptRelinRoundOneStage(envelopes []SignedEnvelope) error {
	if p.phase != PhasePublicKey {
		return ErrState
	}
	stage := TranscriptStage{Operation: OperationRelinShare, Round: 1, Envelopes: envelopes}
	transcript, err := p.withStage(stage)
	if err != nil {
		return err
	}
	aggregate, err := aggregateRelinShare(p.params, stage, 1)
	if err != nil {
		return p.poison(err)
	}
	p.relinOneBytes, err = aggregate.MarshalBinary()
	if err != nil {
		return p.poison(ErrMaterial)
	}
	p.setPending(transcript, PhaseRelinOne, 0, sha256.Sum256(p.relinOneBytes))
	return nil
}

func (p *Participant) RelinRoundTwoEnvelope() (SignedEnvelope, error) {
	if p.phase != PhaseRelinOne || p.secretKey == nil || p.poisoned || p.relinProtocol == nil || p.relinEphemeral == nil || p.wasGenerated("relin-2") {
		return SignedEnvelope{}, ErrState
	}
	p.markGenerated("relin-2")
	_, roundOne, roundTwo := p.relinProtocol.AllocateShare()
	if err := roundOne.UnmarshalBinary(p.relinOneBytes); err != nil {
		return SignedEnvelope{}, p.poison(ErrMaterial)
	}
	p.relinProtocol.GenShareRoundTwo(p.relinEphemeral, p.secretKey, roundOne, &roundTwo)
	payload, err := roundTwo.MarshalBinary()
	if err != nil {
		return SignedEnvelope{}, p.poison(ErrMaterial)
	}
	input := sha256.Sum256(p.relinOneBytes)
	envelope, err := NewSignedEnvelope(p.context, p.signingKey, p.Point(), 0, OperationRelinShare, 2, 0,
		p.transcript.Root(p.context), input, payload)
	if err != nil {
		return SignedEnvelope{}, p.poison(err)
	}
	return envelope, nil
}

func (p *Participant) AcceptRelinRoundTwoStage(envelopes []SignedEnvelope) error {
	if p.phase != PhaseRelinOne {
		return ErrState
	}
	input := sha256.Sum256(p.relinOneBytes)
	for _, envelope := range envelopes {
		if envelope.Header.InputDigest != input {
			return p.poison(ErrBinding)
		}
	}
	stage := TranscriptStage{Operation: OperationRelinShare, Round: 2, Envelopes: envelopes}
	transcript, err := p.withStage(stage)
	if err != nil {
		return p.poison(err)
	}
	roundOne, err := decodeRelinAggregate(p.params, p.relinOneBytes, 1)
	if err != nil {
		return p.poison(err)
	}
	roundTwo, err := aggregateRelinShare(p.params, stage, 2)
	if err != nil {
		return err
	}
	protocol := multiparty.NewRelinearizationKeyGenProtocol(p.params)
	key := rlwe.NewRelinearizationKey(p.params)
	protocol.GenRelinearizationKey(roundOne, roundTwo, key)
	p.relinKeyBytes, err = key.MarshalBinary()
	if err != nil {
		return p.poison(ErrMaterial)
	}
	p.relinEphemeral = nil
	p.setPending(transcript, PhaseRelinTwo, 0, sha256.Sum256(p.relinKeyBytes))
	return nil
}

func (p *Participant) GaloisShareEnvelope(index int) (SignedEnvelope, error) {
	if index < 0 || index >= len(p.context.GaloisElements) || p.secretKey == nil || p.poisoned {
		return SignedEnvelope{}, ErrState
	}
	if (index == 0 && p.phase != PhaseRelinTwo) || (index > 0 && (p.phase != PhaseGalois || p.step != uint32(index-1))) || p.wasGenerated(fmt.Sprintf("galois-%d", index)) {
		return SignedEnvelope{}, ErrState
	}
	p.markGenerated(fmt.Sprintf("galois-%d", index))
	element := p.context.GaloisElements[index]
	protocol := multiparty.NewGaloisKeyGenProtocol(p.params)
	crs, digest, err := p.stageCRS("galois", element)
	if err != nil {
		return SignedEnvelope{}, p.poison(err)
	}
	share := protocol.AllocateShare()
	if err := protocol.GenShare(p.secretKey, element, protocol.SampleCRP(crs), &share); err != nil {
		return SignedEnvelope{}, p.poison(ErrMaterial)
	}
	payload, err := share.MarshalBinary()
	if err != nil {
		return SignedEnvelope{}, p.poison(ErrMaterial)
	}
	envelope, err := NewSignedEnvelope(p.context, p.signingKey, p.Point(), 0, OperationGaloisShare, 1, element,
		p.transcript.Root(p.context), digest, payload)
	if err != nil {
		return SignedEnvelope{}, p.poison(err)
	}
	return envelope, nil
}

func (p *Participant) AcceptGaloisStage(index int, envelopes []SignedEnvelope) error {
	if index < 0 || index >= len(p.context.GaloisElements) || (index == 0 && p.phase != PhaseRelinTwo) ||
		(index > 0 && (p.phase != PhaseGalois || p.step != uint32(index-1))) {
		return ErrState
	}
	element := p.context.GaloisElements[index]
	stage := TranscriptStage{Operation: OperationGaloisShare, Round: 1, GaloisElement: element, Envelopes: envelopes}
	transcript, err := p.withStage(stage)
	if err != nil {
		return err
	}
	key, err := reconstructGaloisKey(p.params, p.context, p.crsSeed, stage)
	if err != nil {
		return p.poison(err)
	}
	encoded, err := key.MarshalBinary()
	if err != nil {
		return p.poison(ErrMaterial)
	}
	p.galoisKeyBytes = append(p.galoisKeyBytes, encoded)
	p.setPending(transcript, PhaseGalois, uint32(index), sha256.Sum256(encoded))
	return nil
}

func (p *Participant) PublicMaterial() (PublicMaterial, error) {
	if p.phase != PhaseGalois || p.step != uint32(len(p.context.GaloisElements)-1) || len(p.galoisKeyBytes) != len(p.context.GaloisElements) {
		return PublicMaterial{}, ErrState
	}
	return PublicMaterial{
		PublicKeyBytes:       slices.Clone(p.publicKeyBytes),
		RelinearizationBytes: slices.Clone(p.relinKeyBytes),
		GaloisKeyBytes:       cloneByteSlices(p.galoisKeyBytes),
	}, nil
}

func (p *Participant) thresholdShareBytes() ([]byte, error) {
	if !p.hasThreshold || p.phase.Terminal() {
		return nil, ErrSecretAccess
	}
	encoded, err := p.thresholdShare.MarshalBinary()
	if err != nil {
		return nil, ErrMaterial
	}
	return encoded, nil
}

func indexOfPoint(context Context, point uint64) int {
	for index, operator := range context.Operators {
		if operator.Point == point {
			return index
		}
	}
	return -1
}

func (p *Participant) Transcript() Transcript { return cloneTranscript(p.transcript) }

func (p *Participant) SetManifestPending(unsignedDigest [32]byte) error {
	if p.phase != PhaseGalois || p.step != uint32(len(p.context.GaloisElements)-1) || isZero32(unsignedDigest) {
		return ErrState
	}
	transcript := cloneTranscript(p.transcript)
	p.setPending(transcript, PhaseManifest, p.step, unsignedDigest)
	return nil
}

func (p *Participant) SetPublishedPending(bundleDigest [32]byte) error {
	if p.phase != PhaseManifest || isZero32(bundleDigest) {
		return ErrState
	}
	transcript := cloneTranscript(p.transcript)
	p.setPending(transcript, PhasePublished, p.step, bundleDigest)
	return nil
}

func (p *Participant) SetCompletedPending(bundleDigest [32]byte) error {
	if p.phase != PhasePublished || isZero32(bundleDigest) {
		return ErrState
	}
	transcript := cloneTranscript(p.transcript)
	p.setPending(transcript, PhaseCompleted, p.step, bundleDigest)
	return nil
}

func (p *Participant) stageTransition(stage TranscriptStage, phase Phase, step uint32, material [32]byte) error {
	transcript, err := p.withStage(stage)
	if err != nil {
		return err
	}
	p.setPending(transcript, phase, step, material)
	return nil
}

func (p *Participant) withStage(stage TranscriptStage) (Transcript, error) {
	transcript := cloneTranscript(p.transcript)
	if err := transcript.Append(p.context, stage); err != nil {
		return Transcript{}, p.poison(err)
	}
	return transcript, nil
}

func (p *Participant) setPending(transcript Transcript, phase Phase, step uint32, material [32]byte) {
	p.pendingTranscript = &transcript
	p.pendingPhase = phase
	p.pendingStep = step
	p.pendingMaterial = material
}

func (p *Participant) stageCRS(operation string, element uint64) (sampling.PRNG, [32]byte, error) {
	var e encoder
	e.text("MordantOneShotStageCRS/v1")
	e.fixed(p.crsSeed[:])
	e.text(operation)
	e.u64(element)
	seed := sha256.Sum256(e.Bytes())
	crs, err := sampling.NewKeyedPRNG(seed[:])
	if err != nil {
		return nil, [32]byte{}, ErrMaterial
	}
	return crs, sha256.Sum256(seed[:]), nil
}

func reconstructPublicKey(params bgv.Parameters, context Context, crsSeed [32]byte, stage TranscriptStage) (*rlwe.PublicKey, error) {
	protocol := multiparty.NewPublicKeyGenProtocol(params)
	crs, _, err := stageCRSFor(crsSeed, "public-key", 0)
	if err != nil {
		return nil, err
	}
	aggregate := protocol.AllocateShare()
	for _, envelope := range stage.Envelopes {
		share := protocol.AllocateShare()
		if err := share.UnmarshalBinary(envelope.Payload); err != nil {
			return nil, ErrMaterial
		}
		protocol.AggregateShares(aggregate, share, &aggregate)
	}
	key := rlwe.NewPublicKey(params)
	protocol.GenPublicKey(aggregate, protocol.SampleCRP(crs), key)
	return key, nil
}

func aggregateRelinShare(params bgv.Parameters, stage TranscriptStage, round int) (multiparty.RelinearizationKeyGenShare, error) {
	protocol := multiparty.NewRelinearizationKeyGenProtocol(params)
	_, one, two := protocol.AllocateShare()
	aggregate := one
	if round == 2 {
		aggregate = two
	}
	for _, envelope := range stage.Envelopes {
		_, shareOne, shareTwo := protocol.AllocateShare()
		share := shareOne
		if round == 2 {
			share = shareTwo
		}
		if err := share.UnmarshalBinary(envelope.Payload); err != nil {
			return aggregate, ErrMaterial
		}
		protocol.AggregateShares(aggregate, share, &aggregate)
	}
	return aggregate, nil
}

func decodeRelinAggregate(params bgv.Parameters, data []byte, round int) (multiparty.RelinearizationKeyGenShare, error) {
	protocol := multiparty.NewRelinearizationKeyGenProtocol(params)
	_, one, two := protocol.AllocateShare()
	share := one
	if round == 2 {
		share = two
	}
	if err := share.UnmarshalBinary(data); err != nil {
		return share, ErrMaterial
	}
	return share, nil
}

func reconstructGaloisKey(params bgv.Parameters, context Context, crsSeed [32]byte, stage TranscriptStage) (*rlwe.GaloisKey, error) {
	protocol := multiparty.NewGaloisKeyGenProtocol(params)
	crs, _, err := stageCRSFor(crsSeed, "galois", stage.GaloisElement)
	if err != nil {
		return nil, err
	}
	aggregate := protocol.AllocateShare()
	aggregate.GaloisElement = stage.GaloisElement
	for _, envelope := range stage.Envelopes {
		share := protocol.AllocateShare()
		if err := share.UnmarshalBinary(envelope.Payload); err != nil || share.GaloisElement != stage.GaloisElement {
			return nil, ErrMaterial
		}
		if err := protocol.AggregateShares(aggregate, share, &aggregate); err != nil {
			return nil, ErrMaterial
		}
	}
	key := rlwe.NewGaloisKey(params)
	if err := protocol.GenGaloisKey(aggregate, protocol.SampleCRP(crs), key); err != nil {
		return nil, ErrMaterial
	}
	return key, nil
}

func stageCRSFor(crsSeed [32]byte, operation string, element uint64) (sampling.PRNG, [32]byte, error) {
	var e encoder
	e.text("MordantOneShotStageCRS/v1")
	e.fixed(crsSeed[:])
	e.text(operation)
	e.u64(element)
	seed := sha256.Sum256(e.Bytes())
	crs, err := sampling.NewKeyedPRNG(seed[:])
	if err != nil {
		return nil, [32]byte{}, ErrMaterial
	}
	return crs, sha256.Sum256(seed[:]), nil
}

func crsContributionCommitment(context Context, point uint64, reveal [32]byte) [32]byte {
	ceremonyID := context.CeremonyID()
	var e encoder
	e.u64(point)
	return hashDomain("MordantOneShotCRSContribution/v1", ceremonyID[:], e.Bytes(), reveal[:])
}

func stageMaterialDigest(stage TranscriptStage) [32]byte {
	encoded, err := stage.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotStageMaterial/v1", encoded)
}

func bytes32(value []byte) [32]byte {
	var out [32]byte
	if len(value) == 32 {
		copy(out[:], value)
	}
	return out
}

func (p *Participant) wasGenerated(label string) bool {
	_, ok := p.generated[label]
	return ok
}

func (p *Participant) markGenerated(label string) { p.generated[label] = struct{}{} }

func (p *Participant) poison(err error) error {
	p.poisoned = true
	p.clearCryptographicSecrets()
	return err
}

func (p *Participant) clearCryptographicSecrets() {
	p.secretKey = nil
	p.shamirPolynomial = multiparty.ShamirPolynomial{}
	p.thresholdShare = multiparty.ShamirSecretShare{}
	p.hasThreshold = false
	p.relinEphemeral = nil
	p.crsReveal = [32]byte{}
	p.crsSeed = [32]byte{}
}

func (p *Participant) clearAttemptSecrets() {
	p.clearCryptographicSecrets()
	p.signingKey = nil
	p.encryptionKey = nil
}

func cloneByteSlices(input [][]byte) [][]byte {
	out := make([][]byte, len(input))
	for i := range input {
		out[i] = slices.Clone(input[i])
	}
	return out
}

func cloneTranscript(input Transcript) Transcript {
	out := Transcript{Stages: make([]TranscriptStage, len(input.Stages))}
	for i := range input.Stages {
		out.Stages[i] = cloneStage(input.Stages[i])
	}
	return out
}
