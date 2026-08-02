package oneshotceremony

import (
	"fmt"
	"slices"
)

type TranscriptStage struct {
	Operation       Operation
	Round           uint16
	GaloisElement   uint64
	Envelopes       []SignedEnvelope
	PrivateMessages []SealedPrivateMessage
}

type Transcript struct {
	Stages []TranscriptStage
}

func (t Transcript) Root(context Context) [32]byte {
	ceremonyID := context.CeremonyID()
	contextDigest := context.ContextDigest()
	rosterDigest := context.RosterDigest()
	root := hashDomain("MordantOneShotTranscriptInitial/v1", ceremonyID[:], contextDigest[:], rosterDigest[:])
	for _, stage := range t.Stages {
		encoded, err := stage.MarshalBinary()
		if err != nil {
			return [32]byte{}
		}
		root = hashDomain("MordantOneShotTranscriptStage/v1", root[:], encoded)
	}
	return root
}

func (t Transcript) PreviousRoot(context Context) [32]byte { return t.Root(context) }

func (t *Transcript) Append(context Context, stage TranscriptStage) error {
	if t == nil {
		return ErrState
	}
	if err := validateStage(context, *t, stage); err != nil {
		return err
	}
	t.Stages = append(t.Stages, cloneStage(stage))
	return nil
}

func (t Transcript) MarshalBinary() ([]byte, error) {
	var e encoder
	e.text("MordantOneShotTranscript/v1")
	e.u32(uint32(len(t.Stages)))
	for _, stage := range t.Stages {
		encoded, err := stage.MarshalBinary()
		if err != nil {
			return nil, err
		}
		e.field(encoded)
	}
	return e.Bytes(), nil
}

func ParseTranscript(context Context, data []byte) (Transcript, error) {
	var transcript Transcript
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != "MordantOneShotTranscript/v1" {
		return transcript, errCanonical
	}
	count, err := d.u32()
	maximum := uint32(6 + len(context.GaloisElements))
	if err != nil || count > maximum {
		return transcript, errCanonical
	}
	for i := uint32(0); i < count; i++ {
		encoded, readErr := d.field()
		if readErr != nil {
			return Transcript{}, readErr
		}
		stage, parseErr := parseTranscriptStage(encoded)
		if parseErr != nil || transcript.Append(context, stage) != nil {
			return Transcript{}, ErrBinding
		}
	}
	if err := d.done(); err != nil {
		return Transcript{}, err
	}
	reencoded, err := transcript.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return Transcript{}, errCanonical
	}
	return transcript, nil
}

func (s TranscriptStage) MarshalBinary() ([]byte, error) {
	if s.Operation == OperationInvalid {
		return nil, ErrBinding
	}
	var e encoder
	e.text("MordantOneShotTranscriptStage/v1")
	e.u16(uint16(s.Operation))
	e.u16(s.Round)
	e.u64(s.GaloisElement)
	e.u32(uint32(len(s.PrivateMessages)))
	for _, message := range s.PrivateMessages {
		encoded, err := message.MarshalBinary()
		if err != nil {
			return nil, err
		}
		e.field(encoded)
	}
	e.u32(uint32(len(s.Envelopes)))
	for _, envelope := range s.Envelopes {
		encoded, err := envelope.MarshalBinary()
		if err != nil {
			return nil, err
		}
		e.field(encoded)
	}
	return e.Bytes(), nil
}

func parseTranscriptStage(data []byte) (TranscriptStage, error) {
	var stage TranscriptStage
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != "MordantOneShotTranscriptStage/v1" {
		return stage, errCanonical
	}
	operation, err := d.u16()
	if err != nil {
		return stage, err
	}
	stage.Operation = Operation(operation)
	if stage.Round, err = d.u16(); err != nil {
		return stage, err
	}
	if stage.GaloisElement, err = d.u64(); err != nil {
		return stage, err
	}
	privateCount, err := d.u32()
	if err != nil || privateCount > PartyCount*PartyCount {
		return stage, errCanonical
	}
	stage.PrivateMessages = make([]SealedPrivateMessage, privateCount)
	for i := range stage.PrivateMessages {
		encoded, readErr := d.field()
		if readErr != nil {
			return TranscriptStage{}, readErr
		}
		if stage.PrivateMessages[i], readErr = ParseSealedPrivateMessage(encoded); readErr != nil {
			return TranscriptStage{}, readErr
		}
	}
	envelopeCount, err := d.u32()
	if err != nil || envelopeCount > PartyCount*PartyCount {
		return stage, errCanonical
	}
	stage.Envelopes = make([]SignedEnvelope, envelopeCount)
	for i := range stage.Envelopes {
		encoded, readErr := d.field()
		if readErr != nil {
			return TranscriptStage{}, readErr
		}
		if stage.Envelopes[i], readErr = ParseSignedEnvelope(encoded); readErr != nil {
			return TranscriptStage{}, readErr
		}
	}
	if err := d.done(); err != nil {
		return TranscriptStage{}, err
	}
	reencoded, err := stage.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return TranscriptStage{}, errCanonical
	}
	return stage, nil
}

func validateStage(context Context, transcript Transcript, stage TranscriptStage) error {
	expectedOperation, expectedRound, expectedGalois, err := expectedStage(context, len(transcript.Stages))
	if err != nil || stage.Operation != expectedOperation || stage.Round != expectedRound || stage.GaloisElement != expectedGalois {
		return ErrState
	}
	previous := transcript.Root(context)
	if isZero32(previous) {
		return ErrBinding
	}
	if stage.Operation == OperationPrivateShareReceipt {
		return validatePrivateStage(context, previous, stage)
	}
	if len(stage.PrivateMessages) != 0 || len(stage.Envelopes) != PartyCount {
		return ErrBinding
	}
	for index, envelope := range stage.Envelopes {
		if _, err := VerifySignedEnvelope(context, envelope); err != nil || envelope.Header.Operation != stage.Operation ||
			envelope.Header.Round != stage.Round || envelope.Header.GaloisElement != stage.GaloisElement ||
			envelope.Header.PreviousTranscriptDigest != previous || envelope.Header.SenderPoint != context.Operators[index].Point {
			return ErrBinding
		}
	}
	return nil
}

func expectedStage(context Context, index int) (Operation, uint16, uint64, error) {
	switch index {
	case 0:
		return OperationCRSCommit, 0, 0, nil
	case 1:
		return OperationCRSReveal, 0, 0, nil
	case 2:
		return OperationPrivateShareReceipt, 0, 0, nil
	case 3:
		return OperationPublicKeyShare, 0, 0, nil
	case 4:
		return OperationRelinShare, 1, 0, nil
	case 5:
		return OperationRelinShare, 2, 0, nil
	default:
		galoisIndex := index - 6
		if galoisIndex < 0 || galoisIndex >= len(context.GaloisElements) {
			return 0, 0, 0, ErrState
		}
		return OperationGaloisShare, 1, context.GaloisElements[galoisIndex], nil
	}
}

func validatePrivateStage(context Context, previous [32]byte, stage TranscriptStage) error {
	expected := PartyCount * PartyCount
	if len(stage.PrivateMessages) != expected || len(stage.Envelopes) != expected {
		return ErrBinding
	}
	for index := 0; index < expected; index++ {
		senderIndex, recipientIndex := index/PartyCount, index%PartyCount
		sender := context.Operators[senderIndex].Point
		recipient := context.Operators[recipientIndex].Point
		message := stage.PrivateMessages[index]
		if message.CeremonyID != context.CeremonyID() || message.ContextDigest != context.ContextDigest() ||
			message.SenderPoint != sender || message.RecipientPoint != recipient || isZero32(message.Digest()) {
			return ErrBinding
		}
		receipt := stage.Envelopes[index]
		if _, err := VerifySignedEnvelope(context, receipt); err != nil || receipt.Header.Operation != OperationPrivateShareReceipt ||
			receipt.Header.SenderPoint != recipient || receipt.Header.PreviousTranscriptDigest != previous {
			return ErrBinding
		}
		receiptSender, receiptRecipient, digest, err := parsePrivateReceipt(receipt.Payload)
		if err != nil || receiptSender != sender || receiptRecipient != recipient || digest != message.Digest() {
			return ErrBinding
		}
	}
	return nil
}

func privateReceiptPayload(sender, recipient uint64, digest [32]byte) []byte {
	var e encoder
	e.text("MordantOneShotPrivateReceipt/v1")
	e.u64(sender)
	e.u64(recipient)
	e.fixed(digest[:])
	return e.Bytes()
}

func parsePrivateReceipt(data []byte) (uint64, uint64, [32]byte, error) {
	var digest [32]byte
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != "MordantOneShotPrivateReceipt/v1" {
		return 0, 0, digest, errCanonical
	}
	sender, err := d.u64()
	if err != nil {
		return 0, 0, digest, err
	}
	recipient, err := d.u64()
	if err != nil {
		return 0, 0, digest, err
	}
	value, err := d.fixed(32)
	if err != nil || copy32(&digest, value) != nil || d.done() != nil {
		return 0, 0, digest, errCanonical
	}
	return sender, recipient, digest, nil
}

func cloneStage(stage TranscriptStage) TranscriptStage {
	out := TranscriptStage{Operation: stage.Operation, Round: stage.Round, GaloisElement: stage.GaloisElement}
	out.Envelopes = make([]SignedEnvelope, len(stage.Envelopes))
	for i, envelope := range stage.Envelopes {
		out.Envelopes[i] = envelope
		out.Envelopes[i].Payload = slices.Clone(envelope.Payload)
	}
	out.PrivateMessages = make([]SealedPrivateMessage, len(stage.PrivateMessages))
	for i, message := range stage.PrivateMessages {
		out.PrivateMessages[i] = message
		out.PrivateMessages[i].Ciphertext = slices.Clone(message.Ciphertext)
	}
	return out
}

func (t Transcript) Complete(context Context) bool {
	return len(t.Stages) == 6+len(context.GaloisElements) && !isZero32(t.Root(context))
}

func (t Transcript) Stage(index int) (TranscriptStage, error) {
	if index < 0 || index >= len(t.Stages) {
		return TranscriptStage{}, fmt.Errorf("%w: transcript stage", ErrState)
	}
	return cloneStage(t.Stages[index]), nil
}
