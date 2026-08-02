package oneshotceremony

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
)

type EnvelopeHeader struct {
	SchemaVersion            string
	SerializationVersion     uint32
	CeremonyID               [32]byte
	ContextDigest            [32]byte
	RosterDigest             [32]byte
	KeyScope                 string
	KeyEpoch                 uint64
	SenderPoint              uint64
	RecipientPoint           uint64
	Operation                Operation
	Round                    uint16
	GaloisElement            uint64
	PreviousTranscriptDigest [32]byte
	InputDigest              [32]byte
	PayloadDigest            [32]byte
}

type SignedEnvelope struct {
	Header    EnvelopeHeader
	Payload   []byte
	Signature [ed25519.SignatureSize]byte
}

func NewSignedEnvelope(context Context, key ed25519.PrivateKey, sender, recipient uint64, operation Operation, round uint16, galoisElement uint64, previous, input [32]byte, payload []byte) (SignedEnvelope, error) {
	identity, ok := context.Operator(sender)
	if !ok || len(key) != ed25519.PrivateKeySize || !slices.Equal(key.Public().(ed25519.PublicKey), identity.SigningPublicKey[:]) || len(payload) == 0 {
		return SignedEnvelope{}, ErrSignature
	}
	header := EnvelopeHeader{
		SchemaVersion:            EnvelopeSchema,
		SerializationVersion:     SerializationVersion,
		CeremonyID:               context.CeremonyID(),
		ContextDigest:            context.ContextDigest(),
		RosterDigest:             context.RosterDigest(),
		KeyScope:                 KeyScope,
		KeyEpoch:                 EphemeralKeyEpoch,
		SenderPoint:              sender,
		RecipientPoint:           recipient,
		Operation:                operation,
		Round:                    round,
		GaloisElement:            galoisElement,
		PreviousTranscriptDigest: previous,
		InputDigest:              input,
		PayloadDigest:            sha256.Sum256(payload),
	}
	if err := validateEnvelopeShape(context, header); err != nil {
		return SignedEnvelope{}, err
	}
	signingBytes := header.signingBytes()
	envelope := SignedEnvelope{Header: header, Payload: slices.Clone(payload)}
	copy(envelope.Signature[:], ed25519.Sign(key, signingBytes))
	return envelope, nil
}

func (h EnvelopeHeader) signingBytes() []byte {
	var e encoder
	e.text(SignatureDomain)
	e.text(h.SchemaVersion)
	e.u32(h.SerializationVersion)
	e.fixed(h.CeremonyID[:])
	e.fixed(h.ContextDigest[:])
	e.fixed(h.RosterDigest[:])
	e.text(h.KeyScope)
	e.u64(h.KeyEpoch)
	e.u64(h.SenderPoint)
	e.u64(h.RecipientPoint)
	e.u16(uint16(h.Operation))
	e.u16(h.Round)
	e.u64(h.GaloisElement)
	e.fixed(h.PreviousTranscriptDigest[:])
	e.fixed(h.InputDigest[:])
	e.fixed(h.PayloadDigest[:])
	return e.Bytes()
}

func (e SignedEnvelope) MarshalBinary() ([]byte, error) {
	if len(e.Payload) == 0 || sha256.Sum256(e.Payload) != e.Header.PayloadDigest {
		return nil, ErrMaterial
	}
	var out encoder
	out.text(EnvelopeSchema)
	out.field(e.Header.signingBytes())
	out.field(e.Payload)
	out.fixed(e.Signature[:])
	return out.Bytes(), nil
}

func ParseSignedEnvelope(data []byte) (SignedEnvelope, error) {
	var envelope SignedEnvelope
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != EnvelopeSchema {
		return envelope, errCanonical
	}
	headerBytes, err := d.field()
	if err != nil {
		return envelope, err
	}
	if envelope.Header, err = parseEnvelopeHeader(headerBytes); err != nil {
		return envelope, err
	}
	if envelope.Payload, err = d.field(); err != nil || len(envelope.Payload) == 0 {
		return envelope, errCanonical
	}
	signature, err := d.fixed(ed25519.SignatureSize)
	if err != nil {
		return envelope, err
	}
	copy(envelope.Signature[:], signature)
	if err := d.done(); err != nil {
		return envelope, err
	}
	if sha256.Sum256(envelope.Payload) != envelope.Header.PayloadDigest {
		return SignedEnvelope{}, ErrMaterial
	}
	reencoded, err := envelope.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return SignedEnvelope{}, errCanonical
	}
	return envelope, nil
}

func parseEnvelopeHeader(data []byte) (EnvelopeHeader, error) {
	var header EnvelopeHeader
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != SignatureDomain {
		return header, errCanonical
	}
	if header.SchemaVersion, err = d.text(); err != nil {
		return header, err
	}
	if header.SerializationVersion, err = d.u32(); err != nil {
		return header, err
	}
	for _, target := range []*[32]byte{&header.CeremonyID, &header.ContextDigest, &header.RosterDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return header, errCanonical
		}
	}
	if header.KeyScope, err = d.text(); err != nil {
		return header, err
	}
	if header.KeyEpoch, err = d.u64(); err != nil {
		return header, err
	}
	if header.SenderPoint, err = d.u64(); err != nil {
		return header, err
	}
	if header.RecipientPoint, err = d.u64(); err != nil {
		return header, err
	}
	operation, err := d.u16()
	if err != nil {
		return header, err
	}
	header.Operation = Operation(operation)
	if header.Round, err = d.u16(); err != nil {
		return header, err
	}
	if header.GaloisElement, err = d.u64(); err != nil {
		return header, err
	}
	for _, target := range []*[32]byte{&header.PreviousTranscriptDigest, &header.InputDigest, &header.PayloadDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return header, errCanonical
		}
	}
	if err := d.done(); err != nil {
		return header, err
	}
	return header, nil
}

func VerifySignedEnvelope(context Context, envelope SignedEnvelope) (uint64, error) {
	if err := validateEnvelopeShape(context, envelope.Header); err != nil || len(envelope.Payload) == 0 || sha256.Sum256(envelope.Payload) != envelope.Header.PayloadDigest {
		return 0, ErrBinding
	}
	signingBytes := envelope.Header.signingBytes()
	var signer uint64
	for _, operator := range context.Operators {
		if ed25519.Verify(operator.SigningPublicKey[:], signingBytes, envelope.Signature[:]) {
			if signer != 0 {
				return 0, ErrSignature
			}
			signer = operator.Point
		}
	}
	if signer == 0 || signer != envelope.Header.SenderPoint {
		return 0, ErrSignature
	}
	return signer, nil
}

func validateEnvelopeShape(context Context, header EnvelopeHeader) error {
	if header.SchemaVersion != EnvelopeSchema || header.SerializationVersion != SerializationVersion ||
		header.CeremonyID != context.CeremonyID() || header.ContextDigest != context.ContextDigest() ||
		header.RosterDigest != context.RosterDigest() || header.KeyScope != KeyScope ||
		header.KeyEpoch != EphemeralKeyEpoch || header.SenderPoint == 0 || header.Operation == OperationInvalid ||
		isZero32(header.PayloadDigest) {
		return ErrBinding
	}
	if _, ok := context.Operator(header.SenderPoint); !ok {
		return ErrBinding
	}
	if header.Operation == OperationPrivateShamirShare {
		if header.RecipientPoint == 0 {
			return ErrBinding
		}
		if _, ok := context.Operator(header.RecipientPoint); !ok {
			return ErrBinding
		}
	} else if header.RecipientPoint != 0 {
		return ErrBinding
	}
	if header.Operation == OperationRelinShare {
		if header.Round != 1 && header.Round != 2 {
			return ErrBinding
		}
	} else if header.Operation == OperationGaloisShare {
		if header.Round != 1 || header.GaloisElement == 0 || !slices.Contains(context.GaloisElements, header.GaloisElement) {
			return ErrBinding
		}
	} else if header.Round != 0 || header.GaloisElement != 0 {
		return ErrBinding
	}
	return nil
}

type SealedPrivateMessage struct {
	SchemaVersion      string
	CeremonyID         [32]byte
	ContextDigest      [32]byte
	SenderPoint        uint64
	RecipientPoint     uint64
	EphemeralPublicKey [32]byte
	Nonce              [12]byte
	Ciphertext         []byte
}

func SealPrivateEnvelope(context Context, envelope SignedEnvelope, random io.Reader) (SealedPrivateMessage, error) {
	if random == nil {
		random = rand.Reader
	}
	if _, err := VerifySignedEnvelope(context, envelope); err != nil || envelope.Header.Operation != OperationPrivateShamirShare {
		return SealedPrivateMessage{}, ErrBinding
	}
	recipient, ok := context.Operator(envelope.Header.RecipientPoint)
	if !ok {
		return SealedPrivateMessage{}, ErrBinding
	}
	curve := ecdh.X25519()
	ephemeral, err := curve.GenerateKey(random)
	if err != nil {
		return SealedPrivateMessage{}, fmt.Errorf("%w: private transport key", ErrMaterial)
	}
	recipientKey, err := curve.NewPublicKey(recipient.EncryptionPublicKey[:])
	if err != nil {
		return SealedPrivateMessage{}, ErrBinding
	}
	shared, err := ephemeral.ECDH(recipientKey)
	if err != nil {
		return SealedPrivateMessage{}, ErrMaterial
	}
	message := SealedPrivateMessage{
		SchemaVersion:  "mordant.fhe-private-wire/oneshot-v1",
		CeremonyID:     context.CeremonyID(),
		ContextDigest:  context.ContextDigest(),
		SenderPoint:    envelope.Header.SenderPoint,
		RecipientPoint: envelope.Header.RecipientPoint,
	}
	copy(message.EphemeralPublicKey[:], ephemeral.PublicKey().Bytes())
	if _, err := io.ReadFull(random, message.Nonce[:]); err != nil {
		return SealedPrivateMessage{}, ErrMaterial
	}
	plaintext, err := envelope.MarshalBinary()
	if err != nil {
		return SealedPrivateMessage{}, err
	}
	aead, err := privateWireAEAD(shared, message)
	if err != nil {
		return SealedPrivateMessage{}, err
	}
	message.Ciphertext = aead.Seal(nil, message.Nonce[:], plaintext, message.additionalData())
	return message, nil
}

func OpenPrivateEnvelope(context Context, message SealedPrivateMessage, recipientPrivate *ecdh.PrivateKey) (SignedEnvelope, error) {
	if message.SchemaVersion != "mordant.fhe-private-wire/oneshot-v1" || message.CeremonyID != context.CeremonyID() ||
		message.ContextDigest != context.ContextDigest() || len(message.Ciphertext) == 0 || recipientPrivate == nil {
		return SignedEnvelope{}, ErrBinding
	}
	recipient, ok := context.Operator(message.RecipientPoint)
	if !ok || !slices.Equal(recipientPrivate.PublicKey().Bytes(), recipient.EncryptionPublicKey[:]) {
		return SignedEnvelope{}, ErrSecretAccess
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(message.EphemeralPublicKey[:])
	if err != nil {
		return SignedEnvelope{}, ErrBinding
	}
	shared, err := recipientPrivate.ECDH(ephemeral)
	if err != nil {
		return SignedEnvelope{}, ErrSecretAccess
	}
	aead, err := privateWireAEAD(shared, message)
	if err != nil {
		return SignedEnvelope{}, err
	}
	plaintext, err := aead.Open(nil, message.Nonce[:], message.Ciphertext, message.additionalData())
	if err != nil {
		return SignedEnvelope{}, ErrSecretAccess
	}
	envelope, err := ParseSignedEnvelope(plaintext)
	if err != nil {
		return SignedEnvelope{}, ErrMaterial
	}
	if _, err := VerifySignedEnvelope(context, envelope); err != nil || envelope.Header.SenderPoint != message.SenderPoint ||
		envelope.Header.RecipientPoint != message.RecipientPoint || envelope.Header.Operation != OperationPrivateShamirShare {
		return SignedEnvelope{}, ErrBinding
	}
	return envelope, nil
}

func (m SealedPrivateMessage) additionalData() []byte {
	var e encoder
	e.text(m.SchemaVersion)
	e.fixed(m.CeremonyID[:])
	e.fixed(m.ContextDigest[:])
	e.u64(m.SenderPoint)
	e.u64(m.RecipientPoint)
	e.fixed(m.EphemeralPublicKey[:])
	return e.Bytes()
}

func (m SealedPrivateMessage) MarshalBinary() ([]byte, error) {
	if m.SchemaVersion != "mordant.fhe-private-wire/oneshot-v1" || isZero32(m.CeremonyID) || isZero32(m.ContextDigest) ||
		m.SenderPoint == 0 || m.RecipientPoint == 0 || isZero32(m.EphemeralPublicKey) || len(m.Ciphertext) == 0 {
		return nil, ErrBinding
	}
	var e encoder
	e.text(m.SchemaVersion)
	e.fixed(m.CeremonyID[:])
	e.fixed(m.ContextDigest[:])
	e.u64(m.SenderPoint)
	e.u64(m.RecipientPoint)
	e.fixed(m.EphemeralPublicKey[:])
	e.fixed(m.Nonce[:])
	e.field(m.Ciphertext)
	return e.Bytes(), nil
}

func ParseSealedPrivateMessage(data []byte) (SealedPrivateMessage, error) {
	var message SealedPrivateMessage
	d := newDecoder(data)
	var err error
	if message.SchemaVersion, err = d.text(); err != nil || message.SchemaVersion != "mordant.fhe-private-wire/oneshot-v1" {
		return message, errCanonical
	}
	for _, target := range []*[32]byte{&message.CeremonyID, &message.ContextDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return message, errCanonical
		}
	}
	if message.SenderPoint, err = d.u64(); err != nil {
		return message, err
	}
	if message.RecipientPoint, err = d.u64(); err != nil {
		return message, err
	}
	value, err := d.fixed(32)
	if err != nil || copy32(&message.EphemeralPublicKey, value) != nil {
		return message, errCanonical
	}
	value, err = d.fixed(12)
	if err != nil {
		return message, err
	}
	copy(message.Nonce[:], value)
	if message.Ciphertext, err = d.field(); err != nil || len(message.Ciphertext) == 0 || d.done() != nil {
		return SealedPrivateMessage{}, errCanonical
	}
	reencoded, err := message.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return SealedPrivateMessage{}, errCanonical
	}
	return message, nil
}

func (m SealedPrivateMessage) Digest() [32]byte {
	encoded, err := m.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotPrivateWireDigest/v1", encoded)
}

func privateWireAEAD(shared []byte, message SealedPrivateMessage) (cipher.AEAD, error) {
	key := hashDomain("MordantOneShotPrivateWireKey/v1", shared, message.CeremonyID[:], message.ContextDigest[:], message.EphemeralPublicKey[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, ErrMaterial
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrMaterial
	}
	return aead, nil
}
