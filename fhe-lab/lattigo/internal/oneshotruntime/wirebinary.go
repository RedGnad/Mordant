package oneshotruntime

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"path/filepath"
	"slices"

	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

const replicaHeadWireSchema = "mordant.oneshot-runtime-replica-head/1"

func marshalReplicaHead(head ceremony.ReplicaHeadAttestation) ([]byte, error) {
	if head.SchemaVersion != "mordant.fhe-replica-head/oneshot-v3" || zero32(head.CeremonyID) || zero32(head.ContextDigest) ||
		head.OperatorPoint == 0 || (head.Sequence == 0 && !zero32(head.EventDigest)) || (head.Sequence > 0 && zero32(head.EventDigest)) {
		return nil, ErrProtocol
	}
	var encoder canonicalEncoder
	encoder.text(replicaHeadWireSchema)
	encoder.text(head.SchemaVersion)
	encoder.fixed(head.CeremonyID[:])
	encoder.fixed(head.ContextDigest[:])
	encoder.u64(head.OperatorPoint)
	encoder.u64(head.Sequence)
	encoder.fixed(head.EventDigest[:])
	encoder.fixed(head.Signature[:])
	return encoder.bytes(), nil
}

func parseReplicaHead(data []byte) (ceremony.ReplicaHeadAttestation, error) {
	var head ceremony.ReplicaHeadAttestation
	decoder := newCanonicalDecoder(data)
	magic, err := decoder.text(256)
	if err != nil || magic != replicaHeadWireSchema {
		return head, ErrProtocol
	}
	if head.SchemaVersion, err = decoder.text(256); err != nil || head.SchemaVersion != "mordant.fhe-replica-head/oneshot-v3" {
		return ceremony.ReplicaHeadAttestation{}, ErrProtocol
	}
	if decoder.copy32(&head.CeremonyID) != nil || decoder.copy32(&head.ContextDigest) != nil {
		return ceremony.ReplicaHeadAttestation{}, ErrProtocol
	}
	if head.OperatorPoint, err = decoder.u64(); err != nil {
		return ceremony.ReplicaHeadAttestation{}, ErrProtocol
	}
	if head.Sequence, err = decoder.u64(); err != nil {
		return ceremony.ReplicaHeadAttestation{}, ErrProtocol
	}
	if decoder.copy32(&head.EventDigest) != nil {
		return ceremony.ReplicaHeadAttestation{}, ErrProtocol
	}
	signature, err := decoder.fixed(ed25519.SignatureSize)
	if err != nil || decoder.done() != nil {
		return ceremony.ReplicaHeadAttestation{}, ErrProtocol
	}
	copy(head.Signature[:], signature)
	canonical, err := marshalReplicaHead(head)
	if err != nil || !bytes.Equal(canonical, data) {
		return ceremony.ReplicaHeadAttestation{}, ErrProtocol
	}
	return head, nil
}

func marshalHeads(heads []ceremony.ReplicaHeadAttestation) ([][]byte, error) {
	result := make([][]byte, len(heads))
	for index := range heads {
		encoded, err := marshalReplicaHead(heads[index])
		if err != nil {
			return nil, err
		}
		result[index] = encoded
	}
	return result, nil
}

func parseHeads(encoded [][]byte) ([]ceremony.ReplicaHeadAttestation, error) {
	if len(encoded) != ceremony.PartyCount {
		return nil, ErrProtocol
	}
	heads := make([]ceremony.ReplicaHeadAttestation, len(encoded))
	for index := range encoded {
		parsed, err := parseReplicaHead(encoded[index])
		if err != nil {
			return nil, err
		}
		heads[index] = parsed
	}
	return heads, nil
}

func parseWitnessStatementBytes(data []byte) (ceremony.WitnessStatement, error) {
	var statement ceremony.WitnessStatement
	decoder := newAcceptedDecoder(data)
	magic, err := decoder.text()
	if err != nil || magic != ceremony.WitnessSchema {
		return statement, ErrProtocol
	}
	if statement.SchemaVersion, err = decoder.text(); err != nil || statement.SchemaVersion != ceremony.WitnessSchema {
		return ceremony.WitnessStatement{}, ErrProtocol
	}
	for _, target := range []*[32]byte{&statement.CeremonyID, &statement.ContextDigest, &statement.RosterDigest} {
		if decoder.copy32(target) != nil {
			return ceremony.WitnessStatement{}, ErrProtocol
		}
	}
	if statement.Sequence, err = decoder.u64(); err != nil {
		return ceremony.WitnessStatement{}, ErrProtocol
	}
	if decoder.copy32(&statement.PreviousDigest) != nil {
		return ceremony.WitnessStatement{}, ErrProtocol
	}
	from, err := decoder.u16()
	if err != nil {
		return ceremony.WitnessStatement{}, ErrProtocol
	}
	to, err := decoder.u16()
	if err != nil {
		return ceremony.WitnessStatement{}, ErrProtocol
	}
	statement.FromPhase, statement.ToPhase = ceremony.Phase(from), ceremony.Phase(to)
	if statement.Step, err = decoder.u32(); err != nil {
		return ceremony.WitnessStatement{}, ErrProtocol
	}
	for _, target := range []*[32]byte{&statement.TranscriptDigest, &statement.MaterialDigest, &statement.ReasonDigest} {
		if decoder.copy32(target) != nil {
			return ceremony.WitnessStatement{}, ErrProtocol
		}
	}
	canonical, err := statement.MarshalBinary()
	if err != nil || decoder.done() != nil || !bytes.Equal(canonical, data) {
		return ceremony.WitnessStatement{}, ErrProtocol
	}
	return statement, nil
}

func marshalWitnessSignature(signature ceremony.WitnessSignature) ([]byte, error) {
	if signature.Point == 0 || bytes.Equal(signature.Signature[:], make([]byte, ed25519.SignatureSize)) {
		return nil, ErrProtocol
	}
	var encoder canonicalEncoder
	encoder.text("mordant.oneshot-runtime-witness-signature/1")
	encoder.u64(signature.Point)
	encoder.fixed(signature.Signature[:])
	return encoder.bytes(), nil
}

func parseWitnessSignature(data []byte) (ceremony.WitnessSignature, error) {
	var signature ceremony.WitnessSignature
	decoder := newCanonicalDecoder(data)
	magic, err := decoder.text(256)
	if err != nil || magic != "mordant.oneshot-runtime-witness-signature/1" {
		return signature, ErrProtocol
	}
	if signature.Point, err = decoder.u64(); err != nil {
		return ceremony.WitnessSignature{}, ErrProtocol
	}
	value, err := decoder.fixed(ed25519.SignatureSize)
	if err != nil || decoder.done() != nil {
		return ceremony.WitnessSignature{}, ErrProtocol
	}
	copy(signature.Signature[:], value)
	canonical, err := marshalWitnessSignature(signature)
	if err != nil || !bytes.Equal(canonical, data) {
		return ceremony.WitnessSignature{}, ErrProtocol
	}
	return signature, nil
}

func parsePublicationReceipt(data []byte) (ceremony.PublicationReceipt, error) {
	var receipt ceremony.PublicationReceipt
	decoder := newAcceptedDecoder(data)
	var err error
	if receipt.SchemaVersion, err = decoder.text(); err != nil || receipt.SchemaVersion != "mordant.fhe-publication-receipt/oneshot-v2" {
		return receipt, ErrProtocol
	}
	for _, target := range []*[32]byte{&receipt.CeremonyID, &receipt.BundleDigest, &receipt.CanonicalBytesSHA256} {
		if decoder.copy32(target) != nil {
			return ceremony.PublicationReceipt{}, ErrProtocol
		}
	}
	if receipt.ObjectPath, err = decoder.text(); err != nil || !filepath.IsAbs(receipt.ObjectPath) {
		return ceremony.PublicationReceipt{}, ErrProtocol
	}
	if receipt.ObjectSize, err = decoder.u64(); err != nil || decoder.done() != nil {
		return ceremony.PublicationReceipt{}, ErrProtocol
	}
	canonical, err := receipt.MarshalBinary()
	if err != nil || !slices.Equal(canonical, data) {
		return ceremony.PublicationReceipt{}, ErrProtocol
	}
	return receipt, nil
}

type acceptedDecoder struct{ reader *bytes.Reader }

func newAcceptedDecoder(data []byte) *acceptedDecoder {
	return &acceptedDecoder{reader: bytes.NewReader(data)}
}
func (d *acceptedDecoder) fixed(length int) ([]byte, error) {
	if length < 0 || length > d.reader.Len() {
		return nil, io.ErrUnexpectedEOF
	}
	value := make([]byte, length)
	_, err := io.ReadFull(d.reader, value)
	return value, err
}
func (d *acceptedDecoder) u16() (uint16, error) {
	value, err := d.fixed(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value), nil
}
func (d *acceptedDecoder) u32() (uint32, error) {
	value, err := d.fixed(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}
func (d *acceptedDecoder) u64() (uint64, error) {
	value, err := d.fixed(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(value), nil
}
func (d *acceptedDecoder) field() ([]byte, error) {
	length, err := d.u32()
	if err != nil || uint64(length) > uint64(d.reader.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	return d.fixed(int(length))
}
func (d *acceptedDecoder) text() (string, error) {
	value, err := d.field()
	return string(value), err
}
func (d *acceptedDecoder) copy32(target *[32]byte) error {
	value, err := d.fixed(32)
	if err != nil {
		return err
	}
	copy(target[:], value)
	return nil
}
func (d *acceptedDecoder) done() error {
	if d.reader.Len() != 0 {
		return ErrProtocol
	}
	return nil
}
