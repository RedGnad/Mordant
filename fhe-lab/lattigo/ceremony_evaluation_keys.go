package lattigospike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Collective evaluation keys are public material. They let a holder evaluate
// the policy circuit homomorphically and nothing else: they carry no capability
// to decrypt, and the evaluator receives only this file plus the collective
// public key.

const evaluationKeyMagic = "MEK1"

// ErrEvaluationKeyMaterial marks malformed collective evaluation material.
var ErrEvaluationKeyMaterial = errors.New("invalid collective evaluation key material")

// MarshalEvaluationKeys serialises the collective relinearization and Galois
// keys with their circuit elements.
func MarshalEvaluationKeys(relinearizationKey *rlwe.RelinearizationKey, galoisKeys []*rlwe.GaloisKey, elements []uint64) ([]byte, error) {
	if relinearizationKey == nil || len(galoisKeys) == 0 || len(galoisKeys) != len(elements) {
		return nil, ErrEvaluationKeyMaterial
	}
	var out bytes.Buffer
	out.WriteString(evaluationKeyMagic)
	relinBytes, err := relinearizationKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	_ = binary.Write(&out, binary.BigEndian, uint32(len(relinBytes)))
	out.Write(relinBytes)
	_ = binary.Write(&out, binary.BigEndian, uint16(len(galoisKeys)))
	for index, key := range galoisKeys {
		encoded, err := key.MarshalBinary()
		if err != nil {
			return nil, err
		}
		_ = binary.Write(&out, binary.BigEndian, elements[index])
		_ = binary.Write(&out, binary.BigEndian, uint32(len(encoded)))
		out.Write(encoded)
	}
	return out.Bytes(), nil
}

// UnmarshalEvaluationKeys loads collective evaluation material. It is the only
// key-loading path the evaluator uses, and it can only produce public keys.
func UnmarshalEvaluationKeys(params bgv.Parameters, data []byte) (*rlwe.RelinearizationKey, []*rlwe.GaloisKey, []uint64, error) {
	reader := bytes.NewReader(data)
	magic := make([]byte, len(evaluationKeyMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != evaluationKeyMagic {
		return nil, nil, nil, ErrEvaluationKeyMaterial
	}
	var length uint32
	if binary.Read(reader, binary.BigEndian, &length) != nil || length == 0 || uint64(length) > uint64(reader.Len()) {
		return nil, nil, nil, ErrEvaluationKeyMaterial
	}
	relinBytes := make([]byte, length)
	if _, err := io.ReadFull(reader, relinBytes); err != nil {
		return nil, nil, nil, ErrEvaluationKeyMaterial
	}
	relinearizationKey := rlwe.NewRelinearizationKey(params)
	if err := relinearizationKey.UnmarshalBinary(relinBytes); err != nil {
		return nil, nil, nil, ErrEvaluationKeyMaterial
	}
	var count uint16
	if binary.Read(reader, binary.BigEndian, &count) != nil || count == 0 || int(count) > 64 {
		return nil, nil, nil, ErrEvaluationKeyMaterial
	}
	keys := make([]*rlwe.GaloisKey, count)
	elements := make([]uint64, count)
	for index := range keys {
		var element uint64
		var size uint32
		if binary.Read(reader, binary.BigEndian, &element) != nil ||
			binary.Read(reader, binary.BigEndian, &size) != nil ||
			size == 0 || uint64(size) > uint64(reader.Len()) {
			return nil, nil, nil, ErrEvaluationKeyMaterial
		}
		encoded := make([]byte, size)
		if _, err := io.ReadFull(reader, encoded); err != nil {
			return nil, nil, nil, ErrEvaluationKeyMaterial
		}
		key := rlwe.NewGaloisKey(params)
		if err := key.UnmarshalBinary(encoded); err != nil {
			return nil, nil, nil, ErrEvaluationKeyMaterial
		}
		keys[index], elements[index] = key, element
	}
	if reader.Len() != 0 {
		return nil, nil, nil, ErrEvaluationKeyMaterial
	}
	return relinearizationKey, keys, elements, nil
}

// EvaluationKeyDigestsFrom recomputes the manifest commitments from serialised
// evaluation material, so a verifier holding the file can confirm the operators
// signed exactly these keys.
func EvaluationKeyDigestsFrom(params bgv.Parameters, data []byte) ([32]byte, [32]byte, error) {
	var relinDigest, galoisDigest [32]byte
	relinearizationKey, galoisKeys, elements, err := UnmarshalEvaluationKeys(params, data)
	if err != nil {
		return relinDigest, galoisDigest, err
	}
	relinBytes, err := relinearizationKey.MarshalBinary()
	if err != nil {
		return relinDigest, galoisDigest, err
	}
	encoded := make([][]byte, len(galoisKeys))
	for index, key := range galoisKeys {
		if encoded[index], err = key.MarshalBinary(); err != nil {
			return relinDigest, galoisDigest, err
		}
	}
	return EvaluationKeyCommitments(relinBytes, encoded, elements)
}
