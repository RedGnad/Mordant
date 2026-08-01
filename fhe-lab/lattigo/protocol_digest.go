package lattigospike

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"golang.org/x/crypto/sha3"
)

const protocolBindingDomain = "mordant.lattigo.threshold-protocol-binding/v1"

// ProtocolKind identifies the cryptographic operation for which a one-shot
// response may be generated. Keeping this set closed prevents a caller from
// manufacturing a new kind to evade the one-shot ledger.
type ProtocolKind uint16

const (
	// ProtocolCollectiveKeySwitchToZero is the Lattigo collective secret-key
	// switch used to reveal the encrypted Boolean decision to the receiver.
	ProtocolCollectiveKeySwitchToZero ProtocolKind = 1
)

var ErrInvalidProtocolBinding = errors.New("invalid threshold protocol binding")

// ProtocolBindingDigest returns the global one-shot key for a threshold
// protocol response. Lattigo's collective key-switch share generation depends
// on ct.Value[1], not ct.Value[0], so the binding deliberately commits to the
// canonical c1 polynomial bytes rather than to the whole ciphertext.
//
// Session identifiers and coalition identifiers are deliberately absent. They
// are request metadata and must never create a fresh opportunity to generate a
// share for the same key epoch, protocol and public polynomial.
func ProtocolBindingDigest(keyID [32]byte, kind ProtocolKind, ct *rlwe.Ciphertext) ([32]byte, error) {
	var zero [32]byte
	if keyID == zero {
		return zero, fmt.Errorf("%w: empty key id", ErrInvalidProtocolBinding)
	}
	if kind != ProtocolCollectiveKeySwitchToZero {
		return zero, fmt.Errorf("%w: unsupported protocol kind %d", ErrInvalidProtocolBinding, kind)
	}
	if ct == nil || len(ct.Value) < 2 || ct.Value[1].N() == 0 || ct.Value[1].Level() < 0 {
		return zero, fmt.Errorf("%w: ciphertext has no c1 polynomial", ErrInvalidProtocolBinding)
	}

	c1, err := ct.Value[1].MarshalBinary()
	if err != nil {
		return zero, fmt.Errorf("%w: marshal c1: %v", ErrInvalidProtocolBinding, err)
	}

	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte(protocolBindingDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(keyID[:])

	var encodedKind [2]byte
	binary.BigEndian.PutUint16(encodedKind[:], uint16(kind))
	_, _ = hash.Write(encodedKind[:])

	var encodedLength [8]byte
	binary.BigEndian.PutUint64(encodedLength[:], uint64(len(c1)))
	_, _ = hash.Write(encodedLength[:])
	_, _ = hash.Write(c1)

	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}
