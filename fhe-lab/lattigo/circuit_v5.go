package lattigospike

import (
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"golang.org/x/crypto/sha3"
)

// CircuitV5Version identifies the recomputable circuit. An operator that does
// not implement this exact version refuses to participate in a release rather
// than recomputing something else and agreeing by coincidence.
const CircuitV5Version uint32 = 5

// CircuitInputsV5 is the complete input to the V5 policy circuit.
//
// It is deliberately a flat set of ciphertexts rather than a *CipherPledge:
// an operator recomputing the circuit must not need, and must not receive,
// the evaluator's admission state, enrollment registry or plaintext context.
// Everything here is public ciphertext that both parties already consented to
// have evaluated.
type CircuitInputsV5 struct {
	PolicyBitsA    *rlwe.Ciphertext
	PolicyBitsB    *rlwe.Ciphertext
	CurrencyBitsA  *rlwe.Ciphertext
	CurrencyBitsB  *rlwe.Ciphertext
	ReceivableIDsA *rlwe.Ciphertext
	ReceivableIDsB *rlwe.Ciphertext
}

// CircuitOutputsV5 carries the two independently released bits.
//
// External audit finding H-02: V4 released a single conjunction, so a false
// result could not distinguish "different receivable" from "same receivable,
// terms do not conflict". The two questions are now two ciphertexts.
//
//	SameEconomicAsset = identityEqual
//	PolicyConflict    = identityEqual AND currencyEqual AND overlap
//	                    AND exclusiveA AND exclusiveB
//
// PolicyConflict has SameEconomicAsset as a factor, which is what makes the
// (false, true) state structurally impossible rather than merely rejected.
type CircuitOutputsV5 struct {
	SameEconomicAsset *rlwe.Ciphertext
	PolicyConflict    *rlwe.Ciphertext
}

// Digest is the order-dependent commitment to both released ciphertexts.
// Operators compare this value, never a tolerant distance.
func (out *CircuitOutputsV5) Digest() ([32]byte, error) {
	var digest [32]byte
	if out == nil || out.SameEconomicAsset == nil || out.PolicyConflict == nil {
		return digest, ErrMalformedPledge
	}
	sameBytes, err := out.SameEconomicAsset.MarshalBinary()
	if err != nil {
		return digest, err
	}
	conflictBytes, err := out.PolicyConflict.MarshalBinary()
	if err != nil {
		return digest, err
	}
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte("mordant.circuit-v5-output/1"))
	_ = writeLengthPrefixed(hash, sameBytes)
	_ = writeLengthPrefixed(hash, conflictBytes)
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

// InputsDigest commits to the six input ciphertexts in fixed order. An operator
// recomputes it locally from the ciphertexts it received, so a coordinator
// cannot claim one input set and supply another.
func (in CircuitInputsV5) Digest() ([32]byte, error) {
	var digest [32]byte
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte("mordant.circuit-v5-input/1"))
	for _, ciphertext := range in.ordered() {
		if ciphertext == nil {
			return digest, ErrMalformedPledge
		}
		encoded, err := ciphertext.MarshalBinary()
		if err != nil {
			return digest, err
		}
		if err := writeLengthPrefixed(hash, encoded); err != nil {
			return digest, err
		}
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

// writeLengthPrefixed makes the digest injective over a sequence of
// variable-length encodings, so two different ciphertext sets can never hash to
// the same value by concatenation coincidence.
func writeLengthPrefixed(h hash.Hash, payload []byte) error {
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], uint64(len(payload)))
	if _, err := h.Write(header[:]); err != nil {
		return err
	}
	_, err := h.Write(payload)
	return err
}

func (in CircuitInputsV5) ordered() []*rlwe.Ciphertext {
	return []*rlwe.Ciphertext{
		in.PolicyBitsA, in.PolicyBitsB,
		in.CurrencyBitsA, in.CurrencyBitsB,
		in.ReceivableIDsA, in.ReceivableIDsB,
	}
}

func (in CircuitInputsV5) validate(n int) error {
	for index, ciphertext := range in.ordered() {
		if ciphertext == nil {
			return fmt.Errorf("circuit input %d: %w", index, ErrMalformedPledge)
		}
		if len(ciphertext.Value) != 2 || ciphertext.Value[0].N() != n {
			return fmt.Errorf("circuit input %d: %w", index, ErrMalformedPledge)
		}
	}
	return nil
}

// RecomputeCircuitV5 evaluates the policy circuit and nothing else.
//
// This is the function an operator runs locally on the ciphertexts it received
// before it will contribute a decryption share, and the same function the
// evaluator runs to produce the candidate outputs. External audit finding H-03:
// in V4 the operators decrypted whatever ciphertext the evaluator handed them,
// so a malicious evaluator could substitute an arbitrary ciphertext (including
// a re-encryption of a private input) and have the quorum decrypt it. Here the
// operator's decryption target is the ciphertext it computed itself.
//
// The function is pure with respect to the runtime: it reads only the public
// evaluation keys and touches no admission state, no nonce ledger and no
// enrollment registry. That is what makes it safe to run on an operator host,
// and what makes byte-identical output across hosts a meaningful check.
func (r *Runtime) RecomputeCircuitV5(inputs CircuitInputsV5) (*CircuitOutputsV5, error) {
	if r == nil {
		return nil, ErrMalformedPledge
	}
	if err := inputs.validate(r.Params.N()); err != nil {
		return nil, err
	}

	// Overlap of the two [activeFrom, activeUntil) windows.
	left, right, err := r.comparisonLayout(inputs.PolicyBitsA, inputs.PolicyBitsB)
	if err != nil {
		return nil, fmt.Errorf("comparison layout: %w", err)
	}
	less, _, err := r.compareTwoBlocks(left, right)
	if err != nil {
		return nil, fmt.Errorf("comparison batch: %w", err)
	}
	aFromBeforeBUntil, err := r.keepSlots(less, []int{0})
	if err != nil {
		return nil, err
	}
	bFromBeforeAUntil, err := r.Evaluator.RotateColumnsNew(less, 64)
	if err != nil {
		return nil, fmt.Errorf("extract second comparison: %w", err)
	}
	if bFromBeforeAUntil, err = r.keepSlots(bFromBeforeAUntil, []int{0}); err != nil {
		return nil, err
	}
	overlap, err := r.mulBoolean(aFromBeforeBUntil, bFromBeforeAUntil)
	if err != nil {
		return nil, fmt.Errorf("overlap AND: %w", err)
	}

	// Both sides claim exclusivity.
	flagsProduct, err := r.mulBoolean(inputs.PolicyBitsA, inputs.PolicyBitsB)
	if err != nil {
		return nil, fmt.Errorf("flag pair AND: %w", err)
	}
	if flagsProduct, err = r.keepSlots(flagsProduct, []int{exclusiveSlot}); err != nil {
		return nil, err
	}
	allFlags, err := r.Evaluator.RotateColumnsNew(flagsProduct, exclusiveSlot)
	if err != nil {
		return nil, fmt.Errorf("extract flags: %w", err)
	}
	if allFlags, err = r.keepSlots(allFlags, []int{0}); err != nil {
		return nil, err
	}

	currencyEqual, err := r.equal256(inputs.CurrencyBitsA, inputs.CurrencyBitsB)
	if err != nil {
		return nil, fmt.Errorf("currency equality: %w", err)
	}

	// Released bit 0. Always computed under full FHE identity: the strict
	// receivable identifier is never compared in the clear, and never through a
	// public commitment the way V4's Mode A gate did.
	identityEqual, err := r.equal256(inputs.ReceivableIDsA, inputs.ReceivableIDsB)
	if err != nil {
		return nil, fmt.Errorf("receivable identity equality: %w", err)
	}

	// Released bit 1.
	overlapAndFlags, err := r.mulBoolean(overlap, allFlags)
	if err != nil {
		return nil, fmt.Errorf("flag AND: %w", err)
	}
	currencyAndIdentity, err := r.mulBoolean(currencyEqual, identityEqual)
	if err != nil {
		return nil, fmt.Errorf("currency and identity AND: %w", err)
	}
	conflict, err := r.mulBoolean(overlapAndFlags, currencyAndIdentity)
	if err != nil {
		return nil, fmt.Errorf("policy final AND: %w", err)
	}

	return &CircuitOutputsV5{SameEconomicAsset: identityEqual, PolicyConflict: conflict}, nil
}
