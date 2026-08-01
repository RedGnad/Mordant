package lattigospike

import (
	"bytes"
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"golang.org/x/crypto/sha3"
)

const (
	fromStart      = 0
	untilStart     = 64
	exclusiveSlot  = 128
	uint64Bits     = 64
	obligationBits = 256
	policyDepth    = 11
)

func (r *Runtime) EncryptPledge(input PlainPledge) (*CipherPledge, EncryptionMetrics, error) {
	return r.EncryptPledgeForMode(input, IdentityPublicCommitment)
}

func (r *Runtime) EncryptPledgeForMode(input PlainPledge, mode IdentityMode) (*CipherPledge, EncryptionMetrics, error) {
	pledge, metrics, err := r.clientEncryptionEngine().encryptPledgeForMode(input, mode)
	if err != nil {
		return nil, metrics, err
	}
	issuedDigest, err := cipherPledgeDigestBytes(pledge)
	if err != nil {
		return nil, metrics, err
	}
	// This registry remains available only for the co-located lab path. An
	// external client cannot write it; external evaluation requires an issuer-
	// signed enrollment that binds the exact ciphertext digest instead.
	r.issuedMu.Lock()
	r.issuedCiphertexts[issuedDigest] = struct{}{}
	r.issuedMu.Unlock()
	return pledge, metrics, nil
}

type clientEncryptionEngine struct {
	params               bgv.Parameters
	encoder              *bgv.Encoder
	encryptor            *rlwe.Encryptor
	keyID                string
	keyIDBytes           [32]byte
	parameterFingerprint [32]byte
	publicKeyBytes       []byte
}

func (r *Runtime) clientEncryptionEngine() clientEncryptionEngine {
	return clientEncryptionEngine{
		params:               r.Params,
		encoder:              r.Encoder,
		encryptor:            r.Encryptor,
		keyID:                r.keyID,
		keyIDBytes:           r.keyIDBytes,
		parameterFingerprint: r.parameterFingerprint,
	}
}

func (e clientEncryptionEngine) encryptPledgeForMode(input PlainPledge, mode IdentityMode) (*CipherPledge, EncryptionMetrics, error) {
	metrics := EncryptionMetrics{}
	if err := validatePlainPledge(input, mode); err != nil {
		return nil, metrics, err
	}
	if mode != IdentityPublicCommitment && mode != IdentityFullFHE256 {
		return nil, metrics, ErrInvalidPlaintext
	}

	policy := make([]uint64, e.params.MaxSlots())
	writeUint64Bits(policy, fromStart, input.ActiveFrom)
	writeUint64Bits(policy, untilStart, input.ActiveUntil)
	policy[exclusiveSlot] = boolToUint64(input.Exclusive)
	currency := make([]uint64, e.params.MaxSlots())
	writeBytesBits(currency, 0, input.Currency[:])

	amount := make([]uint64, e.params.MaxSlots())
	writeUint256Bits(amount, 0, input.Amount)

	obligation := make([]uint64, e.params.MaxSlots())
	writeBytesBits(obligation, 0, input.ObligationID[:])
	receivableID := make([]uint64, e.params.MaxSlots())
	writeBytesBits(receivableID, 0, input.ReceivableID[:])

	started := time.Now()
	phase := time.Now()
	policyCT, err := e.encryptVector(policy)
	if err != nil {
		return nil, metrics, err
	}
	metrics.PolicyBits = time.Since(phase)
	phase = time.Now()
	currencyCT, err := e.encryptVector(currency)
	if err != nil {
		return nil, metrics, err
	}
	metrics.CurrencyBits = time.Since(phase)

	phase = time.Now()
	amountCT, err := e.encryptVector(amount)
	if err != nil {
		return nil, metrics, err
	}
	metrics.AmountBits = time.Since(phase)

	phase = time.Now()
	obligationCT, err := e.encryptVector(obligation)
	if err != nil {
		return nil, metrics, err
	}
	metrics.ObligationBits = time.Since(phase)

	var receivableIDCT *rlwe.Ciphertext
	if mode == IdentityFullFHE256 {
		phase = time.Now()
		if receivableIDCT, err = e.encryptVector(receivableID); err != nil {
			return nil, metrics, err
		}
		metrics.ReceivableIdentityBits = time.Since(phase)
		metrics.IdentityCiphertextBytes = receivableIDCT.BinarySize()
	}
	metrics.Total = time.Since(started)

	pledge := &CipherPledge{
		KeyID:                     e.keyID,
		ParameterFingerprint:      e.parameterFingerprint,
		ReceivableCommitment:      input.ReceivableCommitment,
		AuthorizationCommitment:   input.AuthorizationCommitment,
		PrivateMetadataCommitment: input.PrivateMetadataCommitment,
		PolicyBits:                policyCT,
		CurrencyBits:              currencyCT,
		AmountBits:                amountCT,
		ObligationIDBits:          obligationCT,
		ReceivableIDBits:          receivableIDCT,
	}
	phase = time.Now()
	serialized, err := pledge.MarshalBinary()
	if err != nil {
		return nil, metrics, err
	}
	metrics.Marshal = time.Since(phase)
	metrics.CiphertextBytes = len(serialized)

	phase = time.Now()
	roundTripped, err := UnmarshalCipherPledge(serialized)
	if err != nil {
		return nil, metrics, err
	}
	metrics.Unmarshal = time.Since(phase)
	digest, err := CipherPledgeDigest(roundTripped)
	if err != nil {
		return nil, metrics, err
	}
	metrics.Digest = digest
	return roundTripped, metrics, nil
}

func validatePlainPledge(p PlainPledge, mode IdentityMode) error {
	zero := [32]byte{}
	if p.ActiveFrom >= p.ActiveUntil || p.Amount == (Uint256{}) || p.Currency == zero || p.ObligationID == zero || p.ReceivableID == zero || p.AuthorizationCommitment == zero || p.PrivateMetadataCommitment == zero {
		return ErrInvalidPlaintext
	}
	if mode == IdentityPublicCommitment && p.ReceivableCommitment == zero {
		return ErrInvalidPlaintext
	}
	if mode == IdentityFullFHE256 && p.ReceivableCommitment != zero {
		return ErrInvalidPlaintext
	}
	return nil
}

func (e clientEncryptionEngine) encryptVector(values []uint64) (*rlwe.Ciphertext, error) {
	plaintext := bgv.NewPlaintext(e.params, e.params.MaxLevel())
	if err := e.encoder.Encode(values, plaintext); err != nil {
		return nil, fmt.Errorf("encode encrypted input: %w", err)
	}
	ciphertext, err := e.encryptor.EncryptNew(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt input: %w", err)
	}
	return ciphertext, nil
}

func writeUint64Bits(dst []uint64, start int, value uint64) {
	for i := 0; i < uint64Bits; i++ {
		dst[start+i] = (value >> (uint64Bits - 1 - i)) & 1
	}
}

func writeBytesBits(dst []uint64, start int, value []byte) {
	for i, b := range value {
		for bit := 0; bit < 8; bit++ {
			dst[start+i*8+bit] = uint64((b >> (7 - bit)) & 1)
		}
	}
}

func writeUint256Bits(dst []uint64, start int, value Uint256) {
	for limb, word := range value {
		writeUint64Bits(dst, start+limb*uint64Bits, word)
	}
}

func (r *Runtime) Evaluate(request EvaluationRequest, now time.Time) (*EncryptedDecision, EvaluationMetrics, error) {
	metrics := EvaluationMetrics{
		MultiplicativeDepth:      policyDepth,
		StrictComparisonsInBatch: 2,
	}
	enrollmentIDs, err := r.validateRequest(request, now)
	if err != nil {
		return nil, metrics, err
	}
	if err := r.reserveRequest(request.Nonce, enrollmentIDs); err != nil {
		return nil, metrics, err
	}
	started := time.Now()

	phase := time.Now()
	left, right, err := r.comparisonLayout(request.A.PolicyBits, request.B.PolicyBits)
	if err != nil {
		return nil, metrics, err
	}
	metrics.Layout = time.Since(phase)

	phase = time.Now()
	less, _, err := r.compareTwoBlocks(left, right)
	if err != nil {
		return nil, metrics, err
	}
	metrics.ComparisonBatch = time.Since(phase)
	metrics.ComparisonAAmortized = metrics.ComparisonBatch / 2
	metrics.ComparisonBAmortized = metrics.ComparisonBatch / 2
	phase = time.Now()
	currencyEqual, err := r.equal256(request.A.CurrencyBits, request.B.CurrencyBits)
	if err != nil {
		return nil, metrics, fmt.Errorf("currency equality: %w", err)
	}
	metrics.CurrencyEquality = time.Since(phase)

	phase = time.Now()
	aFromBeforeBUntil, err := r.keepSlots(less, []int{0})
	if err != nil {
		return nil, metrics, err
	}
	bFromBeforeAUntil, err := r.Evaluator.RotateColumnsNew(less, 64)
	if err != nil {
		return nil, metrics, fmt.Errorf("extract second comparison: %w", err)
	}
	if bFromBeforeAUntil, err = r.keepSlots(bFromBeforeAUntil, []int{0}); err != nil {
		return nil, metrics, err
	}
	overlap, err := r.mulBoolean(aFromBeforeBUntil, bFromBeforeAUntil)
	if err != nil {
		return nil, metrics, fmt.Errorf("overlap AND: %w", err)
	}
	flagsProduct, err := r.mulBoolean(request.A.PolicyBits, request.B.PolicyBits)
	if err != nil {
		return nil, metrics, fmt.Errorf("flag pair AND: %w", err)
	}
	if flagsProduct, err = r.keepSlots(flagsProduct, []int{exclusiveSlot}); err != nil {
		return nil, metrics, err
	}
	allFlags := flagsProduct
	if allFlags, err = r.Evaluator.RotateColumnsNew(allFlags, exclusiveSlot); err != nil {
		return nil, metrics, fmt.Errorf("extract flags: %w", err)
	}
	if allFlags, err = r.keepSlots(allFlags, []int{0}); err != nil {
		return nil, metrics, err
	}
	metrics.Conditions = time.Since(phase)

	var encryptedIdentityEqual *rlwe.Ciphertext
	if request.IdentityMode == IdentityFullFHE256 {
		phase = time.Now()
		encryptedIdentityEqual, err = r.equal256(request.A.ReceivableIDBits, request.B.ReceivableIDBits)
		if err != nil {
			return nil, metrics, fmt.Errorf("receivable identity equality: %w", err)
		}
		metrics.IdentityEquality = time.Since(phase)
	}

	phase = time.Now()
	overlapAndFlags, err := r.mulBoolean(overlap, allFlags)
	if err != nil {
		return nil, metrics, fmt.Errorf("flag AND: %w", err)
	}
	var conflict *rlwe.Ciphertext
	if request.IdentityMode == IdentityFullFHE256 {
		currencyAndIdentity, err := r.mulBoolean(currencyEqual, encryptedIdentityEqual)
		if err != nil {
			return nil, metrics, fmt.Errorf("currency and identity AND: %w", err)
		}
		conflict, err = r.mulBoolean(overlapAndFlags, currencyAndIdentity)
		if err != nil {
			return nil, metrics, fmt.Errorf("policy final AND: %w", err)
		}
	} else {
		conflict, err = r.mulBoolean(overlapAndFlags, currencyEqual)
		if err != nil {
			return nil, metrics, fmt.Errorf("policy final AND: %w", err)
		}
		if !bytes.Equal(request.A.ReceivableCommitment[:], request.B.ReceivableCommitment[:]) {
			conflict, err = r.Evaluator.MulNew(conflict, uint64(0))
			if err != nil {
				return nil, metrics, fmt.Errorf("receivable commitment gate: %w", err)
			}
		}
	}
	metrics.FinalAND = time.Since(phase)
	metrics.Total = time.Since(started)

	resultCommitment, err := ciphertextCommitment(conflict)
	if err != nil {
		return nil, metrics, err
	}
	return &EncryptedDecision{Conflict: conflict, Nonce: request.Nonce, ResultCiphertextCommitment: resultCommitment}, metrics, nil
}

func ciphertextCommitment(ciphertext *rlwe.Ciphertext) ([32]byte, error) {
	var commitment [32]byte
	if ciphertext == nil {
		return commitment, ErrMalformedPledge
	}
	data, err := ciphertext.MarshalBinary()
	if err != nil {
		return commitment, err
	}
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(data)
	copy(commitment[:], hash.Sum(nil))
	return commitment, nil
}

func (r *Runtime) validateRequest(request EvaluationRequest, now time.Time) ([][32]byte, error) {
	if request.KeyID != r.keyID {
		return nil, ErrWrongKeyID
	}
	if request.PolicyVersion != PolicyVersion {
		return nil, ErrWrongPolicy
	}
	if now.After(request.ValidUntil) {
		return nil, ErrExpired
	}
	if request.Nonce == ([32]byte{}) {
		return nil, ErrReplay
	}
	if err := validateCipherPledge(request.A); err != nil {
		return nil, err
	}
	if err := validateCipherPledge(request.B); err != nil {
		return nil, err
	}
	if request.A.KeyID != r.keyID || request.B.KeyID != r.keyID || request.A.ParameterFingerprint != r.parameterFingerprint || request.B.ParameterFingerprint != r.parameterFingerprint {
		return nil, ErrWrongKeyID
	}
	if request.IdentityMode != IdentityPublicCommitment && request.IdentityMode != IdentityFullFHE256 {
		return nil, ErrWrongPolicy
	}
	if request.IdentityMode == IdentityFullFHE256 && (request.A.ReceivableIDBits == nil || request.B.ReceivableIDBits == nil) {
		return nil, fmt.Errorf("%w: missing encrypted receivable identity", ErrMalformedPledge)
	}
	zero := [32]byte{}
	if request.IdentityMode == IdentityPublicCommitment && (request.A.ReceivableCommitment == zero || request.B.ReceivableCommitment == zero) {
		return nil, fmt.Errorf("%w: missing public receivable commitment", ErrMalformedPledge)
	}
	if request.IdentityMode == IdentityFullFHE256 && (request.A.ReceivableCommitment != zero || request.B.ReceivableCommitment != zero) {
		return nil, fmt.Errorf("%w: full-FHE identity leaks public linkage", ErrMalformedPledge)
	}

	enrollmentIDs, err := r.externalEnrollmentIDs(request, now)
	if err != nil {
		return nil, err
	}
	if len(enrollmentIDs) == 0 {
		// Explicit compatibility path for the co-located benchmark/workflow. It
		// remains fail-closed: both a local grant and local ciphertext issuance
		// are required. External callers cannot populate either registry.
		r.authorizationMu.RLock()
		grantA, authorizedA := r.authorizedIngress[request.A.AuthorizationCommitment]
		grantB, authorizedB := r.authorizedIngress[request.B.AuthorizationCommitment]
		r.authorizationMu.RUnlock()
		if !authorizedA || !authorizedB ||
			grantA.keyID != r.keyID || grantB.keyID != r.keyID ||
			grantA.policyVersion != request.PolicyVersion || grantB.policyVersion != request.PolicyVersion ||
			now.After(grantA.validUntil) || now.After(grantB.validUntil) {
			return nil, ErrUnauthorizedIngress
		}
		for _, pledge := range []*CipherPledge{request.A, request.B} {
			digest, err := cipherPledgeDigestBytes(pledge)
			if err != nil {
				return nil, ErrMalformedPledge
			}
			r.issuedMu.RLock()
			_, issued := r.issuedCiphertexts[digest]
			r.issuedMu.RUnlock()
			if !issued {
				return nil, ErrCiphertextNotIssued
			}
		}
	}
	cts := []*rlwe.Ciphertext{
		request.A.PolicyBits, request.B.PolicyBits,
		request.A.CurrencyBits, request.B.CurrencyBits,
		request.A.AmountBits, request.B.AmountBits,
		request.A.ObligationIDBits, request.B.ObligationIDBits,
	}
	if request.IdentityMode == IdentityFullFHE256 {
		cts = append(cts, request.A.ReceivableIDBits, request.B.ReceivableIDBits)
	}
	for _, ct := range cts {
		if ct.Level() < policyDepth || ct.Level() > r.Params.MaxLevel() || len(ct.Value) != 2 || ct.Value[0].N() != r.Params.N() || ct.Value[1].N() != r.Params.N() {
			return nil, fmt.Errorf("%w: insufficient ciphertext level", ErrMalformedPledge)
		}
	}
	return enrollmentIDs, nil
}

func (r *Runtime) comparisonLayout(a, b *rlwe.Ciphertext) (*rlwe.Ciphertext, *rlwe.Ciphertext, error) {
	aFrom, err := r.keepRange(a, fromStart, uint64Bits)
	if err != nil {
		return nil, nil, err
	}
	bFrom, err := r.keepRange(b, fromStart, uint64Bits)
	if err != nil {
		return nil, nil, err
	}
	bFrom, err = r.Evaluator.RotateColumnsNew(bFrom, -64)
	if err != nil {
		return nil, nil, fmt.Errorf("place second left operand: %w", err)
	}
	left, err := r.Evaluator.AddNew(aFrom, bFrom)
	if err != nil {
		return nil, nil, fmt.Errorf("assemble left operand: %w", err)
	}

	bUntil, err := r.keepRange(b, untilStart, uint64Bits)
	if err != nil {
		return nil, nil, err
	}
	bUntil, err = r.Evaluator.RotateColumnsNew(bUntil, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("place first right operand: %w", err)
	}
	aUntil, err := r.keepRange(a, untilStart, uint64Bits)
	if err != nil {
		return nil, nil, err
	}
	right, err := r.Evaluator.AddNew(bUntil, aUntil)
	if err != nil {
		return nil, nil, fmt.Errorf("assemble right operand: %w", err)
	}
	return left, right, nil
}

// compareTwoBlocks evaluates two independent strict 64-bit comparisons in
// parallel. Slots 0 and 64 hold the results. Bits are MSB-first.
func (r *Runtime) compareTwoBlocks(left, right *rlwe.Ciphertext) (*rlwe.Ciphertext, *rlwe.Ciphertext, error) {
	product, err := r.mulBoolean(left, right)
	if err != nil {
		return nil, nil, fmt.Errorf("comparison bit products: %w", err)
	}
	less, err := r.Evaluator.SubNew(right, product)
	if err != nil {
		return nil, nil, fmt.Errorf("comparison less bits: %w", err)
	}
	equalBase, err := r.Evaluator.AddNew(left, right)
	if err != nil {
		return nil, nil, fmt.Errorf("comparison equality bits: %w", err)
	}
	if equalBase, err = r.Evaluator.SubNew(equalBase, uint64(1)); err != nil {
		return nil, nil, fmt.Errorf("comparison equality bits: %w", err)
	}
	equal, err := r.mulBoolean(equalBase, equalBase)
	if err != nil {
		return nil, nil, fmt.Errorf("comparison equality bits: %w", err)
	}
	if less, err = r.keepRange(less, 0, 2*uint64Bits); err != nil {
		return nil, nil, err
	}
	if equal, err = r.keepRange(equal, 0, 2*uint64Bits); err != nil {
		return nil, nil, err
	}

	for stride := 1; stride < uint64Bits; stride *= 2 {
		lowerLess, err := r.Evaluator.RotateColumnsNew(less, stride)
		if err != nil {
			return nil, nil, fmt.Errorf("rotate less stride %d: %w", stride, err)
		}
		lowerEqual, err := r.Evaluator.RotateColumnsNew(equal, stride)
		if err != nil {
			return nil, nil, fmt.Errorf("rotate equality stride %d: %w", stride, err)
		}
		continuedLess, err := r.mulBoolean(equal, lowerLess)
		if err != nil {
			return nil, nil, fmt.Errorf("combine less stride %d: %w", stride, err)
		}
		if less, err = r.Evaluator.AddNew(less, continuedLess); err != nil {
			return nil, nil, fmt.Errorf("merge less stride %d: %w", stride, err)
		}
		if equal, err = r.mulBoolean(equal, lowerEqual); err != nil {
			return nil, nil, fmt.Errorf("combine equality stride %d: %w", stride, err)
		}
		starts := blockStarts(2, stride*2)
		if less, err = r.keepSlots(less, starts); err != nil {
			return nil, nil, err
		}
		if equal, err = r.keepSlots(equal, starts); err != nil {
			return nil, nil, err
		}
	}
	return less, equal, nil
}

// equal256 evaluates exact equality for a 256-bit identifier. The input bits
// are packed MSB-first in slots 0..255 and reduced as a balanced AND tree.
func (r *Runtime) equal256(left, right *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	equalBase, err := r.Evaluator.AddNew(left, right)
	if err != nil {
		return nil, err
	}
	if equalBase, err = r.Evaluator.SubNew(equalBase, uint64(1)); err != nil {
		return nil, err
	}
	equal, err := r.mulBoolean(equalBase, equalBase)
	if err != nil {
		return nil, err
	}
	if equal, err = r.keepRange(equal, 0, obligationBits); err != nil {
		return nil, err
	}
	for stride := 1; stride < obligationBits; stride *= 2 {
		lower, err := r.Evaluator.RotateColumnsNew(equal, stride)
		if err != nil {
			return nil, err
		}
		if equal, err = r.mulBoolean(equal, lower); err != nil {
			return nil, err
		}
		starts := make([]int, 0, obligationBits/(2*stride))
		for slot := 0; slot < obligationBits; slot += 2 * stride {
			starts = append(starts, slot)
		}
		if equal, err = r.keepSlots(equal, starts); err != nil {
			return nil, err
		}
	}
	return r.keepSlots(equal, []int{0})
}

func blockStarts(blocks, groupWidth int) []int {
	starts := make([]int, 0, blocks*uint64Bits/groupWidth)
	for block := 0; block < blocks; block++ {
		base := block * uint64Bits
		for offset := 0; offset < uint64Bits; offset += groupWidth {
			starts = append(starts, base+offset)
		}
	}
	return starts
}

func (r *Runtime) mulBoolean(left, right *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	out, err := r.Evaluator.MulRelinNew(left, right)
	if err != nil {
		return nil, err
	}
	if err := r.Evaluator.Rescale(out, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Runtime) oneMinus(value *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	return r.Evaluator.SubNew(r.one, value)
}

func (r *Runtime) keepRange(ciphertext *rlwe.Ciphertext, start, width int) (*rlwe.Ciphertext, error) {
	slots := make([]int, width)
	for i := range slots {
		slots[i] = start + i
	}
	return r.keepSlots(ciphertext, slots)
}

func (r *Runtime) keepSlots(ciphertext *rlwe.Ciphertext, slots []int) (*rlwe.Ciphertext, error) {
	mask := make([]uint64, r.Params.MaxSlots())
	for _, slot := range slots {
		if slot < 0 || slot >= len(mask) {
			return nil, fmt.Errorf("mask slot out of range")
		}
		mask[slot] = 1
	}
	out, err := r.Evaluator.MulNew(ciphertext, mask)
	if err != nil {
		return nil, fmt.Errorf("apply slot mask: %w", err)
	}
	return out, nil
}
