package lattigospike

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"golang.org/x/crypto/sha3"
)

// External audit finding H-03. In V4 an operator's only check on the ciphertext
// it was asked to decrypt was that the ciphertext matched a digest written into
// the release descriptor BY THE EVALUATOR. The operator therefore decrypted
// whatever the evaluator chose, including a re-encryption of a private input.
// The quorum was a signing service, not a check.
//
// In V5 the operator recomputes the circuit itself, from the input ciphertexts
// the enrollments authorize, and releases only the ciphertext it produced. The
// evaluator's proposed output is never decrypted; it is only compared.

var (
	// ErrOperatorRecomputationMismatch reports that the operator's own
	// recomputed output does not equal the one the coordinator proposed. It is
	// terminal for the session and is never retried.
	ErrOperatorRecomputationMismatch = errors.New("operator recomputation does not match the proposed output")
	// ErrOperatorCheckFailed reports a failed pre-release check.
	ErrOperatorCheckFailed = errors.New("operator release check failed")
)

// OperatorReleaseRequestV5 is everything a coordinator may send an operator.
//
// Note what is absent: no plaintext, no result, no claim about what the circuit
// evaluated to, and no digest the operator is expected to take on trust. Every
// load-bearing value in the descriptor is recomputed locally below.
type OperatorReleaseRequestV5 struct {
	Descriptor  ReleaseDescriptorV5
	EnrollmentA *SignedCiphertextEnrollmentV5
	EnrollmentB *SignedCiphertextEnrollmentV5
	Inputs      CircuitInputsV5
	Coalition   [2]uint64
}

// OperatorCheckV5 is one named pre-release check and its outcome. The list is
// emitted into the evidence so a reviewer can see which checks actually ran
// rather than trusting that they did.
type OperatorCheckV5 struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// OperatorVerdictV5 is the operator's local decision.
type OperatorVerdictV5 struct {
	Accepted                bool              `json:"accepted"`
	Checks                  []OperatorCheckV5 `json:"checks"`
	RecomputedInputsDigest  [32]byte          `json:"-"`
	RecomputedOutputsDigest [32]byte          `json:"-"`
	RecomputeDuration       time.Duration     `json:"-"`
	outputs                 *CircuitOutputsV5
}

// ReleaseOperatorV5 is one operator process: a sealed threshold share, the
// PUBLIC evaluation keys needed to recompute the circuit, its own issuer trust
// store, and its own durable one-shot ledger.
//
// Holding the evaluation keys is what makes recomputation possible and is the
// reason an operator's memory and latency cost rise materially against V4. That
// cost is the point: it is what removes the evaluator's ability to choose the
// decryption target.
type ReleaseOperatorV5 struct {
	runtime   *Runtime
	threshold *ThresholdOperator
	ledger    *SessionLedger
}

// NewReleaseOperatorV5 binds a sealed threshold operator to an evaluation
// runtime that holds no threshold party of its own.
func NewReleaseOperatorV5(runtime *Runtime, threshold *ThresholdOperator, ledger *SessionLedger) (*ReleaseOperatorV5, error) {
	if runtime == nil || threshold == nil || ledger == nil {
		return nil, ErrInvalidThresholdOperator
	}
	// An operator that also holds co-located threshold parties inside its
	// evaluation runtime would be able to decrypt alone.
	if runtime.HoldsThresholdParties() {
		return nil, ErrInvalidThresholdOperator
	}
	return &ReleaseOperatorV5{runtime: runtime, threshold: threshold, ledger: ledger}, nil
}

// VerifyAndRecompute runs every pre-release check locally.
//
// The governing rule is that no load-bearing digest supplied by the coordinator
// is trusted without local recomputation. Where a value appears in the
// descriptor, it is recomputed here and compared; it is never read and used.
func (operator *ReleaseOperatorV5) VerifyAndRecompute(request OperatorReleaseRequestV5, now time.Time) (OperatorVerdictV5, error) {
	verdict := OperatorVerdictV5{Checks: make([]OperatorCheckV5, 0, 13)}
	record := func(name string, passed bool, detail string) bool {
		verdict.Checks = append(verdict.Checks, OperatorCheckV5{Name: name, Passed: passed, Detail: detail})
		return passed
	}
	fail := func(name, detail string) (OperatorVerdictV5, error) {
		record(name, false, detail)
		return verdict, fmt.Errorf("%w: %s: %s", ErrOperatorCheckFailed, name, detail)
	}
	descriptor := request.Descriptor

	// 1. The descriptor is structurally complete and internally consistent.
	if err := descriptor.validate(); err != nil {
		return fail("descriptor-shape", err.Error())
	}
	record("descriptor-shape", true, "")

	// 2. The circuit version is the one this operator actually implements.
	// Agreeing on an output while running a different circuit is not agreement.
	if descriptor.CircuitVersion != CircuitV5Version {
		return fail("circuit-version", fmt.Sprintf("descriptor %d, operator %d", descriptor.CircuitVersion, CircuitV5Version))
	}
	record("circuit-version", true, "")

	// 3. The key epoch is this operator's sealed key epoch.
	if descriptor.KeyID != operator.threshold.keyID {
		return fail("key-epoch", "descriptor key id is not this operator's sealed key id")
	}
	record("key-epoch", true, "")

	// 4. The FHE parameters are this operator's parameters.
	if descriptor.ParameterFingerprint != operator.threshold.fingerprint {
		return fail("parameter-fingerprint", "descriptor parameters differ from the sealed parameters")
	}
	record("parameter-fingerprint", true, "")

	// 5. The descriptor has not expired.
	if now.Unix() < 0 || uint64(now.Unix()) > descriptor.ExpiresAt {
		return fail("descriptor-freshness", "release descriptor expired")
	}
	record("descriptor-freshness", true, "")

	// 6. Both issuer signatures verify against THIS operator's trust store,
	// not against a list the coordinator supplied.
	digestA, err := operator.runtime.VerifyEnrollmentV5(request.EnrollmentA, now)
	if err != nil {
		return fail("enrollment-a-signature", err.Error())
	}
	digestB, err := operator.runtime.VerifyEnrollmentV5(request.EnrollmentB, now)
	if err != nil {
		return fail("enrollment-b-signature", err.Error())
	}
	record("enrollment-signatures", true, "")

	// 7. The two enrollments cross-certify as one bilateral session. Recomputed
	// here; the coordinator's assertion that they pair is not consulted.
	paired, err := PairEnrollmentsV5(request.EnrollmentA, request.EnrollmentB)
	if err != nil {
		return fail("bilateral-pairing", err.Error())
	}
	record("bilateral-pairing", true, "")

	// 8. The descriptor names exactly that session and exactly those two
	// enrollments. This is the join between the on-chain commitment and the
	// cryptographic authorization.
	if descriptor.SessionCommitment != paired.SessionCommitment ||
		descriptor.SessionNullifier != paired.SessionNullifier ||
		descriptor.EnrollmentDigestA != digestA || descriptor.EnrollmentDigestB != digestB ||
		digestA != paired.EnrollmentDigestA || digestB != paired.EnrollmentDigestB {
		return fail("descriptor-session-binding", "descriptor does not name the paired session and enrollments")
	}
	record("descriptor-session-binding", true, "")

	// 9. Each received input ciphertext hashes to the digest its own enrollment
	// bound. This is what stops a substituted input.
	boundA, err := CircuitSideDigestV5(request.Inputs.PolicyBitsA, request.Inputs.CurrencyBitsA, request.Inputs.ReceivableIDsA)
	if err != nil {
		return fail("input-digests", err.Error())
	}
	boundB, err := CircuitSideDigestV5(request.Inputs.PolicyBitsB, request.Inputs.CurrencyBitsB, request.Inputs.ReceivableIDsB)
	if err != nil {
		return fail("input-digests", err.Error())
	}
	if boundA != request.EnrollmentA.Enrollment.CiphertextDigest ||
		boundB != request.EnrollmentB.Enrollment.CiphertextDigest {
		return fail("input-digests", "received ciphertexts are not the ones the enrollments authorize")
	}
	if boundA == boundB {
		return fail("input-digests", "both sides submitted the same ciphertext set")
	}
	record("input-digests", true, "")

	// 10. The inputs digest in the descriptor is recomputed, never read.
	inputsDigest, err := request.Inputs.Digest()
	if err != nil {
		return fail("inputs-digest", err.Error())
	}
	if inputsDigest != descriptor.InputsDigest {
		return fail("inputs-digest", "descriptor inputs digest does not match the received ciphertexts")
	}
	verdict.RecomputedInputsDigest = inputsDigest
	record("inputs-digest", true, "")

	// 11. This operator is in the coalition it is being asked to serve.
	if !coalitionContains(request.Coalition, uint64(operator.threshold.point)) {
		return fail("coalition-membership", "operator is not in the requested coalition")
	}
	record("coalition-membership", true, "")

	// 12. This operator has not already served this session. Durable, so a
	// restarted operator does not serve it a second time.
	if existing, err := operator.ledger.Get(descriptor.SessionCommitment); err == nil {
		if existing.State != SessionReserved {
			return fail("operator-one-shot", fmt.Sprintf("session already in state %d", existing.State))
		}
	} else if !errors.Is(err, ErrSessionUnknown) {
		return fail("operator-one-shot", err.Error())
	}
	record("operator-one-shot", true, "")

	// 13. THE check. Recompute the circuit locally and require the coordinator's
	// proposed output to equal it byte for byte. No tolerance: a tolerant
	// comparison here would restore exactly the substitution this prevents.
	started := time.Now()
	outputs, err := operator.runtime.RecomputeCircuitV5(request.Inputs)
	if err != nil {
		return fail("local-recomputation", err.Error())
	}
	verdict.RecomputeDuration = time.Since(started)
	outputsDigest, err := outputs.Digest()
	if err != nil {
		return fail("local-recomputation", err.Error())
	}
	verdict.RecomputedOutputsDigest = outputsDigest
	if outputsDigest != descriptor.OutputsDigest {
		record("local-recomputation", false, "recomputed output differs from the proposed output")
		return verdict, ErrOperatorRecomputationMismatch
	}
	record("local-recomputation", true, "")

	verdict.outputs = outputs
	verdict.Accepted = true
	return verdict, nil
}

// ReleaseShares generates this operator's two key-switch shares, one per
// released bit, against the ciphertexts THIS OPERATOR recomputed.
//
// The ciphertexts the coordinator sent are never passed to the threshold
// protocol. They were only ever compared.
func (operator *ReleaseOperatorV5) ReleaseShares(
	request OperatorReleaseRequestV5,
	verdict OperatorVerdictV5,
	now time.Time,
) (sameAsset ThresholdReleaseResponse, policyConflict ThresholdReleaseResponse, err error) {
	if !verdict.Accepted || verdict.outputs == nil {
		return sameAsset, policyConflict, ErrOperatorCheckFailed
	}
	descriptor := request.Descriptor

	// One share per released bit, each bound to the same session.
	sameAsset, err = operator.shareFor(descriptor, verdict.outputs.SameEconomicAsset, request.Coalition, 0)
	if err != nil {
		return sameAsset, policyConflict, err
	}
	policyConflict, err = operator.shareFor(descriptor, verdict.outputs.PolicyConflict, request.Coalition, 1)
	if err != nil {
		return sameAsset, policyConflict, err
	}
	return sameAsset, policyConflict, nil
}

func (operator *ReleaseOperatorV5) shareFor(
	descriptor ReleaseDescriptorV5,
	ciphertext *rlwe.Ciphertext,
	coalition [2]uint64,
	slot uint8,
) (ThresholdReleaseResponse, error) {
	commitment, err := ciphertextCommitment(ciphertext)
	if err != nil {
		return ThresholdReleaseResponse{}, err
	}
	binding, err := ProtocolBindingDigest(operator.threshold.keyID, ProtocolCollectiveKeySwitchToZero, ciphertext)
	if err != nil {
		return ThresholdReleaseResponse{}, err
	}
	// The V4 descriptor is reused as the threshold-layer wire format, but every
	// field in it is now derived from the operator's own recomputation.
	legacy := ReleaseDescriptor{
		SessionID:                  releaseSlotSessionID(descriptor.SessionCommitment, slot),
		KeyID:                      descriptor.KeyID,
		ParameterFingerprint:       descriptor.ParameterFingerprint,
		PolicyID:                   descriptor.PolicyID,
		PolicyVersion:              descriptor.PolicyVersion,
		InputCommitmentA:           descriptor.EnrollmentDigestA,
		InputCommitmentB:           descriptor.EnrollmentDigestB,
		ResultNonce:                Uint256{0, 0, 0, uint64(slot) + 1},
		ValidUntil:                 descriptor.ExpiresAt,
		ResultCiphertextCommitment: commitment,
		ProtocolBinding:            binding,
		Coalition:                  coalition,
	}
	return operator.threshold.GenerateReleaseShare(legacy, ciphertext)
}

// releaseSlotSessionID gives each released bit its own threshold session id, so
// a share generated for one bit can never be replayed as a share for the other.
func releaseSlotSessionID(sessionCommitment [32]byte, slot uint8) [32]byte {
	encoded := make([]byte, 0, 96)
	domain := legacyKeccak([]byte("mordant.release-slot/1"))
	encoded = append(encoded, domain[:]...)
	encoded = append(encoded, sessionCommitment[:]...)
	encoded = append(encoded, uint8Word(slot)...)
	return legacyKeccak(encoded)
}

// CircuitSideDigestV5 commits to exactly the three ciphertexts one side
// contributes to the circuit, in fixed order and length-prefixed.
//
// It deliberately covers the circuit inputs and nothing else. The V4 pledge
// digest also covered amount and obligation ciphertexts that the circuit never
// reads, so it could not answer the question an operator actually needs
// answered: are these the inputs this enrollment authorized me to evaluate?
func CircuitSideDigestV5(policy, currency, receivable *rlwe.Ciphertext) ([32]byte, error) {
	var digest [32]byte
	if policy == nil || currency == nil || receivable == nil {
		return digest, ErrMalformedPledge
	}
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte("mordant.circuit-v5-side/1"))
	for _, ciphertext := range []*rlwe.Ciphertext{policy, currency, receivable} {
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

/* ------------------------------------------------------------- transcript */

// ReleaseTranscriptV5 is the auditable record of one release. Every field is
// bound into its digest, so the transcript cannot be edited after the fact to
// describe a different release than the one that happened.
type ReleaseTranscriptV5 struct {
	SessionCommitment    [32]byte
	SessionNullifier     [32]byte
	EnrollmentDigestA    [32]byte
	EnrollmentDigestB    [32]byte
	InputsDigest         [32]byte
	OutputsDigest        [32]byte
	CircuitVersion       uint32
	KeyID                [32]byte
	ParameterFingerprint [32]byte
	PolicyID             [32]byte
	PolicyVersion        uint32
	// The operators that actually served, their threshold, and each one's
	// signed statement over its own recomputation.
	Coalition          [2]uint64
	Threshold          uint16
	OperatorStatements [][32]byte
	SameEconomicAsset  bool
	PolicyConflict     bool
	ReleasedAt         uint64
}

func (transcript ReleaseTranscriptV5) validate() error {
	zero := [32]byte{}
	if transcript.SessionCommitment == zero || transcript.SessionNullifier == zero ||
		transcript.EnrollmentDigestA == zero || transcript.EnrollmentDigestB == zero ||
		transcript.EnrollmentDigestA == transcript.EnrollmentDigestB ||
		transcript.InputsDigest == zero || transcript.OutputsDigest == zero ||
		transcript.CircuitVersion != CircuitV5Version || transcript.KeyID == zero ||
		transcript.ParameterFingerprint == zero || transcript.PolicyID == zero ||
		transcript.PolicyVersion != PolicyVersion || transcript.Threshold < 2 ||
		len(transcript.OperatorStatements) < int(transcript.Threshold) ||
		transcript.Coalition[0] == 0 || transcript.Coalition[1] == 0 ||
		transcript.Coalition[0] == transcript.Coalition[1] || transcript.ReleasedAt == 0 {
		return ErrMalformedEnrollment
	}
	// The state (false, true) is structurally impossible: the policy conjunction
	// has identity equality as a factor.
	if transcript.PolicyConflict && !transcript.SameEconomicAsset {
		return fmt.Errorf("%w: policy conflict without asset match", ErrMalformedEnrollment)
	}
	return nil
}

// Digest is the transcript commitment carried in the on-chain result.
func (transcript ReleaseTranscriptV5) Digest() ([32]byte, error) {
	if err := transcript.validate(); err != nil {
		return [32]byte{}, err
	}
	encoded := make([]byte, 0, 32*20)
	domain := legacyKeccak([]byte("mordant.release-transcript/v5"))
	encoded = append(encoded, domain[:]...)
	encoded = append(encoded, transcript.SessionCommitment[:]...)
	encoded = append(encoded, transcript.SessionNullifier[:]...)
	encoded = append(encoded, transcript.EnrollmentDigestA[:]...)
	encoded = append(encoded, transcript.EnrollmentDigestB[:]...)
	encoded = append(encoded, transcript.InputsDigest[:]...)
	encoded = append(encoded, transcript.OutputsDigest[:]...)
	encoded = append(encoded, uint32Word(transcript.CircuitVersion)...)
	encoded = append(encoded, transcript.KeyID[:]...)
	encoded = append(encoded, transcript.ParameterFingerprint[:]...)
	encoded = append(encoded, transcript.PolicyID[:]...)
	encoded = append(encoded, uint32Word(transcript.PolicyVersion)...)
	encoded = append(encoded, uint64Word(transcript.Coalition[0])...)
	encoded = append(encoded, uint64Word(transcript.Coalition[1])...)
	encoded = append(encoded, uint16Word(transcript.Threshold)...)
	for _, statement := range transcript.OperatorStatements {
		encoded = append(encoded, statement[:]...)
	}
	encoded = append(encoded, boolWord(transcript.SameEconomicAsset)...)
	encoded = append(encoded, boolWord(transcript.PolicyConflict)...)
	encoded = append(encoded, uint64Word(transcript.ReleasedAt)...)
	return legacyKeccak(encoded), nil
}

/* ---------------------------------------------------------------- combine */

// ErrReleaseSlotsNotCanonical reports a released plaintext that carries data in
// slots the circuit is supposed to have zeroed.
var ErrReleaseSlotsNotCanonical = errors.New("released plaintext is not canonical")

// CombineReleaseBitV5 aggregates a quorum's shares for ONE released bit and
// asserts the complete decrypted slot vector.
//
// The V4 combiner read slot 0, range-checked it, and ignored the other 32767
// slots. Gate 2 requires the released plaintext to be canonical: exactly one
// meaningful slot, every other slot zero by construction. A ciphertext carrying
// anything in the remaining slots is not the circuit's output, so it fails
// closed rather than being read for its first slot.
func CombineReleaseBitV5(
	params bgv.Parameters,
	descriptor ReleaseDescriptor,
	manifest ThresholdManifest,
	ciphertext *rlwe.Ciphertext,
	responses []ThresholdReleaseResponse,
) (bool, [32]byte, error) {
	var zeroDigest [32]byte
	if err := validateReleaseDescriptor(descriptor); err != nil || len(responses) != int(manifest.Threshold) || manifest.Threshold != 2 {
		return false, zeroDigest, ErrInsufficientShare
	}
	if descriptor.KeyID != manifest.KeyID || descriptor.ParameterFingerprint != manifest.ParameterFingerprint {
		return false, zeroDigest, ErrWrongKeyID
	}
	commitment, err := ciphertextCommitment(ciphertext)
	if err != nil || commitment != descriptor.ResultCiphertextCommitment {
		return false, zeroDigest, ErrMalformedPledge
	}
	binding, err := ProtocolBindingDigest(manifest.KeyID, ProtocolCollectiveKeySwitchToZero, ciphertext)
	if err != nil || binding != descriptor.ProtocolBinding {
		return false, zeroDigest, ErrInvalidProtocolBinding
	}
	publicByID := make(map[[32]byte]ThresholdOperatorPublic, len(manifest.Operators))
	for _, operator := range manifest.Operators {
		publicByID[operator.OperatorID] = operator
	}
	protocol, err := multiparty.NewKeySwitchProtocol(
		params,
		ring.DiscreteGaussian{Sigma: 1 << 30, Bound: 6 * (1 << 30)},
	)
	if err != nil {
		return false, zeroDigest, err
	}
	combined := protocol.AllocateShare(ciphertext.Level())
	seenPoints := make(map[uint64]struct{}, len(responses))
	statementDigests := make([][32]byte, 0, len(responses))
	for _, response := range responses {
		operator, exists := publicByID[response.OperatorID]
		if !exists || operator.Point != response.Point || !coalitionContains(descriptor.Coalition, response.Point) {
			return false, zeroDigest, ErrInvalidReleaseShare
		}
		if _, duplicate := seenPoints[response.Point]; duplicate {
			return false, zeroDigest, ErrInvalidReleaseShare
		}
		seenPoints[response.Point] = struct{}{}
		if response.SessionID != descriptor.SessionID || response.ProtocolBinding != descriptor.ProtocolBinding ||
			response.ShareDigest != legacyKeccak(response.Share) {
			return false, zeroDigest, ErrInvalidReleaseShare
		}
		expectedStatement := thresholdResponseStatementDigest(descriptor, response)
		if subtle.ConstantTimeCompare(expectedStatement[:], response.StatementDigest[:]) != 1 ||
			!ed25519.Verify(operator.SigningPublicKey[:], expectedStatement[:], response.Signature[:]) {
			return false, zeroDigest, ErrInvalidSignature
		}
		share := protocol.AllocateShare(ciphertext.Level())
		if len(response.Share) == 0 || len(response.Share) > maxReleaseShareSize || share.UnmarshalBinary(response.Share) != nil || share.Level() != ciphertext.Level() {
			return false, zeroDigest, ErrInvalidReleaseShare
		}
		if err := protocol.AggregateShares(share, combined, &combined); err != nil {
			return false, zeroDigest, ErrInvalidReleaseShare
		}
		statementDigests = append(statementDigests, expectedStatement)
	}
	if len(seenPoints) != int(manifest.Threshold) {
		return false, zeroDigest, ErrInsufficientShare
	}
	switched := bgv.NewCiphertext(params, 1, ciphertext.Level())
	protocol.KeySwitch(ciphertext, combined, switched)
	zeroKey := rlwe.NewSecretKey(params)
	plaintext := rlwe.NewDecryptor(params, zeroKey).DecryptNew(switched)
	decoded := make([]uint64, params.MaxSlots())
	if err := bgv.NewEncoder(params).Decode(plaintext, decoded); err != nil {
		return false, zeroDigest, ErrInvalidReleaseShare
	}
	if err := requireCanonicalReleaseVector(decoded); err != nil {
		return false, zeroDigest, err
	}
	confirmed := decoded[0] == 1
	transcript := ThresholdTranscriptCommitment(descriptor, statementDigests, confirmed)
	return confirmed, transcript, nil
}

// requireCanonicalReleaseVector asserts the COMPLETE slot vector, not slot 0.
//
// The circuit masks its result to slot 0 at every stage, so a canonical release
// is exactly one Boolean followed by 32767 zeros. Anything else means the
// ciphertext being released is not the circuit's output.
func requireCanonicalReleaseVector(decoded []uint64) error {
	if len(decoded) == 0 {
		return ErrReleaseSlotsNotCanonical
	}
	if decoded[0] > 1 {
		return fmt.Errorf("%w: slot 0 is %d, not a Boolean", ErrReleaseSlotsNotCanonical, decoded[0])
	}
	for index := 1; index < len(decoded); index++ {
		if decoded[index] != 0 {
			return fmt.Errorf("%w: slot %d is %d, expected 0", ErrReleaseSlotsNotCanonical, index, decoded[index])
		}
	}
	return nil
}
