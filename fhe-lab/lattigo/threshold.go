package lattigospike

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	defaultParties   = 3
	defaultThreshold = 2
)

var rotationSteps = []int{1, 2, 4, 8, 16, 32, 64, -64, 128}

type thresholdParty struct {
	multiparty.Combiner
	sk      *rlwe.SecretKey
	tsk     multiparty.ShamirSecretShare
	point   multiparty.ShamirPublicPoint
	ephemSK *rlwe.SecretKey
}

type ingressGrant struct {
	keyID         string
	policyVersion uint32
	validUntil    time.Time
}

type Runtime struct {
	Params    bgv.Parameters
	Encoder   *bgv.Encoder
	Encryptor *rlwe.Encryptor
	Evaluator *bgv.Evaluator

	publicKey            *rlwe.PublicKey
	evalKeys             *rlwe.MemEvaluationKeySet
	one                  *rlwe.Ciphertext
	parties              []*thresholdParty
	threshold            int
	keyID                string
	keyIDBytes           [32]byte
	parameterFingerprint [32]byte
	usedNonce            map[[32]byte]struct{}
	usedEnrollments      map[[32]byte]struct{}
	nonceMu              sync.Mutex
	usedDecrypt          map[[32]byte]struct{}
	decryptMu            sync.Mutex
	authorizedIngress    map[[32]byte]ingressGrant
	authorizationMu      sync.RWMutex
	issuedCiphertexts    map[[32]byte]struct{}
	issuedMu             sync.RWMutex
	trustedIssuers       map[[32]byte]issuerRecord
	issuerMu             sync.RWMutex
}

func NewRuntime() (*Runtime, SetupMetrics, error) {
	started := time.Now()
	metrics := SetupMetrics{}

	// This is Lattigo v6.2.0's official 128-bit N15 scale-invariant BGV/BFV
	// example family (LogQP ~= 880). It provides the noise budget required by
	// this depth-11 exact Boolean circuit; it is still not an audited Mordant
	// production parameter recommendation.
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP:             []int{60, 60, 60},
		PlaintextModulus: 65537,
	})
	if err != nil {
		return nil, metrics, fmt.Errorf("parameters: %w", err)
	}

	parties, thresholdDuration, err := generateThresholdParties(params, defaultParties, defaultThreshold)
	if err != nil {
		return nil, metrics, err
	}
	metrics.ThresholdSetup = thresholdDuration
	metrics.ThresholdShareBytes = parties[0].tsk.BinarySize()

	crs, err := sampling.NewKeyedPRNG([]byte("mordant-lattigo-v6.2.0-kill-test-crs"))
	if err != nil {
		return nil, metrics, fmt.Errorf("crs: %w", err)
	}
	setupGroup := parties[:defaultThreshold]

	var pk *rlwe.PublicKey
	phase := time.Now()
	if pk, err = collectivePublicKey(params, crs, setupGroup); err != nil {
		return nil, metrics, err
	}
	metrics.CollectivePublicKey = time.Since(phase)

	var rlk *rlwe.RelinearizationKey
	phase = time.Now()
	if rlk, err = collectiveRelinearizationKey(params, crs, setupGroup); err != nil {
		return nil, metrics, err
	}
	metrics.RelinearizationKey = time.Since(phase)

	galEls := make([]uint64, len(rotationSteps))
	for i, step := range rotationSteps {
		galEls[i] = params.GaloisElement(step)
	}
	phase = time.Now()
	galoisKeys, err := collectiveGaloisKeys(params, crs, galEls, setupGroup)
	if err != nil {
		return nil, metrics, err
	}
	metrics.GaloisKeys = time.Since(phase)

	evk := rlwe.NewMemEvaluationKeySet(rlk, galoisKeys...)
	phase = time.Now()
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, metrics, fmt.Errorf("marshal public key: %w", err)
	}
	metrics.PublicKeyMarshal = time.Since(phase)
	metrics.PublicKeyBytes = len(pkBytes)

	phase = time.Now()
	evkBytes, err := evk.MarshalBinary()
	if err != nil {
		return nil, metrics, fmt.Errorf("marshal evaluation keys: %w", err)
	}
	metrics.EvaluationKeyMarshal = time.Since(phase)
	metrics.EvaluationKeyBytes = len(evkBytes)
	// Currency equality already requires the 128-slot rotation, so enabling
	// full-FHE receivable equality adds no evaluation-key material.
	metrics.FullFHEIdentityKeyDeltaBytes = 0
	keyDigest := sha256.Sum256(pkBytes)
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, metrics, fmt.Errorf("marshal parameters: %w", err)
	}
	parameterFingerprint := sha256.Sum256(parameterBytes)
	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	ones := make([]uint64, params.MaxSlots())
	for i := range ones {
		ones[i] = 1
	}
	onePlaintext := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(ones, onePlaintext); err != nil {
		return nil, metrics, fmt.Errorf("encode boolean one: %w", err)
	}
	oneCiphertext, err := encryptor.EncryptNew(onePlaintext)
	if err != nil {
		return nil, metrics, fmt.Errorf("encrypt boolean one: %w", err)
	}

	runtime := &Runtime{
		Params:               params,
		Encoder:              encoder,
		Encryptor:            encryptor,
		Evaluator:            bgv.NewEvaluator(params, evk, true),
		publicKey:            pk,
		evalKeys:             evk,
		one:                  oneCiphertext,
		parties:              parties,
		threshold:            defaultThreshold,
		keyID:                fmt.Sprintf("internal-sha256:%x", keyDigest[:]),
		keyIDBytes:           keyDigest,
		parameterFingerprint: parameterFingerprint,
		usedNonce:            make(map[[32]byte]struct{}),
		usedEnrollments:      make(map[[32]byte]struct{}),
		usedDecrypt:          make(map[[32]byte]struct{}),
		authorizedIngress:    make(map[[32]byte]ingressGrant),
		issuedCiphertexts:    make(map[[32]byte]struct{}),
		trustedIssuers:       make(map[[32]byte]issuerRecord),
	}
	metrics.Total = time.Since(started)
	return runtime, metrics, nil
}

func (r *Runtime) KeyID() string { return r.keyID }

func (r *Runtime) KeyIDBytes() [32]byte { return r.keyIDBytes }

func (r *Runtime) ParameterFingerprint() [32]byte { return r.parameterFingerprint }

// GrantIngress represents the trusted-gateway result after an issuer claim
// has been verified. The grant is scoped to this runtime key, policy version
// and expiry. The issuer signature, revocation feed and organizational
// identity system remain integration work; callers cannot provide an
// authorization Boolean to the FHE policy.
func (r *Runtime) GrantIngress(commitment [32]byte, policyVersion uint32, validUntil time.Time) error {
	if commitment == ([32]byte{}) || policyVersion != PolicyVersion || validUntil.IsZero() {
		return ErrUnauthorizedIngress
	}
	r.authorizationMu.Lock()
	r.authorizedIngress[commitment] = ingressGrant{
		keyID:         r.keyID,
		policyVersion: policyVersion,
		validUntil:    validUntil,
	}
	r.authorizationMu.Unlock()
	return nil
}

func (r *Runtime) RevokeIngress(commitment [32]byte) {
	r.authorizationMu.Lock()
	delete(r.authorizedIngress, commitment)
	r.authorizationMu.Unlock()
}

func generateThresholdParties(params bgv.Parameters, n, threshold int) ([]*thresholdParty, time.Duration, error) {
	started := time.Now()
	if n < 2 || threshold < 2 || threshold > n {
		return nil, 0, fmt.Errorf("threshold configuration")
	}

	parties := make([]*thresholdParty, n)
	kgen := rlwe.NewKeyGenerator(params)
	points := make([]multiparty.ShamirPublicPoint, n)
	for i := range parties {
		points[i] = multiparty.ShamirPublicPoint(i + 1)
		parties[i] = &thresholdParty{sk: kgen.GenSecretKeyNew(), point: points[i]}
	}
	for i := range parties {
		parties[i].Combiner = multiparty.NewCombiner(params, parties[i].point, points, threshold)
	}

	thresholdizer := multiparty.NewThresholdizer(params)
	shares := make([][]multiparty.ShamirSecretShare, n)
	for i := range shares {
		shares[i] = make([]multiparty.ShamirSecretShare, n)
		polynomial, err := thresholdizer.GenShamirPolynomial(threshold, parties[i].sk)
		if err != nil {
			return nil, 0, fmt.Errorf("threshold polynomial: %w", err)
		}
		for j := range parties {
			shares[i][j] = thresholdizer.AllocateThresholdSecretShare()
			thresholdizer.GenShamirSecretShare(parties[j].point, polynomial, &shares[i][j])
		}
	}
	for i := range parties {
		parties[i].tsk = thresholdizer.AllocateThresholdSecretShare()
		for j := range parties {
			if err := thresholdizer.AggregateShares(shares[j][i], parties[i].tsk, &parties[i].tsk); err != nil {
				return nil, 0, fmt.Errorf("aggregate threshold shares: %w", err)
			}
		}
	}
	return parties, time.Since(started), nil
}

func partyPoints(parties []*thresholdParty) []multiparty.ShamirPublicPoint {
	points := make([]multiparty.ShamirPublicPoint, len(parties))
	for i := range parties {
		points[i] = parties[i].point
	}
	return points
}

func additiveShares(params bgv.Parameters, parties []*thresholdParty) ([]*rlwe.SecretKey, error) {
	points := partyPoints(parties)
	shares := make([]*rlwe.SecretKey, len(parties))
	for i, p := range parties {
		shares[i] = rlwe.NewSecretKey(params)
		if err := p.GenAdditiveShare(points, p.point, p.tsk, shares[i]); err != nil {
			return nil, err
		}
	}
	return shares, nil
}

func collectivePublicKey(params bgv.Parameters, crs sampling.PRNG, parties []*thresholdParty) (*rlwe.PublicKey, error) {
	shares, err := additiveShares(params, parties)
	if err != nil {
		return nil, fmt.Errorf("collective public key shares: %w", err)
	}
	protocol := multiparty.NewPublicKeyGenProtocol(params)
	crp := protocol.SampleCRP(crs)
	combined := protocol.AllocateShare()
	for i := range parties {
		share := protocol.AllocateShare()
		protocol.GenShare(shares[i], crp, &share)
		protocol.AggregateShares(share, combined, &combined)
	}
	pk := rlwe.NewPublicKey(params)
	protocol.GenPublicKey(combined, crp, pk)
	return pk, nil
}

func collectiveRelinearizationKey(params bgv.Parameters, crs sampling.PRNG, parties []*thresholdParty) (*rlwe.RelinearizationKey, error) {
	shares, err := additiveShares(params, parties)
	if err != nil {
		return nil, fmt.Errorf("collective relinearization shares: %w", err)
	}
	protocol := multiparty.NewRelinearizationKeyGenProtocol(params)
	crp := protocol.SampleCRP(crs)
	roundOne := make([]multiparty.RelinearizationKeyGenShare, len(parties))
	roundTwo := make([]multiparty.RelinearizationKeyGenShare, len(parties))
	_, combinedOne, combinedTwo := protocol.AllocateShare()
	for i, p := range parties {
		p.ephemSK, roundOne[i], roundTwo[i] = protocol.AllocateShare()
		protocol.GenShareRoundOne(shares[i], crp, p.ephemSK, &roundOne[i])
		protocol.AggregateShares(roundOne[i], combinedOne, &combinedOne)
	}
	for i, p := range parties {
		protocol.GenShareRoundTwo(p.ephemSK, shares[i], combinedOne, &roundTwo[i])
		protocol.AggregateShares(roundTwo[i], combinedTwo, &combinedTwo)
	}
	rlk := rlwe.NewRelinearizationKey(params)
	protocol.GenRelinearizationKey(combinedOne, combinedTwo, rlk)
	return rlk, nil
}

func collectiveGaloisKeys(params bgv.Parameters, crs sampling.PRNG, galEls []uint64, parties []*thresholdParty) ([]*rlwe.GaloisKey, error) {
	shares, err := additiveShares(params, parties)
	if err != nil {
		return nil, fmt.Errorf("collective galois shares: %w", err)
	}
	protocol := multiparty.NewGaloisKeyGenProtocol(params)
	keys := make([]*rlwe.GaloisKey, len(galEls))
	for j, galEl := range galEls {
		crp := protocol.SampleCRP(crs)
		combined := protocol.AllocateShare()
		combined.GaloisElement = galEl
		for i := range parties {
			share := protocol.AllocateShare()
			if err := protocol.GenShare(shares[i], galEl, crp, &share); err != nil {
				return nil, fmt.Errorf("galois share: %w", err)
			}
			if err := protocol.AggregateShares(share, combined, &combined); err != nil {
				return nil, fmt.Errorf("aggregate galois share: %w", err)
			}
		}
		keys[j] = rlwe.NewGaloisKey(params)
		if err := protocol.GenGaloisKey(combined, crp, keys[j]); err != nil {
			return nil, fmt.Errorf("galois key: %w", err)
		}
	}
	return keys, nil
}

func (r *Runtime) DecryptThreshold(decision *EncryptedDecision, helperIndex int) (bool, DecryptionMetrics, error) {
	return r.DecryptThresholdWithCoalition(decision, 0, helperIndex)
}

// DecryptThresholdWithCoalition decrypts a decision with any two distinct
// parties from the 2-of-3 Shamir set. This spike co-locates all party material
// in one process so it can exercise the real multiparty protocol; it does not
// model the production trust boundary or transport between organizations.
//
// A result ciphertext is terminal after the first decryption attempt. The
// guard is keyed by the exact c1 polynomial consumed by Lattigo's collective
// key-switch protocol, together with the key epoch and a closed protocol kind.
// Binding the whole ciphertext would be unsafe: c0 is not consumed while a
// caller could mutate it to obtain another commitment for the same c1. This
// legacy path remains process-local; network operators use the durable ledger.
func (r *Runtime) DecryptThresholdWithCoalition(decision *EncryptedDecision, receiverIndex, helperIndex int) (bool, DecryptionMetrics, error) {
	metrics := DecryptionMetrics{
		Participants:  2,
		Threshold:     r.threshold,
		ReceiverIndex: receiverIndex,
		HelperIndex:   helperIndex,
	}
	started := time.Now()
	if decision == nil || decision.Conflict == nil || decision.Nonce == ([32]byte{}) || decision.ResultCiphertextCommitment == ([32]byte{}) {
		return false, metrics, ErrInsufficientShare
	}
	commitment, err := ciphertextCommitment(decision.Conflict)
	if err != nil || commitment != decision.ResultCiphertextCommitment {
		return false, metrics, ErrMalformedPledge
	}
	protocolBinding, err := ProtocolBindingDigest(r.keyIDBytes, ProtocolCollectiveKeySwitchToZero, decision.Conflict)
	if err != nil {
		return false, metrics, ErrInvalidProtocolBinding
	}
	// Pure preflight failures do not consume the result. Once a valid coalition
	// begins the protocol, success or failure is terminal for this ciphertext.
	if receiverIndex < 0 || receiverIndex >= len(r.parties) || helperIndex < 0 || helperIndex >= len(r.parties) || receiverIndex == helperIndex {
		return false, metrics, ErrInsufficientShare
	}
	r.decryptMu.Lock()
	if _, exists := r.usedDecrypt[protocolBinding]; exists {
		r.decryptMu.Unlock()
		return false, metrics, ErrReplay
	}
	r.usedDecrypt[protocolBinding] = struct{}{}
	r.decryptMu.Unlock()
	receiver := r.parties[receiverIndex]
	helper := r.parties[helperIndex]
	active := []*thresholdParty{receiver, helper}
	points := partyPoints(active)
	helperShare := rlwe.NewSecretKey(r.Params)
	if err := helper.GenAdditiveShare(points, helper.point, helper.tsk, helperShare); err != nil {
		return false, metrics, ErrInsufficientShare
	}

	phase := time.Now()
	protocol, err := multiparty.NewKeySwitchProtocol(r.Params, ring.DiscreteGaussian{Sigma: 1 << 30, Bound: 6 * (1 << 30)})
	if err != nil {
		return false, metrics, fmt.Errorf("threshold key switch: %w", err)
	}
	share := protocol.AllocateShare(decision.Conflict.Level())
	zero := rlwe.NewSecretKey(r.Params)
	protocol.GenShare(helperShare, zero, decision.Conflict, &share)
	switched := bgv.NewCiphertext(r.Params, 1, decision.Conflict.Level())
	protocol.KeySwitch(decision.Conflict, share, switched)
	metrics.ThresholdKeySwitch = time.Since(phase)

	receiverShare := rlwe.NewSecretKey(r.Params)
	if err := receiver.GenAdditiveShare(points, receiver.point, receiver.tsk, receiverShare); err != nil {
		return false, metrics, ErrInsufficientShare
	}
	phase = time.Now()
	plaintext := rlwe.NewDecryptor(r.Params, receiverShare).DecryptNew(switched)
	decoded := make([]uint64, r.Params.MaxSlots())
	if err := r.Encoder.Decode(plaintext, decoded); err != nil {
		return false, metrics, fmt.Errorf("decode result: %w", err)
	}
	metrics.ReceiverDecrypt = time.Since(phase)
	metrics.Total = time.Since(started)
	if decoded[0] > 1 {
		return false, metrics, fmt.Errorf("non-boolean decrypted result")
	}
	return decoded[0] == 1, metrics, nil
}
