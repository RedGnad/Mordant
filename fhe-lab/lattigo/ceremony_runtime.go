package lattigospike

import (
	"crypto/sha256"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// NewEvaluationRuntime builds a Runtime that can encrypt-for-test, evaluate the
// policy circuit and validate enrollments, but that holds no threshold party
// and therefore cannot decrypt anything.
//
// This is the constructor the V4 evaluator uses. Unlike the legacy trusted
// dealer path it never generates secret shares: `parties` stays nil for the
// lifetime of the process, so DecryptThresholdWithCoalition and
// ProvisionThresholdOperators both fail closed. The only route from a result
// ciphertext to a Boolean is a 2-of-3 coalition of separate operator processes.
func NewEvaluationRuntime(
	params bgv.Parameters,
	publicKey *rlwe.PublicKey,
	relinearizationKey *rlwe.RelinearizationKey,
	galoisKeys []*rlwe.GaloisKey,
) (*Runtime, error) {
	return newEvaluationRuntime(params, publicKey, relinearizationKey, galoisKeys, ceremonyKeyIDPrefix)
}

// NewGovernedEvaluationRuntime builds the evaluator for one case-specific
// governed-decryptor key. Like NewEvaluationRuntime it holds no secret key and
// no threshold party; the distinct key-id domain prevents custody relabeling.
func NewGovernedEvaluationRuntime(
	params bgv.Parameters,
	publicKey *rlwe.PublicKey,
	relinearizationKey *rlwe.RelinearizationKey,
	galoisKeys []*rlwe.GaloisKey,
) (*Runtime, error) {
	return newEvaluationRuntime(params, publicKey, relinearizationKey, galoisKeys, governedKeyIDPrefix)
}

func newEvaluationRuntime(
	params bgv.Parameters,
	publicKey *rlwe.PublicKey,
	relinearizationKey *rlwe.RelinearizationKey,
	galoisKeys []*rlwe.GaloisKey,
	keyPrefix string,
) (*Runtime, error) {
	if publicKey == nil || relinearizationKey == nil || len(galoisKeys) != len(rotationSteps) {
		return nil, ErrCeremonyMaterial
	}
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal collective public key: %w", err)
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal parameters: %w", err)
	}
	evaluationKeys := rlwe.NewMemEvaluationKeySet(relinearizationKey, galoisKeys...)
	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, publicKey)
	ones := make([]uint64, params.MaxSlots())
	for index := range ones {
		ones[index] = 1
	}
	onePlaintext := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(ones, onePlaintext); err != nil {
		return nil, fmt.Errorf("encode boolean one: %w", err)
	}
	oneCiphertext, err := encryptor.EncryptNew(onePlaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt boolean one: %w", err)
	}
	keyDigest := sha256.Sum256(publicKeyBytes)
	return &Runtime{
		Params:               params,
		Encoder:              encoder,
		Encryptor:            encryptor,
		Evaluator:            bgv.NewEvaluator(params, evaluationKeys, true),
		publicKey:            publicKey,
		evalKeys:             evaluationKeys,
		one:                  oneCiphertext,
		parties:              nil,
		threshold:            defaultThreshold,
		keyID:                fmt.Sprintf("%s%x", keyPrefix, keyDigest[:]),
		keyIDBytes:           keyDigest,
		parameterFingerprint: sha256.Sum256(parameterBytes),
		usedNonce:            make(map[[32]byte]struct{}),
		usedEnrollments:      make(map[[32]byte]struct{}),
		usedDecrypt:          make(map[[32]byte]struct{}),
		authorizedIngress:    make(map[[32]byte]ingressGrant),
		issuedCiphertexts:    make(map[[32]byte]struct{}),
		trustedIssuers:       make(map[[32]byte]issuerRecord),
	}, nil
}

// HoldsThresholdParties reports whether this runtime holds any co-located
// threshold party. A V4 evaluation runtime must always report false; the
// evidence gate asserts it.
func (r *Runtime) HoldsThresholdParties() bool {
	return r != nil && len(r.parties) > 0
}

// CollectiveKeyID is the key epoch identifier derived from the collective
// public key. Operators bind it into their sealed bundles so a release
// descriptor for a different key epoch is refused.
func CollectiveKeyID(publicKey *rlwe.PublicKey) ([32]byte, error) {
	var zero [32]byte
	if publicKey == nil {
		return zero, ErrCeremonyMaterial
	}
	encoded, err := publicKey.MarshalBinary()
	if err != nil {
		return zero, err
	}
	return sha256.Sum256(encoded), nil
}
