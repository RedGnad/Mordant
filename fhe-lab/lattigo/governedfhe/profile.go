// Package governedfhe implements the case-specific governed-decryptor MVP.
// It intentionally exposes one parameter profile, one circuit, one Boolean
// result and one release ordinal. It is not a generic FHE or decrypt API.
package governedfhe

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	fhe "mordant.dev/fhe-lab/lattigo"
)

const (
	ParameterProfile = "mordant.bgv.identity-full-fhe-256.n15/v1"
	ServiceID        = "mordant.private-pledge-matching"
	ServiceVersion   = uint32(1)
	CircuitID        = "mordant.identity-full-fhe-256"
	InputSchema      = "mordant.encrypted-pledge/governed-fhe-v1"
	ResultSchema     = "mordant.fixed-conflict-boolean/v1"

	ReleaseModeGovernedDecryptor = "governed-decryptor-v1"
	ReleaseModeThreshold2Of3     = "threshold-2of3-v1"
	ReleaseOrdinal               = uint32(1)
	ResultSlot                   = uint32(0)

	CaseBindingSchema         = "mordant.fhe-case-binding/1"
	CaseCryptoSchema          = "mordant.fhe-case-crypto/1"
	CaseManifestSchema        = "mordant.fhe-case-manifest/1"
	ParticipantArtifactSchema = "mordant.fhe-participant-artifact/1"
	EvaluatedArtifactSchema   = "mordant.fhe-evaluated-conflict/1"
	GovernedResultSchema      = "mordant.governed-conflict-result/1"
	ReleaseAuthoritySchema    = "mordant.fhe-release-authority/1"
	PrivateCaseSchema         = "mordant.fhe-private-case/1"
	EvaluationAdmissionSchema = "mordant.fhe-evaluation-admission/1"
	EvaluationCompletedSchema = "mordant.fhe-evaluation-completed/1"
	RecomputeAdmissionSchema  = "mordant.fhe-recompute-admission/1"
	RecomputeVerifiedSchema   = "mordant.fhe-recompute-verified/1"
	RecomputeMismatchSchema   = "mordant.fhe-recompute-mismatch/1"
	ReleaseAdmissionSchema    = "mordant.fhe-release-admission/1"
	ReleaseConsumedSchema     = "mordant.fhe-release-consumed/1"
	RecourseRecordSchema      = "mordant.fhe-recourse-adapter-record/1"
	EvidenceSchema            = "mordant.governed-fhe-public-evidence/2"

	PublicCaseQuota  int64 = 1 << 30
	PrivateCaseQuota int64 = 64 << 20
)

var (
	ErrBinding              = errors.New("governed FHE binding rejected")
	ErrArtifact             = errors.New("governed FHE artifact rejected")
	ErrStore                = errors.New("governed FHE store rejected")
	ErrReleaseConsumed      = errors.New("governed FHE release already consumed")
	ErrReleaseAmbiguous     = errors.New("governed FHE release is terminally ambiguous")
	ErrEvaluatorMismatch    = errors.New("governed FHE evaluator result mismatch")
	ErrCiphertextValidation = errors.New("governed FHE fresh participant ciphertext rejected")
	ErrEvaluationAdmission  = errors.New("governed FHE evaluation already admitted")
	ErrRecomputeAdmission   = errors.New("governed FHE recomputation already admitted")
	ErrResourceAdmission    = errors.New("governed FHE resource admission rejected")
	ErrRecourse             = errors.New("governed FHE recourse rejected")
)

var rotationSteps = [...]int{1, 2, 4, 8, 16, 32, 64, -64, 128}

// Parameters returns the exact existing N15 profile used by
// IdentityFullFHE256. It is an MVP parameter family, not a production claim.
func Parameters() (bgv.Parameters, error) {
	return bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP:             []int{60, 60, 60},
		PlaintextModulus: 65537,
	})
}

func RotationSteps() []int {
	return append([]int(nil), rotationSteps[:]...)
}

func GaloisElements(params bgv.Parameters) ([]uint64, error) {
	if err := ValidateParameters(params); err != nil {
		return nil, err
	}
	elements := make([]uint64, len(rotationSteps))
	for index, step := range rotationSteps {
		elements[index] = params.GaloisElement(step)
	}
	return elements, nil
}

func ParameterFingerprint() (Digest, error) {
	params, err := Parameters()
	if err != nil {
		return Digest{}, err
	}
	encoded, err := params.MarshalBinary()
	if err != nil {
		return Digest{}, err
	}
	return Digest(sha256.Sum256(encoded)), nil
}

func ValidateParameters(params bgv.Parameters) error {
	expected, err := Parameters()
	if err != nil {
		return err
	}
	actualBytes, actualErr := params.MarshalBinary()
	expectedBytes, expectedErr := expected.MarshalBinary()
	if actualErr != nil || expectedErr != nil || !bytes.Equal(actualBytes, expectedBytes) {
		return fmt.Errorf("%w: wrong N15 parameters", ErrBinding)
	}
	return nil
}

func FixedCircuitDigest() Digest { return Digest(fhe.CircuitHashV5()) }
