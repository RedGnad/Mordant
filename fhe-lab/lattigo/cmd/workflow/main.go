package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/internal/synthetic"
)

const (
	providerOutputSchema = "mordant.fhe-provider-output/1"
	resultSchema         = "mordant.confidential-policy-result/2"
	providerProofSchema  = "mordant.fhe-provider-proof/1"
	publicNonce          = uint64(7)
	publicValidUntil     = uint64(2_000_000_300)
	publicCureDeadline   = uint64(2_000_003_600)
)

type providerOutput struct {
	SchemaVersion string              `json:"schemaVersion"`
	OK            bool                `json:"ok"`
	Result        publicResult        `json:"result"`
	ProviderProof publicProviderProof `json:"providerProof"`
}

type publicResult struct {
	SchemaVersion           string `json:"schemaVersion"`
	ChainID                 string `json:"chainId"`
	Vault                   string `json:"vault"`
	PolicyID                string `json:"policyId"`
	PolicyVersion           string `json:"policyVersion"`
	InputCommitmentA        string `json:"inputCommitmentA"`
	InputCommitmentB        string `json:"inputCommitmentB"`
	ConflictConfirmed       bool   `json:"conflictConfirmed"`
	ResponsibleRole         string `json:"responsibleRole"`
	CureDeadline            string `json:"cureDeadline"`
	Nonce                   string `json:"nonce"`
	ValidUntil              string `json:"validUntil"`
	ProviderProofCommitment string `json:"providerProofCommitment"`
	ResultCommitment        string `json:"resultCommitment"`
}

type publicProviderProof struct {
	SchemaVersion                 string `json:"schemaVersion"`
	ResultCiphertextCommitment    string `json:"resultCiphertextCommitment"`
	ThresholdTranscriptCommitment string `json:"thresholdTranscriptCommitment"`
	ThresholdSessionID            string `json:"thresholdSessionId"`
	ThresholdKeyCommitment        string `json:"thresholdKeyCommitment"`
	PolicyCircuitCommitment       string `json:"policyCircuitCommitment"`
	ProviderProofCommitment       string `json:"providerProofCommitment"`
}

type failureOutput struct {
	SchemaVersion string `json:"schemaVersion"`
	OK            bool   `json:"ok"`
	ErrorCode     string `json:"errorCode"`
}

func main() {
	if err := run(); err != nil {
		// Failure output is stderr-only. A workflow consuming stdout therefore
		// receives no partial success-shaped fields.
		_ = json.NewEncoder(os.Stderr).Encode(failureOutput{
			SchemaVersion: providerOutputSchema,
			OK:            false,
			ErrorCode:     errorCode(err),
		})
		os.Exit(1)
	}
}

func run() error {
	runtime, _, err := fhe.NewRuntime()
	if err != nil {
		return err
	}
	publicMaterial, err := runtime.ExportPublicEncryptionMaterial()
	if err != nil {
		return err
	}
	client, err := fhe.NewExternalClient(publicMaterial)
	if err != nil {
		return err
	}

	now := time.Unix(2_000_000_000, 0)
	issuerPublicKey, issuerPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if _, err := runtime.RegisterEnrollmentIssuer(issuerPublicKey, now.Add(-time.Hour), now.Add(2*time.Hour)); err != nil {
		return err
	}
	mode := fhe.IdentityPublicCommitment
	a, b, err := synthetic.Pair(runtime, "workflow", mode)
	if err != nil {
		return err
	}
	contextA := synthetic.InputContext(0, 101)
	contextB := synthetic.InputContext(1, 102)
	claimA := synthetic.AuthorizationClaim("a-workflow-external", 101)
	claimB := synthetic.AuthorizationClaim("b-workflow-external", 102)
	a.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claimA)
	if err != nil {
		return err
	}
	b.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claimB)
	if err != nil {
		return err
	}
	encA, _, err := client.EncryptPledgeForMode(a, mode)
	if err != nil {
		return err
	}
	encB, _, err := client.EncryptPledgeForMode(b, mode)
	if err != nil {
		return err
	}
	enrollmentA, err := fhe.SignCiphertextEnrollment(
		client, encA, mode, contextA, claimA, now.Add(-time.Second),
		time.Unix(int64(publicValidUntil), 0), sha256.Sum256([]byte("workflow-enrollment-a")), issuerPrivateKey,
	)
	if err != nil {
		return err
	}
	enrollmentB, err := fhe.SignCiphertextEnrollment(
		client, encB, mode, contextB, claimB, now.Add(-time.Second),
		time.Unix(int64(publicValidUntil), 0), sha256.Sum256([]byte("workflow-enrollment-b")), issuerPrivateKey,
	)
	if err != nil {
		return err
	}
	// Exercise the exact external wire boundary instead of passing Go objects
	// directly from the issuer to the evaluator.
	enrollmentA, err = roundTripEnrollment(enrollmentA)
	if err != nil {
		return err
	}
	enrollmentB, err = roundTripEnrollment(enrollmentB)
	if err != nil {
		return err
	}
	var requestNonce [32]byte
	binary.BigEndian.PutUint64(requestNonce[24:], publicNonce)
	request := fhe.EvaluationRequest{
		KeyID:         runtime.KeyID(),
		PolicyVersion: fhe.PolicyVersion,
		Nonce:         requestNonce,
		ValidUntil:    time.Unix(int64(publicValidUntil), 0),
		IdentityMode:  mode,
		A:             encA,
		B:             encB,
		EnrollmentA:   enrollmentA,
		EnrollmentB:   enrollmentB,
	}
	inputA, inputB, err := runtime.VerifiedExternalInputCommitments(request, now)
	if err != nil {
		return err
	}
	decision, _, err := runtime.Evaluate(request, now)
	if err != nil {
		return err
	}
	configs, manifest, err := runtime.ProvisionThresholdOperators()
	if err != nil {
		return err
	}
	coalitionIndexes := [2]int{1, 2}
	operators := [2]*fhe.ThresholdOperator{}
	for index, operatorIndex := range coalitionIndexes {
		operators[index], err = fhe.NewThresholdOperator(configs[operatorIndex])
		if err != nil {
			return err
		}
	}
	protocolBinding, err := fhe.ProtocolBindingDigest(
		runtime.KeyIDBytes(), fhe.ProtocolCollectiveKeySwitchToZero, decision.Conflict,
	)
	if err != nil {
		return err
	}
	thresholdSessionID := sha256.Sum256([]byte("mordant-controlled-threshold-session-v1"))
	descriptor := fhe.ReleaseDescriptor{
		SessionID:                  thresholdSessionID,
		KeyID:                      runtime.KeyIDBytes(),
		ParameterFingerprint:       runtime.ParameterFingerprint(),
		PolicyID:                   synthetic.PolicyID,
		PolicyVersion:              fhe.PolicyVersion,
		InputCommitmentA:           inputA,
		InputCommitmentB:           inputB,
		ResultNonce:                fhe.Uint256{0, 0, 0, publicNonce},
		ValidUntil:                 publicValidUntil,
		ResultCiphertextCommitment: decision.ResultCiphertextCommitment,
		ProtocolBinding:            protocolBinding,
		Coalition: [2]uint64{
			manifest.Operators[coalitionIndexes[0]].Point,
			manifest.Operators[coalitionIndexes[1]].Point,
		},
	}
	responses := make([]fhe.ThresholdReleaseResponse, len(operators))
	for index, operator := range operators {
		response, err := operator.GenerateReleaseShare(descriptor, decision.Conflict)
		if err != nil {
			return err
		}
		wire, err := response.MarshalBinary()
		if err != nil {
			return err
		}
		responses[index], err = fhe.UnmarshalThresholdReleaseResponse(wire)
		if err != nil {
			return err
		}
	}
	runtime.DetachThresholdParties()
	confirmed, thresholdTranscriptCommitment, err := fhe.CombineZeroKeySwitchShares(
		runtime.Params, descriptor, manifest, decision.Conflict, responses,
	)
	if err != nil {
		return err
	}
	role := [32]byte{}
	cureDeadline := uint64(0)
	if confirmed {
		role = synthetic.Role
		cureDeadline = publicCureDeadline
	}
	thresholdKeyCommitment, err := fhe.ThresholdKeyCommitment(manifest)
	if err != nil {
		return err
	}
	policyCircuitCommitment, err := fhe.PolicyCircuitCommitment(
		runtime.ParameterFingerprint(), synthetic.PolicyID, fhe.PolicyVersion,
	)
	if err != nil {
		return err
	}
	proof := fhe.ProviderProof{
		ResultCiphertextCommitment:    decision.ResultCiphertextCommitment,
		ThresholdTranscriptCommitment: thresholdTranscriptCommitment,
		ThresholdSessionID:            thresholdSessionID,
		ThresholdKeyCommitment:        thresholdKeyCommitment,
		PolicyCircuitCommitment:       policyCircuitCommitment,
	}
	providerProofCommitment, err := fhe.ProviderProofCommitment(proof)
	if err != nil {
		return err
	}
	core := fhe.PublicPolicyResultCore{
		ChainID:                 fhe.Uint256{0, 0, 0, synthetic.ChainID},
		Vault:                   synthetic.Vault,
		PolicyID:                synthetic.PolicyID,
		PolicyVersion:           fhe.PolicyVersion,
		InputCommitmentA:        inputA,
		InputCommitmentB:        inputB,
		ConflictConfirmed:       confirmed,
		ResponsibleRole:         role,
		CureDeadline:            cureDeadline,
		Nonce:                   fhe.Uint256{0, 0, 0, publicNonce},
		ValidUntil:              publicValidUntil,
		ProviderProofCommitment: providerProofCommitment,
	}
	resultCommitment, err := fhe.ResultCommitment(core)
	if err != nil {
		return err
	}
	output := providerOutput{
		SchemaVersion: providerOutputSchema,
		OK:            true,
		Result: publicResult{
			SchemaVersion:           resultSchema,
			ChainID:                 fmt.Sprint(synthetic.ChainID),
			Vault:                   hex20(synthetic.Vault),
			PolicyID:                hex32(synthetic.PolicyID),
			PolicyVersion:           fmt.Sprint(fhe.PolicyVersion),
			InputCommitmentA:        hex32(inputA),
			InputCommitmentB:        hex32(inputB),
			ConflictConfirmed:       confirmed,
			ResponsibleRole:         hex32(role),
			CureDeadline:            fmt.Sprint(cureDeadline),
			Nonce:                   fmt.Sprint(publicNonce),
			ValidUntil:              fmt.Sprint(publicValidUntil),
			ProviderProofCommitment: hex32(providerProofCommitment),
			ResultCommitment:        hex32(resultCommitment),
		},
		ProviderProof: publicProviderProof{
			SchemaVersion:                 providerProofSchema,
			ResultCiphertextCommitment:    hex32(proof.ResultCiphertextCommitment),
			ThresholdTranscriptCommitment: hex32(proof.ThresholdTranscriptCommitment),
			ThresholdSessionID:            hex32(proof.ThresholdSessionID),
			ThresholdKeyCommitment:        hex32(proof.ThresholdKeyCommitment),
			PolicyCircuitCommitment:       hex32(proof.PolicyCircuitCommitment),
			ProviderProofCommitment:       hex32(providerProofCommitment),
		},
	}
	return json.NewEncoder(os.Stdout).Encode(output)
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, fhe.ErrInvalidPlaintext):
		return "INVALID_PRIVATE_INPUT"
	case errors.Is(err, fhe.ErrMalformedPledge):
		return "MALFORMED_CIPHERTEXT"
	case errors.Is(err, fhe.ErrWrongKeyID), errors.Is(err, fhe.ErrCiphertextNotIssued):
		return "KEY_ID_NOT_ACTIVE"
	case errors.Is(err, fhe.ErrWrongPolicy):
		return "POLICY_VERSION_NOT_ACTIVE"
	case errors.Is(err, fhe.ErrExpired):
		return "RESULT_EXPIRED"
	case errors.Is(err, fhe.ErrReplay):
		return "RESULT_REPLAY"
	case errors.Is(err, fhe.ErrEnrollmentReplay):
		return "ENROLLMENT_REPLAY"
	case errors.Is(err, fhe.ErrMalformedEnrollment):
		return "MALFORMED_ENROLLMENT"
	case errors.Is(err, fhe.ErrUnknownIssuer), errors.Is(err, fhe.ErrRevokedIssuer):
		return "ENROLLMENT_ISSUER_NOT_ACTIVE"
	case errors.Is(err, fhe.ErrInvalidSignature):
		return "INVALID_ENROLLMENT_SIGNATURE"
	case errors.Is(err, fhe.ErrInsufficientShare):
		return "THRESHOLD_NOT_MET"
	case errors.Is(err, fhe.ErrInvalidProtocolBinding), errors.Is(err, fhe.ErrInvalidReleaseDescriptor), errors.Is(err, fhe.ErrInvalidReleaseShare):
		return "THRESHOLD_RELEASE_INVALID"
	case errors.Is(err, fhe.ErrUnauthorizedIngress):
		return "UNAUTHORIZED_SUBMITTER"
	default:
		return "FHE_WORKER_FAILURE"
	}
}

func hex32(value [32]byte) string { return "0x" + hex.EncodeToString(value[:]) }

func hex20(value [20]byte) string { return "0x" + hex.EncodeToString(value[:]) }

func roundTripEnrollment(enrollment *fhe.SignedCiphertextEnrollment) (*fhe.SignedCiphertextEnrollment, error) {
	if enrollment == nil {
		return nil, fhe.ErrMalformedEnrollment
	}
	wire, err := enrollment.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return fhe.UnmarshalSignedCiphertextEnrollment(wire)
}
