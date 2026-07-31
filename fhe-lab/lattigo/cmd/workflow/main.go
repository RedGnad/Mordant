package main

import (
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
	resultSchema         = "mordant.confidential-policy-result/1"
	publicNonce          = uint64(7)
	publicValidUntil     = uint64(2_000_000_300)
	publicCureDeadline   = uint64(2_000_003_600)
)

type providerOutput struct {
	SchemaVersion string       `json:"schemaVersion"`
	OK            bool         `json:"ok"`
	Result        publicResult `json:"result"`
}

type publicResult struct {
	SchemaVersion     string `json:"schemaVersion"`
	ChainID           string `json:"chainId"`
	Vault             string `json:"vault"`
	PolicyID          string `json:"policyId"`
	PolicyVersion     string `json:"policyVersion"`
	InputCommitmentA  string `json:"inputCommitmentA"`
	InputCommitmentB  string `json:"inputCommitmentB"`
	ConflictConfirmed bool   `json:"conflictConfirmed"`
	ResponsibleRole   string `json:"responsibleRole"`
	CureDeadline      string `json:"cureDeadline"`
	Nonce             string `json:"nonce"`
	ValidUntil        string `json:"validUntil"`
	ResultCommitment  string `json:"resultCommitment"`
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
	mode := fhe.IdentityPublicCommitment
	a, b, err := synthetic.Pair(runtime, "workflow", mode)
	if err != nil {
		return err
	}
	if err := synthetic.GrantPair(runtime, a, b); err != nil {
		return err
	}
	encA, _, err := runtime.EncryptPledgeForMode(a, mode)
	if err != nil {
		return err
	}
	encB, _, err := runtime.EncryptPledgeForMode(b, mode)
	if err != nil {
		return err
	}
	inputA, err := runtime.CanonicalInputCommitment(encA, synthetic.InputContext(0, 101))
	if err != nil {
		return err
	}
	inputB, err := runtime.CanonicalInputCommitment(encB, synthetic.InputContext(1, 102))
	if err != nil {
		return err
	}

	now := time.Unix(2_000_000_000, 0)
	var requestNonce [32]byte
	binary.BigEndian.PutUint64(requestNonce[24:], publicNonce)
	decision, _, err := runtime.Evaluate(fhe.EvaluationRequest{
		KeyID:         runtime.KeyID(),
		PolicyVersion: fhe.PolicyVersion,
		Nonce:         requestNonce,
		ValidUntil:    time.Unix(int64(publicValidUntil), 0),
		IdentityMode:  mode,
		A:             encA,
		B:             encB,
	}, now)
	if err != nil {
		return err
	}
	confirmed, _, err := runtime.DecryptThresholdWithCoalition(decision, 1, 2)
	if err != nil {
		return err
	}
	role := [32]byte{}
	cureDeadline := uint64(0)
	if confirmed {
		role = synthetic.Role
		cureDeadline = publicCureDeadline
	}
	core := fhe.PublicPolicyResultCore{
		ChainID:           fhe.Uint256{0, 0, 0, synthetic.ChainID},
		Vault:             synthetic.Vault,
		PolicyID:          synthetic.PolicyID,
		PolicyVersion:     fhe.PolicyVersion,
		InputCommitmentA:  inputA,
		InputCommitmentB:  inputB,
		ConflictConfirmed: confirmed,
		ResponsibleRole:   role,
		CureDeadline:      cureDeadline,
		Nonce:             fhe.Uint256{0, 0, 0, publicNonce},
		ValidUntil:        publicValidUntil,
	}
	resultCommitment, err := fhe.ResultCommitment(core)
	if err != nil {
		return err
	}
	output := providerOutput{
		SchemaVersion: providerOutputSchema,
		OK:            true,
		Result: publicResult{
			SchemaVersion:     resultSchema,
			ChainID:           fmt.Sprint(synthetic.ChainID),
			Vault:             hex20(synthetic.Vault),
			PolicyID:          hex32(synthetic.PolicyID),
			PolicyVersion:     fmt.Sprint(fhe.PolicyVersion),
			InputCommitmentA:  hex32(inputA),
			InputCommitmentB:  hex32(inputB),
			ConflictConfirmed: confirmed,
			ResponsibleRole:   hex32(role),
			CureDeadline:      fmt.Sprint(cureDeadline),
			Nonce:             fmt.Sprint(publicNonce),
			ValidUntil:        fmt.Sprint(publicValidUntil),
			ResultCommitment:  hex32(resultCommitment),
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
	case errors.Is(err, fhe.ErrInsufficientShare):
		return "THRESHOLD_NOT_MET"
	case errors.Is(err, fhe.ErrUnauthorizedIngress):
		return "UNAUTHORIZED_SUBMITTER"
	default:
		return "FHE_WORKER_FAILURE"
	}
}

func hex32(value [32]byte) string { return "0x" + hex.EncodeToString(value[:]) }

func hex20(value [20]byte) string { return "0x" + hex.EncodeToString(value[:]) }
