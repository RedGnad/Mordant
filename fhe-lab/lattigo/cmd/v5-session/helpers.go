package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"golang.org/x/crypto/sha3"

	fhe "mordant.dev/fhe-lab/lattigo"
)

// ceremonyMaterial is the reference runner's view of the single ceremony
// driver in the library. The round sequence lives there, not here.
type ceremonyMaterial = fhe.ColocatedCeremonyMaterial

func runCeremony(params bgv.Parameters) (*ceremonyMaterial, error) {
	return fhe.RunColocatedCeremony(params, 2, 3, sha256.Sum256([]byte("mordant-v5-session")))
}

var sessionVault = [20]byte{0xA1, 0xB2, 0xC3, 0xD4, 0xE5}

func authorizationClaim(side string, slot uint8, policyID [32]byte, now time.Time) fhe.AuthorizationClaim {
	return fhe.AuthorizationClaim{
		SubjectCommitment: keccakText("mordant.v5-subject-" + side),
		Role:              keccakText("mordant.v5-role"),
		Vault:             sessionVault,
		PolicyID:          policyID,
		PolicyVersion:     fhe.PolicyVersion,
		ValidUntil:        uint64(now.Add(48 * time.Hour).Unix()),
		Nonce:             fhe.Uint256{0, 0, 0, uint64(slot) + 1},
	}
}

// encryptPair materializes the two synthetic sides in this process only. The
// plaintext values are never written to the output.
func encryptPair(runtime *fhe.Runtime, conflicting bool) (fhe.CircuitInputsV5, error) {
	var out fhe.CircuitInputsV5
	now := time.Now()
	policyID := keccakText("mordant.v5-session-policy")

	build := func(side string, slot uint8, receivable [32]byte, activeFrom, activeUntil uint64) (*fhe.CipherPledge, error) {
		claim := authorizationClaim(side, slot, policyID, now)
		commitment, err := runtime.SubmitterAuthorizationCommitment(claim)
		if err != nil {
			return nil, err
		}
		pledge := fhe.PlainPledge{
			ActiveFrom:                activeFrom,
			ActiveUntil:               activeUntil,
			Amount:                    fhe.Uint256{0, 0, 0, 1_000_000},
			Currency:                  keccakText("currency-usd"),
			ObligationID:              keccakText("mordant.v5-obligation-" + side),
			ReceivableID:              receivable,
			Exclusive:                 true,
			ReceivableCommitment:      [32]byte{},
			AuthorizationCommitment:   commitment,
			PrivateMetadataCommitment: keccakText("mordant.v5-metadata-" + side),
		}
		cipher, _, err := runtime.EncryptPledgeForMode(pledge, fhe.IdentityFullFHE256)
		return cipher, err
	}

	receivableA := keccakText("mordant.v5-receivable")
	receivableB := receivableA
	if !conflicting {
		receivableB = keccakText("mordant.v5-receivable-different")
	}
	// Overlapping windows, both exclusive: the policy conjunction holds when the
	// identities also match.
	cipherA, err := build("a", 0, receivableA, 100, 400)
	if err != nil {
		return out, fmt.Errorf("encrypt A: %w", err)
	}
	cipherB, err := build("b", 1, receivableB, 200, 500)
	if err != nil {
		return out, fmt.Errorf("encrypt B: %w", err)
	}
	return fhe.CircuitInputsV5{
		PolicyBitsA: cipherA.PolicyBits, PolicyBitsB: cipherB.PolicyBits,
		CurrencyBitsA: cipherA.CurrencyBits, CurrencyBitsB: cipherB.CurrencyBits,
		ReceivableIDsA: cipherA.ReceivableIDBits, ReceivableIDsB: cipherB.ReceivableIDBits,
	}, nil
}

type enrollmentSpec struct {
	session, nullifier [32]byte
	own, counterparty  [32]byte
	record, source     [32]byte
	ciphertextDigest   [32]byte
	inputCommitment    [32]byte
	policyID           [32]byte
	slot               uint8
	authorizationEpoch uint32
	budgetEpoch        uint32
	now                time.Time
}

func buildEnrollment(runtime *fhe.Runtime, issuer ed25519.PrivateKey, spec enrollmentSpec) (*fhe.SignedCiphertextEnrollmentV5, error) {
	side := "a"
	if spec.slot == 1 {
		side = "b"
	}
	claim := authorizationClaim(side, spec.slot, keccakText("mordant.v5-session-policy"), spec.now)
	commitment, err := runtime.SubmitterAuthorizationCommitment(claim)
	if err != nil {
		return nil, err
	}
	return fhe.SignEnrollmentV5(fhe.CiphertextEnrollmentV5{
		Binding: fhe.SessionBindingV5{
			SessionCommitment:           spec.session,
			SessionNullifier:            spec.nullifier,
			OwnScopeCommitment:          spec.own,
			CounterpartyScopeCommitment: spec.counterparty,
			GovernanceRecord:            spec.record,
			SourceRecordCommitment:      spec.source,
			AuthorizationEpoch:          spec.authorizationEpoch,
			SubmissionBudgetEpoch:       spec.budgetEpoch,
			InputSlot:                   spec.slot,
		},
		CiphertextDigest:        spec.ciphertextDigest,
		InputCommitment:         spec.inputCommitment,
		KeyID:                   runtime.KeyIDBytes(),
		ParameterFingerprint:    runtime.ParameterFingerprint(),
		PolicyID:                keccakText("mordant.v5-session-policy"),
		PolicyVersion:           fhe.PolicyVersion,
		IdentityMode:            fhe.IdentityFullFHE256,
		AuthorizationClaim:      claim,
		AuthorizationCommitment: commitment,
		IssuedAt:                uint64(spec.now.Add(-time.Minute).Unix()),
		ValidUntil:              uint64(spec.now.Add(12 * time.Hour).Unix()),
		Nonce:                   keccakText("mordant.v5-nonce-" + side),
	}, issuer)
}

// releaseBoth runs the 2-of-3 threshold release for each bit against the
// ciphertext the operators recomputed themselves.
func releaseBoth(
	params bgv.Parameters,
	material *ceremonyMaterial,
	operators []*fhe.ReleaseOperatorV5,
	request fhe.OperatorReleaseRequestV5,
	verdicts []fhe.OperatorVerdictV5,
) (bool, bool, [][32]byte, error) {
	sameShares := make([]fhe.ThresholdReleaseResponse, 0, 2)
	conflictShares := make([]fhe.ThresholdReleaseResponse, 0, 2)
	statements := make([][32]byte, 0, 4)
	for index, operator := range operators {
		same, conflict, err := operator.ReleaseShares(request, verdicts[index], time.Now())
		if err != nil {
			return false, false, nil, fmt.Errorf("operator %d shares: %w", index+1, err)
		}
		sameShares = append(sameShares, same)
		conflictShares = append(conflictShares, conflict)
		statements = append(statements, same.StatementDigest, conflict.StatementDigest)
	}

	outputs := verdicts[0].RecomputedOutputs()
	if outputs == nil {
		return false, false, nil, fmt.Errorf("verdict carries no recomputed outputs")
	}
	sameAsset, err := combineBit(params, material, request, outputs.SameEconomicAsset, sameShares, 0)
	if err != nil {
		return false, false, nil, fmt.Errorf("release sameEconomicAsset: %w", err)
	}
	policyConflict, err := combineBit(params, material, request, outputs.PolicyConflict, conflictShares, 1)
	if err != nil {
		return false, false, nil, fmt.Errorf("release policyConflict: %w", err)
	}
	return sameAsset, policyConflict, statements, nil
}

func combineBit(
	params bgv.Parameters,
	material *ceremonyMaterial,
	request fhe.OperatorReleaseRequestV5,
	ciphertext *rlwe.Ciphertext,
	shares []fhe.ThresholdReleaseResponse,
	slot uint8,
) (bool, error) {
	descriptor, err := fhe.ReleaseDescriptorForSlot(request.Descriptor, ciphertext, request.Coalition, slot, material.Manifest.KeyID)
	if err != nil {
		return false, err
	}
	confirmed, transcript, err := fhe.CombineReleaseBitV5(params, descriptor, material.Manifest, ciphertext, shares)
	if err != nil {
		return false, err
	}
	if transcript == ([32]byte{}) {
		return false, fmt.Errorf("empty threshold transcript")
	}
	return confirmed, nil
}

/* --------------------------------------------------------------- digests */

func keccakText(text string) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte(text))
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

func keccakLabel(domain string, value [32]byte, index uint8) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(value[:])
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], uint64(index))
	_, _ = hash.Write(word[:])
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

func keccakConcat(domain string, values ...[32]byte) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte(domain))
	for _, value := range values {
		_, _ = hash.Write(value[:])
	}
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}
