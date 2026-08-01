// Command v5-session runs one complete V5 confidential-match session and emits
// the values the on-chain result core binds.
//
// It takes the chain-derived facts as input (the session commitment and
// nullifier already admitted on chain, both opaque source-record commitments,
// both scopes and both governance records) and produces the FHE-derived facts:
// the two released bits, both enrollment digests, both ciphertext digests, the
// canonical output-ciphertext commitment, the circuit and parameter
// fingerprints, the evaluation-key digest and the runtime fingerprint.
//
// The two selected operators recompute the circuit CONCURRENTLY and each
// releases shares only against the ciphertext it computed itself. Nothing the
// coordinator asserts is taken on trust.
//
// No private value is ever written to the output. The plaintext pledges exist
// only inside this process.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"

	fhe "mordant.dev/fhe-lab/lattigo"
)

type chainInputs struct {
	SessionCommitment       string `json:"sessionCommitment"`
	SessionNullifier        string `json:"sessionNullifier"`
	SourceRecordCommitmentA string `json:"sourceRecordCommitmentA"`
	SourceRecordCommitmentB string `json:"sourceRecordCommitmentB"`
	ScopeCommitmentA        string `json:"scopeCommitmentA"`
	ScopeCommitmentB        string `json:"scopeCommitmentB"`
	GovernanceRecordA       string `json:"governanceRecordA"`
	GovernanceRecordB       string `json:"governanceRecordB"`
	PolicyID                string `json:"policyId"`
	PolicyVersion           uint32 `json:"policyVersion"`
	AuthorizationEpoch      uint32 `json:"authorizationEpoch"`
	SubmissionBudgetEpoch   uint32 `json:"submissionBudgetEpoch"`
	EvaluationKeyEpoch      uint32 `json:"evaluationKeyEpoch"`
	Vault                   string `json:"vault"`
	ChainID                 uint64 `json:"chainId"`
	// Conflicting selects whether the two synthetic sides describe the same
	// receivable. The negative branch is run to show a refusal is producible.
	Conflicting bool `json:"conflicting"`
}

type sessionOutput struct {
	SchemaVersion string `json:"schemaVersion"`

	SameEconomicAsset bool  `json:"sameEconomicAsset"`
	PolicyConflict    bool  `json:"policyConflict"`
	Outcome           uint8 `json:"outcome"`

	EnrollmentDigestA string `json:"enrollmentDigestA"`
	EnrollmentDigestB string `json:"enrollmentDigestB"`
	CiphertextDigestA string `json:"ciphertextDigestA"`
	CiphertextDigestB string `json:"ciphertextDigestB"`
	InputCommitmentA  string `json:"inputCommitmentA"`
	InputCommitmentB  string `json:"inputCommitmentB"`

	OutputCiphertextCommitment string `json:"outputCiphertextCommitment"`
	InputsDigest               string `json:"inputsDigest"`
	CircuitHash                string `json:"circuitHash"`
	CircuitVersion             uint32 `json:"circuitVersion"`
	ReleaseLayoutVersion       uint16 `json:"releaseLayoutVersion"`
	ParameterFingerprint       string `json:"parameterFingerprint"`
	EvaluationKeyEpoch         uint32 `json:"evaluationKeyEpoch"`
	EvaluationKeyDigest        string `json:"evaluationKeyDigest"`
	RuntimeFingerprint         string `json:"runtimeFingerprint"`
	ProviderProofCommitment    string `json:"providerProofCommitment"`
	GovernanceContext          string `json:"governanceContext"`
	TranscriptCommitment       string `json:"transcriptCommitment"`
	OperatorSetDigest          string `json:"operatorSetDigest"`
	RecomputationQuorum        uint16 `json:"recomputationQuorum"`

	Runtime   fhe.RuntimeDescriptor `json:"runtime"`
	Operators []operatorReport      `json:"operators"`
	Timings   timingReport          `json:"timings"`
}

type operatorReport struct {
	Point           uint64 `json:"point"`
	ChecksRun       int    `json:"checksRun"`
	AllChecksPassed bool   `json:"allChecksPassed"`
	RecomputeMillis int64  `json:"recomputeMs"`
	OutputDigest    string `json:"outputDigest"`
}

type timingReport struct {
	CeremonyMillis      int64  `json:"ceremonyMs"`
	EncryptMillis       int64  `json:"encryptMs"`
	EvaluatorMillis     int64  `json:"evaluatorMs"`
	OperatorsWallMillis int64  `json:"operatorsWallMs"`
	OperatorsSumMillis  int64  `json:"operatorsSumMs"`
	ReleaseMillis       int64  `json:"releaseMs"`
	TotalMillis         int64  `json:"totalMs"`
	CiphertextBytes     int    `json:"ciphertextTransportBytes"`
	PeakSysMegabytes    uint64 `json:"peakSysMb"`
}

func main() {
	inputPath := flag.String("input", "", "JSON file of chain-derived session facts")
	outputPath := flag.String("output", "", "JSON file to write the session result to")
	workRoot := flag.String("work", "", "directory for the operator ledgers")
	flag.Parse()
	if *inputPath == "" || *outputPath == "" || *workRoot == "" {
		fail(fmt.Errorf("-input, -output and -work are required"))
	}
	raw, err := os.ReadFile(*inputPath)
	if err != nil {
		fail(err)
	}
	var inputs chainInputs
	if err := json.Unmarshal(raw, &inputs); err != nil {
		fail(fmt.Errorf("parse input: %w", err))
	}
	output, err := run(inputs, *workRoot)
	if err != nil {
		fail(err)
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*outputPath, append(encoded, '\n'), 0o600); err != nil {
		fail(err)
	}
	fmt.Printf("v5 session complete: sameEconomicAsset=%t policyConflict=%t in %dms\n",
		output.SameEconomicAsset, output.PolicyConflict, output.Timings.TotalMillis)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "v5-session: %v\n", err)
	os.Exit(1)
}

func hex32(value [32]byte) string { return "0x" + hex.EncodeToString(value[:]) }

func parse32(text string) ([32]byte, error) {
	var out [32]byte
	if len(text) >= 2 && text[:2] == "0x" {
		text = text[2:]
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return out, err
	}
	if len(decoded) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(decoded))
	}
	copy(out[:], decoded)
	return out, nil
}

func parameters() (bgv.Parameters, error) {
	return bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP:             []int{60, 60, 60},
		PlaintextModulus: 65537,
	})
}

func run(inputs chainInputs, workRoot string) (*sessionOutput, error) {
	started := time.Now()
	sessionCommitment, err := parse32(inputs.SessionCommitment)
	if err != nil {
		return nil, fmt.Errorf("sessionCommitment: %w", err)
	}
	nullifier, err := parse32(inputs.SessionNullifier)
	if err != nil {
		return nil, fmt.Errorf("sessionNullifier: %w", err)
	}
	sourceA, err := parse32(inputs.SourceRecordCommitmentA)
	if err != nil {
		return nil, fmt.Errorf("sourceRecordCommitmentA: %w", err)
	}
	sourceB, err := parse32(inputs.SourceRecordCommitmentB)
	if err != nil {
		return nil, fmt.Errorf("sourceRecordCommitmentB: %w", err)
	}
	scopeA, err := parse32(inputs.ScopeCommitmentA)
	if err != nil {
		return nil, fmt.Errorf("scopeCommitmentA: %w", err)
	}
	scopeB, err := parse32(inputs.ScopeCommitmentB)
	if err != nil {
		return nil, fmt.Errorf("scopeCommitmentB: %w", err)
	}
	recordA, err := parse32(inputs.GovernanceRecordA)
	if err != nil {
		return nil, fmt.Errorf("governanceRecordA: %w", err)
	}
	recordB, err := parse32(inputs.GovernanceRecordB)
	if err != nil {
		return nil, fmt.Errorf("governanceRecordB: %w", err)
	}
	policyID, err := parse32(inputs.PolicyID)
	if err != nil {
		return nil, fmt.Errorf("policyId: %w", err)
	}

	params, err := parameters()
	if err != nil {
		return nil, err
	}

	ceremonyStart := time.Now()
	material, err := runCeremony(params)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	ceremonyMillis := time.Since(ceremonyStart).Milliseconds()

	evaluator, err := fhe.NewEvaluationRuntime(params, material.publicKey, material.relinKey, material.galoisKeys)
	if err != nil {
		return nil, fmt.Errorf("evaluation runtime: %w", err)
	}
	if evaluator.HoldsThresholdParties() {
		return nil, fmt.Errorf("evaluation runtime holds threshold parties")
	}

	identity, err := fhe.LocalRuntimeIdentity(
		params, material.publicKey, material.relinKey, material.galoisKeys, inputs.EvaluationKeyEpoch,
	)
	if err != nil {
		return nil, fmt.Errorf("runtime identity: %w", err)
	}

	// The two synthetic sides. The plaintext never leaves this process.
	encryptStart := time.Now()
	circuitInputs, err := encryptPair(evaluator, inputs.Conflicting)
	if err != nil {
		return nil, err
	}
	encryptMillis := time.Since(encryptStart).Milliseconds()

	sideDigestA, err := fhe.CircuitSideDigestV5(circuitInputs.PolicyBitsA, circuitInputs.CurrencyBitsA, circuitInputs.ReceivableIDsA)
	if err != nil {
		return nil, err
	}
	sideDigestB, err := fhe.CircuitSideDigestV5(circuitInputs.PolicyBitsB, circuitInputs.CurrencyBitsB, circuitInputs.ReceivableIDsB)
	if err != nil {
		return nil, err
	}
	inputsDigest, err := circuitInputs.Digest()
	if err != nil {
		return nil, err
	}

	// Enrollments, cross-certified against the on-chain session.
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if _, err := evaluator.RegisterEnrollmentIssuer(issuerPublic, now.Add(-time.Hour), now.Add(24*time.Hour)); err != nil {
		return nil, err
	}
	inputCommitmentA := keccakLabel("mordant.v5-input-commitment", sessionCommitment, 0)
	inputCommitmentB := keccakLabel("mordant.v5-input-commitment", sessionCommitment, 1)

	enrollA, err := buildEnrollment(evaluator, issuerPrivate, enrollmentSpec{
		session: sessionCommitment, nullifier: nullifier,
		own: scopeA, counterparty: scopeB, record: recordA, source: sourceA,
		ciphertextDigest: sideDigestA, inputCommitment: inputCommitmentA,
		policyID: policyID, slot: 0, now: now,
		authorizationEpoch: inputs.AuthorizationEpoch, budgetEpoch: inputs.SubmissionBudgetEpoch,
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment A: %w", err)
	}
	enrollB, err := buildEnrollment(evaluator, issuerPrivate, enrollmentSpec{
		session: sessionCommitment, nullifier: nullifier,
		own: scopeB, counterparty: scopeA, record: recordB, source: sourceB,
		ciphertextDigest: sideDigestB, inputCommitment: inputCommitmentB,
		policyID: policyID, slot: 1, now: now,
		authorizationEpoch: inputs.AuthorizationEpoch, budgetEpoch: inputs.SubmissionBudgetEpoch,
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment B: %w", err)
	}
	paired, err := fhe.PairEnrollmentsV5(enrollA, enrollB)
	if err != nil {
		return nil, fmt.Errorf("pair enrollments: %w", err)
	}

	// The coordinator's proposal.
	evaluatorStart := time.Now()
	proposed, err := evaluator.RecomputeCircuitV5(circuitInputs)
	if err != nil {
		return nil, fmt.Errorf("evaluate: %w", err)
	}
	evaluatorMillis := time.Since(evaluatorStart).Milliseconds()
	outputsDigest, err := proposed.Digest()
	if err != nil {
		return nil, err
	}

	descriptor := fhe.ReleaseDescriptorV5{
		SessionCommitment:    sessionCommitment,
		SessionNullifier:     nullifier,
		EnrollmentDigestA:    paired.EnrollmentDigestA,
		EnrollmentDigestB:    paired.EnrollmentDigestB,
		InputsDigest:         inputsDigest,
		OutputsDigest:        outputsDigest,
		CircuitVersion:       fhe.CircuitV5Version,
		RuntimeFingerprint:   identity.Fingerprint(),
		KeyID:                evaluator.KeyIDBytes(),
		ParameterFingerprint: evaluator.ParameterFingerprint(),
		PolicyID:             policyID,
		PolicyVersion:        inputs.PolicyVersion,
		ExpiresAt:            uint64(now.Add(2 * time.Hour).Unix()),
	}

	// Two operators, each its own sealed share, its own durable ledger and its
	// own locally derived runtime identity. They run concurrently.
	operators := make([]*fhe.ReleaseOperatorV5, 0, 2)
	for index := 0; index < 2; index++ {
		threshold, err := fhe.NewThresholdOperator(material.bundles[index])
		if err != nil {
			return nil, err
		}
		ledger, err := fhe.OpenSessionLedger(fmt.Sprintf("%s/operator-%d.db", workRoot, index+1))
		if err != nil {
			return nil, err
		}
		defer ledger.Close()
		operator, err := fhe.NewReleaseOperatorV5(evaluator, threshold, ledger, identity, identity.Fingerprint())
		if err != nil {
			return nil, err
		}
		operators = append(operators, operator)
	}

	request := fhe.OperatorReleaseRequestV5{
		Descriptor:  descriptor,
		EnrollmentA: enrollA,
		EnrollmentB: enrollB,
		Inputs:      circuitInputs,
		Coalition:   [2]uint64{1, 2},
	}

	verdicts := make([]fhe.OperatorVerdictV5, 2)
	errs := make([]error, 2)
	reports := make([]operatorReport, 2)
	operatorsStart := time.Now()
	var group sync.WaitGroup
	for index := 0; index < 2; index++ {
		group.Add(1)
		go func(slot int) {
			defer group.Done()
			verdict, err := operators[slot].VerifyAndRecompute(request, now)
			verdicts[slot], errs[slot] = verdict, err
			passed := true
			for _, check := range verdict.Checks {
				if !check.Passed {
					passed = false
				}
			}
			reports[slot] = operatorReport{
				Point:           uint64(slot + 1),
				ChecksRun:       len(verdict.Checks),
				AllChecksPassed: passed,
				RecomputeMillis: verdict.RecomputeDuration.Milliseconds(),
				OutputDigest:    hex32(verdict.RecomputedOutputsDigest),
			}
		}(index)
	}
	group.Wait()
	operatorsWall := time.Since(operatorsStart).Milliseconds()
	for slot, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("operator %d refused: %w", slot+1, err)
		}
	}
	if verdicts[0].RecomputedOutputsDigest != verdicts[1].RecomputedOutputsDigest {
		return nil, fmt.Errorf("operators recomputed different outputs")
	}
	if verdicts[0].RecomputedOutputsDigest != outputsDigest {
		return nil, fmt.Errorf("operator recomputation differs from the proposal")
	}

	// Release both bits against the operators' own recomputations.
	releaseStart := time.Now()
	sameAsset, policyConflict, statements, err := releaseBoth(params, material, operators[:2], request, verdicts)
	if err != nil {
		return nil, err
	}
	releaseMillis := time.Since(releaseStart).Milliseconds()

	transcript := fhe.ReleaseTranscriptV5{
		SessionCommitment:    sessionCommitment,
		SessionNullifier:     nullifier,
		EnrollmentDigestA:    paired.EnrollmentDigestA,
		EnrollmentDigestB:    paired.EnrollmentDigestB,
		InputsDigest:         inputsDigest,
		OutputsDigest:        outputsDigest,
		CircuitVersion:       fhe.CircuitV5Version,
		KeyID:                evaluator.KeyIDBytes(),
		ParameterFingerprint: evaluator.ParameterFingerprint(),
		PolicyID:             policyID,
		PolicyVersion:        inputs.PolicyVersion,
		Coalition:            [2]uint64{1, 2},
		Threshold:            2,
		OperatorStatements:   statements,
		SameEconomicAsset:    sameAsset,
		PolicyConflict:       policyConflict,
		ReleasedAt:           uint64(time.Now().Unix()),
	}
	transcriptDigest, err := transcript.Digest()
	if err != nil {
		return nil, fmt.Errorf("release transcript: %w", err)
	}

	transport := 0
	for _, ciphertext := range []*rlwe.Ciphertext{
		circuitInputs.PolicyBitsA, circuitInputs.PolicyBitsB,
		circuitInputs.CurrencyBitsA, circuitInputs.CurrencyBitsB,
		circuitInputs.ReceivableIDsA, circuitInputs.ReceivableIDsB,
	} {
		encoded, err := ciphertext.MarshalBinary()
		if err != nil {
			return nil, err
		}
		transport += len(encoded)
	}
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	outcome := uint8(1) // DifferentAsset
	if sameAsset && policyConflict {
		outcome = 3 // SameAssetPolicyConflict
	} else if sameAsset {
		outcome = 2 // SameAssetNoPolicyConflict
	}

	providerProof := keccakLabel("mordant.v5-provider-proof", outputsDigest, 0)
	operatorSet := keccakLabel("mordant.v5-operator-set", transcriptDigest, 0)
	governanceContext := governanceContextOf(recordA, recordB, policyID)

	return &sessionOutput{
		SchemaVersion:              "mordant.v5-session/1",
		SameEconomicAsset:          sameAsset,
		PolicyConflict:             policyConflict,
		Outcome:                    outcome,
		EnrollmentDigestA:          hex32(paired.EnrollmentDigestA),
		EnrollmentDigestB:          hex32(paired.EnrollmentDigestB),
		CiphertextDigestA:          hex32(sideDigestA),
		CiphertextDigestB:          hex32(sideDigestB),
		InputCommitmentA:           hex32(inputCommitmentA),
		InputCommitmentB:           hex32(inputCommitmentB),
		OutputCiphertextCommitment: hex32(outputsDigest),
		InputsDigest:               hex32(inputsDigest),
		CircuitHash:                hex32(identity.CircuitHash()),
		CircuitVersion:             fhe.CircuitV5Version,
		ReleaseLayoutVersion:       fhe.ReleaseLayoutVersion,
		ParameterFingerprint:       hex32(identity.ParameterFingerprint()),
		EvaluationKeyEpoch:         inputs.EvaluationKeyEpoch,
		EvaluationKeyDigest:        hex32(identity.EvaluationKeyDigest()),
		RuntimeFingerprint:         hex32(identity.Fingerprint()),
		ProviderProofCommitment:    hex32(providerProof),
		GovernanceContext:          hex32(governanceContext),
		TranscriptCommitment:       hex32(transcriptDigest),
		OperatorSetDigest:          hex32(operatorSet),
		RecomputationQuorum:        2,
		Runtime:                    identity.Describe(),
		Operators:                  reports,
		Timings: timingReport{
			CeremonyMillis:      ceremonyMillis,
			EncryptMillis:       encryptMillis,
			EvaluatorMillis:     evaluatorMillis,
			OperatorsWallMillis: operatorsWall,
			OperatorsSumMillis:  reports[0].RecomputeMillis + reports[1].RecomputeMillis,
			ReleaseMillis:       releaseMillis,
			TotalMillis:         time.Since(started).Milliseconds(),
			CiphertextBytes:     transport,
			PeakSysMegabytes:    stats.Sys / (1024 * 1024),
		},
	}, nil
}

func governanceContextOf(recordA, recordB, policyID [32]byte) [32]byte {
	return keccakConcat("mordant.v5-governance-context/1", recordA, recordB, policyID)
}
