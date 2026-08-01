package lattigospike

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// End-to-end evidence for external audit finding H-03 and for the owner's
// Gates 2, 3 and 4. Every test here runs a real ceremony, real encryption and a
// real 2-of-3 threshold release.

type v5ReleaseHarness struct {
	fixture   *ceremonyFixture
	operators []*ReleaseOperatorV5
	inputs    CircuitInputsV5
	enrollA   *SignedCiphertextEnrollmentV5
	enrollB   *SignedCiphertextEnrollmentV5
	paired    PairedEnrollmentsV5
	outputs   *CircuitOutputsV5
	request   OperatorReleaseRequestV5
	now       time.Time
}

var (
	v5CeremonyOnce sync.Once
	v5Ceremony     *ceremonyFixture
)

// The ceremony is the expensive part and is identical for every test here, so
// it is built once. Only the pledges and enrollments differ per test, and each
// test still gets its own operators, ledgers and session commitment.
func sharedV5Ceremony(t *testing.T) *ceremonyFixture {
	t.Helper()
	v5CeremonyOnce.Do(func() { v5Ceremony = runCeremony(t) })
	if v5Ceremony == nil {
		t.Fatal("shared V5 ceremony unavailable")
	}
	return v5Ceremony
}

func newV5ReleaseHarness(t *testing.T, conflicting bool) *v5ReleaseHarness {
	t.Helper()
	fixture := sharedV5Ceremony(t)
	now := time.Now()

	label := "v5-release"
	if !conflicting {
		label = "v5-release-distinct"
	}
	pledgeA, pledgeB := fixturePair(label)
	// Full FHE identity: the strict identifier is compared under encryption, so
	// the public commitment must be absent on both sides.
	pledgeA.ReceivableCommitment = [32]byte{}
	pledgeB.ReceivableCommitment = [32]byte{}
	if !conflicting {
		pledgeB.ReceivableID = sha256.Sum256([]byte("a-different-receivable"))
	}
	cipherA, _, err := fixture.runtime.EncryptPledgeForMode(pledgeA, IdentityFullFHE256)
	if err != nil {
		t.Fatal(err)
	}
	cipherB, _, err := fixture.runtime.EncryptPledgeForMode(pledgeB, IdentityFullFHE256)
	if err != nil {
		t.Fatal(err)
	}
	inputs := CircuitInputsV5{
		PolicyBitsA: cipherA.PolicyBits, PolicyBitsB: cipherB.PolicyBits,
		CurrencyBitsA: cipherA.CurrencyBits, CurrencyBitsB: cipherB.CurrencyBits,
		ReceivableIDsA: cipherA.ReceivableIDBits, ReceivableIDsB: cipherB.ReceivableIDBits,
	}

	// One ingress issuer, trusted by every operator's own runtime.
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runtime.RegisterEnrollmentIssuer(issuerPublic, now.Add(-time.Hour), now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	sideDigestA, err := CircuitSideDigestV5(inputs.PolicyBitsA, inputs.CurrencyBitsA, inputs.ReceivableIDsA)
	if err != nil {
		t.Fatal(err)
	}
	sideDigestB, err := CircuitSideDigestV5(inputs.PolicyBitsB, inputs.CurrencyBitsB, inputs.ReceivableIDsB)
	if err != nil {
		t.Fatal(err)
	}

	sessionCommitment := label32("v5-session-commitment-" + label)
	nullifier := label32("v5-session-nullifier-" + label)
	scopeA, scopeB := label32("v5-scope-a"), label32("v5-scope-b")

	build := func(side string, own, counterparty, ciphertextDigest [32]byte, slot uint8) *SignedCiphertextEnrollmentV5 {
		claim := AuthorizationClaim{
			SubjectCommitment: label32("v5-subject-" + side),
			Role:              label32("v5-role"),
			Vault:             [20]byte{0xA1, 0xB2, 0xC3},
			PolicyID:          label32("v5-policy"),
			PolicyVersion:     PolicyVersion,
			ValidUntil:        uint64(now.Add(48 * time.Hour).Unix()),
			Nonce:             Uint256{0, 0, 0, uint64(slot) + 1},
		}
		commitment, err := enrollmentAuthorizationCommitment(claim, fixture.runtime.KeyIDBytes())
		if err != nil {
			t.Fatal(err)
		}
		signed, err := SignEnrollmentV5(CiphertextEnrollmentV5{
			Binding: SessionBindingV5{
				SessionCommitment:           sessionCommitment,
				SessionNullifier:            nullifier,
				OwnScopeCommitment:          own,
				CounterpartyScopeCommitment: counterparty,
				GovernanceRecord:            label32("v5-governance-" + side),
				SourceRecordCommitment:      label32("v5-source-" + side),
				AuthorizationEpoch:          1,
				SubmissionBudgetEpoch:       1,
				InputSlot:                   slot,
			},
			CiphertextDigest:        ciphertextDigest,
			InputCommitment:         label32("v5-input-" + side),
			KeyID:                   fixture.runtime.KeyIDBytes(),
			ParameterFingerprint:    fixture.runtime.ParameterFingerprint(),
			PolicyID:                label32("v5-policy"),
			PolicyVersion:           PolicyVersion,
			IdentityMode:            IdentityFullFHE256,
			AuthorizationClaim:      claim,
			AuthorizationCommitment: commitment,
			IssuedAt:                uint64(now.Add(-time.Minute).Unix()),
			ValidUntil:              uint64(now.Add(12 * time.Hour).Unix()),
			Nonce:                   label32("v5-nonce-" + side),
		}, issuerPrivate)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	enrollA := build("a", scopeA, scopeB, sideDigestA, 0)
	enrollB := build("b", scopeB, scopeA, sideDigestB, 1)
	paired, err := PairEnrollmentsV5(enrollA, enrollB)
	if err != nil {
		t.Fatal(err)
	}

	// The coordinator's proposed outputs.
	outputs, err := fixture.runtime.RecomputeCircuitV5(inputs)
	if err != nil {
		t.Fatal(err)
	}
	outputsDigest, err := outputs.Digest()
	if err != nil {
		t.Fatal(err)
	}
	inputsDigest, err := inputs.Digest()
	if err != nil {
		t.Fatal(err)
	}

	// Each operator is its own process in production. Here each gets its own
	// evaluation runtime, its own sealed share and its own durable ledger.
	operators := make([]*ReleaseOperatorV5, 0, len(fixture.bundles))
	for index, bundle := range fixture.bundles {
		threshold, err := NewThresholdOperator(bundle)
		if err != nil {
			t.Fatal(err)
		}
		ledger, err := OpenSessionLedger(filepath.Join(t.TempDir(), "operator.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ledger.Close() })
		if _, err := fixture.runtime.RegisterEnrollmentIssuer(issuerPublic, now.Add(-time.Hour), now.Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		publicKey, relinKey, galoisKeys, err := fixture.aggregator.CollectiveKeys()
		if err != nil {
			t.Fatal(err)
		}
		identity, err := LocalRuntimeIdentity(fixture.params, publicKey, relinKey, galoisKeys, 1)
		if err != nil {
			t.Fatal(err)
		}
		operator, err := NewReleaseOperatorV5(
			fixture.runtime, threshold, ledger, identity, identity.Fingerprint(),
		)
		if err != nil {
			t.Fatalf("operator %d: %v", index, err)
		}
		operators = append(operators, operator)
	}

	runtimeFingerprint := operators[0].RuntimeIdentity().Fingerprint()
	request := OperatorReleaseRequestV5{
		Descriptor: ReleaseDescriptorV5{
			SessionCommitment:    sessionCommitment,
			SessionNullifier:     nullifier,
			EnrollmentDigestA:    paired.EnrollmentDigestA,
			EnrollmentDigestB:    paired.EnrollmentDigestB,
			InputsDigest:         inputsDigest,
			OutputsDigest:        outputsDigest,
			CircuitVersion:       CircuitV5Version,
			RuntimeFingerprint:   runtimeFingerprint,
			KeyID:                fixture.runtime.KeyIDBytes(),
			ParameterFingerprint: fixture.runtime.ParameterFingerprint(),
			PolicyID:             label32("v5-policy"),
			PolicyVersion:        PolicyVersion,
			ExpiresAt:            uint64(now.Add(time.Hour).Unix()),
		},
		EnrollmentA: enrollA,
		EnrollmentB: enrollB,
		Inputs:      inputs,
		Coalition:   [2]uint64{1, 2},
	}

	return &v5ReleaseHarness{
		fixture: fixture, operators: operators, inputs: inputs,
		enrollA: enrollA, enrollB: enrollB, paired: paired,
		outputs: outputs, request: request, now: now,
	}
}

/* ------------------------------- Gate 3: operator input validation ------- */

func TestAnOperatorRunsEveryCheckBeforeReleasing(t *testing.T) {
	harness := newV5ReleaseHarness(t, true)
	verdict, err := harness.operators[0].VerifyAndRecompute(harness.request, harness.now)
	if err != nil {
		t.Fatalf("operator refused a well-formed release: %v", err)
	}
	if !verdict.Accepted {
		t.Fatal("operator did not accept")
	}
	expected := []string{
		"descriptor-shape", "circuit-version", "key-epoch", "parameter-fingerprint",
		"descriptor-freshness", "enrollment-signatures", "bilateral-pairing",
		"descriptor-session-binding", "input-digests", "inputs-digest",
		"coalition-membership", "operator-one-shot", "runtime-fingerprint",
		"local-recomputation",
	}
	if len(verdict.Checks) != len(expected) {
		t.Fatalf("expected %d checks, got %d", len(expected), len(verdict.Checks))
	}
	for index, name := range expected {
		if verdict.Checks[index].Name != name || !verdict.Checks[index].Passed {
			t.Fatalf("check %d: got %q passed=%t, want %q passed", index, verdict.Checks[index].Name, verdict.Checks[index].Passed, name)
		}
	}
	t.Logf("operator recomputation took %s", verdict.RecomputeDuration)
}

// THE H-03 test. A coordinator proposes an output the operator did not compute.
func TestAnOperatorRefusesACiphertextItDidNotCompute(t *testing.T) {
	harness := newV5ReleaseHarness(t, true)

	// The evaluator substitutes a different ciphertext for release. In V4 this
	// was accepted, because the descriptor's own digest field described it.
	substituted := harness.inputs.ReceivableIDsA
	forged := CircuitOutputsV5{SameEconomicAsset: substituted, PolicyConflict: substituted}
	forgedDigest, err := forged.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := harness.request
	request.Descriptor.OutputsDigest = forgedDigest

	verdict, err := harness.operators[0].VerifyAndRecompute(request, harness.now)
	if !errors.Is(err, ErrOperatorRecomputationMismatch) {
		t.Fatalf("expected ErrOperatorRecomputationMismatch, got %v", err)
	}
	if verdict.Accepted {
		t.Fatal("operator accepted a ciphertext it did not compute")
	}
	last := verdict.Checks[len(verdict.Checks)-1]
	if last.Name != "local-recomputation" || last.Passed {
		t.Fatalf("recomputation check did not fail: %+v", last)
	}
}

func TestAnOperatorRefusesSubstitutedInputCiphertexts(t *testing.T) {
	harness := newV5ReleaseHarness(t, true)
	request := harness.request
	// Swap in a ciphertext the enrollment never authorized.
	request.Inputs.ReceivableIDsB = harness.inputs.ReceivableIDsA

	if _, err := harness.operators[0].VerifyAndRecompute(request, harness.now); !errors.Is(err, ErrOperatorCheckFailed) {
		t.Fatalf("expected ErrOperatorCheckFailed, got %v", err)
	}
}

func TestAnOperatorRefusesADescriptorForAnotherSession(t *testing.T) {
	harness := newV5ReleaseHarness(t, true)
	request := harness.request
	request.Descriptor.SessionCommitment = label32("some-other-session")

	if _, err := harness.operators[0].VerifyAndRecompute(request, harness.now); !errors.Is(err, ErrOperatorCheckFailed) {
		t.Fatalf("expected ErrOperatorCheckFailed, got %v", err)
	}
}

func TestAnOperatorRefusesAnExpiredDescriptor(t *testing.T) {
	harness := newV5ReleaseHarness(t, true)
	if _, err := harness.operators[0].VerifyAndRecompute(harness.request, harness.now.Add(48*time.Hour)); !errors.Is(err, ErrOperatorCheckFailed) {
		t.Fatalf("expected ErrOperatorCheckFailed, got %v", err)
	}
}

func TestAnOperatorOutsideTheCoalitionRefuses(t *testing.T) {
	harness := newV5ReleaseHarness(t, true)
	// Operator index 2 is point 3, which is not in coalition {1,2}.
	if _, err := harness.operators[2].VerifyAndRecompute(harness.request, harness.now); !errors.Is(err, ErrOperatorCheckFailed) {
		t.Fatalf("expected ErrOperatorCheckFailed, got %v", err)
	}
}

// A coordinator claiming a build this operator is not running. Recomputation
// across builds is not a comparison, so it is refused rather than attempted.
func TestAnOperatorRefusesADescriptorForAnotherRuntime(t *testing.T) {
	harness := newV5ReleaseHarness(t, true)
	request := harness.request
	request.Descriptor.RuntimeFingerprint = label32("some-other-build")
	if _, err := harness.operators[0].VerifyAndRecompute(request, harness.now); !errors.Is(err, ErrOperatorCheckFailed) {
		t.Fatalf("expected ErrOperatorCheckFailed, got %v", err)
	}
}

func TestAnOperatorRefusesAnUnknownCircuitVersion(t *testing.T) {
	harness := newV5ReleaseHarness(t, true)
	request := harness.request
	request.Descriptor.CircuitVersion = 99
	if _, err := harness.operators[0].VerifyAndRecompute(request, harness.now); !errors.Is(err, ErrOperatorCheckFailed) {
		t.Fatalf("expected ErrOperatorCheckFailed, got %v", err)
	}
}

/* --------------------------- Gate 2: release-safe canonical output ------- */

func TestTheTwoReleasedBitsDecryptToACanonicalVector(t *testing.T) {
	harness := newV5ReleaseHarness(t, true)
	sameAsset, conflict := harness.release(t)
	// The pair was constructed to be the same receivable with conflicting terms.
	if !sameAsset {
		t.Fatal("expected sameEconomicAsset true")
	}
	if !conflict {
		t.Fatal("expected policyConflict true")
	}
}

func TestADifferentReceivableReleasesFalseOnBothBits(t *testing.T) {
	harness := newV5ReleaseHarness(t, false)
	sameAsset, conflict := harness.release(t)
	if sameAsset {
		t.Fatal("expected sameEconomicAsset false for different receivables")
	}
	// This is the H-02 separation: the policy conjunction has identity equality
	// as a factor, so a different receivable can never report a conflict.
	if conflict {
		t.Fatal("policy conflict reported for different receivables")
	}
}

// A non-canonical plaintext must fail closed rather than be read for slot 0.
func TestANonCanonicalReleaseVectorIsRefused(t *testing.T) {
	canonical := make([]uint64, 32768)
	canonical[0] = 1
	if err := requireCanonicalReleaseVector(canonical); err != nil {
		t.Fatalf("canonical vector refused: %v", err)
	}

	leaking := make([]uint64, 32768)
	leaking[0] = 1
	leaking[7] = 42
	if err := requireCanonicalReleaseVector(leaking); !errors.Is(err, ErrReleaseSlotsNotCanonical) {
		t.Fatalf("expected ErrReleaseSlotsNotCanonical, got %v", err)
	}

	nonBoolean := make([]uint64, 32768)
	nonBoolean[0] = 5
	if err := requireCanonicalReleaseVector(nonBoolean); !errors.Is(err, ErrReleaseSlotsNotCanonical) {
		t.Fatalf("expected ErrReleaseSlotsNotCanonical, got %v", err)
	}
}

// release runs the full 2-of-3 threshold release for both bits and returns the
// two Booleans. Every share is generated against the operator's OWN
// recomputation.
func (harness *v5ReleaseHarness) release(t *testing.T) (bool, bool) {
	t.Helper()
	verdicts := make([]OperatorVerdictV5, 0, 2)
	sameShares := make([]ThresholdReleaseResponse, 0, 2)
	conflictShares := make([]ThresholdReleaseResponse, 0, 2)
	var outputs *CircuitOutputsV5

	for _, operator := range harness.operators[:2] {
		verdict, err := operator.VerifyAndRecompute(harness.request, harness.now)
		if err != nil {
			t.Fatalf("operator verification: %v", err)
		}
		// Every operator must have recomputed the SAME bytes. Gate 1, enforced
		// inside the protocol rather than only measured by the probe.
		if len(verdicts) > 0 && verdict.RecomputedOutputsDigest != verdicts[0].RecomputedOutputsDigest {
			t.Fatal("two operators recomputed different outputs")
		}
		verdicts = append(verdicts, verdict)
		outputs = verdict.outputs

		same, conflict, err := operator.ReleaseShares(harness.request, verdict, harness.now)
		if err != nil {
			t.Fatalf("release shares: %v", err)
		}
		sameShares = append(sameShares, same)
		conflictShares = append(conflictShares, conflict)
	}

	sameAsset := harness.combine(t, outputs.SameEconomicAsset, sameShares, 0)
	conflict := harness.combine(t, outputs.PolicyConflict, conflictShares, 1)
	return sameAsset, conflict
}

func (harness *v5ReleaseHarness) combine(t *testing.T, ciphertext *rlwe.Ciphertext, shares []ThresholdReleaseResponse, slot uint8) bool {
	t.Helper()
	commitment, err := ciphertextCommitment(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ProtocolBindingDigest(harness.fixture.keyID, ProtocolCollectiveKeySwitchToZero, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := ReleaseDescriptor{
		SessionID:                  releaseSlotSessionID(harness.request.Descriptor.SessionCommitment, slot),
		KeyID:                      harness.request.Descriptor.KeyID,
		ParameterFingerprint:       harness.request.Descriptor.ParameterFingerprint,
		PolicyID:                   harness.request.Descriptor.PolicyID,
		PolicyVersion:              harness.request.Descriptor.PolicyVersion,
		InputCommitmentA:           harness.request.Descriptor.EnrollmentDigestA,
		InputCommitmentB:           harness.request.Descriptor.EnrollmentDigestB,
		ResultNonce:                Uint256{0, 0, 0, uint64(slot) + 1},
		ValidUntil:                 harness.request.Descriptor.ExpiresAt,
		ResultCiphertextCommitment: commitment,
		ProtocolBinding:            binding,
		Coalition:                  harness.request.Coalition,
	}
	// CombineReleaseBitV5 asserts the COMPLETE decrypted slot vector, so this
	// call failing is itself the Gate 2 assertion.
	confirmed, transcript, err := CombineReleaseBitV5(
		harness.fixture.params, descriptor, harness.fixture.manifest, ciphertext, shares)
	if err != nil {
		t.Fatalf("combine slot %d: %v", slot, err)
	}
	if transcript == ([32]byte{}) {
		t.Fatal("empty threshold transcript")
	}
	return confirmed
}

/* ------------------------------- Gate 4: release transcript -------------- */

func TestTheReleaseTranscriptBindsEveryRequiredField(t *testing.T) {
	base := ReleaseTranscriptV5{
		SessionCommitment:    label32("session"),
		SessionNullifier:     label32("nullifier"),
		EnrollmentDigestA:    label32("enroll-a"),
		EnrollmentDigestB:    label32("enroll-b"),
		InputsDigest:         label32("inputs"),
		OutputsDigest:        label32("outputs"),
		CircuitVersion:       CircuitV5Version,
		KeyID:                label32("key"),
		ParameterFingerprint: label32("params"),
		PolicyID:             label32("policy"),
		PolicyVersion:        PolicyVersion,
		Coalition:            [2]uint64{1, 2},
		Threshold:            2,
		OperatorStatements:   [][32]byte{label32("statement-1"), label32("statement-2")},
		SameEconomicAsset:    true,
		PolicyConflict:       true,
		ReleasedAt:           uint64(time.Now().Unix()),
	}
	baseline, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ReleaseTranscriptV5){
		"session commitment":  func(x *ReleaseTranscriptV5) { x.SessionCommitment = label32("z") },
		"session nullifier":   func(x *ReleaseTranscriptV5) { x.SessionNullifier = label32("z") },
		"enrollment A":        func(x *ReleaseTranscriptV5) { x.EnrollmentDigestA = label32("z") },
		"enrollment B":        func(x *ReleaseTranscriptV5) { x.EnrollmentDigestB = label32("z") },
		"inputs digest":       func(x *ReleaseTranscriptV5) { x.InputsDigest = label32("z") },
		"outputs digest":      func(x *ReleaseTranscriptV5) { x.OutputsDigest = label32("z") },
		"key id":              func(x *ReleaseTranscriptV5) { x.KeyID = label32("z") },
		"parameters":          func(x *ReleaseTranscriptV5) { x.ParameterFingerprint = label32("z") },
		"policy id":           func(x *ReleaseTranscriptV5) { x.PolicyID = label32("z") },
		"coalition":           func(x *ReleaseTranscriptV5) { x.Coalition = [2]uint64{1, 3} },
		"operator statements": func(x *ReleaseTranscriptV5) { x.OperatorStatements[0] = label32("z") },
		"released bits":       func(x *ReleaseTranscriptV5) { x.PolicyConflict = false },
		"released at":         func(x *ReleaseTranscriptV5) { x.ReleasedAt++ },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := base
			mutated.OperatorStatements = append([][32]byte(nil), base.OperatorStatements...)
			mutate(&mutated)
			digest, err := mutated.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if digest == baseline {
				t.Fatalf("%s is not bound into the release transcript", name)
			}
		})
	}
}

// The impossible state must not be representable in a transcript either.
func TestATranscriptCannotClaimAConflictWithoutAnAssetMatch(t *testing.T) {
	transcript := ReleaseTranscriptV5{
		SessionCommitment:    label32("session"),
		SessionNullifier:     label32("nullifier"),
		EnrollmentDigestA:    label32("enroll-a"),
		EnrollmentDigestB:    label32("enroll-b"),
		InputsDigest:         label32("inputs"),
		OutputsDigest:        label32("outputs"),
		CircuitVersion:       CircuitV5Version,
		KeyID:                label32("key"),
		ParameterFingerprint: label32("params"),
		PolicyID:             label32("policy"),
		PolicyVersion:        PolicyVersion,
		Coalition:            [2]uint64{1, 2},
		Threshold:            2,
		OperatorStatements:   [][32]byte{label32("s1"), label32("s2")},
		SameEconomicAsset:    false,
		PolicyConflict:       true,
		ReleasedAt:           uint64(time.Now().Unix()),
	}
	if _, err := transcript.Digest(); err == nil {
		t.Fatal("a transcript claimed a policy conflict without an asset match")
	}
}
