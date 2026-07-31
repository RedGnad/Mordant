package lattigospike

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestSeparatedThresholdOperatorsReleaseBoundBoolean(t *testing.T) {
	runtime := sharedTestRuntime(t)
	a, b := fixturePair("separated-threshold")
	authorizePair(t, runtime, a, b)
	encA, _, err := runtime.EncryptPledge(a)
	if err != nil {
		t.Fatal(err)
	}
	encB, _, err := runtime.EncryptPledge(b)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0)
	request := fixtureRequest(runtime, "separated-threshold", encA, encB, now)
	decision, _, err := runtime.Evaluate(request, now)
	if err != nil {
		t.Fatal(err)
	}
	contextA := InputCommitmentContext{
		ChainID:       Uint256{0, 0, 0, 31_337},
		Vault:         filled20(0x11),
		PolicyID:      filled32(0x22),
		PolicyVersion: PolicyVersion,
		InputSlot:     0,
		ClientNonce:   Uint256{0, 0, 0, 501},
	}
	contextB := contextA
	contextB.InputSlot = 1
	contextB.ClientNonce = Uint256{0, 0, 0, 502}
	inputA, err := runtime.CanonicalInputCommitment(encA, contextA)
	if err != nil {
		t.Fatal(err)
	}
	inputB, err := runtime.CanonicalInputCommitment(encB, contextB)
	if err != nil {
		t.Fatal(err)
	}
	configs, manifest, err := runtime.ProvisionThresholdOperators()
	if err != nil {
		t.Fatal(err)
	}
	operators := make([]*ThresholdOperator, 2)
	for i := range operators {
		operators[i], err = NewThresholdOperator(configs[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	binding, err := ProtocolBindingDigest(runtime.KeyIDBytes(), ProtocolCollectiveKeySwitchToZero, decision.Conflict)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := ReleaseDescriptor{
		SessionID:                  sha256.Sum256([]byte("threshold-session-separated")),
		KeyID:                      runtime.KeyIDBytes(),
		ParameterFingerprint:       runtime.ParameterFingerprint(),
		PolicyID:                   contextA.PolicyID,
		PolicyVersion:              PolicyVersion,
		InputCommitmentA:           inputA,
		InputCommitmentB:           inputB,
		ResultNonce:                Uint256{0, 0, 0, 77},
		ValidUntil:                 uint64(now.Add(time.Hour).Unix()),
		ResultCiphertextCommitment: decision.ResultCiphertextCommitment,
		ProtocolBinding:            binding,
		Coalition:                  [2]uint64{manifest.Operators[0].Point, manifest.Operators[1].Point},
	}
	descriptorWire, err := descriptor.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decodedDescriptor, err := UnmarshalReleaseDescriptor(descriptorWire)
	if err != nil || decodedDescriptor != descriptor {
		t.Fatalf("release descriptor did not round-trip: %+v %v", decodedDescriptor, err)
	}
	if _, err := UnmarshalReleaseDescriptor(append(descriptorWire, 0)); !errors.Is(err, ErrInvalidReleaseDescriptor) {
		t.Fatalf("trailing descriptor bytes accepted: %v", err)
	}
	zeroNonce := descriptor
	zeroNonce.ResultNonce = Uint256{}
	if _, err := zeroNonce.MarshalBinary(); !errors.Is(err, ErrInvalidReleaseDescriptor) {
		t.Fatalf("zero result nonce accepted: %v", err)
	}
	responses := make([]ThresholdReleaseResponse, 2)
	for i := range responses {
		responses[i], err = operators[i].GenerateReleaseShare(descriptor, decision.Conflict)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := responses[i].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		responses[i], err = UnmarshalThresholdReleaseResponse(wire)
		if err != nil {
			t.Fatal(err)
		}
	}
	runtime.DetachThresholdParties()
	if _, _, err := runtime.DecryptThresholdWithCoalition(decision, 0, 1); !errors.Is(err, ErrInsufficientShare) {
		t.Fatalf("coordinator retained local decrypt capability: %v", err)
	}
	confirmed, transcript, err := CombineZeroKeySwitchShares(runtime.Params, descriptor, manifest, decision.Conflict, responses)
	if err != nil || !confirmed || transcript == ([32]byte{}) {
		t.Fatalf("separated release failed: confirmed=%t transcript=%x err=%v", confirmed, transcript, err)
	}
	keyCommitment, err := ThresholdKeyCommitment(manifest)
	if err != nil || keyCommitment == ([32]byte{}) {
		t.Fatalf("invalid threshold key commitment: %x %v", keyCommitment, err)
	}
	policyCommitment, err := PolicyCircuitCommitment(runtime.ParameterFingerprint(), descriptor.PolicyID, PolicyVersion)
	if err != nil || policyCommitment == ([32]byte{}) {
		t.Fatalf("invalid policy commitment: %x %v", policyCommitment, err)
	}
	proofCommitment, err := ProviderProofCommitment(ProviderProof{
		ResultCiphertextCommitment:    decision.ResultCiphertextCommitment,
		ThresholdTranscriptCommitment: transcript,
		ThresholdSessionID:            descriptor.SessionID,
		ThresholdKeyCommitment:        keyCommitment,
		PolicyCircuitCommitment:       policyCommitment,
	})
	if err != nil || proofCommitment == ([32]byte{}) {
		t.Fatalf("invalid provider proof commitment: %x %v", proofCommitment, err)
	}

	tampered := append([]ThresholdReleaseResponse(nil), responses...)
	tampered[0].Signature[0] ^= 0x80
	if _, _, err := CombineZeroKeySwitchShares(runtime.Params, descriptor, manifest, decision.Conflict, tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered operator statement accepted: %v", err)
	}
}

func TestProtocolBindingUsesC1RatherThanWholeCiphertext(t *testing.T) {
	runtime := sharedTestRuntime(t)
	a, b := fixturePair("protocol-binding-c1")
	decision := evaluateFixture(t, runtime, "protocol-binding-c1", a, b, IdentityPublicCommitment)
	originalBinding, err := ProtocolBindingDigest(runtime.KeyIDBytes(), ProtocolCollectiveKeySwitchToZero, decision.Conflict)
	if err != nil {
		t.Fatal(err)
	}
	originalWhole, err := ciphertextCommitment(decision.Conflict)
	if err != nil {
		t.Fatal(err)
	}

	changedC0 := decision.Conflict.CopyNew()
	changedC0.Value[0].Coeffs[0][0] ^= 1
	changedWhole, err := ciphertextCommitment(changedC0)
	if err != nil {
		t.Fatal(err)
	}
	changedBinding, err := ProtocolBindingDigest(runtime.KeyIDBytes(), ProtocolCollectiveKeySwitchToZero, changedC0)
	if err != nil {
		t.Fatal(err)
	}
	if changedWhole == originalWhole {
		t.Fatal("c0 mutation did not change whole-ciphertext commitment")
	}
	if changedBinding != originalBinding {
		t.Fatal("c0 mutation bypassed the c1 one-shot binding")
	}

	changedC1 := decision.Conflict.CopyNew()
	changedC1.Value[1].Coeffs[0][0] ^= 1
	changedC1Binding, err := ProtocolBindingDigest(runtime.KeyIDBytes(), ProtocolCollectiveKeySwitchToZero, changedC1)
	if err != nil {
		t.Fatal(err)
	}
	if changedC1Binding == originalBinding {
		t.Fatal("c1 mutation was not bound")
	}
}
