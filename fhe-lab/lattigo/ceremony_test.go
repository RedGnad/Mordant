package lattigospike

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// ceremonyFixture is one complete dealerless run. Each operator is a distinct
// CeremonyOperatorState with its own local secret; nothing in this fixture ever
// places two operators' secret material in the same variable.
type ceremonyFixture struct {
	params     bgv.Parameters
	roster     CeremonyRoster
	operators  []*CeremonyOperatorState
	aggregator *CeremonyAggregator
	digests    CeremonyKeyDigests
	bundles    [][]byte
	manifest   ThresholdManifest
	runtime    *Runtime
	nonce      uint64
	keyID      [32]byte
}

func ceremonyParameters(t *testing.T) bgv.Parameters {
	t.Helper()
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP:             []int{60, 60, 60},
		PlaintextModulus: 65537,
	})
	if err != nil {
		t.Fatalf("parameters: %v", err)
	}
	return params
}

func newCeremonyRoster(t *testing.T, params bgv.Parameters, keys []ed25519.PrivateKey) CeremonyRoster {
	t.Helper()
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var ceremonyID [32]byte
	if _, err := rand.Read(ceremonyID[:]); err != nil {
		t.Fatal(err)
	}
	operators := make([]CeremonyOperatorIdentity, len(keys))
	for index, key := range keys {
		operators[index] = CeremonyOperatorIdentity{Point: uint64(index + 1)}
		copy(operators[index].SigningPublicKey[:], key.Public().(ed25519.PublicKey))
	}
	return CeremonyRoster{
		ParameterFingerprint: sha256.Sum256(parameterBytes),
		Threshold:            2,
		CeremonyID:           ceremonyID,
		KeyEpoch:             1,
		Operators:            operators,
	}
}

// runCeremony executes the full dealerless protocol. It is deliberately written
// as an explicit round-by-round driver so that a missing or reordered round
// shows up as a test failure rather than as a silently different key.
func runCeremony(t *testing.T) *ceremonyFixture {
	t.Helper()
	params := ceremonyParameters(t)
	keys := make([]ed25519.PrivateKey, 3)
	for index := range keys {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[index] = key
	}
	roster := newCeremonyRoster(t, params, keys)
	operators := make([]*CeremonyOperatorState, 3)
	for index := range operators {
		state, err := NewCeremonyOperatorState(params, roster, uint64(index+1), keys[index])
		if err != nil {
			t.Fatalf("operator %d setup: %v", index+1, err)
		}
		operators[index] = state
	}
	aggregator, err := NewCeremonyAggregator(params, roster)
	if err != nil {
		t.Fatal(err)
	}

	// Round 1: public CRS contributions, exchanged among all operators and the
	// aggregator so every participant derives the identical CRS stream.
	for _, source := range operators {
		contribution := source.CRSContribution()
		if err := aggregator.AcceptCRSContribution(source.Point(), contribution); err != nil {
			t.Fatal(err)
		}
		for _, target := range operators {
			if target.Point() == source.Point() {
				continue
			}
			if err := target.AcceptCRSContribution(source.Point(), contribution); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, operator := range operators {
		if err := operator.SealCRS(); err != nil {
			t.Fatal(err)
		}
	}
	if err := aggregator.SealCRS(); err != nil {
		t.Fatal(err)
	}
	for _, operator := range operators {
		if operator.CRSCommitment() != aggregator.CRSCommitment() {
			t.Fatal("operators and aggregator disagree on the collaborative CRS")
		}
	}

	// Round 2: private pairwise Shamir re-sharing. The aggregator is not a
	// participant and never observes these messages.
	for _, sender := range operators {
		for _, recipient := range operators {
			share, err := sender.PrivateShareFor(recipient.Point())
			if err != nil {
				t.Fatalf("private share %d->%d: %v", sender.Point(), recipient.Point(), err)
			}
			wire, err := share.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := UnmarshalCeremonyPrivateShare(wire)
			if err != nil {
				t.Fatal(err)
			}
			if err := recipient.AcceptPrivateShare(decoded); err != nil {
				t.Fatalf("accept share %d->%d: %v", sender.Point(), recipient.Point(), err)
			}
		}
	}
	for _, operator := range operators {
		if err := operator.SealThresholdShare(); err != nil {
			t.Fatal(err)
		}
	}

	// Round 3: collective public key, all three operators contributing.
	for _, operator := range operators {
		wire, err := operator.PublicKeyShare()
		if err != nil {
			t.Fatal(err)
		}
		if err := aggregator.AcceptPublicKeyShare(operator.Point(), wire); err != nil {
			t.Fatal(err)
		}
	}

	// Round 4 and 5: two-round collective relinearization key.
	for _, operator := range operators {
		wire, err := operator.RelinearizationShareRoundOne()
		if err != nil {
			t.Fatal(err)
		}
		if err := aggregator.AcceptRelinearizationShareRoundOne(operator.Point(), wire); err != nil {
			t.Fatal(err)
		}
	}
	combined, err := aggregator.AggregatedRelinearizationRoundOne()
	if err != nil {
		t.Fatal(err)
	}
	for _, operator := range operators {
		wire, err := operator.RelinearizationShareRoundTwo(combined)
		if err != nil {
			t.Fatal(err)
		}
		if err := aggregator.AcceptRelinearizationShareRoundTwo(operator.Point(), wire); err != nil {
			t.Fatal(err)
		}
	}

	// Round 6: one collective Galois key per rotation the circuit needs.
	for {
		element, pending := aggregator.CurrentGaloisElement()
		if !pending {
			break
		}
		for _, operator := range operators {
			wire, err := operator.GaloisShare(element)
			if err != nil {
				t.Fatalf("galois share for %d: %v", element, err)
			}
			if err := aggregator.AcceptGaloisShare(operator.Point(), wire); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !aggregator.Complete() {
		t.Fatal("ceremony did not complete")
	}

	publicKey, relinKey, galoisKeys, err := aggregator.CollectiveKeys()
	if err != nil {
		t.Fatal(err)
	}
	policyID := sha256.Sum256([]byte("ceremony-policy"))
	digests, err := aggregator.KeyDigests(policyID, PolicyVersion)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := CollectiveKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Round 7: every operator erases its transient secrets and countersigns.
	attestations := make([]CeremonyAttestation, 0, len(operators))
	bundles := make([][]byte, 0, len(operators))
	publics := make([]ThresholdOperatorPublic, 0, len(operators))
	for _, operator := range operators {
		attestation, err := operator.Seal(digests)
		if err != nil {
			t.Fatal(err)
		}
		if operator.HoldsLocalSecretKey() {
			t.Fatalf("operator %d retained its local RLWE secret after seal", operator.Point())
		}
		attestations = append(attestations, attestation)
		bundle, err := operator.SealedOperatorBundle(keyID)
		if err != nil {
			t.Fatal(err)
		}
		bundles = append(bundles, bundle)
		imported, err := NewThresholdOperator(bundle)
		if err != nil {
			t.Fatal(err)
		}
		publics = append(publics, imported.Public())
	}
	if err := VerifyCeremonyAttestations(roster, digests, attestations); err != nil {
		t.Fatalf("manifest attestations: %v", err)
	}

	runtime, err := NewEvaluationRuntime(params, publicKey, relinKey, galoisKeys)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.HoldsThresholdParties() {
		t.Fatal("evaluation runtime holds threshold parties")
	}
	return &ceremonyFixture{
		params:     params,
		roster:     roster,
		operators:  operators,
		aggregator: aggregator,
		digests:    digests,
		bundles:    bundles,
		manifest: ThresholdManifest{
			KeyID:                keyID,
			ParameterFingerprint: roster.ParameterFingerprint,
			Threshold:            roster.Threshold,
			Operators:            publics,
		},
		runtime: runtime,
		keyID:   keyID,
	}
}

// releaseWithCoalition drives one 2-of-3 release against the sealed bundles.
func (fixture *ceremonyFixture) releaseWithCoalition(t *testing.T, decision *EncryptedDecision, inputA, inputB [32]byte, first, second int, sessionLabel string) (bool, error) {
	t.Helper()
	operatorFirst, err := NewThresholdOperator(fixture.bundles[first])
	if err != nil {
		t.Fatal(err)
	}
	operatorSecond, err := NewThresholdOperator(fixture.bundles[second])
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ProtocolBindingDigest(fixture.keyID, ProtocolCollectiveKeySwitchToZero, decision.Conflict)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := ReleaseDescriptor{
		SessionID:                  sha256.Sum256([]byte("ceremony-session-" + sessionLabel)),
		KeyID:                      fixture.keyID,
		ParameterFingerprint:       fixture.roster.ParameterFingerprint,
		PolicyID:                   sha256.Sum256([]byte("ceremony-policy")),
		PolicyVersion:              PolicyVersion,
		InputCommitmentA:           inputA,
		InputCommitmentB:           inputB,
		ResultNonce:                Uint256{0, 0, 0, 991},
		ValidUntil:                 uint64(time.Now().Add(time.Hour).Unix()),
		ResultCiphertextCommitment: decision.ResultCiphertextCommitment,
		ProtocolBinding:            binding,
		Coalition:                  [2]uint64{operatorFirst.Public().Point, operatorSecond.Public().Point},
	}
	responseFirst, err := operatorFirst.GenerateReleaseShare(descriptor, decision.Conflict)
	if err != nil {
		return false, err
	}
	responseSecond, err := operatorSecond.GenerateReleaseShare(descriptor, decision.Conflict)
	if err != nil {
		return false, err
	}
	confirmed, transcript, err := CombineZeroKeySwitchShares(
		fixture.params, descriptor, fixture.manifest, decision.Conflict,
		[]ThresholdReleaseResponse{responseFirst, responseSecond},
	)
	if err != nil {
		return false, err
	}
	if transcript == ([32]byte{}) {
		t.Fatal("empty threshold transcript")
	}
	return confirmed, nil
}

// evaluatePolicy runs the exact unchanged conflict policy under the collectively
// generated keys. Client A and Client B are separate ExternalClient instances
// that hold only public material, and each crosses the evaluator boundary with
// its own signed ciphertext enrollment, exactly as the process-separated run
// does. The evaluator never receives a plaintext pledge.
func (fixture *ceremonyFixture) evaluatePolicy(t *testing.T, label string) (*EncryptedDecision, [32]byte, [32]byte) {
	t.Helper()
	material, err := fixture.runtime.ExportPublicEncryptionMaterial()
	if err != nil {
		t.Fatal(err)
	}
	clientA, err := NewExternalClient(material)
	if err != nil {
		t.Fatal(err)
	}
	clientB, err := NewExternalClient(material)
	if err != nil {
		t.Fatal(err)
	}
	if clientA.CustodyModel() != CustodyDealerlessCeremony {
		t.Fatalf("client accepted a non-ceremony key: %s", clientA.CustodyModel())
	}
	now := time.Unix(1_900_000_000, 0)
	issuerKey := deterministicIssuerKey("ceremony-issuer-" + label)
	if _, err := fixture.runtime.RegisterEnrollmentIssuer(issuerKey.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	contextA, contextB := enrollmentContexts()
	claimA := enrollmentClaim("a-"+label, contextA, uint64(now.Add(10*time.Minute).Unix()), fixture.nextNonce())
	claimB := enrollmentClaim("b-"+label, contextB, uint64(now.Add(10*time.Minute).Unix()), fixture.nextNonce())
	pledgeA, pledgeB := fixturePair(label)
	if pledgeA.AuthorizationCommitment, err = clientA.SubmitterAuthorizationCommitment(claimA); err != nil {
		t.Fatal(err)
	}
	if pledgeB.AuthorizationCommitment, err = clientB.SubmitterAuthorizationCommitment(claimB); err != nil {
		t.Fatal(err)
	}
	authorizePair(t, fixture.runtime, pledgeA, pledgeB)
	cipherA, _, err := clientA.EncryptPledgeForMode(pledgeA, IdentityPublicCommitment)
	if err != nil {
		t.Fatal(err)
	}
	cipherB, _, err := clientB.EncryptPledgeForMode(pledgeB, IdentityPublicCommitment)
	if err != nil {
		t.Fatal(err)
	}
	request := fixtureRequest(fixture.runtime, label+"-"+string(rune('a'+fixture.nonce%26)), cipherA, cipherB, now)
	request.EnrollmentA = signTestEnrollment(t, clientA, cipherA, contextA, claimA, now, fixture.nextNonce(), issuerKey)
	request.EnrollmentB = signTestEnrollment(t, clientB, cipherB, contextB, claimB, now, fixture.nextNonce(), issuerKey)
	inputA, inputB, err := fixture.runtime.VerifiedExternalInputCommitments(request, now)
	if err != nil {
		t.Fatalf("verified external input commitments: %v", err)
	}
	decision, _, err := fixture.runtime.Evaluate(request, now)
	if err != nil {
		t.Fatalf("policy evaluation under ceremony keys: %v", err)
	}
	return decision, inputA, inputB
}

func (fixture *ceremonyFixture) nextNonce() uint64 {
	fixture.nonce++
	return fixture.nonce
}

func TestDealerlessCeremonyEvaluatesExactPolicyAndReleasesWithAnyTwoOperators(t *testing.T) {
	fixture := runCeremony(t)
	decision, inputA, inputB := fixture.evaluatePolicy(t, "dealerless-exact-policy")

	// Every valid 2-of-3 coalition must release the same true Boolean. Each
	// coalition uses a fresh evaluation so the one-shot release guard is not
	// the thing being measured.
	for _, coalition := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		freshDecision, freshA, freshB := decision, inputA, inputB
		if coalition != [2]int{0, 1} {
			freshDecision, freshA, freshB = fixture.evaluatePolicy(t, "dealerless-coalition")
		}
		confirmed, err := fixture.releaseWithCoalition(t, freshDecision, freshA, freshB, coalition[0], coalition[1], "c")
		if err != nil {
			t.Fatalf("coalition %v failed to release: %v", coalition, err)
		}
		if !confirmed {
			t.Fatalf("coalition %v released the wrong Boolean", coalition)
		}
	}
}

func TestDealerlessCeremonyOneOperatorCannotRelease(t *testing.T) {
	fixture := runCeremony(t)
	decision, inputA, inputB := fixture.evaluatePolicy(t, "single-operator")
	operator, err := NewThresholdOperator(fixture.bundles[0])
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ProtocolBindingDigest(fixture.keyID, ProtocolCollectiveKeySwitchToZero, decision.Conflict)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := ReleaseDescriptor{
		SessionID:                  sha256.Sum256([]byte("single-operator-session")),
		KeyID:                      fixture.keyID,
		ParameterFingerprint:       fixture.roster.ParameterFingerprint,
		PolicyID:                   sha256.Sum256([]byte("ceremony-policy")),
		PolicyVersion:              PolicyVersion,
		InputCommitmentA:           inputA,
		InputCommitmentB:           inputB,
		ResultNonce:                Uint256{0, 0, 0, 992},
		ValidUntil:                 uint64(time.Now().Add(time.Hour).Unix()),
		ResultCiphertextCommitment: decision.ResultCiphertextCommitment,
		ProtocolBinding:            binding,
		Coalition:                  [2]uint64{1, 2},
	}
	response, err := operator.GenerateReleaseShare(descriptor, decision.Conflict)
	if err != nil {
		t.Fatal(err)
	}
	// One share is not a quorum: the combiner requires exactly `threshold`
	// responses and must refuse a single-operator release.
	if _, _, err := CombineZeroKeySwitchShares(
		fixture.params, descriptor, fixture.manifest, decision.Conflict,
		[]ThresholdReleaseResponse{response},
	); !errors.Is(err, ErrInsufficientShare) {
		t.Fatalf("single operator release was not refused: %v", err)
	}
	// The same operator's share duplicated is also not a coalition.
	if _, _, err := CombineZeroKeySwitchShares(
		fixture.params, descriptor, fixture.manifest, decision.Conflict,
		[]ThresholdReleaseResponse{response, response},
	); err == nil {
		t.Fatal("duplicated single-operator share was accepted as a coalition")
	}
}

func TestEvaluationRuntimeCannotDecryptOrProvision(t *testing.T) {
	fixture := runCeremony(t)
	decision, _, _ := fixture.evaluatePolicy(t, "evaluator-negative")

	// The evaluator holds no party, so the legacy co-located decrypt path fails
	// closed rather than returning a Boolean.
	if _, _, err := fixture.runtime.DecryptThresholdWithCoalition(decision, 0, 1); !errors.Is(err, ErrInsufficientShare) {
		t.Fatalf("evaluation runtime decrypted a result: %v", err)
	}
	// It also cannot manufacture operator bundles, so it cannot mint a share.
	if _, _, err := fixture.runtime.ProvisionThresholdOperators(); !errors.Is(err, ErrInvalidThresholdOperator) {
		t.Fatalf("evaluation runtime provisioned operators: %v", err)
	}
	if fixture.runtime.HoldsThresholdParties() {
		t.Fatal("evaluation runtime holds threshold parties")
	}

	// A decryptor built from a freshly sampled key must not recover the result:
	// the evaluator has no path to the collective secret.
	stranger := rlwe.NewKeyGenerator(fixture.params).GenSecretKeyNew()
	plaintext := rlwe.NewDecryptor(fixture.params, stranger).DecryptNew(decision.Conflict)
	decoded := make([]uint64, fixture.params.MaxSlots())
	if err := fixture.runtime.Encoder.Decode(plaintext, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded[0] == 1 {
		t.Fatal("a stranger key decrypted the collective result")
	}
}
