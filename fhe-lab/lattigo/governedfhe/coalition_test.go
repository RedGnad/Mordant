package governedfhe

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
)

// Coalition release, end to end on the product path.
//
// The positive tests run both branches for real: a conflicting pair and a
// non-conflicting pair, each released by a 2-of-3 quorum whose operators verify
// the L1 enrollments and recompute the circuit themselves. The negative tests
// are the ones that matter: they establish that a single operator is not
// enough, that divergence and unavailability fail closed, and that there is no
// secret key anywhere in the case to fall back to.

type coalitionFixture struct {
	publicRoot    string
	privateRoot   string
	operatorRoots []string
	ledgerRoot    string
	now           time.Time
	spec          CaseSpec
	binding       FHECaseBinding
	manifest      FHECaseManifest
	artifact      EvaluatedConflictArtifact
}

func newCoalitionFixture(t *testing.T, conflict bool) *coalitionFixture {
	t.Helper()
	root := taskTempDir(t, "mordant-coalition-")
	fixture := &coalitionFixture{
		publicRoot:  filepath.Join(root, "public"),
		privateRoot: filepath.Join(root, "private"),
		ledgerRoot:  filepath.Join(root, "ledgers"),
		now:         time.Now().UTC().Truncate(time.Second),
	}
	for index := 0; index < CoalitionOperators; index++ {
		fixture.operatorRoots = append(fixture.operatorRoots, filepath.Join(root, "operator", string(rune('a'+index))))
	}
	if err := os.MkdirAll(fixture.ledgerRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	publicA, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, privateB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	label := strings.ReplaceAll(t.Name(), "/", "-")
	protection := validProductBinding(t)
	fixture.spec = CaseSpec{
		CaseID:        testDigest(label + "/coalition-case"),
		AssetIdentity: DeployedCaseAdapterAssets()[0],
		PolicyID:      protection.PolicyID,
		ParticipantA:  ParticipantIdentity{ID: testDigest(label + "/participant-a"), Role: RoleA, SigningPublicKey: publicA},
		ParticipantB:  ParticipantIdentity{ID: testDigest(label + "/participant-b"), Role: RoleB, SigningPublicKey: publicB},
		CaseNonce:     testDigest(label + "/case-nonce"),
		CreatedAtUnix: fixture.now.Unix(), ExpiresAtUnix: fixture.now.Add(2 * time.Hour).Unix(),
	}

	binding, _, err := CreateCase(CreateCaseOptions{
		PublicRoot: fixture.publicRoot, PrivateRoot: fixture.privateRoot, Spec: fixture.spec,
		ReleaseMode: ReleaseModeCoalitionV5, OperatorRoots: fixture.operatorRoots,
		SourceProvenance: testDigest(label + "/keygen"),
	})
	if err != nil {
		t.Fatalf("create coalition case: %v", err)
	}
	fixture.binding = binding

	expiry := fixture.now.Add(time.Hour).Unix()
	pledgeA, pledgeB := coalitionPledges(conflict)
	for _, side := range []struct {
		role  string
		key   ed25519.PrivateKey
		value fhe.PlainPledge
	}{{RoleA, privateA, pledgeA}, {RoleB, privateB, pledgeB}} {
		if _, _, err := SubmitParticipant(ParticipantSubmissionOptions{
			PublicRoot: fixture.publicRoot, Role: side.role, SigningKey: side.key, Pledge: side.value,
			SubmissionNonce: testDigest(label + "/nonce/" + side.role), ExpiresAtUnix: expiry, Now: fixture.now,
		}); err != nil {
			t.Fatalf("submit %s: %v", side.role, err)
		}
	}
	manifest, err := FinalizeCase(fixture.publicRoot)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	fixture.manifest = manifest

	artifact, _, err := EvaluateFixedConflict(EvaluatorConfig{
		PublicRoot: fixture.publicRoot, Provenance: testDigest(label + "/evaluator"), Now: fixture.now,
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	fixture.artifact = artifact
	return fixture
}

func (f *coalitionFixture) release(t *testing.T, roots []string) (CoalitionConflictResult, error) {
	t.Helper()
	decryptor, err := NewCoalitionDecryptor(CoalitionDecryptorConfig{
		PublicRoot: f.publicRoot, OperatorRoots: roots, LedgerRoot: f.ledgerRoot,
		Provenance: testDigest("coalition/decryptor"), Now: f.now.Add(time.Second),
	})
	if err != nil {
		return CoalitionConflictResult{}, err
	}
	defer decryptor.Close()
	result, _, err := decryptor.Release(f.artifact)
	return result, err
}

// Both real branches. The circuit's two bits are released separately, so a
// non-conflicting pair over the same receivable still reports the asset match.
func TestCoalitionReleasesBothBitsOnBothBranches(t *testing.T) {
	for _, branch := range []struct {
		name              string
		conflict          bool
		sameEconomicAsset bool
		policyConflict    bool
	}{
		{"same_receivable_overlapping_windows", true, true, true},
		{"same_receivable_disjoint_windows", false, true, false},
	} {
		t.Run(branch.name, func(t *testing.T) {
			fixture := newCoalitionFixture(t, branch.conflict)
			result, err := fixture.release(t, fixture.operatorRoots)
			if err != nil {
				t.Fatalf("coalition release: %v", err)
			}
			if result.SameEconomicAsset != branch.sameEconomicAsset || result.PolicyConflict != branch.policyConflict {
				t.Fatalf("released bits sameEconomicAsset=%t policyConflict=%t, want %t/%t",
					result.SameEconomicAsset, result.PolicyConflict, branch.sameEconomicAsset, branch.policyConflict)
			}
			if result.ReleaseMode != ReleaseModeCoalitionV5 || result.Threshold != CoalitionThreshold ||
				len(result.Coalition) != 2 || result.Coalition[0] == result.Coalition[1] {
				t.Fatalf("release is not a 2-of-3 coalition: %+v", result)
			}
			// One statement per released bit per serving operator.
			if len(result.OperatorStatements) != 2*int(CoalitionThreshold) {
				t.Fatalf("expected %d operator statements, got %d", 2*int(CoalitionThreshold), len(result.OperatorStatements))
			}
			if result.ReleaseTranscript == "" || !result.RecomputedByAllOfQuorum {
				t.Fatalf("release carries no transcript or no recomputation claim: %+v", result)
			}
			// Every statement must be signed and attributable, and both released
			// bits must be covered by both serving operators.
			seen := map[uint64]map[uint8]bool{}
			for _, statement := range result.OperatorStatements {
				if statement.Signature == "" || statement.StatementDigest == "" || statement.Point == 0 {
					t.Fatalf("unsigned or unattributed operator statement: %+v", statement)
				}
				if seen[statement.Point] == nil {
					seen[statement.Point] = map[uint8]bool{}
				}
				seen[statement.Point][statement.Slot] = true
			}
			for _, point := range result.Coalition {
				if !seen[point][0] || !seen[point][1] {
					t.Fatalf("operator %d did not attest both released bits", point)
				}
			}
			if result.OperatorTopology != OperatorTopologyColocated {
				t.Fatalf("operator topology must be recorded as %q, got %q", OperatorTopologyColocated, result.OperatorTopology)
			}
			assertNoSecretKeyAnywhere(t, fixture)
		})
	}
}

// H-02 stated as a test. The two bits are separate facts, so the released
// result distinguishes "same receivable, no policy conflict" from "different
// receivable", which a single conjunction cannot.
func TestCoalitionDistinguishesAssetMatchFromPolicyConflict(t *testing.T) {
	same := newCoalitionFixture(t, true)
	sameResult, err := same.release(t, same.operatorRoots)
	if err != nil {
		t.Fatalf("conflicting release: %v", err)
	}
	disjoint := newCoalitionFixture(t, false)
	disjointResult, err := disjoint.release(t, disjoint.operatorRoots)
	if err != nil {
		t.Fatalf("non-conflicting release: %v", err)
	}
	if !sameResult.SameEconomicAsset || !disjointResult.SameEconomicAsset {
		t.Fatal("both branches pledge the same receivable, so both must report the asset match")
	}
	if !sameResult.PolicyConflict || disjointResult.PolicyConflict {
		t.Fatal("the two branches must differ on the policy conflict and only on it")
	}
	// The distinction is the finding: identical asset bit, different policy bit.
	if sameResult.SameEconomicAsset != disjointResult.SameEconomicAsset {
		t.Fatal("asset bit must be independent of the policy bit")
	}
}

// A single operator is not a coalition. This is the property the whole
// increment exists for.
func TestCoalitionRefusesASingleOperator(t *testing.T) {
	fixture := newCoalitionFixture(t, true)
	if _, err := fixture.release(t, fixture.operatorRoots[:1]); err == nil {
		t.Fatal("one operator released the case")
	} else if !errors.Is(err, ErrCoalition) && !errors.Is(err, ErrCoalitionQuorumUnavailable) {
		t.Fatalf("expected a coalition failure, got %v", err)
	}
}

// Losing one operator of three is survivable; losing two is not, and the case
// then does not release at all rather than releasing by another route.
func TestCoalitionSurvivesOneLossAndFailsClosedOnTwo(t *testing.T) {
	fixture := newCoalitionFixture(t, true)
	if _, err := fixture.release(t, fixture.operatorRoots[1:]); err != nil {
		t.Fatalf("2 of 3 operators must be enough: %v", err)
	}

	unavailable := newCoalitionFixture(t, true)
	for _, root := range unavailable.operatorRoots[1:] {
		if err := os.Remove(filepath.Join(root, operatorBundleObject)); err != nil {
			t.Fatalf("remove operator share: %v", err)
		}
	}
	if _, err := unavailable.release(t, unavailable.operatorRoots); err == nil {
		t.Fatal("released with only one share available")
	} else if !errors.Is(err, ErrCoalitionQuorumUnavailable) {
		t.Fatalf("expected quorum unavailable, got %v", err)
	}
	assertNoSecretKeyAnywhere(t, unavailable)
}

// There is nothing to fall back to. A coalition case has no secret key object
// and no release-authority key, so a failed quorum cannot be worked around by
// opening the governed decryptor.
func TestCoalitionCaseHasNoCentralKeyToFallBackTo(t *testing.T) {
	fixture := newCoalitionFixture(t, true)
	assertNoSecretKeyAnywhere(t, fixture)

	if len(fixture.binding.ReleaseAuthorityPublicKey) != 0 {
		t.Fatalf("coalition binding carries a release authority key: %x", fixture.binding.ReleaseAuthorityPublicKey)
	}
	// The governed decryptor must refuse the case outright rather than partially
	// proceed against it.
	decryptor, err := NewGovernedDecryptor(GovernedDecryptorConfig{
		PublicRoot: fixture.publicRoot, PrivateRoot: fixture.privateRoot,
		Provenance: testDigest("coalition/governed-attempt"), Now: fixture.now.Add(time.Second),
	})
	if err != nil {
		return
	}
	defer decryptor.Close()
	if _, _, err := decryptor.ReleaseFixedConflict(fixture.artifact); err == nil {
		t.Fatal("the governed decryptor released a coalition case")
	}
}

// An operator whose share belongs to a different ceremony cannot contribute to
// this case's quorum.
func TestCoalitionRefusesForeignOperatorShare(t *testing.T) {
	fixture := newCoalitionFixture(t, true)
	foreign := newCoalitionFixture(t, true)

	swapped := append([]string(nil), fixture.operatorRoots...)
	swapped[1] = foreign.operatorRoots[1]
	swapped[2] = foreign.operatorRoots[2]
	if _, err := fixture.release(t, swapped); err == nil {
		t.Fatal("released with shares from another ceremony")
	}
}

// The coalition consumes the L1 enrollments. Removing one leaves the pair
// unauthorized and the release must stop before any share is generated.
func TestCoalitionRefusesWithoutEnrollments(t *testing.T) {
	fixture := newCoalitionFixture(t, true)
	if err := os.Remove(filepath.Join(fixture.publicRoot, enrollmentAObject)); err != nil {
		t.Fatalf("remove enrollment: %v", err)
	}
	if _, err := fixture.release(t, fixture.operatorRoots); err == nil {
		t.Fatal("released a case whose pair is not enrolled")
	} else if !errors.Is(err, ErrEnrollmentV5) {
		t.Fatalf("expected an enrollment failure, got %v", err)
	}
}

// The published threshold manifest is the case's release authority. Editing it
// breaks that identity, and the case stops being releasable rather than
// releasing under a manifest nobody committed to.
func TestCoalitionRefusesEditedThresholdManifest(t *testing.T) {
	fixture := newCoalitionFixture(t, true)
	var manifest CoalitionThresholdManifest
	raw, err := os.ReadFile(filepath.Join(fixture.publicRoot, thresholdManifestObject))
	if err != nil {
		t.Fatal(err)
	}
	if decodeStrict(raw, &manifest) != nil {
		t.Fatal("threshold manifest must decode")
	}
	manifest.Operators[0].Point = 99
	writeJSONObject(t, fixture.publicRoot, thresholdManifestObject, manifest)
	if _, err := fixture.release(t, fixture.operatorRoots); err == nil {
		t.Fatal("released under an edited threshold manifest")
	} else if !errors.Is(err, ErrCoalition) {
		t.Fatalf("expected a coalition failure, got %v", err)
	}
}

func assertNoSecretKeyAnywhere(t *testing.T, fixture *coalitionFixture) {
	t.Helper()
	roots := append([]string{fixture.publicRoot, fixture.privateRoot}, fixture.operatorRoots...)
	for _, root := range roots {
		for _, forbidden := range []string{secretKeyObject, decryptorSigningKeyObject, privateCaseObject, releaseAuthorityObject} {
			if _, err := os.Stat(filepath.Join(root, forbidden)); err == nil {
				t.Fatalf("coalition case holds %s under %s", forbidden, root)
			}
		}
	}
}

func writeJSONObject(t *testing.T, root, name string, value any) {
	t.Helper()
	encoded, err := canonicalJSONForTest(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

// coalitionPledges is the pair that makes the H-02 distinction visible: both
// sides always pledge the SAME receivable, so the asset bit is true either way,
// and only the activity windows differ. A pledge pair with different
// receivables could not show that the two bits are independent.
func coalitionPledges(overlapping bool) (fhe.PlainPledge, fhe.PlainPledge) {
	receivable := sha256.Sum256([]byte("coalition/shared-receivable"))
	build := func(side string, activeFrom, activeUntil uint64) fhe.PlainPledge {
		return fhe.PlainPledge{
			ActiveFrom: activeFrom, ActiveUntil: activeUntil, Amount: fhe.Uint256{0, 0, 0, 1_000_000},
			Currency: sha256.Sum256([]byte("currency/usd")), ObligationID: sha256.Sum256([]byte("coalition/obligation/" + side)),
			ReceivableID: receivable, Exclusive: true,
			AuthorizationCommitment:   sha256.Sum256([]byte("coalition/authorization/" + side)),
			PrivateMetadataCommitment: sha256.Sum256([]byte("coalition/private-metadata/" + side)),
		}
	}
	if overlapping {
		return build("a", 100, 400), build("b", 200, 500)
	}
	// Same receivable, windows that do not meet: an asset match with no policy
	// conflict, which a single conjunction would report exactly as "no match".
	return build("a", 100, 200), build("b", 300, 500)
}

func canonicalJSONForTest(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// External audit finding H-03 at the case level.
//
// The coalition never decrypts what the evaluator proposed and never releases
// against it. It still refuses to release when the published evaluation and the
// recomputed circuit disagree, because one of the two is then wrong and
// releasing the other silently would leave that unresolved. The refusal is
// terminal.
func TestCoalitionRefusesPublishedEvaluationThatDisagrees(t *testing.T) {
	fixture := newCoalitionFixture(t, true)
	path := filepath.Join(fixture.publicRoot, resultCiphertextObject)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A different but structurally valid result ciphertext: the same case run
	// over the other branch produces one.
	other := newCoalitionFixture(t, false)
	substitute, err := os.ReadFile(filepath.Join(other.publicRoot, resultCiphertextObject))
	if err != nil {
		t.Fatal(err)
	}
	if len(substitute) != len(original) {
		t.Skipf("branches produced different ciphertext sizes (%d vs %d)", len(substitute), len(original))
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, substitute, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.release(t, fixture.operatorRoots); err == nil {
		t.Fatal("released against a published evaluation that disagrees with the circuit")
	}
	assertNoSecretKeyAnywhere(t, fixture)
}

// The release is one-shot. A second attempt against the same evaluated artifact
// must not produce a second release.
func TestCoalitionReleaseIsOneShot(t *testing.T) {
	fixture := newCoalitionFixture(t, true)
	if _, err := fixture.release(t, fixture.operatorRoots); err != nil {
		t.Fatalf("first release: %v", err)
	}
	if _, err := fixture.release(t, fixture.operatorRoots); err == nil {
		t.Fatal("the case released twice")
	}
}
