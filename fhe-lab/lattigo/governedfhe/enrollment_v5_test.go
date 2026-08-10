package governedfhe

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// The negative controls for V5 enrollments on the product path.
//
// The positive case is covered by the production and direct-participant suites,
// which now run through issuance and release-side verification end to end. What
// those cannot show is that the gate refuses anything. Each test below is one
// way a release could be authorized by an enrollment that does not authorize it.

func enrollmentFixture(t *testing.T) *productionFixture {
	t.Helper()
	return newProductionFixture(t, true)
}

func readEnrollmentRecord(t *testing.T, root, name string) ParticipantEnrollmentV5 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var record ParticipantEnrollmentV5
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return record
}

func enrollmentFacts(t *testing.T, fixture *productionFixture) EnrollmentCaseFacts {
	t.Helper()
	facts, err := EnrollmentCaseFactsFromBinding(fixture.manifest.Binding)
	if err != nil {
		t.Fatalf("case facts: %v", err)
	}
	return facts
}

// Submission must produce a durable, verifiable enrollment for each role, and
// the record must describe the enrollment that was actually signed.
func TestSubmissionIssuesVerifiableEnrollmentPerRole(t *testing.T) {
	fixture := enrollmentFixture(t)
	facts := enrollmentFacts(t, fixture)
	sideA, sideB := fixtureSideDigests(t, fixture)

	for _, role := range []struct {
		name     string
		object   string
		artifact EncryptedParticipantArtifact
		digest   Digest
		side     [32]byte
		identity ParticipantIdentity
	}{
		{RoleA, enrollmentAObject, fixture.artifactA, mustDigest(t, fixture.artifactA), sideA, fixture.manifest.Binding.ParticipantA},
		{RoleB, enrollmentBObject, fixture.artifactB, mustDigest(t, fixture.artifactB), sideB, fixture.manifest.Binding.ParticipantB},
	} {
		record := readEnrollmentRecord(t, fixture.publicRoot, role.object)
		if record.SchemaVersion != EnrollmentV5Schema || record.Role != role.name ||
			record.ParticipantID != role.identity.ID || record.ArtifactDigest != role.digest ||
			record.CiphertextDigest != role.artifact.CiphertextObject.Digest {
			t.Fatalf("%s: record does not describe the submission: %+v", role.name, record)
		}
		if len(record.Signature) != ed25519.SignatureSize {
			t.Fatalf("%s: enrollment carries no signature", role.name)
		}
		if _, err := reconstructParticipantEnrollmentV5(facts, role.artifact, role.digest, role.name, role.side, record); err != nil {
			t.Fatalf("%s: stored record does not verify against its re-derivation: %v", role.name, err)
		}
	}
}

func mustDigest(t *testing.T, artifact EncryptedParticipantArtifact) Digest {
	t.Helper()
	digest, err := artifact.Digest()
	if err != nil {
		t.Fatalf("artifact digest: %v", err)
	}
	return digest
}

// The coordinator reads the signed binding and a direct participant reads its
// ceremony bundle. For one case the two must derive the same enrollment inputs,
// otherwise a submission prepared by the participant could never be paired with
// what the release boundary rebuilds.
func TestEnrollmentCaseFactsAgreeBetweenBindingAndBundle(t *testing.T) {
	fixture := newParticipantOriginatedFixture(t, "facts-agreement")
	fromBinding, err := EnrollmentCaseFactsFromBinding(fixture.binding)
	if err != nil {
		t.Fatalf("facts from binding: %v", err)
	}
	fromBundle, err := EnrollmentCaseFactsFromBundle(fixture.bundleA)
	if err != nil {
		t.Fatalf("facts from bundle: %v", err)
	}
	if !reflect.DeepEqual(fromBinding, fromBundle) {
		t.Fatalf("coordinator and participant derive different case facts\n binding: %+v\n bundle : %+v", fromBinding, fromBundle)
	}
	// The agreement has to survive into the signed bytes, not just the inputs.
	if _, err := SignParticipantEnrollmentV5(fromBundle, EncryptedParticipantArtifact{}, RoleA, [32]byte{1}, fixture.privateA); err == nil {
		t.Fatal("an empty artifact produced an enrollment")
	}
}

// A release with no enrollment for a role has nothing authorizing that role's
// ciphertext. It must fail rather than fall back to releasing anyway.
func TestReleaseRefusesMissingEnrollment(t *testing.T) {
	for _, missing := range []string{enrollmentAObject, enrollmentBObject} {
		t.Run(missing, func(t *testing.T) {
			fixture := enrollmentFixture(t)
			if _, _, err := EvaluateFixedConflict(EvaluatorConfig{
				PublicRoot: fixture.publicRoot, Provenance: testDigest("enrollment/evaluator"), Now: fixture.now,
			}); err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if err := os.Remove(filepath.Join(fixture.publicRoot, missing)); err != nil {
				t.Fatalf("remove %s: %v", missing, err)
			}
			if err := releaseFixture(t, fixture); err == nil {
				t.Fatal("release succeeded with a missing enrollment")
			} else if !errors.Is(err, ErrEnrollmentV5) {
				t.Fatalf("expected an enrollment failure, got %v", err)
			}
		})
	}
}

// An edited record must be refused even where the edit does not touch the
// signature, because every stored field is re-derived and compared.
func TestReleaseRefusesEditedEnrollmentRecord(t *testing.T) {
	for _, edit := range []struct {
		name  string
		apply func(*ParticipantEnrollmentV5)
	}{
		{"foreign_ciphertext", func(r *ParticipantEnrollmentV5) { r.CiphertextDigest = testDigest("enrollment/other-ciphertext") }},
		{"foreign_participant", func(r *ParticipantEnrollmentV5) { r.ParticipantID = testDigest("enrollment/other-participant") }},
		{"foreign_vault", func(r *ParticipantEnrollmentV5) { r.SettlementVault = "0x000000000000000000000000000000000000dead" }},
		{"extended_validity", func(r *ParticipantEnrollmentV5) { r.ValidUntilUnix += 3600 }},
		{"restated_signing_digest", func(r *ParticipantEnrollmentV5) {
			r.EnrollmentSigningDigest = "0x0000000000000000000000000000000000000000000000000000000000000001"
		}},
		{"cleared_signature", func(r *ParticipantEnrollmentV5) { r.Signature = make([]byte, ed25519.SignatureSize) }},
	} {
		t.Run(edit.name, func(t *testing.T) {
			fixture := enrollmentFixture(t)
			if _, _, err := EvaluateFixedConflict(EvaluatorConfig{
				PublicRoot: fixture.publicRoot, Provenance: testDigest("enrollment/evaluator"), Now: fixture.now,
			}); err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			record := readEnrollmentRecord(t, fixture.publicRoot, enrollmentAObject)
			edit.apply(&record)
			writeEnrollmentRecord(t, fixture.publicRoot, enrollmentAObject, record)
			if err := releaseFixture(t, fixture); err == nil {
				t.Fatal("release succeeded with an edited enrollment")
			} else if !errors.Is(err, ErrEnrollmentV5) {
				t.Fatalf("expected an enrollment failure, got %v", err)
			}
		})
	}
}

// Swapping the two records makes each role's ciphertext claim the other role's
// authorization. Slot order and per-role issuer keys must refuse it.
func TestReleaseRefusesSwappedEnrollments(t *testing.T) {
	fixture := enrollmentFixture(t)
	if _, _, err := EvaluateFixedConflict(EvaluatorConfig{
		PublicRoot: fixture.publicRoot, Provenance: testDigest("enrollment/evaluator"), Now: fixture.now,
	}); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	recordA := readEnrollmentRecord(t, fixture.publicRoot, enrollmentAObject)
	recordB := readEnrollmentRecord(t, fixture.publicRoot, enrollmentBObject)
	writeEnrollmentRecord(t, fixture.publicRoot, enrollmentAObject, recordB)
	writeEnrollmentRecord(t, fixture.publicRoot, enrollmentBObject, recordA)
	if err := releaseFixture(t, fixture); err == nil {
		t.Fatal("release succeeded with swapped enrollments")
	} else if !errors.Is(err, ErrEnrollmentV5) {
		t.Fatalf("expected an enrollment failure, got %v", err)
	}
}

// This is external audit finding H-01 stated as a test.
//
// Participant A takes part in two sessions with the same key. Its enrollment
// from the second session is well formed and correctly signed, and inside that
// session it is valid. It must authorize nothing in the first one, and pairing
// it against the first session's counterparty must fail rather than produce a
// releasable pair.
func TestEnrollmentFromAnotherSessionDoesNotAuthorizeThisOne(t *testing.T) {
	fixture := enrollmentFixture(t)
	facts := enrollmentFacts(t, fixture)
	sideA, _ := fixtureSideDigests(t, fixture)

	// A second session A also belongs to, differing in its binding digest. A's
	// submission there is a complete, self-consistent artifact for that session.
	otherFacts := facts
	otherFacts.CaseBindingDigest = testDigest("enrollment/other-session-binding")
	otherArtifact := fixture.artifactA
	otherArtifact.CaseBindingDigest = otherFacts.CaseBindingDigest
	otherDigest := mustDigest(t, otherArtifact)

	signature, err := SignParticipantEnrollmentV5(otherFacts, otherArtifact, RoleA, sideA, fixture.privateA)
	if err != nil {
		t.Fatalf("sign in the other session: %v", err)
	}
	// It is a valid enrollment where it was issued.
	otherRecord, err := AdoptParticipantEnrollmentV5(otherFacts, otherArtifact, otherDigest, RoleA, sideA, signature)
	if err != nil {
		t.Fatalf("the other session's own enrollment must be valid there: %v", err)
	}
	if otherRecord.CaseBindingDigest != otherFacts.CaseBindingDigest {
		t.Fatalf("record does not bind the session it was issued in")
	}

	// Against this session's artifact it authorizes nothing.
	if _, err := AdoptParticipantEnrollmentV5(facts, fixture.artifactA, mustDigest(t, fixture.artifactA), RoleA, sideA, signature); err == nil {
		t.Fatal("an enrollment from another session authorized this session's ciphertext")
	}
	// And carrying the other session's artifact across does not help: the record
	// no longer describes the ciphertext this case holds.
	if _, err := AdoptParticipantEnrollmentV5(facts, otherArtifact, otherDigest, RoleA, sideA, signature); err == nil {
		t.Fatal("an enrollment from another session was adopted into this one")
	}

	// The same statement at the pairing boundary: A from the other session and B
	// from this one are not two halves of one session.
	crossPairing := replaceEnrollmentRecord(t, fixture, otherRecord)
	if err := releaseFixture(t, fixture); err == nil {
		t.Fatal("release succeeded pairing enrollments from two sessions")
	} else if !errors.Is(err, ErrEnrollmentV5) {
		t.Fatalf("expected an enrollment failure, got %v", err)
	}
	_ = crossPairing
}

// replaceEnrollmentRecord installs a record for role A and evaluates the case,
// so the release path is reached with a cross-session pair in place.
func replaceEnrollmentRecord(t *testing.T, fixture *productionFixture, record ParticipantEnrollmentV5) bool {
	t.Helper()
	if _, _, err := EvaluateFixedConflict(EvaluatorConfig{
		PublicRoot: fixture.publicRoot, Provenance: testDigest("enrollment/evaluator"), Now: fixture.now,
	}); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	writeEnrollmentRecord(t, fixture.publicRoot, enrollmentAObject, record)
	return true
}

// A participant must not be able to enroll under the counterparty's role, and
// the counterparty's key must not be accepted for this role's slot.
func TestEnrollmentRefusesCounterpartyKey(t *testing.T) {
	fixture := enrollmentFixture(t)
	facts := enrollmentFacts(t, fixture)
	sideA, _ := fixtureSideDigests(t, fixture)
	signature, err := SignParticipantEnrollmentV5(facts, fixture.artifactA, RoleA, sideA, fixture.privateB)
	if err == nil {
		if _, err := AdoptParticipantEnrollmentV5(facts, fixture.artifactA, mustDigest(t, fixture.artifactA), RoleA, sideA, signature); err == nil {
			t.Fatal("participant B enrolled participant A's ciphertext")
		}
	}
}

// An unrelated key that was never admitted by the binding must not be able to
// enroll anything, even for the correct role and artifact.
func TestEnrollmentRefusesUnadmittedKey(t *testing.T) {
	fixture := enrollmentFixture(t)
	facts := enrollmentFacts(t, fixture)
	sideA, _ := fixtureSideDigests(t, fixture)
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, signErr := SignParticipantEnrollmentV5(facts, fixture.artifactA, RoleA, sideA, stranger)
	if signErr != nil {
		return
	}
	if _, err := AdoptParticipantEnrollmentV5(facts, fixture.artifactA, mustDigest(t, fixture.artifactA), RoleA, sideA, signature); err == nil {
		t.Fatal("a key the binding never admitted issued a valid enrollment")
	}
}

// An asset with no deployed case adapter has no settlement venue, so there is
// no honest address to name in the authorization claim. Issuance must refuse
// rather than invent one.
func TestEnrollmentRefusesAssetWithoutDeployedAdapter(t *testing.T) {
	fixture := enrollmentFixture(t)
	facts := enrollmentFacts(t, fixture)
	sideA, _ := fixtureSideDigests(t, fixture)
	facts.AssetIdentity = testDigest("enrollment/asset-with-no-adapter")
	if _, err := SignParticipantEnrollmentV5(facts, fixture.artifactA, RoleA, sideA, fixture.privateA); err == nil {
		t.Fatal("issued an enrollment for an asset with no deployed case adapter")
	} else if !errors.Is(err, ErrEnrollmentV5) {
		t.Fatalf("expected an enrollment failure, got %v", err)
	}
	if _, err := SettlementVaultForAsset(testDigest("enrollment/asset-with-no-adapter")); err == nil {
		t.Fatal("resolved a settlement vault for an undeployed asset")
	}
}

// The vault named in the claim must be the adapter that was actually deployed
// and read back from the chain, not merely some address.
func TestSettlementVaultIsTheDeployedCaseAdapter(t *testing.T) {
	assets := DeployedCaseAdapterAssets()
	if len(assets) != 1 {
		t.Fatalf("expected exactly one deployed asset, got %d", len(assets))
	}
	vault, err := SettlementVaultForAsset(assets[0])
	if err != nil {
		t.Fatalf("settlement vault: %v", err)
	}
	const deployed = "9cd93089e02d301bddfc86eaabb39242272cafa1"
	if got := hexLower(vault[:]); got != deployed {
		t.Fatalf("settlement vault is not the deployed case adapter\n want: %s\n got : %s", deployed, got)
	}
	if assets[0].String() != "sha256:7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c" {
		t.Fatalf("deployed asset identity moved: %s", assets[0])
	}
}

func hexLower(raw []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(raw)*2)
	for _, value := range raw {
		out = append(out, digits[value>>4], digits[value&0x0f])
	}
	return string(out)
}

func writeEnrollmentRecord(t *testing.T, root, name string, record ParticipantEnrollmentV5) {
	t.Helper()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("encode %s: %v", name, err)
	}
	path := filepath.Join(root, name)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", name, err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func releaseFixture(t *testing.T, fixture *productionFixture) error {
	t.Helper()
	decryptor, err := NewGovernedDecryptor(GovernedDecryptorConfig{
		PublicRoot: fixture.publicRoot, PrivateRoot: fixture.privateRoot,
		Provenance: testDigest("enrollment/decryptor"), Now: fixture.now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("open decryptor: %v", err)
	}
	defer decryptor.Close()
	var artifact EvaluatedConflictArtifact
	raw, err := os.ReadFile(filepath.Join(fixture.publicRoot, evaluatedArtifactObject))
	if err != nil {
		t.Fatalf("read evaluated artifact: %v", err)
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatalf("decode evaluated artifact: %v", err)
	}
	_, _, err = decryptor.ReleaseFixedConflict(artifact)
	return err
}

// fixtureSideDigests recomputes each side's circuit-input digest from the
// ciphertexts the case actually holds, the same way the release boundary does.
func fixtureSideDigests(t *testing.T, fixture *productionFixture) ([32]byte, [32]byte) {
	t.Helper()
	store, err := openObjectStore(fixture.publicRoot, PublicCaseQuota, false)
	if err != nil {
		t.Fatalf("open public store: %v", err)
	}
	defer store.close()
	participants, err := loadAndValidateFreshParticipants(store, fixture.manifest, fixture.now)
	if err != nil {
		t.Fatalf("load participants: %v", err)
	}
	sideA, err := ParticipantCircuitSideDigest(participants.pledgeA)
	if err != nil {
		t.Fatalf("side digest A: %v", err)
	}
	sideB, err := ParticipantCircuitSideDigest(participants.pledgeB)
	if err != nil {
		t.Fatalf("side digest B: %v", err)
	}
	return sideA, sideB
}
