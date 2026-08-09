package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
)

func participantOriginatedRepeated32(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}

func TestParticipantOriginatedCrossLanguageDigestVectors(t *testing.T) {
	bundle := ParticipantOriginatedClientBundle{
		SchemaVersion: ParticipantOriginatedClientBundleSchema,
		RunID:         "8a44f9e0-20d7-4ca3-8762-82bcbfc648af",
		Role:          RoleA,
		CaseID:        Digest(participantOriginatedRepeated32(0x41)),
	}
	pledge := fhe.PlainPledge{
		ActiveFrom: 100, ActiveUntil: 400, Amount: fhe.Uint256{0, 0, 0, 100_000_000},
		Currency: participantOriginatedRepeated32(0x51), ObligationID: participantOriginatedRepeated32(0x52),
		ReceivableID: participantOriginatedRepeated32(0x53), Exclusive: true,
	}
	commitment, err := ParticipantOriginatedClaimCommitment(bundle, pledge, participantOriginatedRepeated32(0x71))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := commitment.String(), "sha256:07667545fd9d8c81058b4b693bf8c5c8577ede1a0847571bda5355c718950292"; got != want {
		t.Fatalf("TS/Go claim commitment mismatch: got %s want %s", got, want)
	}
	pledge.ReceivableCommitment = participantOriginatedRepeated32(0x57)
	if _, err := ParticipantOriginatedClaimCommitment(bundle, pledge, participantOriginatedRepeated32(0x71)); !errors.Is(err, ErrParticipantOriginated) {
		t.Fatalf("nonzero full-FHE receivableCommitment was not rejected: %v", err)
	}
	keyBytes := participantOriginatedRepeated32(0x31)
	keyDigest, err := ParticipantOriginatedSigningKeyDigest(keyBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := keyDigest.String(), "sha256:8a83665f3798727f14f92ad0e6c99fdab08ee731d6cd644c131223fd2f4fed2a"; got != want {
		t.Fatalf("TS/Go signing-key digest mismatch: got %s want %s", got, want)
	}
	authorization := ParticipantOriginatedAuthorizationDigest(participantOriginatedRepeated32(0xab))
	encoded, err := json.Marshal(authorization)
	if err != nil || string(encoded) != `"0xabababababababababababababababababababababababababababababababab"` {
		t.Fatalf("EIP-712 bytes32 JSON mismatch: %s %v", encoded, err)
	}
}

type participantOriginatedFixture struct {
	root         string
	publicRoot   string
	privateRoot  string
	journalRoot  string
	ceremonyRoot string
	now          time.Time
	spec         CaseSpec
	binding      FHECaseBinding
	privateA     ed25519.PrivateKey
	privateB     ed25519.PrivateKey
	bundleA      ParticipantOriginatedClientBundle
	bundleB      ParticipantOriginatedClientBundle
	bundleRootA  string
	bundleRootB  string
	bundleDigA   Digest
	bundleDigB   Digest
	source       Digest
	build        Digest
	client       Digest
}

func newParticipantOriginatedFixture(t *testing.T, label string) *participantOriginatedFixture {
	t.Helper()
	root := taskTempDir(t, "mordant-participant-originated-")
	publicRoot := filepath.Join(root, "coordinator-public")
	privateRoot := filepath.Join(root, "decryptor-private")
	ceremonyRoot := filepath.Join(root, "coordinator-ceremony")
	publicA, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, privateB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	protection := validProductBinding(t)
	protection.CleanverseAssetRecordDigest = testDigest(label + "/asset")
	protection.HolderRecordDate = now.Add(-time.Minute).Format(time.RFC3339Nano)
	protection.CaseNonce = testDigest(label + "/case-nonce")
	protection.HolderAllocationDigest, err = protectionHolderAllocationDigest(protection)
	if err != nil {
		t.Fatal(err)
	}
	protection.FHECaseID, err = protectionFHECaseID(protection, protection.HolderAllocationDigest)
	if err != nil {
		t.Fatal(err)
	}
	spec := CaseSpec{
		CaseID: protection.FHECaseID, AssetIdentity: protection.CleanverseAssetRecordDigest,
		PolicyID:     protection.PolicyID,
		ParticipantA: ParticipantIdentity{ID: testDigest(label + "/participant-a"), Role: RoleA, SigningPublicKey: publicA},
		ParticipantB: ParticipantIdentity{ID: testDigest(label + "/participant-b"), Role: RoleB, SigningPublicKey: publicB},
		CaseNonce:    protection.CaseNonce, CreatedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(2 * time.Hour).Unix(),
	}
	binding, _, _, err := CreateParticipantOriginatedFoundation(ParticipantOriginatedFoundationOptions{
		CreateCaseOptions: CreateCaseOptions{
			PublicRoot: publicRoot, PrivateRoot: privateRoot, Spec: spec,
			SourceProvenance: testDigest(label + "/keygen-binary"),
		},
		ProtectionBinding: protection,
	})
	if err != nil {
		t.Fatalf("public-key-only foundation: %v", err)
	}
	sourceDigest := testDigest(label + "/source")
	buildDigest := testDigest(label + "/build-manifest")
	clientDigest := testDigest(label + "/client-binary")
	requestA, err := BuildParticipantOriginatedCeremonyRequest(publicRoot, label, RoleA, sourceDigest, buildDigest, clientDigest)
	if err != nil {
		t.Fatal(err)
	}
	requestB, err := BuildParticipantOriginatedCeremonyRequest(publicRoot, label, RoleB, sourceDigest, buildDigest, clientDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignParticipantOriginatedCeremony(requestA, privateB, now); !errors.Is(err, ErrParticipantOriginated) {
		t.Fatalf("wrong participant key signed role A ceremony: %v", err)
	}
	signedA, err := SignParticipantOriginatedCeremony(requestA, privateA, now)
	if err != nil {
		t.Fatal(err)
	}
	signedB, err := SignParticipantOriginatedCeremony(requestB, privateB, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ImportParticipantOriginatedCeremony(publicRoot, ceremonyRoot, requestA, signedA); err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeParticipantOriginatedCase(publicRoot); err == nil {
		t.Fatal("case finalized before participant B signed both retained bindings")
	}
	if err := ImportParticipantOriginatedCeremony(publicRoot, ceremonyRoot, requestB, signedB); err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeParticipantOriginatedCase(publicRoot); err != nil {
		t.Fatalf("finalize retained case manifest: %v", err)
	}
	bundleRootA := filepath.Join(root, "participant-a-bundle")
	bundleRootB := filepath.Join(root, "participant-b-bundle")
	bundleA, bundleDigA, err := ExportParticipantOriginatedClientBundle(publicRoot, ceremonyRoot, bundleRootA, RoleA)
	if err != nil {
		t.Fatal(err)
	}
	bundleB, bundleDigB, err := ExportParticipantOriginatedClientBundle(publicRoot, ceremonyRoot, bundleRootB, RoleB)
	if err != nil {
		t.Fatal(err)
	}
	return &participantOriginatedFixture{
		root: root, publicRoot: publicRoot, privateRoot: privateRoot, ceremonyRoot: ceremonyRoot,
		journalRoot: filepath.Join(root, "coordinator-import-journal"),
		now:         now, spec: spec, binding: binding, privateA: privateA, privateB: privateB,
		bundleA: bundleA, bundleB: bundleB, bundleRootA: bundleRootA, bundleRootB: bundleRootB,
		bundleDigA: bundleDigA, bundleDigB: bundleDigB, source: sourceDigest, build: buildDigest, client: clientDigest,
	}
}

func bundleExpectations(fixture *participantOriginatedFixture, role string) ParticipantOriginatedBundleExpectations {
	return ParticipantOriginatedBundleExpectations{
		RunID: fixture.bundleA.RunID, Role: role, CaseID: fixture.spec.CaseID, AssetIdentity: fixture.spec.AssetIdentity,
		ExpectedSourceDigest: fixture.source, ExpectedBuildManifestDigest: fixture.build,
		ExpectedClientBinaryDigest: fixture.client, Now: fixture.now,
	}
}

func TestParticipantOriginatedCeremonyAndAuthenticatedThinBundle(t *testing.T) {
	fixture := newParticipantOriginatedFixture(t, "participant-originated-ceremony")
	if _, _, err := VerifyParticipantOriginatedClientBundle(fixture.bundleRootA, bundleExpectations(fixture, RoleA)); err != nil {
		t.Fatalf("verify role A bundle: %v", err)
	}
	if _, _, err := VerifyParticipantOriginatedClientBundle(fixture.bundleRootB, bundleExpectations(fixture, RoleB)); err != nil {
		t.Fatalf("verify role B bundle: %v", err)
	}
	stale := bundleExpectations(fixture, RoleA)
	stale.Now = time.Unix(fixture.binding.ExpiresAtUnix, 0)
	if _, _, err := VerifyParticipantOriginatedClientBundle(fixture.bundleRootA, stale); err == nil {
		t.Fatal("stale participant bundle verified")
	}
	wrongBinary := bundleExpectations(fixture, RoleA)
	wrongBinary.ExpectedClientBinaryDigest = testDigest("wrong/client-binary")
	if _, _, err := VerifyParticipantOriginatedClientBundle(fixture.bundleRootA, wrongBinary); err == nil {
		t.Fatal("bundle accepted another client executable digest")
	}
	names := participantOriginatedBundleObjectNames()
	if participantOriginatedBundleContainsEvaluationKeyBytes(names) || assertParticipantOriginatedBundleThin(names) != nil {
		t.Fatal("client bundle copied evaluation-key bytes")
	}
	for _, root := range []string{fixture.publicRoot, fixture.privateRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(root, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, fixture.privateA) || bytes.Contains(data, fixture.privateB) {
				t.Fatalf("participant private key reached coordinator object %s/%s", root, entry.Name())
			}
		}
	}
}

func participantOriginatedPledges(label string, conflict bool) (fhe.PlainPledge, fhe.PlainPledge) {
	receivable := sha256.Sum256([]byte("same-private-receivable/" + label))
	currency := sha256.Sum256([]byte("currency/usd"))
	makePledge := func(side string, from, until uint64) fhe.PlainPledge {
		return fhe.PlainPledge{
			ActiveFrom: from, ActiveUntil: until, Amount: fhe.Uint256{0, 0, 0, 1_000_000}, Currency: currency,
			ObligationID: sha256.Sum256([]byte("obligation/" + label + "/" + side)), ReceivableID: receivable, Exclusive: true,
		}
	}
	if conflict {
		return makePledge("a", 100, 400), makePledge("b", 200, 500)
	}
	// Adjacent half-open windows over the same receivable are non-overlapping.
	return makePledge("a", 100, 200), makePledge("b", 200, 300)
}

func prepareParticipantOriginatedRole(t *testing.T, fixture *participantOriginatedFixture, role string, pledge fhe.PlainPledge) (ParticipantOriginatedPreparedArtifact, string) {
	t.Helper()
	bundleRoot, key := fixture.bundleRootA, fixture.privateA
	if role == RoleB {
		bundleRoot, key = fixture.bundleRootB, fixture.privateB
	}
	outputRoot := filepath.Join(fixture.root, role+"-private-output")
	claimSalt, err := GenerateParticipantOriginatedClaimSalt()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareParticipantOriginatedArtifact(ParticipantOriginatedPreparationOptions{
		BundleRoot: bundleRoot, OutputRoot: outputRoot, BundleExpectations: bundleExpectations(fixture, role),
		SigningKey: key, Pledge: pledge, ClaimSalt: claimSalt,
		EncryptionIntentDigest: ParticipantOriginatedAuthorizationDigest(testDigest("intent/" + role + "/" + fixture.bundleA.RunID)),
		SubmissionNonce:        testDigest("submission/" + role + "/" + fixture.bundleA.RunID),
		ExpiresAtUnix:          fixture.now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("prepare %s locally: %v", role, err)
	}
	entries, err := os.ReadDir(outputRoot)
	if err != nil || len(entries) != 2 {
		t.Fatalf("participant output is not exact: %v %+v", err, entries)
	}
	return prepared, outputRoot
}

func stagePreparedArtifact(t *testing.T, role, outputRoot, quarantineRoot string, prepared ParticipantOriginatedPreparedArtifact) {
	t.Helper()
	_, ciphertextName, manifestName, _ := participantFiles(role)
	artifactFile, err := os.Open(filepath.Join(outputRoot, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	defer artifactFile.Close()
	ciphertextFile, err := os.Open(filepath.Join(outputRoot, ciphertextName))
	if err != nil {
		t.Fatal(err)
	}
	defer ciphertextFile.Close()
	if _, err := StageParticipantOriginatedArtifact(ParticipantOriginatedStageOptions{
		QuarantineRoot: quarantineRoot, Role: role,
		Objects: []ParticipantOriginatedImportObject{
			{Name: manifestName, Reader: artifactFile, Expected: prepared.ArtifactObject},
			{Name: ciphertextName, Reader: ciphertextFile, Expected: prepared.CiphertextObject},
		},
	}); err != nil {
		t.Fatalf("stage %s: %v", role, err)
	}
}

func participantOriginatedExpectationsForPrepared(t *testing.T, fixture *participantOriginatedFixture, role string, prepared ParticipantOriginatedPreparedArtifact) ParticipantOriginatedArtifactExpectations {
	t.Helper()
	bundleDigest := fixture.bundleDigA
	identity := fixture.spec.ParticipantA
	if role == RoleB {
		bundleDigest = fixture.bundleDigB
		identity = fixture.spec.ParticipantB
	}
	keyDigest, err := ParticipantOriginatedSigningKeyDigest(identity.SigningPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bindingDigest, _ := fixture.binding.Digest()
	return ParticipantOriginatedArtifactExpectations{
		Role: role, CaseID: fixture.spec.CaseID, AssetIdentity: fixture.spec.AssetIdentity, CaseBindingDigest: bindingDigest,
		SigningKeyDigest: keyDigest, BundleDigest: bundleDigest, EncryptionIntentDigest: prepared.EncryptionIntentDigest,
		ClaimCommitment: prepared.ClaimCommitment, SubmissionNonce: prepared.Artifact.SubmissionNonce,
		ArtifactDigest: prepared.ArtifactDigest, CiphertextDigest: prepared.CiphertextDigest,
		FinalEncryptedAdmissionDigest: ParticipantOriginatedAuthorizationDigest(testDigest("final-wallet-admission/" + role + "/" + fixture.bundleA.RunID)), Now: fixture.now,
	}
}

func cloneParticipantOriginatedQuarantine(t *testing.T, source, label string) string {
	t.Helper()
	destination := filepath.Join(taskTempDir(t, "mordant-participant-mutation-"), label)
	if err := os.MkdirAll(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil || os.WriteFile(filepath.Join(destination, entry.Name()), data, 0o444) != nil {
			t.Fatalf("clone quarantine object %s: %v", entry.Name(), err)
		}
	}
	return destination
}

func rewriteParticipantOriginatedObject(t *testing.T, root, name string, data []byte) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
}

func mutateParticipantOriginatedManifest(t *testing.T, root string, key ed25519.PrivateKey, mutate func(*EncryptedParticipantArtifact)) EncryptedParticipantArtifact {
	t.Helper()
	path := filepath.Join(root, submissionAManifest)
	data, err := os.ReadFile(path)
	var artifact EncryptedParticipantArtifact
	if err != nil || decodeStrict(data, &artifact) != nil {
		t.Fatalf("load mutation manifest: %v", err)
	}
	mutate(&artifact)
	artifact.Signature, err = signCanonical(key, "MordantEncryptedParticipantArtifact/v1", artifact.signingValue())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalCanonical(artifact)
	if err != nil {
		t.Fatal(err)
	}
	rewriteParticipantOriginatedObject(t, root, submissionAManifest, encoded)
	return artifact
}

func mutateParticipantOriginatedCiphertext(t *testing.T, root string, key ed25519.PrivateKey, mutate func(*fhe.CipherPledge)) EncryptedParticipantArtifact {
	t.Helper()
	ciphertext, err := os.ReadFile(filepath.Join(root, submissionAObject))
	if err != nil {
		t.Fatal(err)
	}
	pledge, err := fhe.UnmarshalCipherPledge(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	mutate(pledge)
	mutated, err := pledge.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	rewriteParticipantOriginatedObject(t, root, submissionAObject, mutated)
	return mutateParticipantOriginatedManifest(t, root, key, func(artifact *EncryptedParticipantArtifact) {
		artifact.CiphertextObject = ObjectRef{Path: submissionAObject, Digest: DigestBytes(mutated), Length: int64(len(mutated))}
	})
}

func verifyAndPublishPrepared(t *testing.T, fixture *participantOriginatedFixture, role string, prepared ParticipantOriginatedPreparedArtifact, quarantineRoot string) ParticipantOriginatedArtifactVerification {
	t.Helper()
	expected := participantOriginatedExpectationsForPrepared(t, fixture, role, prepared)
	wrongIntent := expected
	wrongIntent.EncryptionIntentDigest = ParticipantOriginatedAuthorizationDigest(testDigest("wrong/intent"))
	if _, err := VerifyStagedParticipantOriginatedArtifact(ParticipantOriginatedVerificationOptions{
		PublicRoot: fixture.publicRoot, QuarantineRoot: quarantineRoot, Expected: wrongIntent,
	}); err == nil {
		t.Fatalf("%s artifact accepted another wallet encryption intent", role)
	}
	verified, err := VerifyStagedParticipantOriginatedArtifact(ParticipantOriginatedVerificationOptions{
		PublicRoot: fixture.publicRoot, QuarantineRoot: quarantineRoot, Expected: expected,
	})
	if err != nil {
		t.Fatalf("verify staged %s: %v", role, err)
	}
	if verified.EncryptionIntentDigest != prepared.EncryptionIntentDigest || verified.ClaimCommitment != prepared.ClaimCommitment {
		t.Fatal("verification did not recover the exact opaque intent and salted claim commitment")
	}
	if verified.ParameterProfile != ParameterProfile || verified.ParameterFingerprint != fixture.binding.ParameterFingerprint ||
		verified.FHEPublicKeyDigest != fixture.binding.PublicKeyDigest || verified.CircuitDigest != fixture.binding.CircuitDigest {
		t.Fatal("verification omitted or changed the Phase2 FHE artifact context")
	}
	if _, err := PublishParticipantOriginatedArtifact(ParticipantOriginatedPublicationOptions{
		PublicRoot: fixture.publicRoot, QuarantineRoot: quarantineRoot, JournalRoot: fixture.journalRoot,
		Expected: expected, Now: fixture.now,
	}); err != nil {
		t.Fatalf("publish %s: %v", role, err)
	}
	if _, err := PublishParticipantOriginatedArtifact(ParticipantOriginatedPublicationOptions{
		PublicRoot: fixture.publicRoot, QuarantineRoot: quarantineRoot, JournalRoot: fixture.journalRoot,
		Expected: expected, Now: fixture.now,
	}); !errors.Is(err, ErrParticipantImportReplay) {
		t.Fatalf("completed %s admission replay was not rejected: %v", role, err)
	}
	afterExpiry := time.Unix(prepared.Artifact.ExpiresAtUnix+1, 0).UTC()
	if _, err := PublishParticipantOriginatedArtifact(ParticipantOriginatedPublicationOptions{
		PublicRoot: fixture.publicRoot, QuarantineRoot: quarantineRoot, JournalRoot: fixture.journalRoot,
		Expected: expected, Now: afterExpiry,
	}); err == nil {
		t.Fatalf("expired %s artifact admitted as a new publication", role)
	}
	reconciled, err := ReconcileParticipantOriginatedImport(ParticipantOriginatedPublicationOptions{
		PublicRoot: fixture.publicRoot, QuarantineRoot: quarantineRoot, JournalRoot: fixture.journalRoot,
		Expected: expected, Now: afterExpiry,
	})
	if err != nil || !reconciled.Reconciled {
		t.Fatalf("reconcile completed %s admission: %+v %v", role, reconciled, err)
	}
	return verified
}

func TestParticipantOriginatedImportedArtifactsDriveUnchangedGovernedFlow(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		conflict bool
	}{
		{"same_receivable_overlapping_windows_conflict", true},
		{"same_receivable_non_overlapping_windows_no_conflict", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newParticipantOriginatedFixture(t, "participant-originated-"+testCase.name)
			pledgeA, pledgeB := participantOriginatedPledges(testCase.name, testCase.conflict)
			preparedA, outputA := prepareParticipantOriginatedRole(t, fixture, RoleA, pledgeA)
			preparedB, outputB := prepareParticipantOriginatedRole(t, fixture, RoleB, pledgeB)
			if preparedA.ClaimCommitment == preparedB.ClaimCommitment {
				t.Fatal("independently salted claims produced the same commitment")
			}
			quarantineA := filepath.Join(fixture.root, "coordinator-quarantine-a")
			quarantineB := filepath.Join(fixture.root, "coordinator-quarantine-b")
			stagePreparedArtifact(t, RoleA, outputA, quarantineA, preparedA)
			stagePreparedArtifact(t, RoleB, outputB, quarantineB, preparedB)
			verifyAndPublishPrepared(t, fixture, RoleA, preparedA, quarantineA)
			verifyAndPublishPrepared(t, fixture, RoleB, preparedB, quarantineB)

			evaluated, _, err := EvaluateFixedConflict(EvaluatorConfig{
				PublicRoot: fixture.publicRoot, Provenance: testDigest(testCase.name + "/evaluator-binary"), Now: fixture.now,
			})
			if err != nil {
				t.Fatalf("unchanged evaluator rejected imported artifacts: %v", err)
			}
			decryptor, err := NewGovernedDecryptor(GovernedDecryptorConfig{
				PublicRoot: fixture.publicRoot, PrivateRoot: fixture.privateRoot,
				Provenance: testDigest(testCase.name + "/decryptor-binary"), Now: fixture.now,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer decryptor.Close()
			result, _, err := decryptor.ReleaseFixedConflict(evaluated)
			if err != nil {
				t.Fatalf("unchanged governed decryptor rejected imported evaluation: %v", err)
			}
			if result.Conflict != testCase.conflict {
				t.Fatalf("governed result conflict=%v want %v", result.Conflict, testCase.conflict)
			}
			for _, forbidden := range []string{
				participantOriginatedClientBundleObject, "participant-a-import-admitted.json", "participant-b-import-admitted.json",
			} {
				if _, err := os.Stat(filepath.Join(fixture.publicRoot, forbidden)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("experimental coordinator object polluted governed public root: %s", forbidden)
				}
			}
		})
	}
}

func TestParticipantOriginatedImportRejectsBoundArtifactMutations(t *testing.T) {
	fixture := newParticipantOriginatedFixture(t, "participant-originated-import-negatives")
	pledge, _ := participantOriginatedPledges("import-negatives", true)
	prepared, output := prepareParticipantOriginatedRole(t, fixture, RoleA, pledge)
	baseQuarantine := filepath.Join(fixture.root, "negative-base-quarantine")
	stagePreparedArtifact(t, RoleA, output, baseQuarantine, prepared)
	baseExpected := participantOriginatedExpectationsForPrepared(t, fixture, RoleA, prepared)
	if _, err := VerifyStagedParticipantOriginatedArtifact(ParticipantOriginatedVerificationOptions{
		PublicRoot: fixture.publicRoot, QuarantineRoot: baseQuarantine, Expected: baseExpected,
	}); err != nil {
		t.Fatalf("valid negative-test baseline: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(string, *ParticipantOriginatedArtifactExpectations)
	}{
		{"role_swap", func(root string, expected *ParticipantOriginatedArtifactExpectations) {
			artifact := mutateParticipantOriginatedManifest(t, root, fixture.privateA, func(artifact *EncryptedParticipantArtifact) {
				artifact.ParticipantRole = RoleB
			})
			expected.ArtifactDigest, _ = artifact.Digest()
		}},
		{"cross_case", func(root string, expected *ParticipantOriginatedArtifactExpectations) {
			artifact := mutateParticipantOriginatedManifest(t, root, fixture.privateA, func(artifact *EncryptedParticipantArtifact) {
				artifact.CaseID = testDigest("another-case")
			})
			expected.ArtifactDigest, _ = artifact.Digest()
		}},
		{"wrong_participant_signing_key", func(root string, expected *ParticipantOriginatedArtifactExpectations) {
			artifact := mutateParticipantOriginatedManifest(t, root, fixture.privateB, func(*EncryptedParticipantArtifact) {})
			expected.ArtifactDigest, _ = artifact.Digest()
		}},
		{"wrong_fhe_public_key", func(root string, expected *ParticipantOriginatedArtifactExpectations) {
			artifact := mutateParticipantOriginatedManifest(t, root, fixture.privateA, func(artifact *EncryptedParticipantArtifact) {
				artifact.PublicKeyDigest = testDigest("another-fhe-public-key")
			})
			expected.ArtifactDigest, _ = artifact.Digest()
		}},
		{"wrong_parameter_profile", func(root string, expected *ParticipantOriginatedArtifactExpectations) {
			artifact := mutateParticipantOriginatedManifest(t, root, fixture.privateA, func(artifact *EncryptedParticipantArtifact) {
				artifact.ParameterProfile += ".substituted"
			})
			expected.ArtifactDigest, _ = artifact.Digest()
		}},
		{"wrong_parameter_fingerprint", func(root string, expected *ParticipantOriginatedArtifactExpectations) {
			artifact := mutateParticipantOriginatedManifest(t, root, fixture.privateA, func(artifact *EncryptedParticipantArtifact) {
				artifact.ParameterFingerprint = testDigest("another-parameter-set")
			})
			expected.ArtifactDigest, _ = artifact.Digest()
		}},
		{"wrong_circuit", func(root string, expected *ParticipantOriginatedArtifactExpectations) {
			artifact := mutateParticipantOriginatedManifest(t, root, fixture.privateA, func(artifact *EncryptedParticipantArtifact) {
				artifact.CircuitDigest = testDigest("another-circuit")
			})
			expected.ArtifactDigest, _ = artifact.Digest()
		}},
		{"wrong_ciphertext_fhe_key", func(root string, expected *ParticipantOriginatedArtifactExpectations) {
			artifact := mutateParticipantOriginatedCiphertext(t, root, fixture.privateA, func(pledge *fhe.CipherPledge) {
				pledge.KeyID += "-substituted"
			})
			expected.CiphertextDigest = artifact.CiphertextObject.Digest
			expected.ArtifactDigest, _ = artifact.Digest()
		}},
		{"wrong_ciphertext_parameters", func(root string, expected *ParticipantOriginatedArtifactExpectations) {
			artifact := mutateParticipantOriginatedCiphertext(t, root, fixture.privateA, func(pledge *fhe.CipherPledge) {
				pledge.ParameterFingerprint[0] ^= 0xff
			})
			expected.CiphertextDigest = artifact.CiphertextObject.Digest
			expected.ArtifactDigest, _ = artifact.Digest()
		}},
		{"expired", func(_ string, expected *ParticipantOriginatedArtifactExpectations) {
			expected.Now = time.Unix(prepared.Artifact.ExpiresAtUnix, 0)
		}},
		{"truncated_ciphertext", func(root string, _ *ParticipantOriginatedArtifactExpectations) {
			data, err := os.ReadFile(filepath.Join(root, submissionAObject))
			if err != nil {
				t.Fatal(err)
			}
			rewriteParticipantOriginatedObject(t, root, submissionAObject, data[:len(data)-1])
		}},
		{"wrong_artifact_digest", func(_ string, expected *ParticipantOriginatedArtifactExpectations) {
			expected.ArtifactDigest = testDigest("wrong-artifact-digest")
		}},
		{"wrong_ciphertext_digest", func(_ string, expected *ParticipantOriginatedArtifactExpectations) {
			expected.CiphertextDigest = testDigest("wrong-ciphertext-digest")
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			quarantine := cloneParticipantOriginatedQuarantine(t, baseQuarantine, testCase.name)
			expected := baseExpected
			testCase.mutate(quarantine, &expected)
			if _, err := VerifyStagedParticipantOriginatedArtifact(ParticipantOriginatedVerificationOptions{
				PublicRoot: fixture.publicRoot, QuarantineRoot: quarantine, Expected: expected,
			}); err == nil {
				t.Fatal("mutated import verified")
			}
		})
	}

	t.Run("replacement_after_verify", func(t *testing.T) {
		quarantine := cloneParticipantOriginatedQuarantine(t, baseQuarantine, "replacement-after-verify")
		if _, err := VerifyStagedParticipantOriginatedArtifact(ParticipantOriginatedVerificationOptions{
			PublicRoot: fixture.publicRoot, QuarantineRoot: quarantine, Expected: baseExpected,
		}); err != nil {
			t.Fatal(err)
		}
		mutateParticipantOriginatedManifest(t, quarantine, fixture.privateA, func(artifact *EncryptedParticipantArtifact) {
			artifact.SubmissionNonce = testDigest("replacement-nonce")
		})
		if _, err := PublishParticipantOriginatedArtifact(ParticipantOriginatedPublicationOptions{
			PublicRoot: fixture.publicRoot, QuarantineRoot: quarantine, JournalRoot: fixture.journalRoot,
			Expected: baseExpected, Now: fixture.now,
		}); err == nil {
			t.Fatal("post-verification artifact replacement published")
		}
	})

	t.Run("occupied_role", func(t *testing.T) {
		publicStore, err := openObjectStore(fixture.publicRoot, PublicCaseQuota, false)
		if err != nil {
			t.Fatal(err)
		}
		defer publicStore.close()
		for _, name := range []string{submissionAObject, submissionAManifest} {
			data, err := os.ReadFile(filepath.Join(output, name))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := publicStore.create(name, data); err != nil {
				t.Fatal(err)
			}
		}
		quarantine := cloneParticipantOriginatedQuarantine(t, baseQuarantine, "occupied-role")
		if _, err := PublishParticipantOriginatedArtifact(ParticipantOriginatedPublicationOptions{
			PublicRoot: fixture.publicRoot, QuarantineRoot: quarantine, JournalRoot: fixture.journalRoot,
			Expected: baseExpected, Now: fixture.now,
		}); !errors.Is(err, ErrParticipantRoleOccupied) {
			t.Fatalf("occupied role error=%v", err)
		}
	})
}

func TestParticipantOriginatedStageRejectsArbitraryNames(t *testing.T) {
	for _, name := range []string{"../submission-a.bin", "/submission-a.bin", "nested/submission-a.bin", `nested\submission-a.bin`} {
		_, err := StageParticipantOriginatedArtifact(ParticipantOriginatedStageOptions{
			QuarantineRoot: filepath.Join(t.TempDir(), "quarantine"), Role: RoleA,
			Objects: []ParticipantOriginatedImportObject{
				{Name: "submission-a.json", Reader: bytes.NewReader([]byte("{}\n"))},
				{Name: name, Reader: io.LimitReader(bytes.NewReader([]byte("ciphertext")), 32)},
			},
		})
		if err == nil {
			t.Fatalf("arbitrary staged filename accepted: %q", name)
		}
	}
}

func TestPublishParticipantOriginatedObjectAuthenticatesBeforePublicLink(t *testing.T) {
	root := taskTempDir(t, "mordant-participant-publish-copy-")
	source, err := openObjectStore(filepath.Join(root, "quarantine"), PublicCaseQuota, false)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	destination, err := openObjectStore(filepath.Join(root, "public"), PublicCaseQuota, false)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.close()
	replacement := []byte("quarantine-object-replaced-after-verification")
	actual, err := source.create(submissionAObject, replacement)
	if err != nil {
		t.Fatal(err)
	}
	expected := actual
	expected.Digest = testDigest("expected-ciphertext-before-replacement")
	if _, err := publishStagedObject(
		destination,
		source,
		submissionAObject,
		expected,
		participantOriginatedMaximumCiphertextBytes,
		false,
	); err == nil {
		t.Fatal("mismatched quarantine source published")
	}
	if destination.exists(submissionAObject) {
		t.Fatal("failed authenticated copy poisoned the create-only public name")
	}
	if names, err := destination.names(); err != nil || len(names) != 0 {
		t.Fatalf("failed authenticated copy left public objects: %v %v", names, err)
	}
}

func TestParticipantOriginatedStageRejectsAuthenticatedObjectRefMismatch(t *testing.T) {
	manifest := []byte("manifest")
	ciphertext := []byte("ciphertext")
	_, err := StageParticipantOriginatedArtifact(ParticipantOriginatedStageOptions{
		QuarantineRoot: filepath.Join(taskTempDir(t, "mordant-participant-stage-ref-"), "quarantine"), Role: RoleA,
		Objects: []ParticipantOriginatedImportObject{
			{Name: submissionAManifest, Reader: bytes.NewReader(manifest), Expected: ObjectRef{
				Path: submissionAManifest, Digest: testDigest("authenticated-but-wrong-manifest"), Length: int64(len(manifest)),
			}},
			{Name: submissionAObject, Reader: bytes.NewReader(ciphertext), Expected: ObjectRef{
				Path: submissionAObject, Digest: DigestBytes(ciphertext), Length: int64(len(ciphertext)),
			}},
		},
	})
	if !errors.Is(err, ErrArtifact) {
		t.Fatalf("authenticated object-ref mismatch error=%v", err)
	}
}

func TestStageParticipantOriginatedObjectUsesDerivedCreateOnlyTarget(t *testing.T) {
	root := filepath.Join(taskTempDir(t, "mordant-participant-stage-object-"), "quarantine")
	manifest := []byte("exact-manifest-stream")
	ciphertext := []byte("exact-ciphertext-stream")
	manifestRef := ObjectRef{Path: submissionAManifest, Digest: DigestBytes(manifest), Length: int64(len(manifest))}
	ciphertextRef := ObjectRef{Path: submissionAObject, Digest: DigestBytes(ciphertext), Length: int64(len(ciphertext))}
	if _, err := StageParticipantOriginatedObject(ParticipantOriginatedStageObjectOptions{
		QuarantineRoot: root, Role: RoleA, Kind: ParticipantOriginatedStageManifest,
		Expected: manifestRef, Reader: bytes.NewReader(manifest),
	}); !errors.Is(err, ErrParticipantImportMismatch) {
		t.Fatalf("manifest-first ordering error=%v", err)
	}
	created, err := StageParticipantOriginatedObject(ParticipantOriginatedStageObjectOptions{
		QuarantineRoot: root, Role: RoleA, Kind: ParticipantOriginatedStageCiphertext,
		Expected: ciphertextRef, Reader: bytes.NewReader(ciphertext),
	})
	if err != nil || created != ciphertextRef {
		t.Fatalf("stage ciphertext object: %+v %v", created, err)
	}
	if _, err := StageParticipantOriginatedObject(ParticipantOriginatedStageObjectOptions{
		QuarantineRoot: root, Role: RoleA, Kind: ParticipantOriginatedStageCiphertext,
		Expected: ciphertextRef, Reader: bytes.NewReader(ciphertext),
	}); !errors.Is(err, ErrParticipantRoleOccupied) {
		t.Fatalf("single-object overwrite error=%v", err)
	}
	created, err = StageParticipantOriginatedObject(ParticipantOriginatedStageObjectOptions{
		QuarantineRoot: root, Role: RoleA, Kind: ParticipantOriginatedStageManifest,
		Expected: manifestRef, Reader: bytes.NewReader(manifest),
	})
	if err != nil || created != manifestRef {
		t.Fatalf("stage manifest-last commit: %+v %v", created, err)
	}
}

func TestParticipantOriginatedNonceClaimIsAtomicAcrossRoles(t *testing.T) {
	journalRoot := filepath.Join(taskTempDir(t, "mordant-participant-nonce-"), "journal")
	nonce := testDigest("shared-submission-nonce")
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, role := range []string{RoleA, RoleB} {
		role := role
		go func() {
			journal, err := openObjectStore(journalRoot, PrivateCaseQuota, true)
			if err != nil {
				results <- err
				return
			}
			defer journal.close()
			<-start
			verification := ParticipantOriginatedArtifactVerification{
				Role: role, CaseID: testDigest("nonce-case"), SubmissionNonce: nonce,
				ArtifactDigest: testDigest("artifact/" + role),
			}
			_, err = claimParticipantOriginatedNonce(journal, testDigest("verification/"+role), verification)
			results <- err
		}()
	}
	close(start)
	successes, replays := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrParticipantImportReplay):
			replays++
		default:
			t.Fatalf("unexpected nonce claim result: %v", err)
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("nonce race admitted successes=%d replays=%d", successes, replays)
	}
}

func assertNoParticipantOriginatedTemporaryObjects(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mordant-create-") {
			t.Fatalf("temporary object remained: %s", entry.Name())
		}
	}
}

func TestParticipantOriginatedStoreRecoversBoundedCrashTemporaries(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		postLink bool
	}{
		{"pre_link", false},
		{"post_link", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := filepath.Join(taskTempDir(t, "mordant-participant-temp-recovery-"), "quarantine")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			temporaryName := ".mordant-create-00000000000000000000000000000001"
			temporaryPath := filepath.Join(root, temporaryName)
			payload := []byte("participant-originated-crash-temporary")
			if err := os.WriteFile(temporaryPath, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if testCase.postLink {
				if err := os.Chmod(temporaryPath, 0o444); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(temporaryPath, filepath.Join(root, submissionAObject)); err != nil {
					t.Fatal(err)
				}
			}
			store, err := openParticipantOriginatedArtifactStore(root, PublicCaseQuota, false, RoleA)
			if err != nil {
				t.Fatalf("recover %s temporary: %v", testCase.name, err)
			}
			_ = store.close()
			assertNoParticipantOriginatedTemporaryObjects(t, root)
			published, readErr := os.ReadFile(filepath.Join(root, submissionAObject))
			if testCase.postLink {
				if readErr != nil || !bytes.Equal(published, payload) {
					t.Fatalf("post-link target not preserved: %q %v", published, readErr)
				}
			} else if !errors.Is(readErr, os.ErrNotExist) {
				t.Fatalf("pre-link recovery created a target: %v", readErr)
			}
		})
	}

	t.Run("malformed_name_is_not_recovered", func(t *testing.T) {
		root := filepath.Join(taskTempDir(t, "mordant-participant-temp-malformed-"), "quarantine")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		malformed := filepath.Join(root, ".mordant-create-not-a-crash-id")
		if err := os.WriteFile(malformed, []byte("do-not-delete"), 0o600); err != nil {
			t.Fatal(err)
		}
		if store, err := openParticipantOriginatedArtifactStore(root, PublicCaseQuota, false, RoleA); err == nil {
			_ = store.close()
			t.Fatal("malformed temporary name was recovered")
		}
		if got, err := os.ReadFile(malformed); err != nil || string(got) != "do-not-delete" {
			t.Fatalf("malformed temporary was changed: %q %v", got, err)
		}
	})
}

type participantOriginatedHookReader struct {
	reader *bytes.Reader
	hook   func() error
	done   bool
}

func (r *participantOriginatedHookReader) Read(target []byte) (int, error) {
	if !r.done {
		r.done = true
		if err := r.hook(); err != nil {
			return 0, err
		}
	}
	return r.reader.Read(target)
}

func replaceParticipantOriginatedStoreRoot(root, old string) error {
	if err := os.Rename(root, old); err != nil {
		return err
	}
	return os.Mkdir(root, 0o755)
}

func TestCreateFromReaderExpectedFailsClosedOnParentReplacement(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		afterCommit bool
	}{
		{"during_stream", false},
		{"after_commit", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			parent := taskTempDir(t, "mordant-participant-parent-race-")
			root := filepath.Join(parent, "quarantine")
			old := filepath.Join(parent, "quarantine-old")
			store, err := openObjectStore(root, PublicCaseQuota, false)
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			payload := []byte("exact-stream-under-pinned-parent")
			expected := ObjectRef{Path: submissionAObject, Digest: DigestBytes(payload), Length: int64(len(payload))}
			reader := io.Reader(bytes.NewReader(payload))
			hooks := objectCreateHooks{}
			if testCase.afterCommit {
				hooks.afterCommit = func(int, string) error {
					return replaceParticipantOriginatedStoreRoot(root, old)
				}
			} else {
				reader = &participantOriginatedHookReader{
					reader: bytes.NewReader(payload),
					hook:   func() error { return replaceParticipantOriginatedStoreRoot(root, old) },
				}
			}
			if _, err := store.createFromReaderExpectedWithHooks(
				submissionAObject, reader, participantOriginatedMaximumCiphertextBytes, &expected, hooks,
			); err == nil {
				t.Fatal("parent replacement accepted")
			}
			for _, candidate := range []string{root, old} {
				if _, err := os.Stat(filepath.Join(candidate, submissionAObject)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed create left target in %s: %v", candidate, err)
				}
				assertNoParticipantOriginatedTemporaryObjects(t, candidate)
			}
		})
	}
}
