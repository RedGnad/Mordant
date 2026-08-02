package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	fhe "mordant.dev/fhe-lab/lattigo"
)

const (
	evaluatorBinaryEnvironment = "MORDANT_FHE_EVALUATOR_BIN"
	decryptorBinaryEnvironment = "MORDANT_FHE_DECRYPTOR_BIN"
)

type productionFixture struct {
	publicRoot   string
	privateRoot  string
	now          time.Time
	spec         CaseSpec
	privateA     ed25519.PrivateKey
	privateB     ed25519.PrivateKey
	pledgeA      fhe.PlainPledge
	pledgeB      fhe.PlainPledge
	artifactA    EncryptedParticipantArtifact
	artifactB    EncryptedParticipantArtifact
	keyReport    KeyGenerationReport
	reportA      SubmissionReport
	reportB      SubmissionReport
	evaluatorLog []byte
	decryptorLog []byte
}

type evaluatorProcessOutput struct {
	ArtifactDigest Digest `json:"artifactDigest"`
	DurationNanos  int64  `json:"durationNanos"`
	ResultBytes    int64  `json:"resultBytes"`
	ArtifactBytes  int64  `json:"artifactBytes"`
}

type decryptorProcessOutput struct {
	ResultDigest  Digest `json:"resultDigest"`
	Conflict      bool   `json:"conflict"`
	ReleaseMode   string `json:"releaseMode"`
	DurationNanos int64  `json:"durationNanos"`
	ResultBytes   int64  `json:"resultBytes"`
	ExactRetry    bool   `json:"exactRetry"`
}

func TestGovernedFHEProductionPaths(t *testing.T) {
	evaluatorBinary := requiredProcessBinary(t, evaluatorBinaryEnvironment)
	decryptorBinary := requiredProcessBinary(t, decryptorBinaryEnvironment)

	t.Run("conflict_bindings_release_and_recourse", func(t *testing.T) {
		fixture := newProductionFixture(t, true)
		assertFixedN15Material(t, fixture)
		assertEvaluatorAndReleaseAPIsAreNarrow(t)
		assertParticipantAndCaseMutationsRejected(t, fixture)

		evaluationOutput := runJSONProcess(t, evaluatorBinary, "-public-root", fixture.publicRoot)
		fixture.evaluatorLog = append([]byte(nil), evaluationOutput...)
		var evaluation evaluatorProcessOutput
		decodeProcessOutput(t, evaluationOutput, &evaluation)
		if !nonzero(evaluation.ArtifactDigest) || evaluation.DurationNanos <= 0 || evaluation.ResultBytes <= 0 || evaluation.ArtifactBytes <= 0 {
			t.Fatalf("invalid evaluator report: %+v", evaluation)
		}
		artifact, err := LoadEvaluatedConflictArtifact(fixture.publicRoot)
		if err != nil {
			t.Fatalf("load evaluated artifact: %v", err)
		}
		artifactDigest, _ := artifact.Digest()
		if artifactDigest != evaluation.ArtifactDigest {
			t.Fatalf("evaluator artifact digest mismatch")
		}
		assertEvaluatorProvenance(t, evaluatorBinary, artifact)
		assertEvaluatorResultSubstitutionRejected(t, fixture, artifact)
		assertArbitraryDecryptRequestRejected(t, fixture, artifact)

		firstOutput := runJSONProcess(t, decryptorBinary, "-public-root", fixture.publicRoot, "-private-root", fixture.privateRoot)
		fixture.decryptorLog = append([]byte(nil), firstOutput...)
		var first decryptorProcessOutput
		decodeProcessOutput(t, firstOutput, &first)
		if !first.Conflict || first.ExactRetry || first.ReleaseMode != ReleaseModeGovernedDecryptor || first.DurationNanos <= 0 || first.ResultBytes <= 0 {
			t.Fatalf("invalid first governed release: %+v", first)
		}
		result, publicResultBytes, err := LoadGovernedConflictResult(fixture.publicRoot)
		if err != nil {
			t.Fatalf("load governed result: %v", err)
		}
		assertResultReleaseBinding(t, fixture, artifact, result, decryptorBinary)
		assertSecondDistinctReleaseRejected(t, fixture, artifact)

		retainedBefore := mustReadFile(t, filepath.Join(fixture.privateRoot, retainedResultObject))
		retryOutput := runJSONProcess(t, decryptorBinary, "-public-root", fixture.publicRoot, "-private-root", fixture.privateRoot)
		var retry decryptorProcessOutput
		decodeProcessOutput(t, retryOutput, &retry)
		retainedAfter := mustReadFile(t, filepath.Join(fixture.privateRoot, retainedResultObject))
		if !retry.ExactRetry || retry.ResultDigest != first.ResultDigest || retry.Conflict != first.Conflict ||
			retry.ReleaseMode != first.ReleaseMode || !bytes.Equal(retainedBefore, retainedAfter) || !bytes.Equal(publicResultBytes, retainedAfter) {
			t.Fatalf("exact retry did not return the identical signed result")
		}

		holderAllocation := testDigest("conflict/holder-allocation")
		adapterNow := time.Unix(result.ReleasedAtUnix, 0).UTC()
		releaseAuthority, err := LoadReleaseAuthorityManifest(fixture.publicRoot)
		if err != nil {
			t.Fatalf("load pinned release authority: %v", err)
		}
		adapterConfig := RecourseAdapterConfig{
			RecordRoot: fixture.publicRoot, ExpectedCaseID: fixture.spec.CaseID,
			ExpectedBindingDigest: result.CaseBindingDigest, ExpectedAssetIdentity: fixture.spec.AssetIdentity,
			ExpectedPolicyID: fixture.spec.PolicyID, CaseCreatedAtUnix: fixture.spec.CreatedAtUnix,
			ExpectedReleaseMode: releaseAuthority.ReleaseMode, ExpectedReleaseAuthorityID: releaseAuthority.AuthorityID,
			CaseExpiresAtUnix: fixture.spec.ExpiresAtUnix, RecordDateUnix: fixture.spec.CreatedAtUnix - 60,
			CurePeriod: 24 * time.Hour, ReserveBasisPoints: MVPReserveBasisPoints,
			HolderAllocationDigest: holderAllocation, Now: adapterNow,
		}
		wrongAsset := adapterConfig
		wrongAsset.ExpectedAssetIdentity = testDigest("wrong/recourse-asset")
		if _, err := AdaptSignedResultToRecourse(wrongAsset, publicResultBytes); !errors.Is(err, ErrRecourse) {
			t.Fatalf("signed result was reusable for another asset: %v", err)
		}
		wrongPolicy := adapterConfig
		wrongPolicy.ExpectedPolicyID = testDigest("wrong/recourse-policy")
		if _, err := AdaptSignedResultToRecourse(wrongPolicy, publicResultBytes); !errors.Is(err, ErrRecourse) {
			t.Fatalf("signed result was reusable for another policy: %v", err)
		}
		wrongAuthority := adapterConfig
		wrongAuthority.ExpectedReleaseAuthorityID = testDigest("wrong/recourse-release-authority")
		if _, err := AdaptSignedResultToRecourse(wrongAuthority, publicResultBytes); !errors.Is(err, ErrRecourse) {
			t.Fatalf("signed result was reusable under another release authority: %v", err)
		}
		record, err := AdaptSignedResultToRecourse(adapterConfig, publicResultBytes)
		if err != nil {
			t.Fatalf("adapt true result to recourse: %v", err)
		}
		if !record.Open || !record.OriginalReceivableIntact || record.CaseID != result.CaseID || record.AssetIdentity != result.AssetIdentity ||
			record.PolicyID != result.PolicyID || record.ReleaseMode != result.ReleaseMode || record.ReleaseAuthorityID != result.ReleaseAuthorityID ||
			record.RecordDateUnix > fixture.spec.CreatedAtUnix || record.BoundAtUnix != adapterNow.Unix() ||
			record.CureDeadlineUnix != adapterNow.Add(24*time.Hour).Unix() || record.ReserveBasisPoints != MVPReserveBasisPoints ||
			record.HolderAllocationDigest != holderAllocation {
			t.Fatalf("recourse chronology or exact binding changed: %+v", record)
		}

		measurements := SmokeMeasurements{
			KeyGeneration: fixture.keyReport, Submissions: []SubmissionReport{fixture.reportA, fixture.reportB},
			Evaluation: EvaluationReport{Duration: time.Duration(evaluation.DurationNanos), ResultCiphertextBytes: evaluation.ResultBytes, ArtifactBytes: evaluation.ArtifactBytes},
			Release:    ReleaseReport{Duration: time.Duration(first.DurationNanos), ResultBytes: first.ResultBytes},
		}
		evidence, err := ExportPublicEvidence(fixture.publicRoot, fixture.privateRoot, measurements, adapterNow)
		if err != nil {
			t.Fatalf("export public evidence: %v", err)
		}
		if !evidence.SecretScanClean || evidence.ProductClaim != ProductClaim || evidence.ReleaseMode != ReleaseModeGovernedDecryptor ||
			evidence.ReleaseAuthorityID != result.ReleaseAuthorityID || evidence.GovernedResultDigest != first.ResultDigest {
			t.Fatalf("invalid public evidence: %+v", evidence)
		}
		assertNoPrivateOrPlaintextMaterialIsPublic(t, fixture)
	})

	t.Run("no_conflict_cannot_activate_recourse", func(t *testing.T) {
		fixture := newProductionFixture(t, false)
		evaluationOutput := runJSONProcess(t, evaluatorBinary, "-public-root", fixture.publicRoot)
		var evaluation evaluatorProcessOutput
		decodeProcessOutput(t, evaluationOutput, &evaluation)
		if evaluation.DurationNanos <= 0 || evaluation.ResultBytes <= 0 {
			t.Fatalf("real no-conflict evaluation did not complete")
		}
		releaseOutput := runJSONProcess(t, decryptorBinary, "-public-root", fixture.publicRoot, "-private-root", fixture.privateRoot)
		var release decryptorProcessOutput
		decodeProcessOutput(t, releaseOutput, &release)
		if release.Conflict || release.ExactRetry || release.ReleaseMode != ReleaseModeGovernedDecryptor {
			t.Fatalf("no-conflict release was not false: %+v", release)
		}
		result, signedResult, err := LoadGovernedConflictResult(fixture.publicRoot)
		if err != nil {
			t.Fatalf("load no-conflict result: %v", err)
		}
		releaseAuthority, err := LoadReleaseAuthorityManifest(fixture.publicRoot)
		if err != nil {
			t.Fatalf("load no-conflict release authority: %v", err)
		}
		_, err = AdaptSignedResultToRecourse(RecourseAdapterConfig{
			RecordRoot: fixture.publicRoot, ExpectedCaseID: fixture.spec.CaseID,
			ExpectedBindingDigest: result.CaseBindingDigest, ExpectedAssetIdentity: fixture.spec.AssetIdentity,
			ExpectedPolicyID: fixture.spec.PolicyID, CaseCreatedAtUnix: fixture.spec.CreatedAtUnix,
			ExpectedReleaseMode: releaseAuthority.ReleaseMode, ExpectedReleaseAuthorityID: releaseAuthority.AuthorityID,
			CaseExpiresAtUnix: fixture.spec.ExpiresAtUnix, RecordDateUnix: fixture.spec.CreatedAtUnix - 60,
			CurePeriod: 24 * time.Hour, ReserveBasisPoints: MVPReserveBasisPoints,
			HolderAllocationDigest: testDigest("no-conflict/holder-allocation"), Now: time.Now().UTC(),
		}, signedResult)
		if !errors.Is(err, ErrRecourse) {
			t.Fatalf("false result activated recourse: %v", err)
		}
	})
}

func TestAcceptedOneShotBoundariesAreNotImported(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate governed FHE package")
	}
	entries, err := os.ReadDir(filepath.Dir(filename))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		data := mustReadFile(t, filepath.Join(filepath.Dir(filename), entry.Name()))
		if bytes.Contains(data, []byte("oneshotceremony")) || bytes.Contains(data, []byte("oneshotruntime")) {
			t.Fatalf("governed FHE package references accepted one-shot boundary in %s", entry.Name())
		}
	}
}

func newProductionFixture(t *testing.T, conflict bool) *productionFixture {
	t.Helper()
	root := taskTempDir(t, "mordant-governed-production-")
	publicRoot := filepath.Join(root, "public")
	privateRoot := filepath.Join(root, "decryptor-private")
	publicA, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, privateB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	label := strings.ReplaceAll(t.Name(), "/", "-")
	now := time.Now().UTC()
	spec := CaseSpec{
		CaseID: testDigest(label + "/case"), AssetIdentity: testDigest(label + "/asset"),
		PolicyID:     testDigest("conflicting-pledge-policy/v1"),
		ParticipantA: ParticipantIdentity{ID: testDigest(label + "/participant-a"), Role: RoleA, SigningPublicKey: publicA},
		ParticipantB: ParticipantIdentity{ID: testDigest(label + "/participant-b"), Role: RoleB, SigningPublicKey: publicB},
		CaseNonce:    testDigest(label + "/case-nonce"), CreatedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(2 * time.Hour).Unix(),
	}
	_, keyReport, err := CreateCase(CreateCaseOptions{
		PublicRoot: publicRoot, PrivateRoot: privateRoot, Spec: spec, SourceProvenance: testDigest("keygen/source"),
	})
	if err != nil {
		t.Fatalf("real N15 case key generation: %v", err)
	}
	pledgeA, pledgeB := productionPledgePair(label, conflict)
	artifactA, reportA, err := SubmitParticipant(ParticipantSubmissionOptions{
		PublicRoot: publicRoot, Role: RoleA, SigningKey: privateA, Pledge: pledgeA,
		SubmissionNonce: testDigest(label + "/submission-a"), ExpiresAtUnix: now.Add(time.Hour).Unix(), Now: now,
	})
	if err != nil {
		t.Fatalf("participant A real encryption: %v", err)
	}
	artifactB, reportB, err := SubmitParticipant(ParticipantSubmissionOptions{
		PublicRoot: publicRoot, Role: RoleB, SigningKey: privateB, Pledge: pledgeB,
		SubmissionNonce: testDigest(label + "/submission-b"), ExpiresAtUnix: now.Add(time.Hour).Unix(), Now: now,
	})
	if err != nil {
		t.Fatalf("participant B real encryption: %v", err)
	}
	if artifactA.CiphertextObject.Length <= 0 || artifactB.CiphertextObject.Length <= 0 || reportA.CiphertextBytes <= 0 || reportB.CiphertextBytes <= 0 {
		t.Fatalf("real participant ciphertexts were not produced")
	}
	if _, err := FinalizeCase(publicRoot); err != nil {
		t.Fatalf("finalize exact two-party case binding: %v", err)
	}
	return &productionFixture{
		publicRoot: publicRoot, privateRoot: privateRoot, now: now, spec: spec, privateA: privateA, privateB: privateB,
		pledgeA: pledgeA, pledgeB: pledgeB, artifactA: artifactA, artifactB: artifactB,
		keyReport: keyReport, reportA: reportA, reportB: reportB,
	}
}

func assertFixedN15Material(t *testing.T, fixture *productionFixture) {
	t.Helper()
	store, err := openObjectStore(fixture.publicRoot, PublicCaseQuota, false)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCaseManifest(store)
	if err != nil {
		t.Fatal(err)
	}
	params, _, err := loadPublicEncryptionMaterial(store, manifest.Crypto)
	if err != nil || ValidateParameters(params) != nil || params.LogN() != 15 || params.PlaintextModulus() != 65537 {
		t.Fatalf("wrong fixed N15 parameters: %v", err)
	}
	expectedElements, err := GaloisElements(params)
	if err != nil || len(expectedElements) != 9 || len(manifest.Crypto.EvaluationKeys.GaloisKeys) != 9 || len(fixture.keyReport.GaloisKeyBytes) != 9 {
		t.Fatalf("wrong exact Galois-key count")
	}
	for index, expectedElement := range expectedElements {
		entry := manifest.Crypto.EvaluationKeys.GaloisKeys[index]
		encoded, readErr := store.read(entry.Object, 96<<20)
		key := rlwe.NewGaloisKey(params)
		if readErr != nil || key.UnmarshalBinary(encoded) != nil || entry.Step != rotationSteps[index] || entry.Element != expectedElement ||
			key.GaloisElement != expectedElement || fixture.keyReport.GaloisKeyBytes[index] != int64(len(encoded)) {
			t.Fatalf("Galois key %d does not match fixed rotation %d", index, rotationSteps[index])
		}
	}
	privateInfo, err := os.Stat(filepath.Join(fixture.privateRoot, secretKeyObject))
	if err != nil || privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("secret key is not a restrictive private object: %v", err)
	}
	if rootsDisjoint(fixture.publicRoot, filepath.Join(fixture.publicRoot, "x")) || rootsDisjoint(filepath.Join(fixture.privateRoot, "x"), fixture.privateRoot) {
		t.Fatalf("nested public/private roots accepted")
	}
	if _, err := store.create(publicKeyObject, []byte("overwrite")); !errors.Is(err, ErrStore) {
		t.Fatalf("create-only public store allowed overwrite: %v", err)
	}
}

func assertEvaluatorAndReleaseAPIsAreNarrow(t *testing.T) {
	t.Helper()
	evaluatorType := reflect.TypeOf(EvaluatorConfig{})
	expectedFields := []string{"PublicRoot", "Provenance", "Now"}
	if evaluatorType.NumField() != len(expectedFields) {
		t.Fatalf("evaluator configuration widened: %v", evaluatorType)
	}
	for index, expected := range expectedFields {
		if evaluatorType.Field(index).Name != expected {
			t.Fatalf("evaluator configuration contains unexpected field %s", evaluatorType.Field(index).Name)
		}
	}
	interfaceType := reflect.TypeOf((*FixedConflictReleaser)(nil)).Elem()
	method, ok := interfaceType.MethodByName("ReleaseFixedConflict")
	if !ok || method.Type.NumIn() != 1 || method.Type.In(0) != reflect.TypeOf(EvaluatedConflictArtifact{}) || method.Type.NumOut() != 3 {
		t.Fatalf("fixed release boundary widened: %v", interfaceType)
	}
	if ReleaseModeGovernedDecryptor != "governed-decryptor-v1" || ReleaseModeThreshold2Of3 != "threshold-2of3-v1" {
		t.Fatalf("release-mode identities changed")
	}
}

func assertParticipantAndCaseMutationsRejected(t *testing.T, fixture *productionFixture) {
	t.Helper()
	participantCases := []struct {
		name   string
		role   string
		mutate func(*EncryptedParticipantArtifact)
	}{
		{"wrong_case", RoleA, func(value *EncryptedParticipantArtifact) { value.CaseID = testDigest("wrong/case") }},
		{"wrong_asset", RoleA, func(value *EncryptedParticipantArtifact) { value.AssetIdentity = testDigest("wrong/asset") }},
		{"wrong_participant", RoleA, func(value *EncryptedParticipantArtifact) { value.ParticipantID = fixture.spec.ParticipantB.ID }},
		{"wrong_public_key", RoleA, func(value *EncryptedParticipantArtifact) { value.PublicKeyDigest = testDigest("wrong/public-key") }},
		{"wrong_parameter_profile", RoleA, func(value *EncryptedParticipantArtifact) { value.ParameterProfile = "other-profile" }},
		{"wrong_parameter_fingerprint", RoleA, func(value *EncryptedParticipantArtifact) { value.ParameterFingerprint = testDigest("wrong/parameters") }},
		{"wrong_circuit", RoleA, func(value *EncryptedParticipantArtifact) { value.CircuitDigest = testDigest("wrong/circuit") }},
		{"component_substitution", RoleA, func(value *EncryptedParticipantArtifact) {
			value.Components[0].Digest = testDigest("substituted/component")
		}},
		{"expired_submission", RoleA, func(value *EncryptedParticipantArtifact) { value.ExpiresAtUnix = fixture.now.Add(-time.Second).Unix() }},
		{"duplicate_submission_nonce", RoleB, func(value *EncryptedParticipantArtifact) { value.SubmissionNonce = fixture.artifactA.SubmissionNonce }},
	}
	for _, testCase := range participantCases {
		t.Run(testCase.name, func(t *testing.T) {
			clone := cloneFlatRoot(t, fixture.publicRoot)
			store, err := openObjectStore(clone, PublicCaseQuota, false)
			if err != nil {
				t.Fatal(err)
			}
			_, _, manifestName, _ := participantFiles(testCase.role)
			var artifact EncryptedParticipantArtifact
			if _, _, err := store.readJSON(manifestName, &artifact); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(&artifact)
			key := fixture.privateA
			if testCase.role == RoleB {
				key = fixture.privateB
			}
			artifact.Signature, err = signCanonical(key, "MordantEncryptedParticipantArtifact/v1", artifact.signingValue())
			if err != nil {
				t.Fatal(err)
			}
			replaceCanonicalObject(t, clone, manifestName, artifact)
			if _, _, err := EvaluateFixedConflict(EvaluatorConfig{PublicRoot: clone, Provenance: testDigest("evaluator"), Now: fixture.now}); err == nil {
				t.Fatalf("evaluator accepted %s", testCase.name)
			}
		})
	}
	t.Run("swapped_participant_order", func(t *testing.T) {
		clone := cloneFlatRoot(t, fixture.publicRoot)
		store, _ := openObjectStore(clone, PublicCaseQuota, false)
		var manifest FHECaseManifest
		if _, _, err := store.readJSON(caseManifestObject, &manifest); err != nil {
			t.Fatal(err)
		}
		manifest.Binding.ParticipantOrder[0], manifest.Binding.ParticipantOrder[1] = manifest.Binding.ParticipantOrder[1], manifest.Binding.ParticipantOrder[0]
		replaceCanonicalObject(t, clone, caseManifestObject, manifest)
		if _, _, err := EvaluateFixedConflict(EvaluatorConfig{PublicRoot: clone, Provenance: testDigest("evaluator"), Now: fixture.now}); err == nil {
			t.Fatalf("evaluator accepted swapped participant order")
		}
	})
}

func assertEvaluatorProvenance(t *testing.T, binary string, artifact EvaluatedConflictArtifact) {
	t.Helper()
	executableBytes := mustReadFile(t, binary)
	if artifact.EvaluatorProvenance != DigestBytes(executableBytes) {
		t.Fatalf("evaluated artifact does not bind the real evaluator executable")
	}
}

func assertEvaluatorResultSubstitutionRejected(t *testing.T, fixture *productionFixture, artifact EvaluatedConflictArtifact) {
	t.Helper()
	clone := cloneFlatRoot(t, fixture.publicRoot)
	resultPath := filepath.Join(clone, resultCiphertextObject)
	resultBytes := mustReadFile(t, resultPath)
	resultBytes[len(resultBytes)-1] ^= 1
	if err := os.Remove(resultPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resultPath, resultBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	decryptor, err := NewGovernedDecryptor(GovernedDecryptorConfig{
		PublicRoot: clone, PrivateRoot: fixture.privateRoot, Provenance: testDigest("decryptor"), Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decryptor.ReleaseFixedConflict(artifact); err == nil {
		t.Fatalf("substituted evaluator result was accepted")
	}
	if fileExists(filepath.Join(fixture.privateRoot, releaseAdmissionObject)) {
		t.Fatalf("invalid evaluator result consumed the release")
	}
}

func assertArbitraryDecryptRequestRejected(t *testing.T, fixture *productionFixture, artifact EvaluatedConflictArtifact) {
	t.Helper()
	decryptor, err := NewGovernedDecryptor(GovernedDecryptorConfig{
		PublicRoot: fixture.publicRoot, PrivateRoot: fixture.privateRoot, Provenance: testDigest("decryptor"), Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	mutated := artifact
	mutated.ResultCiphertext.Path = submissionAObject
	mutated.OutputSlot = 1
	if _, _, err := decryptor.ReleaseFixedConflict(mutated); !errors.Is(err, ErrBinding) {
		t.Fatalf("arbitrary ciphertext/slot request was not rejected: %v", err)
	}
	if fileExists(filepath.Join(fixture.privateRoot, releaseAdmissionObject)) {
		t.Fatalf("arbitrary request consumed the fixed release")
	}
}

func assertResultReleaseBinding(t *testing.T, fixture *productionFixture, artifact EvaluatedConflictArtifact, result GovernedConflictResult, decryptorBinary string) {
	t.Helper()
	store, _ := openObjectStore(fixture.publicRoot, PublicCaseQuota, false)
	manifest, err := loadCaseManifest(store)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := loadReleaseAuthority(store, manifest)
	if err != nil {
		t.Fatal(err)
	}
	decryptorDigest := DigestBytes(mustReadFile(t, decryptorBinary))
	if result.ReleaseMode != ReleaseModeGovernedDecryptor || result.ReleaseOrdinal != ReleaseOrdinal ||
		result.ReleaseAuthorityID != authority.AuthorityID || !bytes.Equal(result.ReleaseAuthorityPublicKey, authority.SigningPublicKey) ||
		result.SourceProvenance != decryptorDigest || result.CaseID != fixture.spec.CaseID || result.AssetIdentity != fixture.spec.AssetIdentity ||
		result.PolicyID != fixture.spec.PolicyID || result.ResultCiphertextDigest != artifact.ResultCiphertext.Digest ||
		result.ResultCiphertextCommitment != artifact.ResultCiphertextCommitment {
		t.Fatalf("signed result omitted an exact release or case binding")
	}
	mutated := result
	mutated.ReleaseMode = ReleaseModeThreshold2Of3
	if verifyGovernedResult(mutated, manifest, artifact, authority) == nil {
		t.Fatalf("signed result accepted a substituted release mode")
	}
	mutated = result
	mutated.ReleaseAuthorityID = testDigest("substituted/authority")
	if verifyGovernedResult(mutated, manifest, artifact, authority) == nil {
		t.Fatalf("signed result accepted a substituted release authority")
	}
}

func assertSecondDistinctReleaseRejected(t *testing.T, fixture *productionFixture, artifact EvaluatedConflictArtifact) {
	t.Helper()
	decryptor, err := NewGovernedDecryptor(GovernedDecryptorConfig{
		PublicRoot: fixture.publicRoot, PrivateRoot: fixture.privateRoot, Provenance: testDigest("decryptor/retry"), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	mutated := artifact
	mutated.ResultCiphertextCommitment = testDigest("second/distinct/result")
	if _, _, err := decryptor.ReleaseFixedConflict(mutated); !errors.Is(err, ErrBinding) {
		t.Fatalf("second distinct release was not rejected: %v", err)
	}
	if !fileExists(filepath.Join(fixture.privateRoot, releaseConsumedObject)) {
		t.Fatalf("release was not durably consumed")
	}
}

func assertNoPrivateOrPlaintextMaterialIsPublic(t *testing.T, fixture *productionFixture) {
	t.Helper()
	secretKey := mustReadFile(t, filepath.Join(fixture.privateRoot, secretKeyObject))
	signingKey := mustReadFile(t, filepath.Join(fixture.privateRoot, decryptorSigningKeyObject))
	for _, name := range []string{secretKeyObject, decryptorSigningKeyObject, privateCaseObject, retainedResultObject, releaseAdmissionObject, releaseConsumedObject} {
		if fileExists(filepath.Join(fixture.publicRoot, name)) {
			t.Fatalf("private object %s is public", name)
		}
	}
	for _, entry := range mustReadDirectory(t, fixture.publicRoot) {
		data := mustReadFile(t, filepath.Join(fixture.publicRoot, entry.Name()))
		if bytes.Contains(data, secretKey) || bytes.Contains(data, signingKey) {
			t.Fatalf("private key material appears in public object %s", entry.Name())
		}
		sensitivePlaintext := [][]byte{
			fixture.pledgeA.ReceivableID[:], fixture.pledgeB.ReceivableID[:], fixture.pledgeA.ObligationID[:], fixture.pledgeB.ObligationID[:],
		}
		for _, plaintext := range sensitivePlaintext {
			if bytes.Contains(data, plaintext) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(plaintext))) {
				t.Fatalf("encrypted pledge field appears in public object %s", entry.Name())
			}
		}
		// CipherPledge deliberately carries authorization and private-metadata
		// commitments as opaque public values. They still must never be copied
		// into a JSON manifest, result statement or evidence record.
		if filepath.Ext(entry.Name()) == ".json" {
			for _, plaintext := range [][]byte{
				fixture.pledgeA.AuthorizationCommitment[:], fixture.pledgeB.AuthorizationCommitment[:],
				fixture.pledgeA.PrivateMetadataCommitment[:], fixture.pledgeB.PrivateMetadataCommitment[:],
			} {
				if bytes.Contains(data, plaintext) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(plaintext))) {
					t.Fatalf("opaque pledge commitment appears in public JSON object %s", entry.Name())
				}
			}
		}
	}
	combinedLogs := append(append([]byte(nil), fixture.evaluatorLog...), fixture.decryptorLog...)
	if bytes.Contains(combinedLogs, secretKey) || bytes.Contains(combinedLogs, signingKey) || bytes.Contains(combinedLogs, fixture.pledgeA.ReceivableID[:]) {
		t.Fatalf("private or plaintext input material appears in process output")
	}
	if evidenceBytes := mustReadFile(t, filepath.Join(fixture.publicRoot, evidenceObject)); bytes.Contains(evidenceBytes, secretKey) || bytes.Contains(evidenceBytes, signingKey) || bytes.Contains(evidenceBytes, fixture.pledgeA.ReceivableID[:]) {
		t.Fatalf("private or plaintext input material appears in evidence")
	}
}

func productionPledgePair(label string, conflict bool) (fhe.PlainPledge, fhe.PlainPledge) {
	receivableA := sha256.Sum256([]byte("synthetic-private-receivable/" + label))
	receivableB := receivableA
	if !conflict {
		receivableB = sha256.Sum256([]byte("synthetic-private-receivable/" + label + "/different"))
	}
	makePledge := func(side string, receivable [32]byte, activeFrom, activeUntil uint64) fhe.PlainPledge {
		return fhe.PlainPledge{
			ActiveFrom: activeFrom, ActiveUntil: activeUntil, Amount: fhe.Uint256{0, 0, 0, 1_000_000},
			Currency: sha256.Sum256([]byte("currency/usd")), ObligationID: sha256.Sum256([]byte("obligation/" + label + "/" + side)),
			ReceivableID: receivable, Exclusive: true,
			AuthorizationCommitment:   sha256.Sum256([]byte("authorization/" + label + "/" + side)),
			PrivateMetadataCommitment: sha256.Sum256([]byte("private-metadata/" + label + "/" + side)),
		}
	}
	return makePledge("a", receivableA, 100, 400), makePledge("b", receivableB, 200, 500)
}

func requiredProcessBinary(t *testing.T, environment string) string {
	t.Helper()
	path := os.Getenv(environment)
	if !filepath.IsAbs(path) {
		t.Fatalf("%s must name an absolute binary built from this checkout", environment)
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		t.Fatalf("invalid process binary in %s: %v", environment, err)
	}
	return path
}

func runJSONProcess(t *testing.T, binary string, arguments ...string) []byte {
	t.Helper()
	command := exec.Command(binary, arguments...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("%s failed: %v: %s", filepath.Base(binary), err, stderr.String())
	}
	return output
}

func decodeProcessOutput(t *testing.T, data []byte, target any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode process output: %v", err)
	}
}

func cloneFlatRoot(t *testing.T, source string) string {
	t.Helper()
	clone := filepath.Join(taskTempDir(t, "mordant-governed-attack-"), "public")
	if err := os.Mkdir(clone, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, entry := range mustReadDirectory(t, source) {
		if entry.IsDir() {
			t.Fatalf("unexpected directory in flat store: %s", entry.Name())
		}
		if err := os.Link(filepath.Join(source, entry.Name()), filepath.Join(clone, entry.Name())); err != nil {
			t.Fatalf("hard-link test fixture %s: %v", entry.Name(), err)
		}
	}
	return clone
}

func replaceCanonicalObject(t *testing.T, root, name string, value any) {
	t.Helper()
	encoded, err := marshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func testDigest(label string) Digest {
	return DigestBytes([]byte("MordantGovernedFHETest/v1\x00" + label))
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustReadDirectory(t *testing.T, path string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func taskTempDir(t *testing.T, pattern string) string {
	t.Helper()
	root, err := os.MkdirTemp("/private/tmp", pattern)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove generated test directory %s: %v", root, err)
		}
	})
	return root
}

func ExampleFixedConflictReleaser() {
	var releaseBoundary FixedConflictReleaser
	fmt.Printf("%T %s %s\n", releaseBoundary, ReleaseModeGovernedDecryptor, ReleaseModeThreshold2Of3)
	// Output: <nil> governed-decryptor-v1 threshold-2of3-v1
}
