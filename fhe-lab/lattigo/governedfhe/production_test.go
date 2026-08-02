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
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
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
	manifest     FHECaseManifest
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
	ResultDigest  Digest              `json:"resultDigest"`
	Conflict      bool                `json:"conflict"`
	ReleaseMode   string              `json:"releaseMode"`
	DurationNanos int64               `json:"durationNanos"`
	ResultBytes   int64               `json:"resultBytes"`
	ExactRetry    bool                `json:"exactRetry"`
	TrustedPins   TrustedRecoursePins `json:"trustedRecoursePins"`
}

func TestGovernedFHEProductionPaths(t *testing.T) {
	evaluatorBinary := requiredProcessBinary(t, evaluatorBinaryEnvironment)
	decryptorBinary := requiredProcessBinary(t, decryptorBinaryEnvironment)

	t.Run("conflict_bindings_release_and_recourse", func(t *testing.T) {
		fixture := newProductionFixture(t, true)
		assertFixedN15Material(t, fixture)
		assertEvaluatorAndReleaseAPIsAreNarrow(t)
		assertParticipantSignedReleaseAuthority(t, fixture)
		assertSubstitutedReleaseAuthorityRejected(t, fixture)
		assertForgedEvaluatorCannotDictate(t, fixture, false)
		assertObjectCountExhaustionIsEarly(t, fixture)
		assertParticipantAndCaseMutationsRejected(t, fixture)

		evaluationOutput := runConcurrentEvaluatorProcesses(t, evaluatorBinary, fixture.publicRoot)
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

		firstOutput := runConcurrentDecryptorProcesses(t, decryptorBinary, fixture.publicRoot, fixture.privateRoot)
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
		adapterConfig := RecourseAdapterConfig{
			RecordRoot: fixture.publicRoot, CaseManifest: fixture.manifest, ExpectedPins: first.TrustedPins,
			RecordDateUnix: fixture.spec.CreatedAtUnix - 60,
			CurePeriod:     24 * time.Hour, ReserveBasisPoints: MVPReserveBasisPoints,
			HolderAllocationDigest: holderAllocation, Now: adapterNow,
		}
		wrongAsset := adapterConfig
		wrongAsset.CaseManifest.Binding.AssetIdentity = testDigest("wrong/recourse-asset")
		if _, err := AdaptSignedResultToRecourse(wrongAsset, publicResultBytes); !errors.Is(err, ErrRecourse) {
			t.Fatalf("signed result was reusable for another asset: %v", err)
		}
		wrongPolicy := adapterConfig
		wrongPolicy.CaseManifest.Binding.PolicyID = testDigest("wrong/recourse-policy")
		if _, err := AdaptSignedResultToRecourse(wrongPolicy, publicResultBytes); !errors.Is(err, ErrRecourse) {
			t.Fatalf("signed result was reusable for another policy: %v", err)
		}
		wrongAuthority := adapterConfig
		wrongAuthority.ExpectedPins.ReleaseAuthorityID = testDigest("wrong/recourse-release-authority")
		if _, err := AdaptSignedResultToRecourse(wrongAuthority, publicResultBytes); !errors.Is(err, ErrRecourse) {
			t.Fatalf("signed result was reusable under another release authority: %v", err)
		}
		assertEveryRecoursePinIsRequired(t, adapterConfig, publicResultBytes)
		assertThresholdModeRejected(t, fixture, result, adapterConfig)
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
			Release:    ReleaseReport{Duration: time.Duration(first.DurationNanos), ResultBytes: first.ResultBytes, Pins: first.TrustedPins},
		}
		evidence, err := ExportPublicEvidence(fixture.publicRoot, measurements, adapterNow)
		if err != nil {
			t.Fatalf("export public evidence: %v", err)
		}
		if !evidence.PublicStructureValidated || evidence.ProductionIsolationProven || evidence.ProductClaim != ProductClaim || evidence.ReleaseMode != ReleaseModeGovernedDecryptor ||
			evidence.ReleaseAuthorityID != result.ReleaseAuthorityID || evidence.GovernedResultDigest != first.ResultDigest {
			t.Fatalf("invalid public evidence: %+v", evidence)
		}
		assertNoPrivateOrPlaintextMaterialIsPublic(t, fixture)
	})

	t.Run("no_conflict_cannot_activate_recourse", func(t *testing.T) {
		fixture := newProductionFixture(t, false)
		assertForgedEvaluatorCannotDictate(t, fixture, true)
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
		_, signedResult, err := LoadGovernedConflictResult(fixture.publicRoot)
		if err != nil {
			t.Fatalf("load no-conflict result: %v", err)
		}
		_, err = AdaptSignedResultToRecourse(RecourseAdapterConfig{
			RecordRoot: fixture.publicRoot, CaseManifest: fixture.manifest, ExpectedPins: release.TrustedPins,
			RecordDateUnix: fixture.spec.CreatedAtUnix - 60,
			CurePeriod:     24 * time.Hour, ReserveBasisPoints: MVPReserveBasisPoints,
			HolderAllocationDigest: testDigest("no-conflict/holder-allocation"), Now: time.Now().UTC(),
		}, signedResult)
		if !errors.Is(err, ErrRecourse) {
			t.Fatalf("false result activated recourse: %v", err)
		}
		offlinePrivateRoot := fixture.privateRoot + "-offline"
		if err := os.Rename(fixture.privateRoot, offlinePrivateRoot); err != nil {
			t.Fatalf("take private root offline before evidence export: %v", err)
		}
		measurements := SmokeMeasurements{
			KeyGeneration: fixture.keyReport, Submissions: []SubmissionReport{fixture.reportA, fixture.reportB},
			Evaluation: EvaluationReport{Duration: time.Duration(evaluation.DurationNanos), ResultCiphertextBytes: evaluation.ResultBytes, ArtifactBytes: evaluation.ArtifactBytes},
			Release:    ReleaseReport{Duration: time.Duration(release.DurationNanos), ResultBytes: release.ResultBytes, Pins: release.TrustedPins},
		}
		evidence, err := ExportPublicEvidence(fixture.publicRoot, measurements, time.Now().UTC())
		if err != nil || !evidence.PublicStructureValidated || evidence.ProductionIsolationProven ||
			evidence.ExecutionClass != EvidenceExecutionClass || evidence.DeploymentClass != EvidenceDeploymentClass ||
			evidence.ReleaseClass != EvidenceReleaseClass || evidence.RecourseClass != EvidenceRecourseClass {
			t.Fatalf("public-only structural evidence failed with private root offline: %+v %v", evidence, err)
		}
	})
}

func TestFreshParticipantCiphertextValidationBeforeAdmission(t *testing.T) {
	fixture := newProductionFixture(t, true)
	tests := []struct {
		name   string
		mutate func(*testing.T, bgv.Parameters, *rlwe.PublicKey, *fhe.CipherPledge)
	}{
		{
			name: "insufficient_level",
			mutate: func(t *testing.T, params bgv.Parameters, publicKey *rlwe.PublicKey, pledge *fhe.CipherPledge) {
				values := make([]uint64, params.MaxSlots())
				plaintext := bgv.NewPlaintext(params, 0)
				if err := bgv.NewEncoder(params).Encode(values, plaintext); err != nil {
					t.Fatal(err)
				}
				ciphertext, err := rlwe.NewEncryptor(params, publicKey).EncryptNew(plaintext)
				if err != nil || ciphertext.Degree() != 1 || ciphertext.Level() != 0 {
					t.Fatalf("construct genuine level-zero N15 ciphertext: %v", err)
				}
				pledge.PolicyBits = ciphertext
			},
		},
		{
			name: "incorrect_scale",
			mutate: func(t *testing.T, params bgv.Parameters, _ *rlwe.PublicKey, pledge *fhe.CipherPledge) {
				pledge.PolicyBits = pledge.PolicyBits.CopyNew()
				pledge.PolicyBits.Scale = rlwe.NewScaleModT(params.DefaultScale().Uint64()+1, params.PlaintextModulus())
				if pledge.PolicyBits.Scale.Equal(params.DefaultScale()) {
					t.Fatal("test scale mutation did not change the fresh metadata")
				}
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			publicRoot := cloneFlatRoot(t, fixture.publicRoot)
			privateRoot := copyFlatRoot(t, fixture.privateRoot, 0o700)
			mutatedA := replaceAuthorizedParticipantCiphertext(t, publicRoot, fixture.manifest, fixture.privateA, testCase.mutate)

			store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
			if err != nil {
				t.Fatal(err)
			}
			loadedA, _, err := loadParticipantArtifactMetadata(store, fixture.manifest, RoleA, fixture.now)
			if err != nil {
				_ = store.close()
				t.Fatalf("mutated participant signature or artifact binding is invalid: %v", err)
			}
			if _, err := loadParticipantCiphertext(store, fixture.manifest, loadedA); err != nil {
				_ = store.close()
				t.Fatalf("mutated ciphertext digest, length, or canonical encoding is stale: %v", err)
			}
			if err := store.close(); err != nil {
				t.Fatal(err)
			}

			beforeEvaluation := evaluationExecutionCount.Load()
			if _, _, err := EvaluateFixedConflict(EvaluatorConfig{
				PublicRoot: publicRoot, Provenance: testDigest("gfhe-07r/evaluator/" + testCase.name), Now: fixture.now,
			}); !errors.Is(err, ErrCiphertextValidation) {
				t.Fatalf("evaluator rejected for the wrong reason: %v", err)
			}
			if evaluationExecutionCount.Load() != beforeEvaluation || fileExists(filepath.Join(publicRoot, evaluationAdmissionObject)) ||
				fileExists(filepath.Join(publicRoot, evaluationCompletedObject)) || fileExists(filepath.Join(publicRoot, resultCiphertextObject)) ||
				fileExists(filepath.Join(publicRoot, evaluatedArtifactObject)) {
				t.Fatalf("invalid participant input crossed the evaluator admission boundary")
			}

			forgedArtifact := publishForgedEvaluatorArtifact(t, publicRoot, fixture.manifest, mutatedA, fixture.artifactB, false, fixture.now)
			if err := os.Rename(filepath.Join(privateRoot, secretKeyObject), filepath.Join(privateRoot, "secret-key.unavailable")); err != nil {
				t.Fatal(err)
			}
			beforeRecomputation := recomputationExecutionCount.Load()
			beforeSignatures := releaseSignatureCount.Load()
			decryptor, err := NewGovernedDecryptor(GovernedDecryptorConfig{
				PublicRoot: publicRoot, PrivateRoot: privateRoot,
				Provenance: testDigest("gfhe-07r/decryptor/" + testCase.name), Now: fixture.now,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, _, releaseErr := decryptor.ReleaseFixedConflict(forgedArtifact)
			if closeErr := decryptor.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if !errors.Is(releaseErr, ErrCiphertextValidation) {
				t.Fatalf("decryptor rejected for the wrong reason: %v", releaseErr)
			}
			if recomputationExecutionCount.Load() != beforeRecomputation || releaseSignatureCount.Load() != beforeSignatures ||
				fileExists(filepath.Join(privateRoot, recomputeAdmissionObject)) || fileExists(filepath.Join(privateRoot, recomputeMismatchObject)) ||
				fileExists(filepath.Join(privateRoot, releaseAdmissionObject)) || fileExists(filepath.Join(privateRoot, releaseConsumedObject)) ||
				fileExists(filepath.Join(privateRoot, retainedResultObject)) || fileExists(filepath.Join(publicRoot, publicResultObject)) {
				t.Fatalf("invalid participant input crossed the decryptor admission or release boundary")
			}
		})
	}
}

func replaceAuthorizedParticipantCiphertext(
	t *testing.T,
	publicRoot string,
	manifest FHECaseManifest,
	signingKey ed25519.PrivateKey,
	mutate func(*testing.T, bgv.Parameters, *rlwe.PublicKey, *fhe.CipherPledge),
) EncryptedParticipantArtifact {
	t.Helper()
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		t.Fatal(err)
	}
	params, publicKey, err := loadPublicEncryptionMaterial(store, manifest.Crypto)
	if err != nil {
		_ = store.close()
		t.Fatal(err)
	}
	var artifact EncryptedParticipantArtifact
	if _, _, err := store.readJSON(submissionAManifest, &artifact); err != nil {
		_ = store.close()
		t.Fatal(err)
	}
	pledge, err := loadParticipantCiphertext(store, manifest, artifact)
	if err != nil {
		_ = store.close()
		t.Fatal(err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}

	mutate(t, params, publicKey, pledge)
	encoded, err := pledge.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	artifact.CiphertextObject = ObjectRef{Path: submissionAObject, Digest: DigestBytes(encoded), Length: int64(len(encoded))}
	artifact.Components, err = componentRefs(pledge)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Signature, err = signCanonical(signingKey, "MordantEncryptedParticipantArtifact/v1", artifact.signingValue())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(publicRoot, submissionAObject)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(publicRoot, submissionAObject), encoded, 0o444); err != nil {
		t.Fatal(err)
	}
	replaceCanonicalObject(t, publicRoot, submissionAManifest, artifact)
	return artifact
}

func TestPinnedStoreSurvivesRootReplacement(t *testing.T) {
	parent := taskTempDir(t, "mordant-pinned-store-")
	root := filepath.Join(parent, "active")
	store, err := openObjectStore(root, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	ref, err := store.create("object.bin", []byte("original pinned object"))
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		used, err := store.usedBytes()
		if err != nil || used != ref.Length {
			t.Fatalf("repeated pinned quota inventory undercounted objects: %d %v", used, err)
		}
	}
	for index := 1; index < maxPublicCaseObjects; index++ {
		if _, err := store.create(fmt.Sprintf("quota-%02d.bin", index), []byte{byte(index)}); err != nil {
			t.Fatalf("populate object-count boundary: %v", err)
		}
	}
	if _, err := store.create("quota-overflow.bin", []byte("overflow")); !errors.Is(err, ErrResourceAdmission) {
		t.Fatalf("incremental object-count limit was bypassed: %v", err)
	}
	moved := filepath.Join(parent, "original-pinned")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "object.bin"), []byte("attacker replacement"), 0o444); err != nil {
		t.Fatal(err)
	}
	data, err := store.read(ref, 1<<20)
	if err != nil || string(data) != "original pinned object" {
		t.Fatalf("store followed replaced root: %q %v", data, err)
	}
}

func assertParticipantSignedReleaseAuthority(t *testing.T, fixture *productionFixture) {
	t.Helper()
	binding := fixture.manifest.Binding
	if binding.ReleaseMode != ReleaseModeGovernedDecryptor || !nonzero(binding.ReleaseAuthorityID) ||
		len(binding.ReleaseAuthorityPublicKey) != ed25519.PublicKeySize ||
		releaseAuthorityIdentity(binding.ReleaseMode, ed25519.PublicKey(binding.ReleaseAuthorityPublicKey)) != binding.ReleaseAuthorityID {
		t.Fatalf("case binding does not contain the exact governed release authority")
	}
	if verifyBindingSignature(binding, fixture.manifest.SignatureA, binding.ParticipantA) != nil ||
		verifyBindingSignature(binding, fixture.manifest.SignatureB, binding.ParticipantB) != nil {
		t.Fatalf("both participant signatures must bind release mode and authority")
	}
	mutated := fixture.manifest
	mutated.Binding.ReleaseAuthorityID = testDigest("substituted/binding-authority")
	if _, _, err := verifyRecourseCaseManifest(mutated); !errors.Is(err, ErrRecourse) {
		t.Fatalf("participant-signed authority mutation was accepted: %v", err)
	}
}

func assertSubstitutedReleaseAuthorityRejected(t *testing.T, fixture *productionFixture) {
	t.Helper()
	clone := cloneFlatRoot(t, fixture.publicRoot)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bindingDigest, _ := fixture.manifest.Binding.Digest()
	substituted := ReleaseAuthorityManifest{
		SchemaVersion: ReleaseAuthoritySchema, CaseID: fixture.spec.CaseID, CaseBindingDigest: bindingDigest,
		ReleaseMode: ReleaseModeGovernedDecryptor, AuthorityID: releaseAuthorityIdentity(ReleaseModeGovernedDecryptor, publicKey),
		SigningPublicKey: publicKey, SourceProvenance: testDigest("substituted/release-authority"),
	}
	substituted.Signature, err = signCanonical(privateKey, "MordantReleaseAuthority/v1", substituted.signingValue())
	if err != nil {
		t.Fatal(err)
	}
	replaceCanonicalObject(t, clone, releaseAuthorityObject, substituted)
	if _, err := LoadReleaseAuthorityManifest(clone); err == nil {
		t.Fatalf("another valid self-signed release authority was accepted")
	}
}

func assertForgedEvaluatorCannotDictate(t *testing.T, fixture *productionFixture, forgedConflict bool) {
	t.Helper()
	t.Run(fmt.Sprintf("forged_evaluator_%t_rejected", forgedConflict), func(t *testing.T) {
		publicClone := cloneFlatRoot(t, fixture.publicRoot)
		privateClone := copyFlatRoot(t, fixture.privateRoot, 0o700)
		artifact := publishForgedEvaluatorArtifact(t, publicClone, fixture.manifest, fixture.artifactA, fixture.artifactB, forgedConflict, fixture.now)
		if _, err := LoadEvaluatedConflictArtifact(publicClone); err != nil {
			t.Fatalf("forged evaluator artifact was not structurally valid: %v", err)
		}
		if err := os.Rename(filepath.Join(privateClone, secretKeyObject), filepath.Join(privateClone, "secret-key.unavailable")); err != nil {
			t.Fatal(err)
		}
		beforeRecompute := recomputationExecutionCount.Load()
		beforeSignatures := releaseSignatureCount.Load()
		decryptor, err := NewGovernedDecryptor(GovernedDecryptorConfig{
			PublicRoot: publicClone, PrivateRoot: privateClone, Provenance: testDigest("exploit/decryptor"), Now: fixture.now,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer decryptor.Close()
		if _, _, err := decryptor.ReleaseFixedConflict(artifact); !errors.Is(err, ErrEvaluatorMismatch) {
			t.Fatalf("forged evaluator Boolean was not rejected before secret access: %v", err)
		}
		if recomputationExecutionCount.Load()-beforeRecompute != 1 || releaseSignatureCount.Load() != beforeSignatures {
			t.Fatalf("forgery did not cause exactly one independent recomputation and zero signatures")
		}
		if fileExists(filepath.Join(privateClone, releaseAdmissionObject)) || fileExists(filepath.Join(privateClone, retainedResultObject)) ||
			fileExists(filepath.Join(publicClone, publicResultObject)) || !fileExists(filepath.Join(privateClone, recomputeMismatchObject)) {
			t.Fatalf("forgery crossed the release boundary")
		}
		if _, _, err := decryptor.ReleaseFixedConflict(artifact); !errors.Is(err, ErrEvaluatorMismatch) {
			t.Fatalf("recorded evaluator mismatch was not deterministic: %v", err)
		}
		if recomputationExecutionCount.Load()-beforeRecompute != 1 || releaseSignatureCount.Load() != beforeSignatures {
			t.Fatalf("mismatch retry repeated recomputation or signed a Boolean")
		}
	})
}

func publishForgedEvaluatorArtifact(t *testing.T, publicRoot string, manifest FHECaseManifest, artifactA, artifactB EncryptedParticipantArtifact, conflict bool, now time.Time) EvaluatedConflictArtifact {
	t.Helper()
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	params, publicKey, err := loadPublicEncryptionMaterial(store, manifest.Crypto)
	if err != nil {
		t.Fatal(err)
	}
	values := make([]uint64, params.MaxSlots())
	if conflict {
		values[0] = 1
	}
	plaintext := bgv.NewPlaintext(params, 0)
	if err := bgv.NewEncoder(params).Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := rlwe.NewEncryptor(params, publicKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	resultBytes, err := ciphertext.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	digestA, _ := artifactA.Digest()
	digestB, _ := artifactB.Digest()
	bindingDigest, _ := manifest.Binding.Digest()
	provenance := testDigest(fmt.Sprintf("malicious-evaluator/%t", conflict))
	admission := evaluationAdmission{
		SchemaVersion: EvaluationAdmissionSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		ParticipantArtifactDigests: []Digest{digestA, digestB}, EvaluatorProvenance: provenance, AdmittedAtUnix: now.Unix(),
	}
	if _, _, err := store.createJSON(evaluationAdmissionObject, admission); err != nil {
		t.Fatal(err)
	}
	resultRef, err := store.create(resultCiphertextObject, resultBytes)
	if err != nil {
		t.Fatal(err)
	}
	commitment := DigestBytes(append([]byte("MordantFixedConflictCiphertext/v1\x00"), resultBytes...))
	artifact := EvaluatedConflictArtifact{
		SchemaVersion: EvaluatedArtifactSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		AssetIdentity: manifest.Binding.AssetIdentity, ParticipantArtifactDigests: []Digest{digestA, digestB},
		PublicKeyDigest: manifest.Binding.PublicKeyDigest, ParameterProfile: ParameterProfile,
		ParameterFingerprint: manifest.Binding.ParameterFingerprint, CircuitID: CircuitID, CircuitVersion: fhe.CircuitV5Version,
		CircuitDigest: FixedCircuitDigest(), ResultCiphertext: resultRef, ResultCiphertextCommitment: commitment,
		OutputSchema: ResultSchema, OutputSlot: ResultSlot, EvaluatorProvenance: provenance, EvaluatedAtUnix: now.Unix(),
	}
	if _, _, err := store.createJSON(evaluatedArtifactObject, artifact); err != nil {
		t.Fatal(err)
	}
	artifactDigest, _ := artifact.Digest()
	completed := evaluationCompleted{
		SchemaVersion: EvaluationCompletedSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		EvaluatedArtifactDigest: artifactDigest, ResultCiphertextDigest: resultRef.Digest,
		ResultCiphertextCommitment: commitment, CompletedAtUnix: now.Unix(),
	}
	if _, _, err := store.createJSON(evaluationCompletedObject, completed); err != nil {
		t.Fatal(err)
	}
	return artifact
}

func assertObjectCountExhaustionIsEarly(t *testing.T, fixture *productionFixture) {
	t.Helper()
	clone := cloneFlatRoot(t, fixture.publicRoot)
	entries := mustReadDirectory(t, clone)
	for index := len(entries); index <= maxPublicCaseObjects; index++ {
		name := fmt.Sprintf("exhaustion-%02d.bin", index)
		if err := os.WriteFile(filepath.Join(clone, name), []byte{byte(index + 1)}, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	before := evaluationExecutionCount.Load()
	if _, _, err := EvaluateFixedConflict(EvaluatorConfig{PublicRoot: clone, Provenance: testDigest("exhausted/evaluator"), Now: fixture.now}); !errors.Is(err, ErrResourceAdmission) {
		t.Fatalf("object-count exhaustion was not rejected at admission: %v", err)
	}
	if evaluationExecutionCount.Load() != before {
		t.Fatalf("object-count exhaustion reached N15 evaluation")
	}
}

func assertEveryRecoursePinIsRequired(t *testing.T, config RecourseAdapterConfig, signedResult []byte) {
	t.Helper()
	tests := []struct {
		name   string
		mutate func(*TrustedRecoursePins)
	}{
		{"participant_a", func(p *TrustedRecoursePins) { p.ParticipantArtifactDigestA = testDigest("wrong/pin-a") }},
		{"participant_b", func(p *TrustedRecoursePins) { p.ParticipantArtifactDigestB = testDigest("wrong/pin-b") }},
		{"evaluated_artifact", func(p *TrustedRecoursePins) { p.EvaluatedArtifactDigest = testDigest("wrong/evaluated") }},
		{"recomputed_result", func(p *TrustedRecoursePins) { p.RecomputedResultCiphertextDigest = testDigest("wrong/recomputed") }},
		{"result_commitment", func(p *TrustedRecoursePins) { p.ResultCiphertextCommitment = testDigest("wrong/commitment") }},
		{"decryptor_provenance", func(p *TrustedRecoursePins) { p.DecryptorProvenance = testDigest("wrong/decryptor") }},
	}
	for _, testCase := range tests {
		t.Run("recourse_pin_"+testCase.name, func(t *testing.T) {
			mutated := config
			testCase.mutate(&mutated.ExpectedPins)
			if _, err := AdaptSignedResultToRecourse(mutated, signedResult); !errors.Is(err, ErrRecourse) {
				t.Fatalf("wrong %s pin was accepted: %v", testCase.name, err)
			}
		})
	}
}

func assertThresholdModeRejected(t *testing.T, fixture *productionFixture, result GovernedConflictResult, config RecourseAdapterConfig) {
	t.Helper()
	signingKey := ed25519.PrivateKey(mustReadFile(t, filepath.Join(fixture.privateRoot, decryptorSigningKeyObject)))
	thresholdResult := result
	thresholdResult.ReleaseMode = ReleaseModeThreshold2Of3
	thresholdResult.ReleaseAuthorityID = releaseAuthorityIdentity(ReleaseModeThreshold2Of3, ed25519.PublicKey(result.ReleaseAuthorityPublicKey))
	var err error
	thresholdResult.Signature, err = signCanonical(signingKey, "MordantGovernedConflictResult/v1", thresholdResult.signingValue())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalCanonical(thresholdResult)
	if err != nil {
		t.Fatal(err)
	}
	thresholdManifest := fixture.manifest
	thresholdManifest.Binding.ReleaseMode = ReleaseModeThreshold2Of3
	thresholdManifest.Binding.ReleaseAuthorityID = thresholdResult.ReleaseAuthorityID
	bindingDigest, _ := thresholdManifest.Binding.Digest()
	thresholdManifest.SignatureA = signBindingForTest(t, thresholdManifest.Binding.ParticipantA, fixture.privateA, bindingDigest)
	thresholdManifest.SignatureB = signBindingForTest(t, thresholdManifest.Binding.ParticipantB, fixture.privateB, bindingDigest)
	config.CaseManifest = thresholdManifest
	config.ExpectedPins.ReleaseMode = ReleaseModeThreshold2Of3
	config.ExpectedPins.ReleaseAuthorityID = thresholdResult.ReleaseAuthorityID
	if _, err := AdaptSignedResultToRecourse(config, encoded); !errors.Is(err, ErrRecourse) {
		t.Fatalf("unimplemented threshold mode was accepted with valid signatures: %v", err)
	}
}

func signBindingForTest(t *testing.T, identity ParticipantIdentity, key ed25519.PrivateKey, bindingDigest Digest) ParticipantBindingSignature {
	t.Helper()
	signature := ParticipantBindingSignature{Role: identity.Role, ParticipantID: identity.ID, BindingDigest: bindingDigest}
	value := struct {
		Role          string `json:"role"`
		ParticipantID Digest `json:"participantId"`
		BindingDigest Digest `json:"bindingDigest"`
	}{signature.Role, signature.ParticipantID, signature.BindingDigest}
	var err error
	signature.Signature, err = signCanonical(key, "MordantFHECaseBindingSignature/v1", value)
	if err != nil {
		t.Fatal(err)
	}
	return signature
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
	manifest, err := FinalizeCase(publicRoot)
	if err != nil {
		t.Fatalf("finalize exact two-party case binding: %v", err)
	}
	return &productionFixture{
		publicRoot: publicRoot, privateRoot: privateRoot, now: now, spec: spec, privateA: privateA, privateB: privateB,
		pledgeA: pledgeA, pledgeB: pledgeB, artifactA: artifactA, artifactB: artifactB, manifest: manifest,
		keyReport: keyReport, reportA: reportA, reportB: reportB,
	}
}

func assertFixedN15Material(t *testing.T, fixture *productionFixture) {
	t.Helper()
	store, err := openObjectStore(fixture.publicRoot, PublicCaseQuota, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
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
	if err != nil || privateInfo.Mode().Perm() != 0o400 {
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
	evidenceType := reflect.TypeOf(ExportPublicEvidence)
	if evidenceType.NumIn() != 3 || evidenceType.In(0).Kind() != reflect.String {
		t.Fatalf("evidence exporter regained a private-root input: %v", evidenceType)
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
			defer store.close()
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
		defer store.close()
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
	defer decryptor.Close()
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
	defer decryptor.Close()
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
	defer store.close()
	manifest, err := loadCaseManifest(store)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := loadReleaseAuthority(store, manifest)
	if err != nil {
		t.Fatal(err)
	}
	decryptorDigest := DigestBytes(mustReadFile(t, decryptorBinary))
	artifactDigest, _ := artifact.Digest()
	if result.ReleaseMode != ReleaseModeGovernedDecryptor || result.ReleaseOrdinal != ReleaseOrdinal ||
		result.ReleaseAuthorityID != authority.AuthorityID || !bytes.Equal(result.ReleaseAuthorityPublicKey, authority.SigningPublicKey) ||
		result.SourceProvenance != decryptorDigest || result.CaseID != fixture.spec.CaseID || result.AssetIdentity != fixture.spec.AssetIdentity ||
		result.PolicyID != fixture.spec.PolicyID || result.EvaluatedArtifactDigest != artifactDigest ||
		result.ResultCiphertextDigest != artifact.ResultCiphertext.Digest ||
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
	defer decryptor.Close()
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
	for _, name := range []string{secretKeyObject, decryptorSigningKeyObject, privateCaseObject, recomputeAdmissionObject,
		recomputedResultObject, recomputeVerifiedObject, recomputeMismatchObject, retainedResultObject, releaseAdmissionObject, releaseConsumedObject} {
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

type processAttempt struct {
	output []byte
	err    error
}

func runConcurrentProcessAttempts(binary string, count int, arguments ...string) []processAttempt {
	start := make(chan struct{})
	results := make(chan processAttempt, count)
	for index := 0; index < count; index++ {
		go func() {
			<-start
			command := exec.Command(binary, arguments...)
			var stderr bytes.Buffer
			command.Stderr = &stderr
			output, err := command.Output()
			if err != nil {
				err = fmt.Errorf("%w: %s", err, stderr.String())
			}
			results <- processAttempt{output: output, err: err}
		}()
	}
	close(start)
	attempts := make([]processAttempt, count)
	for index := range attempts {
		attempts[index] = <-results
	}
	return attempts
}

func runConcurrentEvaluatorProcesses(t *testing.T, binary, publicRoot string) []byte {
	t.Helper()
	attempts := runConcurrentProcessAttempts(binary, 2, "-public-root", publicRoot)
	var successful [][]byte
	for _, attempt := range attempts {
		if attempt.err == nil {
			successful = append(successful, attempt.output)
		}
	}
	if len(successful) != 1 {
		t.Fatalf("concurrent evaluators produced %d successful N15 evaluations: %+v", len(successful), attempts)
	}
	return successful[0]
}

func runConcurrentDecryptorProcesses(t *testing.T, binary, publicRoot, privateRoot string) []byte {
	t.Helper()
	attempts := runConcurrentProcessAttempts(binary, 2, "-public-root", publicRoot, "-private-root", privateRoot)
	var selected []byte
	var selectedOutput decryptorProcessOutput
	successes := 0
	uniqueReleases := 0
	for _, attempt := range attempts {
		if attempt.err != nil {
			continue
		}
		successes++
		var output decryptorProcessOutput
		decodeProcessOutput(t, attempt.output, &output)
		if !output.ExactRetry {
			uniqueReleases++
		}
		if selected == nil || !output.ExactRetry {
			selected, selectedOutput = attempt.output, output
		}
	}
	if successes == 0 || selected == nil || selectedOutput.ExactRetry || uniqueReleases != 1 {
		t.Fatalf("concurrent decryptors produced %d unique releases: %+v", uniqueReleases, attempts)
	}
	if !fileExists(filepath.Join(privateRoot, recomputeAdmissionObject)) || !fileExists(filepath.Join(privateRoot, recomputeVerifiedObject)) ||
		!fileExists(filepath.Join(privateRoot, releaseConsumedObject)) || !fileExists(filepath.Join(privateRoot, retainedResultObject)) {
		t.Fatalf("concurrent decryptor state machine did not reach one completed release")
	}
	return selected
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

func copyFlatRoot(t *testing.T, source string, directoryMode os.FileMode) string {
	t.Helper()
	clone := filepath.Join(taskTempDir(t, "mordant-governed-private-attack-"), "store")
	if err := os.Mkdir(clone, directoryMode); err != nil {
		t.Fatal(err)
	}
	for _, entry := range mustReadDirectory(t, source) {
		if entry.IsDir() {
			t.Fatalf("unexpected directory in flat store: %s", entry.Name())
		}
		data := mustReadFile(t, filepath.Join(source, entry.Name()))
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(clone, entry.Name())
		file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(data); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Chmod(info.Mode().Perm()); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
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
