package governedfhe

import (
	"bytes"
	"time"
)

const (
	EvidenceExecutionClass  = "REAL_BGV_FHE"
	EvidenceDeploymentClass = "LOCAL_SINGLE_HOST"
	EvidenceReleaseClass    = "GOVERNED_DECRYPTOR"
	EvidenceRecourseClass   = "LOCAL_PROTOCOL_DOUBLE"
)

type SmokeMeasurements struct {
	KeyGeneration    KeyGenerationReport `json:"keyGeneration"`
	Submissions      []SubmissionReport  `json:"submissions"`
	Evaluation       EvaluationReport    `json:"evaluation"`
	Release          ReleaseReport       `json:"release"`
	CompleteDuration time.Duration       `json:"completeDuration"`
	PeakRSSBytes     uint64              `json:"peakRssBytes"`
}

type PublicEvidence struct {
	SchemaVersion                    string            `json:"schemaVersion"`
	CaseID                           Digest            `json:"caseId"`
	AssetIdentity                    Digest            `json:"assetIdentity"`
	CaseBindingDigest                Digest            `json:"caseBindingDigest"`
	CaseManifestDigest               Digest            `json:"caseManifestDigest"`
	SubmissionDigests                []Digest          `json:"submissionDigests"`
	EvaluatedArtifactDigest          Digest            `json:"evaluatedArtifactDigest"`
	ResultCiphertextDigest           Digest            `json:"resultCiphertextDigest"`
	ResultCiphertextCommitment       Digest            `json:"resultCiphertextCommitment"`
	EvaluatorProvenance              Digest            `json:"evaluatorProvenance"`
	RecomputedResultCiphertextDigest Digest            `json:"recomputedResultCiphertextDigest"`
	DecryptorProvenance              Digest            `json:"decryptorProvenance"`
	GovernedResultDigest             Digest            `json:"governedResultDigest"`
	ProtectionBindingDigest          Digest            `json:"protectionBindingDigest"`
	RecourseAttestationDigest        Digest            `json:"recourseAttestationDigest"`
	RecourseRecordDigest             Digest            `json:"recourseRecordDigest,omitempty"`
	ReleaseMode                      string            `json:"releaseMode"`
	ReleaseAuthorityID               Digest            `json:"releaseAuthorityId"`
	Conflict                         bool              `json:"conflict"`
	PublicStructureValidated         bool              `json:"publicStructureValidated"`
	ExecutionClass                   string            `json:"executionClass"`
	DeploymentClass                  string            `json:"deploymentClass"`
	ReleaseClass                     string            `json:"releaseClass"`
	RecourseClass                    string            `json:"recourseClass"`
	ProductionIsolationProven        bool              `json:"productionIsolationProven"`
	PublicArtifactBytes              int64             `json:"publicArtifactBytes"`
	Measurements                     SmokeMeasurements `json:"measurements"`
	ProductClaim                     string            `json:"productClaim"`
	GeneratedAtUnix                  int64             `json:"generatedAtUnix"`
}

func expectedPublicFiles(includeRecourse, includeEvidence bool) map[string]bool {
	allowed := map[string]bool{
		parametersObject: true, publicKeyObject: true, relinearizationKeyObject: true,
		caseCryptoObject: true, caseBindingObject: true, caseManifestObject: true,
		bindingSignatureAObject: true, bindingSignatureBObject: true,
		submissionAObject: true, submissionBObject: true, submissionAManifest: true, submissionBManifest: true,
		evaluationAdmissionObject: true, evaluationCompletedObject: true,
		resultCiphertextObject: true, evaluatedArtifactObject: true, releaseAuthorityObject: true, publicResultObject: true,
		protectionBindingObject: true, protectionSignatureAObject: true, protectionSignatureBObject: true,
		productAttestationObject: true,
	}
	for index := range rotationSteps {
		allowed[galoisObject(index)] = true
	}
	if includeRecourse {
		allowed[recourseRecordObject] = true
	}
	if includeEvidence {
		allowed[evidenceObject] = true
	}
	return allowed
}

func ExportPublicEvidence(publicRoot string, measurements SmokeMeasurements, now time.Time) (PublicEvidence, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	publicStore, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return PublicEvidence{}, err
	}
	defer publicStore.close()
	manifest, err := loadCaseManifest(publicStore)
	if err != nil {
		return PublicEvidence{}, err
	}
	authorization, err := loadProtectionAuthorization(publicStore, manifest.Binding)
	if err != nil {
		return PublicEvidence{}, err
	}
	artifactA, _, digestA, err := loadParticipantArtifact(publicStore, manifest, RoleA, now)
	if err != nil {
		return PublicEvidence{}, err
	}
	artifactB, _, digestB, err := loadParticipantArtifact(publicStore, manifest, RoleB, now)
	if err != nil || artifactA.SubmissionNonce == artifactB.SubmissionNonce {
		return PublicEvidence{}, ErrArtifact
	}
	if runtime, err := loadEvaluationRuntime(publicStore, manifest); err != nil || runtime.HoldsThresholdParties() {
		return PublicEvidence{}, ErrArtifact
	}
	artifact, _, artifactDigest, err := loadEvaluatedArtifact(publicStore, manifest)
	if err != nil || artifact.ParticipantArtifactDigests[0] != digestA || artifact.ParticipantArtifactDigests[1] != digestB {
		return PublicEvidence{}, ErrArtifact
	}
	authority, err := loadReleaseAuthority(publicStore, manifest)
	if err != nil {
		return PublicEvidence{}, err
	}
	var result GovernedConflictResult
	resultBytes, _, err := publicStore.readJSON(publicResultObject, &result)
	if err != nil || verifyGovernedResult(result, manifest, artifact, authority) != nil {
		return PublicEvidence{}, ErrArtifact
	}
	manifestBytes, _, err := publicStore.readNamed(caseManifestObject, maxManifestBytes)
	if err != nil {
		return PublicEvidence{}, err
	}
	manifestDigest := DigestBytes(manifestBytes[:len(manifestBytes)-1])
	resultDigest := DigestBytes(resultBytes[:len(resultBytes)-1])
	var recourseDigest Digest
	includeRecourse := publicStore.exists(recourseRecordObject)
	if includeRecourse {
		var recourse RecourseRecord
		recourseBytes, _, err := publicStore.readJSON(recourseRecordObject, &recourse)
		if err != nil || validateCompleteRecourseRecord(
			recourse, manifest.Binding, result, resultDigest,
			authorization.Binding.HolderRecordDate, authorization.Binding.HolderAllocationDigest,
		) != nil {
			return PublicEvidence{}, ErrArtifact
		}
		recourseDigest = DigestBytes(recourseBytes[:len(recourseBytes)-1])
	}
	attestation, err := loadProductAttestation(publicStore, authorization, result, resultDigest, func() *RecourseRecord {
		if !includeRecourse {
			return nil
		}
		var record RecourseRecord
		if _, _, readErr := publicStore.readJSON(recourseRecordObject, &record); readErr != nil {
			return nil
		}
		return &record
	}())
	if err != nil {
		return PublicEvidence{}, err
	}
	attestationDigest, err := attestation.Digest()
	if err != nil {
		return PublicEvidence{}, err
	}
	if publicStore.rejectUnknown(expectedPublicFiles(includeRecourse, false)) != nil {
		return PublicEvidence{}, ErrArtifact
	}
	for _, name := range []string{secretKeyObject, decryptorSigningKeyObject, privateCaseObject, recomputeAdmissionObject,
		recomputedResultObject, recomputeVerifiedObject, recomputeMismatchObject, releaseAdmissionObject, releaseConsumedObject, retainedResultObject} {
		if publicStore.exists(name) {
			return PublicEvidence{}, ErrArtifact
		}
	}
	for _, name := range []string{caseCryptoObject, caseBindingObject, caseManifestObject, bindingSignatureAObject, bindingSignatureBObject,
		submissionAManifest, submissionBManifest, evaluationAdmissionObject, evaluationCompletedObject, evaluatedArtifactObject,
		releaseAuthorityObject, publicResultObject, recourseRecordObject, protectionBindingObject, protectionSignatureAObject,
		protectionSignatureBObject, productAttestationObject} {
		if !publicStore.exists(name) {
			continue
		}
		data, _, err := publicStore.readNamed(name, maxManifestBytes)
		if err != nil || bytes.Contains(data, []byte(`"secretKey"`)) || bytes.Contains(data, []byte(`"signingKey"`)) ||
			bytes.Contains(data, []byte("secret-key.bin")) || bytes.Contains(data, []byte("decryptor-signing-key.bin")) ||
			bytes.Contains(data, []byte(`"privateRoot"`)) {
			return PublicEvidence{}, ErrArtifact
		}
	}
	publicBytes, err := publicStore.usedBytes()
	if err != nil {
		return PublicEvidence{}, err
	}
	evidence := PublicEvidence{
		SchemaVersion: EvidenceSchema, CaseID: manifest.Binding.CaseID, AssetIdentity: manifest.Binding.AssetIdentity, CaseBindingDigest: artifact.CaseBindingDigest,
		CaseManifestDigest: manifestDigest, SubmissionDigests: []Digest{digestA, digestB},
		EvaluatedArtifactDigest: artifactDigest, ResultCiphertextDigest: artifact.ResultCiphertext.Digest,
		ResultCiphertextCommitment: artifact.ResultCiphertextCommitment, EvaluatorProvenance: artifact.EvaluatorProvenance,
		RecomputedResultCiphertextDigest: result.ResultCiphertextDigest, DecryptorProvenance: result.SourceProvenance,
		GovernedResultDigest: resultDigest, ProtectionBindingDigest: authorization.Digest,
		RecourseAttestationDigest: attestationDigest, RecourseRecordDigest: recourseDigest,
		ReleaseMode: result.ReleaseMode, ReleaseAuthorityID: result.ReleaseAuthorityID, Conflict: result.Conflict,
		PublicStructureValidated: true, ExecutionClass: EvidenceExecutionClass, DeploymentClass: EvidenceDeploymentClass,
		ReleaseClass: EvidenceReleaseClass, RecourseClass: EvidenceRecourseClass, ProductionIsolationProven: false,
		PublicArtifactBytes: publicBytes, Measurements: measurements, ProductClaim: ProductClaimIdentifier, GeneratedAtUnix: now.Unix(),
	}
	if _, _, err := publicStore.createJSON(evidenceObject, evidence); err != nil {
		return PublicEvidence{}, err
	}
	return evidence, nil
}
