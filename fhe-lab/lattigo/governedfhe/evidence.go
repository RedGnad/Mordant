package governedfhe

import (
	"bytes"
	"os"
	"time"
)

const ProductClaim = "Mordant performs real private pledge matching under BGV FHE. The evaluator cannot inspect the parties’ inputs or decrypt the result. The MVP uses a designated governed decryptor for the final Boolean; threshold output release is a planned cryptographic upgrade."

type SmokeMeasurements struct {
	KeyGeneration    KeyGenerationReport `json:"keyGeneration"`
	Submissions      []SubmissionReport  `json:"submissions"`
	Evaluation       EvaluationReport    `json:"evaluation"`
	Release          ReleaseReport       `json:"release"`
	CompleteDuration time.Duration       `json:"completeDuration"`
	PeakRSSBytes     uint64              `json:"peakRssBytes"`
}

type PublicEvidence struct {
	SchemaVersion           string            `json:"schemaVersion"`
	CaseID                  Digest            `json:"caseId"`
	CaseBindingDigest       Digest            `json:"caseBindingDigest"`
	CaseManifestDigest      Digest            `json:"caseManifestDigest"`
	SubmissionDigests       []Digest          `json:"submissionDigests"`
	EvaluatedArtifactDigest Digest            `json:"evaluatedArtifactDigest"`
	GovernedResultDigest    Digest            `json:"governedResultDigest"`
	RecourseRecordDigest    Digest            `json:"recourseRecordDigest,omitempty"`
	ReleaseMode             string            `json:"releaseMode"`
	ReleaseAuthorityID      Digest            `json:"releaseAuthorityId"`
	Conflict                bool              `json:"conflict"`
	SecretScanClean         bool              `json:"secretScanClean"`
	PublicArtifactBytes     int64             `json:"publicArtifactBytes"`
	Measurements            SmokeMeasurements `json:"measurements"`
	ProductClaim            string            `json:"productClaim"`
	GeneratedAtUnix         int64             `json:"generatedAtUnix"`
}

func expectedPublicFiles(includeRecourse, includeEvidence bool) map[string]bool {
	allowed := map[string]bool{
		parametersObject: true, publicKeyObject: true, relinearizationKeyObject: true,
		caseCryptoObject: true, caseBindingObject: true, caseManifestObject: true,
		bindingSignatureAObject: true, bindingSignatureBObject: true,
		submissionAObject: true, submissionBObject: true, submissionAManifest: true, submissionBManifest: true,
		resultCiphertextObject: true, evaluatedArtifactObject: true, releaseAuthorityObject: true, publicResultObject: true,
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

func ExportPublicEvidence(publicRoot, privateRoot string, measurements SmokeMeasurements, now time.Time) (PublicEvidence, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	publicStore, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return PublicEvidence{}, err
	}
	privateStore, err := openObjectStore(privateRoot, PrivateCaseQuota, true)
	if err != nil {
		return PublicEvidence{}, err
	}
	manifest, err := loadCaseManifest(publicStore)
	if err != nil {
		return PublicEvidence{}, err
	}
	artifact, _, artifactDigest, err := loadEvaluatedArtifact(publicStore, manifest)
	if err != nil {
		return PublicEvidence{}, err
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
	manifestBytes, _, _ := publicStore.readNamed(caseManifestObject, maxManifestBytes)
	manifestDigest := DigestBytes(manifestBytes[:len(manifestBytes)-1])
	resultDigest := DigestBytes(resultBytes[:len(resultBytes)-1])
	var recourseDigest Digest
	includeRecourse := publicStore.exists(recourseRecordObject)
	if includeRecourse {
		recourseBytes, _, err := publicStore.readNamed(recourseRecordObject, maxManifestBytes)
		if err != nil {
			return PublicEvidence{}, err
		}
		recourseDigest = DigestBytes(recourseBytes[:len(recourseBytes)-1])
	}
	if publicStore.rejectUnknown(expectedPublicFiles(includeRecourse, false)) != nil {
		return PublicEvidence{}, ErrArtifact
	}
	var privateCase PrivateCaseManifest
	if _, _, err := privateStore.readJSON(privateCaseObject, &privateCase); err != nil {
		return PublicEvidence{}, err
	}
	secretBytes, err := privateStore.read(privateCase.SecretKey, 32<<20)
	if err != nil {
		return PublicEvidence{}, err
	}
	signingBytes, err := privateStore.read(privateCase.SigningKey, 1<<20)
	if err != nil {
		return PublicEvidence{}, err
	}
	names, err := publicStore.names()
	if err != nil {
		return PublicEvidence{}, err
	}
	for _, name := range names {
		path, _ := publicStore.path(name)
		data, err := os.ReadFile(path)
		if err != nil || bytes.Contains(data, secretBytes) || bytes.Contains(data, signingBytes) ||
			bytes.Contains(data, []byte("secret-key.bin")) || bytes.Contains(data, []byte("decryptor-signing-key.bin")) {
			return PublicEvidence{}, ErrArtifact
		}
	}
	publicBytes, err := publicStore.usedBytes()
	if err != nil {
		return PublicEvidence{}, err
	}
	evidence := PublicEvidence{
		SchemaVersion: EvidenceSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: artifact.CaseBindingDigest,
		CaseManifestDigest: manifestDigest, SubmissionDigests: append([]Digest(nil), artifact.ParticipantArtifactDigests...),
		EvaluatedArtifactDigest: artifactDigest, GovernedResultDigest: resultDigest, RecourseRecordDigest: recourseDigest,
		ReleaseMode: result.ReleaseMode, ReleaseAuthorityID: result.ReleaseAuthorityID, Conflict: result.Conflict,
		SecretScanClean: true, PublicArtifactBytes: publicBytes, Measurements: measurements, ProductClaim: ProductClaim,
		GeneratedAtUnix: now.Unix(),
	}
	if _, _, err := publicStore.createJSON(evidenceObject, evidence); err != nil {
		return PublicEvidence{}, err
	}
	return evidence, nil
}
