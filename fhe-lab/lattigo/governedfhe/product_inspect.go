package governedfhe

import (
	"bytes"
	"os"
	"time"
)

// ProductInspection is a read-only reconciliation projection for the narrow
// Cleanverse product orchestrator. It exposes no decryption capability or
// private material.
type ProductInspection struct {
	Foundation                *ProductKeygenInspection     `json:"foundation,omitempty"`
	SubmissionA               *ProductSubmissionInspection `json:"submissionA,omitempty"`
	SubmissionB               *ProductSubmissionInspection `json:"submissionB,omitempty"`
	Finalized                 bool                         `json:"finalized"`
	EvaluationAdmission       bool                         `json:"evaluationAdmission"`
	Evaluation                *ProductEvaluationInspection `json:"evaluation,omitempty"`
	ReleaseAdmission          bool                         `json:"releaseAdmission"`
	FoundationPrivateComplete bool                         `json:"foundationPrivateComplete"`
	ReleasePrivateComplete    bool                         `json:"releasePrivateComplete"`
	Release                   *ProductReleaseInspection    `json:"release,omitempty"`
	Recourse                  *RecourseRecord              `json:"recourse,omitempty"`
	ProtectionBindingDigest   *Digest                      `json:"protectionBindingDigest,omitempty"`
	RecourseAttestationDigest *Digest                      `json:"recourseAttestationDigest,omitempty"`
	Evidence                  *PublicEvidence              `json:"evidence,omitempty"`
	Ambiguous                 bool                         `json:"ambiguous"`
	AmbiguousReason           string                       `json:"ambiguousReason,omitempty"`
}

type ProductKeygenInspection struct {
	BindingDigest Digest              `json:"bindingDigest"`
	Report        KeyGenerationReport `json:"report"`
}

type ProductSubmissionInspection struct {
	ArtifactDigest  Digest `json:"artifactDigest"`
	CiphertextBytes int64  `json:"ciphertextBytes"`
	ArtifactBytes   int64  `json:"artifactBytes"`
}

type ProductEvaluationInspection struct {
	ArtifactDigest Digest `json:"artifactDigest"`
	ResultBytes    int64  `json:"resultBytes"`
	ArtifactBytes  int64  `json:"artifactBytes"`
}

type ProductReleaseInspection struct {
	ResultDigest        Digest              `json:"resultDigest"`
	Conflict            bool                `json:"conflict"`
	ReleaseMode         string              `json:"releaseMode"`
	ResultBytes         int64               `json:"resultBytes"`
	ExactRetry          bool                `json:"exactRetry"`
	TrustedRecoursePins TrustedRecoursePins `json:"trustedRecoursePins"`
}

func inspectSubmission(store *objectStore, manifest FHECaseManifest, role string) (*ProductSubmissionInspection, error) {
	_, _, name, err := participantFiles(role)
	if err != nil || !store.exists(name) {
		return nil, err
	}
	var projection EncryptedParticipantArtifact
	encoded, ref, err := store.readJSON(name, &projection)
	if err != nil || projection.ExpiresAtUnix <= 0 {
		return nil, ErrArtifact
	}
	artifact, _, digest, err := loadParticipantArtifact(store, manifest, role, time.Unix(projection.ExpiresAtUnix-1, 0))
	if err != nil || digest != DigestBytes(encoded[:len(encoded)-1]) {
		return nil, ErrArtifact
	}
	return &ProductSubmissionInspection{ArtifactDigest: digest, CiphertextBytes: artifact.CiphertextObject.Length, ArtifactBytes: ref.Length}, nil
}

func inspectPrivateFoundation(store *objectStore, binding FHECaseBinding, bindingDigest Digest) error {
	var privateCase PrivateCaseManifest
	if _, _, err := store.readJSON(privateCaseObject, &privateCase); err != nil || privateCase.SchemaVersion != PrivateCaseSchema ||
		privateCase.CaseID != binding.CaseID || privateCase.CaseBindingDigest != bindingDigest ||
		privateCase.ReleaseAuthorityID != binding.ReleaseAuthorityID || privateCase.SecretKey.Path != secretKeyObject ||
		privateCase.SigningKey.Path != decryptorSigningKeyObject {
		return ErrBinding
	}
	secret, err := store.read(privateCase.SecretKey, 32<<20)
	if err != nil || len(secret) == 0 {
		return ErrArtifact
	}
	for index := range secret {
		secret[index] = 0
	}
	signing, err := store.read(privateCase.SigningKey, 1<<20)
	if err != nil || len(signing) != 64 {
		return ErrArtifact
	}
	for index := range signing {
		signing[index] = 0
	}
	return nil
}

// InspectProductCase verifies public terminal objects only. It never opens a
// private root and is safe for GET/read reconciliation.
func InspectProductCase(publicRoot string) (ProductInspection, error) {
	var inspection ProductInspection
	if _, err := os.Stat(publicRoot); os.IsNotExist(err) {
		return inspection, nil
	}
	publicStore, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return inspection, err
	}
	defer publicStore.close()
	publicNames, _ := publicStore.names()
	if len(publicNames) == 0 {
		return inspection, nil
	}
	binding, cryptoManifest, foundationErr := loadCaseFoundation(publicStore)
	if foundationErr != nil {
		inspection.Ambiguous, inspection.AmbiguousReason = true, "PARTIAL_KEYGEN_FOUNDATION"
		return inspection, nil
	}
	bindingDigest, _ := binding.Digest()
	temporaryManifest := FHECaseManifest{Binding: binding, Crypto: cryptoManifest}
	if _, err := loadReleaseAuthority(publicStore, temporaryManifest); err != nil {
		inspection.Ambiguous, inspection.AmbiguousReason = true, "PARTIAL_KEYGEN_AUTHORITY"
		return inspection, nil
	}
	authorization, err := loadProtectionAuthorization(publicStore, binding)
	if err != nil {
		inspection.Ambiguous, inspection.AmbiguousReason = true, "PARTIAL_PRODUCT_AUTHORIZATION"
		return inspection, nil
	}
	inspection.ProtectionBindingDigest = &authorization.Digest
	publicBytes, _ := publicStore.usedBytes()
	report := KeyGenerationReport{
		ParameterBytes: cryptoManifest.Parameters.Length, PublicKeyBytes: cryptoManifest.PublicKey.Length,
		RelinearizationKeyBytes: cryptoManifest.EvaluationKeys.RelinearizationKey.Length,
		PublicArtifactBytes:     publicBytes,
	}
	for _, key := range cryptoManifest.EvaluationKeys.GaloisKeys {
		report.GaloisKeyBytes = append(report.GaloisKeyBytes, key.Object.Length)
	}
	inspection.Foundation = &ProductKeygenInspection{BindingDigest: bindingDigest, Report: report}

	inspection.SubmissionA, err = inspectSubmission(publicStore, temporaryManifest, RoleA)
	if err != nil {
		inspection.Ambiguous, inspection.AmbiguousReason = true, "INVALID_SUBMISSION_A"
		return inspection, nil
	}
	inspection.SubmissionB, err = inspectSubmission(publicStore, temporaryManifest, RoleB)
	if err != nil {
		inspection.Ambiguous, inspection.AmbiguousReason = true, "INVALID_SUBMISSION_B"
		return inspection, nil
	}

	var manifest FHECaseManifest
	if publicStore.exists(caseManifestObject) {
		manifest, err = loadCaseManifest(publicStore)
		if err != nil {
			inspection.Ambiguous, inspection.AmbiguousReason = true, "INVALID_FINALIZED_MANIFEST"
			return inspection, nil
		}
		inspection.Finalized = true
	} else {
		manifest = temporaryManifest
	}

	inspection.EvaluationAdmission = publicStore.exists(evaluationAdmissionObject)
	if publicStore.exists(evaluatedArtifactObject) || publicStore.exists(evaluationCompletedObject) || publicStore.exists(resultCiphertextObject) {
		artifact, _, digest, loadErr := loadEvaluatedArtifact(publicStore, manifest)
		if loadErr != nil {
			inspection.Ambiguous, inspection.AmbiguousReason = true, "INCOMPLETE_EVALUATION_ADMISSION"
			return inspection, nil
		}
		_, artifactRef, _ := publicStore.readJSON(evaluatedArtifactObject, &EvaluatedConflictArtifact{})
		inspection.Evaluation = &ProductEvaluationInspection{
			ArtifactDigest: digest, ResultBytes: artifact.ResultCiphertext.Length, ArtifactBytes: artifactRef.Length,
		}
	}

	if publicStore.exists(publicResultObject) {
		if inspection.Evaluation == nil {
			inspection.Ambiguous, inspection.AmbiguousReason = true, "RESULT_WITHOUT_EVALUATION"
			return inspection, nil
		}
		artifact, _, _, _ := loadEvaluatedArtifact(publicStore, manifest)
		authority, authorityErr := loadReleaseAuthority(publicStore, manifest)
		var result GovernedConflictResult
		resultBytes, resultRef, resultErr := publicStore.readJSON(publicResultObject, &result)
		if authorityErr != nil || resultErr != nil ||
			verifyGovernedResult(result, manifest, artifact, authority) != nil {
			inspection.Ambiguous, inspection.AmbiguousReason = true, "INCOMPLETE_RELEASE_ADMISSION"
			return inspection, nil
		}
		inspection.Release = &ProductReleaseInspection{
			ResultDigest: DigestBytes(resultBytes[:len(resultBytes)-1]), Conflict: result.Conflict, ReleaseMode: result.ReleaseMode,
			ResultBytes: resultRef.Length, ExactRetry: true, TrustedRecoursePins: recoursePinsForResult(result),
		}
	}

	if publicStore.exists(recourseRecordObject) {
		var record RecourseRecord
		if _, _, err := publicStore.readJSON(recourseRecordObject, &record); err != nil || inspection.Release == nil ||
			func() error {
				var result GovernedConflictResult
				if _, _, resultErr := publicStore.readJSON(publicResultObject, &result); resultErr != nil {
					return resultErr
				}
				return validateCompleteRecourseRecord(record, binding, result, inspection.Release.ResultDigest,
					authorization.Binding.HolderRecordDate, authorization.Binding.HolderAllocationDigest)
			}() != nil {
			inspection.Ambiguous, inspection.AmbiguousReason = true, "INVALID_RECOURSE_RECORD"
			return inspection, nil
		}
		inspection.Recourse = &record
	}
	if publicStore.exists(productAttestationObject) {
		var result GovernedConflictResult
		resultBytes, _, resultErr := publicStore.readJSON(publicResultObject, &result)
		if resultErr != nil || len(resultBytes) < 2 {
			inspection.Ambiguous, inspection.AmbiguousReason = true, "INVALID_PRODUCT_ATTESTATION"
			return inspection, nil
		}
		var record *RecourseRecord
		if inspection.Recourse != nil {
			record = inspection.Recourse
		}
		attestation, attestationErr := loadProductAttestation(publicStore, authorization, result, DigestBytes(resultBytes[:len(resultBytes)-1]), record)
		if attestationErr != nil {
			inspection.Ambiguous, inspection.AmbiguousReason = true, "INVALID_PRODUCT_ATTESTATION"
			return inspection, nil
		}
		digest, _ := attestation.Digest()
		inspection.RecourseAttestationDigest = &digest
	}

	if publicStore.exists(evidenceObject) {
		var evidence PublicEvidence
		if _, _, err := publicStore.readJSON(evidenceObject, &evidence); err != nil || inspection.Release == nil ||
			evidence.SchemaVersion != EvidenceSchema || evidence.CaseID != binding.CaseID || evidence.AssetIdentity != binding.AssetIdentity ||
			evidence.CaseBindingDigest != bindingDigest || evidence.GovernedResultDigest != inspection.Release.ResultDigest ||
			evidence.ProtectionBindingDigest != authorization.Digest || inspection.RecourseAttestationDigest == nil ||
			evidence.RecourseAttestationDigest != *inspection.RecourseAttestationDigest ||
			evidence.Conflict != inspection.Release.Conflict || evidence.ReleaseAuthorityID != binding.ReleaseAuthorityID ||
			evidence.ReleaseMode != binding.ReleaseMode || !evidence.PublicStructureValidated {
			inspection.Ambiguous, inspection.AmbiguousReason = true, "INVALID_PUBLIC_EVIDENCE"
			return inspection, nil
		}
		inspection.Evidence = &evidence
	}
	return inspection, nil
}

// InspectPendingProductPrivate opens private state only for the exact pending
// operation that requires private one-shot admission recovery.
func InspectPendingProductPrivate(publicRoot, privateRoot, phase string) (ProductInspection, error) {
	var inspection ProductInspection
	if phase != "PREPARING" && phase != "RELEASING" {
		return inspection, ErrBinding
	}
	publicStore, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return inspection, err
	}
	defer publicStore.close()
	privateStore, err := openObjectStore(privateRoot, PrivateCaseQuota, true)
	if err != nil {
		return inspection, err
	}
	defer privateStore.close()
	binding, _, err := loadCaseFoundation(publicStore)
	if err != nil {
		inspection.Ambiguous, inspection.AmbiguousReason = true, "PARTIAL_KEYGEN_FOUNDATION"
		return inspection, nil
	}
	if _, err := loadProtectionAuthorization(publicStore, binding); err != nil {
		inspection.Ambiguous, inspection.AmbiguousReason = true, "PARTIAL_PRODUCT_AUTHORIZATION"
		return inspection, nil
	}
	bindingDigest, _ := binding.Digest()
	if phase == "PREPARING" {
		if inspectPrivateFoundation(privateStore, binding, bindingDigest) != nil {
			inspection.Ambiguous, inspection.AmbiguousReason = true, "PARTIAL_KEYGEN_PRIVATE_FOUNDATION"
			return inspection, nil
		}
		inspection.FoundationPrivateComplete = true
		return inspection, nil
	}
	inspection.ReleaseAdmission = privateStore.exists(recomputeAdmissionObject) || privateStore.exists(releaseAdmissionObject) || privateStore.exists(releaseConsumedObject)
	if !publicStore.exists(publicResultObject) || !privateStore.exists(retainedResultObject) {
		return inspection, nil
	}
	manifest, err := loadCaseManifest(publicStore)
	if err != nil {
		return inspection, err
	}
	artifact, _, _, err := loadEvaluatedArtifact(publicStore, manifest)
	authority, authorityErr := loadReleaseAuthority(publicStore, manifest)
	var result, retained GovernedConflictResult
	resultBytes, _, resultErr := publicStore.readJSON(publicResultObject, &result)
	retainedBytes, _, retainedErr := privateStore.readJSON(retainedResultObject, &retained)
	if err != nil || authorityErr != nil || resultErr != nil || retainedErr != nil || !bytes.Equal(resultBytes, retainedBytes) ||
		verifyGovernedResult(result, manifest, artifact, authority) != nil {
		inspection.Ambiguous, inspection.AmbiguousReason = true, "INCOMPLETE_RELEASE_ADMISSION"
		return inspection, nil
	}
	inspection.ReleasePrivateComplete = true
	return inspection, nil
}
