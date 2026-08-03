package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
)

const MVPReserveBasisPoints = uint32(1000)

type RecourseAdapterConfig struct {
	RecordRoot   string
	CaseManifest FHECaseManifest
	ExpectedPins TrustedRecoursePins
}

const recourseClockSchema = "mordant.fhe-recourse-clock-binding/1"

type recourseClockBinding struct {
	SchemaVersion          string `json:"schemaVersion"`
	CaseID                 Digest `json:"caseId"`
	CaseBindingDigest      Digest `json:"caseBindingDigest"`
	ResultDigest           Digest `json:"resultDigest"`
	ProtectionDigest       Digest `json:"protectionBindingDigest"`
	RecordDateUnix         int64  `json:"recordDateUnix"`
	HolderAllocationDigest Digest `json:"holderAllocationDigest"`
	BoundAtUnix            int64  `json:"boundAtUnix"`
	CureDeadlineUnix       int64  `json:"cureDeadlineUnix"`
}

// AdaptSignedResultToRecourse is a local protocol-double for the existing V5
// governed recourse admission. Its only release input is the exact signed
// Boolean result; RecordRoot is an output capability, not a case-artifact read
// capability. It does not change or invoke the frozen contracts.
func AdaptSignedResultToRecourse(config RecourseAdapterConfig, signedResult []byte) (RecourseRecord, error) {
	return adaptSignedResultToRecourse(config, signedResult, time.Now)
}

// adaptSignedResultToRecourse keeps the clock injectable only inside this
// package's tests. No CLI or network request can choose the recourse time.
func adaptSignedResultToRecourse(config RecourseAdapterConfig, signedResult []byte, clock func() time.Time) (RecourseRecord, error) {
	binding, bindingDigest, err := verifyRecourseCaseManifest(config.CaseManifest)
	if err != nil {
		return RecourseRecord{}, ErrRecourse
	}
	if clock == nil || !knownReleaseMode(config.ExpectedPins.ReleaseMode) ||
		!nonzero(config.ExpectedPins.ParticipantArtifactDigestA, config.ExpectedPins.ParticipantArtifactDigestB,
			config.ExpectedPins.EvaluatedArtifactDigest, config.ExpectedPins.RecomputedResultCiphertextDigest,
			config.ExpectedPins.ResultCiphertextCommitment, config.ExpectedPins.DecryptorProvenance,
			config.ExpectedPins.ReleaseAuthorityID) ||
		config.ExpectedPins.ReleaseMode != binding.ReleaseMode || config.ExpectedPins.ReleaseAuthorityID != binding.ReleaseAuthorityID {
		return RecourseRecord{}, ErrRecourse
	}
	var result GovernedConflictResult
	if decodeStrict(signedResult, &result) != nil || verifyRecourseResultEnvelope(result) != nil ||
		result.CaseID != binding.CaseID || result.CaseBindingDigest != bindingDigest ||
		result.AssetIdentity != binding.AssetIdentity || result.PolicyID != binding.PolicyID ||
		len(result.ParticipantArtifactDigests) != 2 ||
		result.ParticipantArtifactDigests[0] != config.ExpectedPins.ParticipantArtifactDigestA ||
		result.ParticipantArtifactDigests[1] != config.ExpectedPins.ParticipantArtifactDigestB ||
		result.EvaluatedArtifactDigest != config.ExpectedPins.EvaluatedArtifactDigest ||
		result.ResultCiphertextDigest != config.ExpectedPins.RecomputedResultCiphertextDigest ||
		result.ResultCiphertextCommitment != config.ExpectedPins.ResultCiphertextCommitment ||
		result.SourceProvenance != config.ExpectedPins.DecryptorProvenance ||
		result.ReleaseMode != config.ExpectedPins.ReleaseMode || result.ReleaseAuthorityID != config.ExpectedPins.ReleaseAuthorityID {
		return RecourseRecord{}, ErrRecourse
	}
	if !result.Conflict {
		return RecourseRecord{}, ErrRecourse
	}
	store, err := openObjectStore(config.RecordRoot, PublicCaseQuota, false)
	if err != nil {
		return RecourseRecord{}, err
	}
	defer store.close()
	authorization, err := loadProtectionAuthorization(store, binding)
	if err != nil {
		return RecourseRecord{}, ErrRecourse
	}
	recordDate, dateErr := time.Parse(time.RFC3339Nano, authorization.Binding.HolderRecordDate)
	if dateErr != nil || recordDate.Unix() <= 0 || recordDate.Unix() > binding.CreatedAtUnix ||
		result.ReleasedAtUnix < binding.CreatedAtUnix {
		return RecourseRecord{}, ErrRecourse
	}
	resultDigest, digestErr := result.Digest()
	if digestErr != nil {
		return RecourseRecord{}, ErrRecourse
	}
	clockBinding := recourseClockBinding{}
	if store.exists(recourseClockObject) {
		if _, _, err := store.readJSON(recourseClockObject, &clockBinding); err != nil {
			return RecourseRecord{}, ErrRecourse
		}
	} else {
		now := clock().UTC().Truncate(time.Second)
		if now.Unix() < result.ReleasedAtUnix || now.Unix() > binding.ExpiresAtUnix {
			return RecourseRecord{}, ErrRecourse
		}
		clockBinding = recourseClockBinding{
			SchemaVersion: recourseClockSchema, CaseID: binding.CaseID, CaseBindingDigest: bindingDigest,
			ResultDigest: resultDigest, ProtectionDigest: authorization.Digest, RecordDateUnix: recordDate.Unix(),
			HolderAllocationDigest: authorization.Binding.HolderAllocationDigest, BoundAtUnix: now.Unix(),
			CureDeadlineUnix: now.Add(24 * time.Hour).Unix(),
		}
		// This create-only object is the irreversible clock boundary. It is
		// durably published before the recourse record is constructed.
		if _, _, err := store.createJSON(recourseClockObject, clockBinding); err != nil {
			return RecourseRecord{}, err
		}
	}
	if validateRecourseClockBinding(clockBinding, binding, bindingDigest, result, resultDigest, authorization) != nil {
		return RecourseRecord{}, ErrRecourse
	}
	record := RecourseRecord{
		SchemaVersion: RecourseRecordSchema, CaseID: result.CaseID, CaseBindingDigest: result.CaseBindingDigest,
		AssetIdentity: result.AssetIdentity, PolicyID: result.PolicyID, PolicyVersion: result.PolicyVersion,
		ResultDigest: resultDigest, ReleaseMode: result.ReleaseMode, ReleaseAuthorityID: result.ReleaseAuthorityID,
		RecordDateUnix: clockBinding.RecordDateUnix, BoundAtUnix: clockBinding.BoundAtUnix, CureDeadlineUnix: clockBinding.CureDeadlineUnix,
		ReserveBasisPoints: MVPReserveBasisPoints, HolderAllocationDigest: clockBinding.HolderAllocationDigest,
		OriginalReceivableIntact: true, Open: true,
	}
	if validateCompleteRecourseRecord(
		record, binding, result, resultDigest,
		authorization.Binding.HolderRecordDate, authorization.Binding.HolderAllocationDigest,
	) != nil {
		return RecourseRecord{}, ErrRecourse
	}
	if store.exists(recourseRecordObject) {
		var prior RecourseRecord
		priorBytes, _, err := store.readJSON(recourseRecordObject, &prior)
		expectedBytes, _ := marshalCanonical(record)
		if err != nil || !bytes.Equal(priorBytes, expectedBytes) {
			return RecourseRecord{}, ErrRecourse
		}
		return prior, nil
	}
	if _, _, err := store.createJSON(recourseRecordObject, record); err != nil {
		return RecourseRecord{}, err
	}
	return record, nil
}

func validateRecourseClockBinding(
	clockBinding recourseClockBinding,
	binding FHECaseBinding,
	bindingDigest Digest,
	result GovernedConflictResult,
	resultDigest Digest,
	authorization ProtectionAuthorization,
) error {
	recordDate, err := time.Parse(time.RFC3339Nano, authorization.Binding.HolderRecordDate)
	if err != nil || clockBinding.SchemaVersion != recourseClockSchema || clockBinding.CaseID != binding.CaseID ||
		clockBinding.CaseBindingDigest != bindingDigest || clockBinding.ResultDigest != resultDigest ||
		clockBinding.ProtectionDigest != authorization.Digest || clockBinding.RecordDateUnix != recordDate.Unix() ||
		clockBinding.HolderAllocationDigest != authorization.Binding.HolderAllocationDigest ||
		clockBinding.BoundAtUnix < result.ReleasedAtUnix || clockBinding.BoundAtUnix > binding.ExpiresAtUnix ||
		clockBinding.CureDeadlineUnix != clockBinding.BoundAtUnix+int64((24*time.Hour)/time.Second) {
		return ErrRecourse
	}
	return nil
}

func loadValidatedRecourseRecord(
	store *objectStore,
	binding FHECaseBinding,
	result GovernedConflictResult,
	resultDigest Digest,
	authorization ProtectionAuthorization,
) (*RecourseRecord, error) {
	if !store.exists(recourseRecordObject) {
		if store.exists(recourseClockObject) {
			return nil, ErrRecourse
		}
		return nil, nil
	}
	var record RecourseRecord
	var clockBinding recourseClockBinding
	bindingDigest, err := binding.Digest()
	if err != nil {
		return nil, ErrRecourse
	}
	if _, _, err := store.readJSON(recourseRecordObject, &record); err != nil ||
		validateCompleteRecourseRecord(record, binding, result, resultDigest,
			authorization.Binding.HolderRecordDate, authorization.Binding.HolderAllocationDigest) != nil {
		return nil, ErrRecourse
	}
	if _, _, err := store.readJSON(recourseClockObject, &clockBinding); err != nil ||
		validateRecourseClockBinding(clockBinding, binding, bindingDigest, result, resultDigest, authorization) != nil ||
		clockBinding.RecordDateUnix != record.RecordDateUnix || clockBinding.BoundAtUnix != record.BoundAtUnix ||
		clockBinding.CureDeadlineUnix != record.CureDeadlineUnix || clockBinding.HolderAllocationDigest != record.HolderAllocationDigest {
		return nil, ErrRecourse
	}
	return &record, nil
}

// validateCompleteRecourseRecord is the single full validator used by record
// creation, public evidence export, and product inspection.
func validateCompleteRecourseRecord(
	record RecourseRecord,
	binding FHECaseBinding,
	result GovernedConflictResult,
	resultDigest Digest,
	expectedRecordDate string,
	expectedHolderAllocation Digest,
) error {
	bindingDigest, err := binding.Digest()
	recordDate, dateErr := time.Parse(time.RFC3339Nano, expectedRecordDate)
	if err != nil || dateErr != nil || !result.Conflict || record.SchemaVersion != RecourseRecordSchema ||
		record.CaseID != binding.CaseID || record.CaseBindingDigest != bindingDigest ||
		record.AssetIdentity != binding.AssetIdentity || record.PolicyID != binding.PolicyID ||
		record.PolicyVersion != result.PolicyVersion || record.ResultDigest != resultDigest ||
		record.ReleaseMode != result.ReleaseMode || record.ReleaseAuthorityID != result.ReleaseAuthorityID ||
		record.RecordDateUnix != recordDate.Unix() || record.RecordDateUnix <= 0 || record.RecordDateUnix > binding.CreatedAtUnix ||
		record.BoundAtUnix < result.ReleasedAtUnix || record.BoundAtUnix > binding.ExpiresAtUnix ||
		record.CureDeadlineUnix != record.BoundAtUnix+int64((24*time.Hour)/time.Second) ||
		record.ReserveBasisPoints != MVPReserveBasisPoints || record.HolderAllocationDigest != expectedHolderAllocation ||
		!nonzero(record.HolderAllocationDigest) || !record.OriginalReceivableIntact || !record.Open {
		return ErrRecourse
	}
	return nil
}

func verifyRecourseCaseManifest(manifest FHECaseManifest) (FHECaseBinding, Digest, error) {
	if manifest.SchemaVersion != CaseManifestSchema || manifest.Binding.validate() != nil ||
		validateCryptoManifest(manifest.Binding, manifest.Crypto) != nil ||
		verifyBindingSignature(manifest.Binding, manifest.SignatureA, manifest.Binding.ParticipantA) != nil ||
		verifyBindingSignature(manifest.Binding, manifest.SignatureB, manifest.Binding.ParticipantB) != nil {
		return FHECaseBinding{}, Digest{}, ErrRecourse
	}
	digest, err := manifest.Binding.Digest()
	if err != nil {
		return FHECaseBinding{}, Digest{}, ErrRecourse
	}
	return manifest.Binding, digest, nil
}

func verifyRecourseResultEnvelope(result GovernedConflictResult) error {
	expectedFingerprint, err := ParameterFingerprint()
	if err != nil || result.SchemaVersion != GovernedResultSchema || result.ServiceID != ServiceID || result.ServiceVersion != ServiceVersion ||
		result.PolicyVersion != fhe.PolicyVersion || result.CircuitID != CircuitID || result.CircuitVersion != fhe.CircuitV5Version ||
		result.CircuitDigest != FixedCircuitDigest() || result.ParameterProfile != ParameterProfile || result.ParameterFingerprint != expectedFingerprint ||
		assertDigestSlice(result.ParticipantArtifactDigests, 2) != nil ||
		!nonzero(result.CaseID, result.CaseBindingDigest, result.AssetIdentity, result.PolicyID, result.ResultCiphertextDigest,
			result.EvaluatedArtifactDigest, result.ResultCiphertextCommitment, result.ReleaseAuthorityID, result.SourceProvenance) ||
		result.ReleaseOrdinal != ReleaseOrdinal || !knownReleaseMode(result.ReleaseMode) || result.ReleasedAtUnix <= 0 ||
		len(result.ReleaseAuthorityPublicKey) != ed25519.PublicKeySize ||
		releaseAuthorityIdentity(result.ReleaseMode, ed25519.PublicKey(result.ReleaseAuthorityPublicKey)) != result.ReleaseAuthorityID ||
		verifyCanonical(ed25519.PublicKey(result.ReleaseAuthorityPublicKey), "MordantGovernedConflictResult/v1", result.signingValue(), result.Signature) != nil {
		return ErrRecourse
	}
	return nil
}
