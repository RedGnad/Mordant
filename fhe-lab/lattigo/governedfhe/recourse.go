package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
)

const MVPReserveBasisPoints = uint32(1000)

type RecourseAdapterConfig struct {
	RecordRoot             string
	CaseManifest           FHECaseManifest
	ExpectedPins           TrustedRecoursePins
	RecordDateUnix         int64
	CurePeriod             time.Duration
	ReserveBasisPoints     uint32
	HolderAllocationDigest Digest
	Now                    time.Time
}

// AdaptSignedResultToRecourse is a local protocol-double for the existing V5
// governed recourse admission. Its only release input is the exact signed
// Boolean result; RecordRoot is an output capability, not a case-artifact read
// capability. It does not change or invoke the frozen contracts.
func AdaptSignedResultToRecourse(config RecourseAdapterConfig, signedResult []byte) (RecourseRecord, error) {
	if config.Now.IsZero() {
		config.Now = time.Now().UTC()
	}
	binding, bindingDigest, err := verifyRecourseCaseManifest(config.CaseManifest)
	if err != nil {
		return RecourseRecord{}, ErrRecourse
	}
	if config.CurePeriod <= 0 || config.ReserveBasisPoints != MVPReserveBasisPoints ||
		!knownReleaseMode(config.ExpectedPins.ReleaseMode) ||
		!nonzero(config.ExpectedPins.ParticipantArtifactDigestA, config.ExpectedPins.ParticipantArtifactDigestB,
			config.ExpectedPins.EvaluatedArtifactDigest, config.ExpectedPins.RecomputedResultCiphertextDigest,
			config.ExpectedPins.ResultCiphertextCommitment, config.ExpectedPins.DecryptorProvenance,
			config.ExpectedPins.ReleaseAuthorityID, config.HolderAllocationDigest) ||
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
	if config.RecordDateUnix <= 0 || config.RecordDateUnix > binding.CreatedAtUnix ||
		result.ReleasedAtUnix < binding.CreatedAtUnix || result.ReleasedAtUnix > config.Now.Unix() ||
		config.Now.Unix() > binding.ExpiresAtUnix {
		return RecourseRecord{}, ErrRecourse
	}
	resultDigest := DigestBytes(signedResult[:len(signedResult)-1])
	record := RecourseRecord{
		SchemaVersion: RecourseRecordSchema, CaseID: result.CaseID, CaseBindingDigest: result.CaseBindingDigest,
		AssetIdentity: result.AssetIdentity, PolicyID: result.PolicyID, PolicyVersion: result.PolicyVersion,
		ResultDigest: resultDigest, ReleaseMode: result.ReleaseMode, ReleaseAuthorityID: result.ReleaseAuthorityID,
		RecordDateUnix: config.RecordDateUnix, BoundAtUnix: config.Now.Unix(), CureDeadlineUnix: config.Now.Add(config.CurePeriod).Unix(),
		ReserveBasisPoints: config.ReserveBasisPoints, HolderAllocationDigest: config.HolderAllocationDigest,
		OriginalReceivableIntact: true, Open: true,
	}
	if validateCompleteRecourseRecord(
		record, binding, result, resultDigest,
		time.Unix(config.RecordDateUnix, 0).UTC().Format(time.RFC3339), config.HolderAllocationDigest,
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
