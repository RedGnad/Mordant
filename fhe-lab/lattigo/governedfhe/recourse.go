package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
)

const MVPReserveBasisPoints = uint32(1000)

type RecourseAdapterConfig struct {
	RecordRoot                 string
	ExpectedCaseID             Digest
	ExpectedBindingDigest      Digest
	ExpectedAssetIdentity      Digest
	ExpectedPolicyID           Digest
	ExpectedReleaseMode        string
	ExpectedReleaseAuthorityID Digest
	CaseCreatedAtUnix          int64
	CaseExpiresAtUnix          int64
	RecordDateUnix             int64
	CurePeriod                 time.Duration
	ReserveBasisPoints         uint32
	HolderAllocationDigest     Digest
	Now                        time.Time
}

// AdaptSignedResultToRecourse is a local protocol-double for the existing V5
// governed recourse admission. Its only release input is the exact signed
// Boolean result; RecordRoot is an output capability, not a case-artifact read
// capability. It does not change or invoke the frozen contracts.
func AdaptSignedResultToRecourse(config RecourseAdapterConfig, signedResult []byte) (RecourseRecord, error) {
	if config.Now.IsZero() {
		config.Now = time.Now().UTC()
	}
	if config.CurePeriod <= 0 || config.ReserveBasisPoints != MVPReserveBasisPoints ||
		!knownReleaseMode(config.ExpectedReleaseMode) ||
		!nonzero(config.ExpectedCaseID, config.ExpectedBindingDigest, config.ExpectedAssetIdentity, config.ExpectedPolicyID,
			config.ExpectedReleaseAuthorityID, config.HolderAllocationDigest) ||
		config.CaseCreatedAtUnix <= 0 || config.CaseExpiresAtUnix <= config.CaseCreatedAtUnix {
		return RecourseRecord{}, ErrRecourse
	}
	var result GovernedConflictResult
	if decodeStrict(signedResult, &result) != nil || verifyRecourseResultEnvelope(result) != nil ||
		result.CaseID != config.ExpectedCaseID || result.CaseBindingDigest != config.ExpectedBindingDigest ||
		result.AssetIdentity != config.ExpectedAssetIdentity || result.PolicyID != config.ExpectedPolicyID ||
		result.ReleaseMode != config.ExpectedReleaseMode || result.ReleaseAuthorityID != config.ExpectedReleaseAuthorityID {
		return RecourseRecord{}, ErrRecourse
	}
	store, err := openObjectStore(config.RecordRoot, PublicCaseQuota, false)
	if err != nil {
		return RecourseRecord{}, err
	}
	if !result.Conflict {
		return RecourseRecord{}, ErrRecourse
	}
	if config.RecordDateUnix <= 0 || config.RecordDateUnix > config.CaseCreatedAtUnix ||
		result.ReleasedAtUnix < config.CaseCreatedAtUnix || result.ReleasedAtUnix > config.Now.Unix() ||
		config.Now.Unix() > config.CaseExpiresAtUnix {
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

func verifyRecourseResultEnvelope(result GovernedConflictResult) error {
	expectedFingerprint, err := ParameterFingerprint()
	if err != nil || result.SchemaVersion != GovernedResultSchema || result.ServiceID != ServiceID || result.ServiceVersion != ServiceVersion ||
		result.PolicyVersion != fhe.PolicyVersion || result.CircuitID != CircuitID || result.CircuitVersion != fhe.CircuitV5Version ||
		result.CircuitDigest != FixedCircuitDigest() || result.ParameterProfile != ParameterProfile || result.ParameterFingerprint != expectedFingerprint ||
		assertDigestSlice(result.ParticipantArtifactDigests, 2) != nil ||
		!nonzero(result.CaseID, result.CaseBindingDigest, result.AssetIdentity, result.PolicyID, result.ResultCiphertextDigest,
			result.ResultCiphertextCommitment, result.ReleaseAuthorityID, result.SourceProvenance) ||
		result.ReleaseOrdinal != ReleaseOrdinal || !knownReleaseMode(result.ReleaseMode) || result.ReleasedAtUnix <= 0 ||
		len(result.ReleaseAuthorityPublicKey) != ed25519.PublicKeySize ||
		releaseAuthorityIdentity(result.CaseBindingDigest, result.ReleaseMode, ed25519.PublicKey(result.ReleaseAuthorityPublicKey)) != result.ReleaseAuthorityID ||
		verifyCanonical(ed25519.PublicKey(result.ReleaseAuthorityPublicKey), "MordantGovernedConflictResult/v1", result.signingValue(), result.Signature) != nil {
		return ErrRecourse
	}
	return nil
}
