package governedfhe

import (
	"testing"
	"time"
)

func validProductBinding(t *testing.T) MordantProtectionBinding {
	t.Helper()
	policy, err := protectionPolicyID()
	if err != nil {
		t.Fatal(err)
	}
	binding := MordantProtectionBinding{
		SchemaVersion: ProtectionBindingSchema, CleanverseAssetRecordDigest: DigestBytes([]byte("cleanverse-asset")),
		ProtectionService: ProtectionService, ProtectionServiceVersion: ProtectionServiceVersion,
		PolicyID: policy, PolicyVersion: ProtectionPolicyVersion, ProductScenario: "conflict",
		FixtureClassification: ProtectionFixtureClass,
		ProtectedAmount:       ProductAmount{Asset: "aUSDC", MinorUnits: "100000000"},
		ReserveBasisPoints:    MVPReserveBasisPoints, ReserveAmount: ProductAmount{Asset: "aUSDC", MinorUnits: "10000000"},
		HolderRecordDate: "2026-08-03T12:00:00.000Z",
		HolderSnapshot: []ProductHolderAllocation{
			{HolderID: "HOLDER_A", ProtectedUnits: "60000000", AllocationBPS: 6000},
			{HolderID: "HOLDER_B", ProtectedUnits: "40000000", AllocationBPS: 4000},
		},
		CaseNonce: DigestBytes([]byte("case-nonce")), GovernedReleaseMode: ReleaseModeGovernedDecryptor,
	}
	binding.HolderAllocationDigest, err = protectionHolderAllocationDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	binding.FHECaseID, err = protectionFHECaseID(binding, binding.HolderAllocationDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := binding.Validate(); err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestProductProofBindingDerivations(t *testing.T) {
	binding := validProductBinding(t)
	mutations := map[string]func(*MordantProtectionBinding){
		"asset": func(value *MordantProtectionBinding) {
			value.CleanverseAssetRecordDigest = DigestBytes([]byte("other"))
		},
		"scenario":    func(value *MordantProtectionBinding) { value.ProductScenario = "other" },
		"reserve":     func(value *MordantProtectionBinding) { value.ReserveBasisPoints++ },
		"record-date": func(value *MordantProtectionBinding) { value.HolderRecordDate = "2026-08-03T12:00:01.000Z" },
		"allocation":  func(value *MordantProtectionBinding) { value.HolderSnapshot[0].AllocationBPS++ },
		"case-id":     func(value *MordantProtectionBinding) { value.FHECaseID = DigestBytes([]byte("substituted")) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := binding
			candidate.HolderSnapshot = append([]ProductHolderAllocation(nil), binding.HolderSnapshot...)
			mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("mutated canonical product binding accepted")
			}
		})
	}
}

func TestProductChronologyUsesExactProductSequence(t *testing.T) {
	binding := validProductBinding(t)
	result := GovernedConflictResult{
		Conflict: true,
		ParticipantArtifactDigests: []Digest{
			DigestBytes([]byte("participant-a")),
			DigestBytes([]byte("participant-b")),
		},
		EvaluatedArtifactDigest:    DigestBytes([]byte("evaluated")),
		ResultCiphertextDigest:     DigestBytes([]byte("ciphertext")),
		ResultCiphertextCommitment: DigestBytes([]byte("commitment")),
	}
	resultDigest, err := result.Digest()
	if err != nil {
		t.Fatal(err)
	}
	deadline := "2026-08-04T12:10:00.000Z"
	record := RecourseRecord{CureDeadlineUnix: time.Date(2026, 8, 4, 12, 10, 0, 0, time.UTC).Unix()}
	event := func(ordinal uint32, kind, at, label, classification string, evidenceRef Digest) ProductChronologyEvent {
		return ProductChronologyEvent{Ordinal: ordinal, Kind: kind, At: at, Label: label, Classification: classification, EvidenceRef: evidenceRef}
	}
	chronology := ProductChronology{
		RecordDate: binding.HolderRecordDate, HolderAllocationDigest: binding.HolderAllocationDigest, CureDeadline: &deadline,
		Events: []ProductChronologyEvent{
			event(1, "PROTECTION_ACTIVATED", "2026-08-03T12:01:00.000Z", "Mordant protection activated for the canonical Cleanverse asset", "LOCAL_EXECUTION", binding.CleanverseAssetRecordDigest),
			event(2, "HOLDER_SNAPSHOT_RECORDED", "2026-08-03T12:02:00.000Z", "Record-date holder allocation fixed at 60 / 40 and reserve held separately", "PROTOCOL_DOUBLE", binding.HolderAllocationDigest),
			event(3, "PARTICIPANT_A_ENCRYPTED_PLEDGE_RECEIVED", "2026-08-03T12:03:00.000Z", "Participant A encrypted pledge received", "LOCAL_EXECUTION", result.ParticipantArtifactDigests[0]),
			event(4, "PARTICIPANT_B_ENCRYPTED_PLEDGE_RECEIVED", "2026-08-03T12:04:00.000Z", "Participant B encrypted pledge received", "LOCAL_EXECUTION", result.ParticipantArtifactDigests[1]),
			event(5, "FHE_EVALUATION_COMPLETE", "2026-08-03T12:05:00.000Z", "Fixed N15 BGV conflict circuit evaluated without an evaluator decryption key", "LOCAL_EXECUTION", result.EvaluatedArtifactDigest),
			event(6, "GOVERNED_RECOMPUTATION_VERIFIED", "2026-08-03T12:06:00.000Z", "Governed decryptor independently recomputed the fixed circuit", "LOCAL_EXECUTION", result.ResultCiphertextDigest),
			event(7, "SIGNED_CONFLICT_CONFIRMED", "2026-08-03T12:06:00.000Z", "Signed Boolean confirmed a conflicting pledge", "LOCAL_EXECUTION", resultDigest),
			event(8, "CURE_WINDOW_OPENED", "2026-08-03T12:10:00.000Z", "Record-date holders remain fixed while the cure / dispute window runs", "PROTOCOL_DOUBLE", binding.HolderAllocationDigest),
			event(9, "RECOURSE_AVAILABLE_AFTER_CURE", "2026-08-04T12:10:01.000Z", "Local chronology reached the cure deadline; governed recourse is available", "PROTOCOL_DOUBLE", resultDigest),
		},
	}
	if _, _, state, err := validateChronology(chronology, binding, result, &record); err != nil || state != RecourseStateAvailable {
		t.Fatalf("canonical chronology rejected: state=%s err=%v", state, err)
	}
	chronology.Events[1].Classification = "REAL_BGV_FHE"
	if _, _, _, err := validateChronology(chronology, binding, result, &record); err == nil {
		t.Fatal("evidence-level classification accepted in the product chronology")
	}
}

func TestProductInspectorRecourseValidatorRejectsIncompleteRecord(t *testing.T) {
	binding := FHECaseBinding{
		CaseID: DigestBytes([]byte("case")), AssetIdentity: DigestBytes([]byte("asset")), PolicyID: DigestBytes([]byte("policy")),
		PolicyVersion: 1, CreatedAtUnix: 1_800_000_000, ExpiresAtUnix: 1_800_020_000,
	}
	bindingDigest, err := binding.Digest()
	if err != nil {
		t.Fatal(err)
	}
	result := GovernedConflictResult{
		CaseID: binding.CaseID, CaseBindingDigest: bindingDigest, AssetIdentity: binding.AssetIdentity,
		PolicyID: binding.PolicyID, PolicyVersion: 1, Conflict: true, ReleasedAtUnix: 1_800_000_100,
		ReleaseMode: ReleaseModeGovernedDecryptor, ReleaseAuthorityID: DigestBytes([]byte("authority")),
	}
	holderDigest := DigestBytes([]byte("holders"))
	recordDate := time.Unix(1_799_999_000, 0).UTC().Format(time.RFC3339)
	record := RecourseRecord{
		SchemaVersion: RecourseRecordSchema, CaseID: binding.CaseID, CaseBindingDigest: bindingDigest,
		AssetIdentity: binding.AssetIdentity, PolicyID: binding.PolicyID, PolicyVersion: 1,
		ResultDigest: DigestBytes([]byte("result")), ReleaseMode: result.ReleaseMode, ReleaseAuthorityID: result.ReleaseAuthorityID,
		RecordDateUnix: 1_799_999_000, BoundAtUnix: 1_800_000_200, CureDeadlineUnix: 1_800_086_600,
		ReserveBasisPoints: MVPReserveBasisPoints, HolderAllocationDigest: holderDigest,
		OriginalReceivableIntact: true, Open: true,
	}
	if err := validateCompleteRecourseRecord(record, binding, result, record.ResultDigest, recordDate, holderDigest); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	record.CureDeadlineUnix = 0
	if validateCompleteRecourseRecord(record, binding, result, record.ResultDigest, recordDate, holderDigest) == nil {
		t.Fatal("incomplete recourse record accepted by inspector validator")
	}
}
