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
		SchemaVersion: ProtectionBindingSchema, CleanverseAssetRecordDigest: DeployedCaseAdapterAssets()[0],
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
	fheBinding := FHECaseBinding{
		CaseID: binding.FHECaseID, AssetIdentity: binding.CleanverseAssetRecordDigest,
		PolicyID: binding.PolicyID, PolicyVersion: binding.PolicyVersion,
		CreatedAtUnix: time.Date(2026, 8, 3, 12, 1, 0, 0, time.UTC).Unix(),
		ExpiresAtUnix: time.Date(2026, 8, 5, 12, 1, 0, 0, time.UTC).Unix(),
	}
	bindingDigest, err := fheBinding.Digest()
	if err != nil {
		t.Fatal(err)
	}
	result := GovernedConflictResult{
		CaseID: binding.FHECaseID, CaseBindingDigest: bindingDigest, AssetIdentity: binding.CleanverseAssetRecordDigest,
		PolicyID: binding.PolicyID, PolicyVersion: binding.PolicyVersion, Conflict: true,
		ParticipantArtifactDigests: []Digest{
			DigestBytes([]byte("participant-a")),
			DigestBytes([]byte("participant-b")),
		},
		EvaluatedArtifactDigest:    DigestBytes([]byte("evaluated")),
		ResultCiphertextDigest:     DigestBytes([]byte("ciphertext")),
		ResultCiphertextCommitment: DigestBytes([]byte("commitment")),
		ReleasedAtUnix:             time.Date(2026, 8, 3, 12, 6, 0, 0, time.UTC).Unix(),
	}
	resultDigest, err := result.Digest()
	if err != nil {
		t.Fatal(err)
	}
	record := RecourseRecord{
		SchemaVersion: RecourseRecordSchema, CaseID: fheBinding.CaseID, CaseBindingDigest: bindingDigest,
		AssetIdentity: fheBinding.AssetIdentity, PolicyID: fheBinding.PolicyID, PolicyVersion: fheBinding.PolicyVersion,
		ResultDigest: resultDigest, ReleaseMode: result.ReleaseMode, ReleaseAuthorityID: result.ReleaseAuthorityID,
		RecordDateUnix:     time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC).Unix(),
		BoundAtUnix:        time.Date(2026, 8, 3, 12, 10, 0, 0, time.UTC).Unix(),
		CureDeadlineUnix:   time.Date(2026, 8, 4, 12, 10, 0, 0, time.UTC).Unix(),
		ReserveBasisPoints: MVPReserveBasisPoints, HolderAllocationDigest: binding.HolderAllocationDigest,
		OriginalReceivableIntact: true, Open: true,
	}
	authorization := ProtectionAuthorization{Binding: binding, Digest: DigestBytes([]byte("protection-authorization"))}
	artifact := EvaluatedConflictArtifact{CaseID: fheBinding.CaseID}
	chronology, err := canonicalProductChronology(
		authorization, FHECaseManifest{Binding: fheBinding}, artifact, result.EvaluatedArtifactDigest,
		result, resultDigest, &record, ClockClassSimulatedProtocol, result.ReleasedAtUnix,
	)
	if err != nil || chronology.FinalRecourseState != RecourseStateSimulated || chronology.SimulationAsOfUnix == nil {
		t.Fatalf("canonical chronology rejected: state=%s err=%v", chronology.FinalRecourseState, err)
	}
	chronology.Events[1].ClockSource = "CALLER_SUPPLIED_CLOCK"
	if chronology.validateCanonicalOrder() != nil {
		// Shape validation alone is intentionally insufficient; reconstruction
		// below proves substituted values cannot become canonical.
	}
	rebuilt, err := canonicalProductChronology(
		authorization, FHECaseManifest{Binding: fheBinding}, artifact, result.EvaluatedArtifactDigest,
		result, resultDigest, &record, ClockClassSimulatedProtocol, result.ReleasedAtUnix,
	)
	if err != nil || rebuilt.Events[1].ClockSource == chronology.Events[1].ClockSource {
		t.Fatal("caller-supplied chronology influenced signer reconstruction")
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
