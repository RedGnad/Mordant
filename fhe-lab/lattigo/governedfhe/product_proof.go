package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"
)

const (
	ProtectionBindingSchema = "mordant.protection-binding/1"
	// V2 is the isolated custom-supervised authorization. It carries a neutral
	// execution variant instead of a product scenario, so nothing about the
	// expected conflict Boolean is bound or signed before governed release.
	ProtectionBindingSchemaV2        = "mordant.protection-binding/2"
	ExecutionVariantCustomSupervised = "CUSTOM_SUPERVISED"
	ProtectionAttestationSchema      = "mordant.recourse-attestation/2"
	ProductChronologySchema          = "mordant.product-chronology/1"
	ProtectionService                = "Conflicting Pledge Protection"
	ProtectionServiceVersion         = uint32(1)
	ProtectionPolicyVersion          = uint32(1)
	ProtectionFixtureClass           = "SYNTHETIC_HACKATHON_FIXTURE"
	ProductClaimIdentifier           = "mordant.conflicting-pledge-protection/governed-fhe-mvp-v1"
	SimulatedProductClaim            = "mordant.conflicting-pledge-protection/governed-fhe-mvp-simulated-protocol-clock-v1"
	RealObservedProductClaim         = "mordant.conflicting-pledge-protection/governed-fhe-mvp-real-observed-clock-v1"
	ProductClaim                     = ProductClaimIdentifier
	RecourseRefusalNone              = "NONE"
	RecourseRefusalSignedFalse       = "SIGNED_RESULT_FALSE"
	RecourseStateAvailable           = "AVAILABLE"
	RecourseStateSimulated           = "SIMULATED_AVAILABLE"
	RecourseStateRefused             = "REFUSED"
	ClockClassRealObserved           = "REAL_OBSERVED_CLOCK"
	ClockClassSimulatedProtocol      = "SIMULATED_PROTOCOL_CLOCK"
)

type ProductAmount struct {
	Asset      string `json:"asset"`
	MinorUnits string `json:"minorUnits"`
}

type ProductHolderAllocation struct {
	HolderID       string `json:"holderId"`
	ProtectedUnits string `json:"protectedUnits"`
	AllocationBPS  uint32 `json:"allocationBps"`
}

type MordantProtectionBinding struct {
	SchemaVersion               string `json:"schemaVersion"`
	CleanverseAssetRecordDigest Digest `json:"cleanverseAssetRecordDigest"`
	ProtectionService           string `json:"protectionService"`
	ProtectionServiceVersion    uint32 `json:"protectionServiceVersion"`
	PolicyID                    Digest `json:"policyId"`
	PolicyVersion               uint32 `json:"policyVersion"`
	// V1 only. Empty and omitted for V2, so a custom case binds no expected
	// result. `omitempty` leaves V1 bytes untouched because V1 always sets it.
	ProductScenario        string                    `json:"productScenario,omitempty"`
	FixtureClassification  string                    `json:"fixtureClassification"`
	ProtectedAmount        ProductAmount             `json:"protectedAmount"`
	ReserveBasisPoints     uint32                    `json:"reserveBasisPoints"`
	ReserveAmount          ProductAmount             `json:"reserveAmount"`
	HolderRecordDate       string                    `json:"holderRecordDate"`
	HolderSnapshot         []ProductHolderAllocation `json:"holderSnapshot"`
	HolderAllocationDigest Digest                    `json:"holderAllocationDigest"`
	CaseNonce              Digest                    `json:"caseNonce"`
	FHECaseID              Digest                    `json:"fheCaseId"`
	GovernedReleaseMode    string                    `json:"governedReleaseMode"`
	// V2 only, and last in the struct so that an omitted V2 field cannot move a
	// single byte of the retained V1 encoding.
	ExecutionVariant string `json:"executionVariant,omitempty"`
}

func digestDomainCanonical(domain string, value any) (Digest, error) {
	encoded, err := json.Marshal(value)
	if err != nil || domain == "" {
		return Digest{}, ErrBinding
	}
	message := append(append([]byte(domain), 0), encoded...)
	return Digest(sha256.Sum256(message)), nil
}

func protectionPolicyID() (Digest, error) {
	return digestDomainCanonical("MordantConflictingPledgePolicy/v1", struct {
		PolicyVersion  uint32 `json:"policyVersion"`
		Service        string `json:"service"`
		ServiceVersion uint32 `json:"serviceVersion"`
	}{ProtectionPolicyVersion, ProtectionService, ProtectionServiceVersion})
}

func protectionHolderAllocationDigest(binding MordantProtectionBinding) (Digest, error) {
	type holder struct {
		AllocationBPS  uint32 `json:"allocationBps"`
		HolderID       string `json:"holderId"`
		ProtectedUnits string `json:"protectedUnits"`
	}
	holders := make([]holder, len(binding.HolderSnapshot))
	for index, entry := range binding.HolderSnapshot {
		holders[index] = holder{entry.AllocationBPS, entry.HolderID, entry.ProtectedUnits}
	}
	return digestDomainCanonical("MordantProtectedHolderSnapshot/v1", struct {
		AssetDigest Digest   `json:"assetDigest"`
		Holders     []holder `json:"holders"`
		RecordDate  string   `json:"recordDate"`
	}{binding.CleanverseAssetRecordDigest, holders, binding.HolderRecordDate})
}

func protectionFHECaseID(binding MordantProtectionBinding, allocation Digest) (Digest, error) {
	// V2 uses its own domain and binds the neutral execution variant in place of
	// the product scenario. No function of the entered pledge windows, and no
	// prediction of the circuit output, enters this derivation.
	if binding.SchemaVersion == ProtectionBindingSchemaV2 {
		return digestDomainCanonical("MordantProtectionFHECase/v2", struct {
			AssetDigest            Digest `json:"assetDigest"`
			CaseNonce              Digest `json:"caseNonce"`
			ExecutionVariant       string `json:"executionVariant"`
			HolderAllocationDigest Digest `json:"holderAllocationDigest"`
			PolicyID               Digest `json:"policyId"`
		}{binding.CleanverseAssetRecordDigest, binding.CaseNonce, binding.ExecutionVariant, allocation, binding.PolicyID})
	}
	return digestDomainCanonical("MordantProtectionFHECase/v1", struct {
		AssetDigest            Digest `json:"assetDigest"`
		CaseNonce              Digest `json:"caseNonce"`
		HolderAllocationDigest Digest `json:"holderAllocationDigest"`
		PolicyID               Digest `json:"policyId"`
		Scenario               string `json:"scenario"`
	}{binding.CleanverseAssetRecordDigest, binding.CaseNonce, allocation, binding.PolicyID, binding.ProductScenario})
}

func (binding MordantProtectionBinding) Validate() error {
	policy, policyErr := protectionPolicyID()
	allocation, allocationErr := protectionHolderAllocationDigest(binding)
	caseID, caseErr := protectionFHECaseID(binding, allocation)
	// Schema-discriminated, never permissive: exactly one of the two authorization
	// shapes must hold, and each rejects the other's discriminating member.
	switch binding.SchemaVersion {
	case ProtectionBindingSchema:
		if binding.ProductScenario != "conflict" && binding.ProductScenario != "no-conflict" {
			return ErrBinding
		}
		if binding.ExecutionVariant != "" {
			return ErrBinding
		}
	case ProtectionBindingSchemaV2:
		if binding.ExecutionVariant != ExecutionVariantCustomSupervised {
			return ErrBinding
		}
		if binding.ProductScenario != "" {
			return ErrBinding
		}
	default:
		return ErrBinding
	}
	if policyErr != nil || allocationErr != nil || caseErr != nil ||
		binding.ProtectionService != ProtectionService ||
		binding.ProtectionServiceVersion != ProtectionServiceVersion || binding.PolicyID != policy ||
		binding.PolicyVersion != ProtectionPolicyVersion ||
		binding.FixtureClassification != ProtectionFixtureClass ||
		binding.ProtectedAmount != (ProductAmount{Asset: "aUSDC", MinorUnits: "100000000"}) ||
		binding.ReserveBasisPoints != MVPReserveBasisPoints ||
		binding.ReserveAmount != (ProductAmount{Asset: "aUSDC", MinorUnits: "10000000"}) ||
		len(binding.HolderSnapshot) != 2 ||
		binding.HolderSnapshot[0] != (ProductHolderAllocation{HolderID: "HOLDER_A", ProtectedUnits: "60000000", AllocationBPS: 6000}) ||
		binding.HolderSnapshot[1] != (ProductHolderAllocation{HolderID: "HOLDER_B", ProtectedUnits: "40000000", AllocationBPS: 4000}) ||
		binding.HolderAllocationDigest != allocation || binding.FHECaseID != caseID ||
		binding.GovernedReleaseMode != ReleaseModeGovernedDecryptor ||
		!nonzero(binding.CleanverseAssetRecordDigest, binding.PolicyID, binding.HolderAllocationDigest, binding.CaseNonce, binding.FHECaseID) {
		return ErrBinding
	}
	if parsed, err := time.Parse(time.RFC3339Nano, binding.HolderRecordDate); err != nil || parsed.Unix() <= 0 {
		return ErrBinding
	}
	return nil
}

func (binding MordantProtectionBinding) Digest() (Digest, error) {
	if binding.Validate() != nil {
		return Digest{}, ErrBinding
	}
	digest, _, err := digestCanonical(binding)
	return digest, err
}

type ProtectionBindingSignature struct {
	Role                    string `json:"role"`
	ParticipantID           Digest `json:"participantId"`
	ProtectionBindingDigest Digest `json:"protectionBindingDigest"`
	Signature               []byte `json:"signature"`
}

type ProtectionAuthorization struct {
	Binding    MordantProtectionBinding   `json:"binding"`
	Digest     Digest                     `json:"digest"`
	SignatureA ProtectionBindingSignature `json:"signatureA"`
	SignatureB ProtectionBindingSignature `json:"signatureB"`
}

func protectionSignatureValue(signature ProtectionBindingSignature) any {
	return struct {
		Role                    string `json:"role"`
		ParticipantID           Digest `json:"participantId"`
		ProtectionBindingDigest Digest `json:"protectionBindingDigest"`
	}{signature.Role, signature.ParticipantID, signature.ProtectionBindingDigest}
}

func signProtectionBinding(identity ParticipantIdentity, key ed25519.PrivateKey, digest Digest) (ProtectionBindingSignature, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), identity.SigningPublicKey) {
		return ProtectionBindingSignature{}, ErrBinding
	}
	signature := ProtectionBindingSignature{Role: identity.Role, ParticipantID: identity.ID, ProtectionBindingDigest: digest}
	encoded, err := signCanonical(key, "MordantProtectionBindingSignature/v1", protectionSignatureValue(signature))
	if err != nil {
		return ProtectionBindingSignature{}, err
	}
	signature.Signature = encoded
	return signature, nil
}

func verifyProtectionSignature(signature ProtectionBindingSignature, identity ParticipantIdentity, digest Digest) error {
	if signature.Role != identity.Role || signature.ParticipantID != identity.ID || signature.ProtectionBindingDigest != digest {
		return ErrBinding
	}
	return verifyCanonical(ed25519.PublicKey(identity.SigningPublicKey), "MordantProtectionBindingSignature/v1", protectionSignatureValue(signature), signature.Signature)
}

func bindingMatchesFHE(binding MordantProtectionBinding, fheBinding FHECaseBinding) bool {
	return binding.CleanverseAssetRecordDigest == fheBinding.AssetIdentity && binding.PolicyID == fheBinding.PolicyID &&
		binding.PolicyVersion == fheBinding.PolicyVersion && binding.FHECaseID == fheBinding.CaseID &&
		binding.CaseNonce == fheBinding.CaseNonce && binding.GovernedReleaseMode == fheBinding.ReleaseMode
}

func loadProtectionAuthorization(store *objectStore, fheBinding FHECaseBinding) (ProtectionAuthorization, error) {
	var binding MordantProtectionBinding
	if _, _, err := store.readJSON(protectionBindingObject, &binding); err != nil || binding.Validate() != nil || !bindingMatchesFHE(binding, fheBinding) {
		return ProtectionAuthorization{}, ErrBinding
	}
	digest, err := binding.Digest()
	if err != nil {
		return ProtectionAuthorization{}, err
	}
	var signatureA, signatureB ProtectionBindingSignature
	if _, _, err := store.readJSON(protectionSignatureAObject, &signatureA); err != nil {
		return ProtectionAuthorization{}, ErrBinding
	}
	if _, _, err := store.readJSON(protectionSignatureBObject, &signatureB); err != nil ||
		verifyProtectionSignature(signatureA, fheBinding.ParticipantA, digest) != nil ||
		verifyProtectionSignature(signatureB, fheBinding.ParticipantB, digest) != nil {
		return ProtectionAuthorization{}, ErrBinding
	}
	return ProtectionAuthorization{Binding: binding, Digest: digest, SignatureA: signatureA, SignatureB: signatureB}, nil
}

type ProductAuthorizedCreateOptions struct {
	CreateCaseOptions
	ProtectionBinding      MordantProtectionBinding
	ParticipantASigningKey ed25519.PrivateKey
	ParticipantBSigningKey ed25519.PrivateKey
}

func CreateProductAuthorizedCase(options ProductAuthorizedCreateOptions) (FHECaseBinding, KeyGenerationReport, ProtectionAuthorization, error) {
	var empty ProtectionAuthorization
	if options.ProtectionBinding.Validate() != nil || options.Spec.CaseID != options.ProtectionBinding.FHECaseID ||
		options.Spec.AssetIdentity != options.ProtectionBinding.CleanverseAssetRecordDigest ||
		options.Spec.PolicyID != options.ProtectionBinding.PolicyID || options.Spec.CaseNonce != options.ProtectionBinding.CaseNonce {
		return FHECaseBinding{}, KeyGenerationReport{}, empty, ErrBinding
	}
	binding, report, err := CreateCase(options.CreateCaseOptions)
	if err != nil {
		return FHECaseBinding{}, report, empty, err
	}
	digest, err := options.ProtectionBinding.Digest()
	if err != nil {
		return FHECaseBinding{}, report, empty, err
	}
	signatureA, err := signProtectionBinding(binding.ParticipantA, options.ParticipantASigningKey, digest)
	if err != nil {
		return FHECaseBinding{}, report, empty, err
	}
	signatureB, err := signProtectionBinding(binding.ParticipantB, options.ParticipantBSigningKey, digest)
	if err != nil {
		return FHECaseBinding{}, report, empty, err
	}
	store, err := openObjectStore(options.PublicRoot, PublicCaseQuota, false)
	if err != nil {
		return FHECaseBinding{}, report, empty, err
	}
	defer store.close()
	if _, _, err := store.createJSON(protectionBindingObject, options.ProtectionBinding); err != nil {
		return FHECaseBinding{}, report, empty, err
	}
	if _, _, err := store.createJSON(protectionSignatureAObject, signatureA); err != nil {
		return FHECaseBinding{}, report, empty, err
	}
	if _, _, err := store.createJSON(protectionSignatureBObject, signatureB); err != nil {
		return FHECaseBinding{}, report, empty, err
	}
	authorization := ProtectionAuthorization{Binding: options.ProtectionBinding, Digest: digest, SignatureA: signatureA, SignatureB: signatureB}
	return binding, report, authorization, nil
}

func VerifyProtectionAuthorization(publicRoot string) (ProtectionAuthorization, error) {
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return ProtectionAuthorization{}, err
	}
	defer store.close()
	binding, _, err := loadCaseFoundation(store)
	if err != nil {
		return ProtectionAuthorization{}, err
	}
	return loadProtectionAuthorization(store, binding)
}

type ProductChronologyEvent struct {
	Ordinal     uint32 `json:"ordinal"`
	Kind        string `json:"kind"`
	AtUnix      *int64 `json:"atUnix"`
	ClockSource string `json:"clockSource"`
	EvidenceRef Digest `json:"evidenceRef"`
}

type ProductChronology struct {
	SchemaVersion          string                   `json:"schemaVersion"`
	ClockClass             string                   `json:"clockClass"`
	SignedAtUnix           int64                    `json:"signedAtUnix"`
	SimulationAsOfUnix     *int64                   `json:"simulationAsOfUnix"`
	RecordDate             string                   `json:"recordDate"`
	HolderAllocationDigest Digest                   `json:"holderAllocationDigest"`
	CureDeadlineUnix       *int64                   `json:"cureDeadlineUnix"`
	FinalIncidentState     string                   `json:"finalIncidentState"`
	FinalRecourseState     string                   `json:"finalRecourseState"`
	Events                 []ProductChronologyEvent `json:"events"`
}

func (chronology ProductChronology) Digest() (Digest, error) {
	if len(chronology.Events) == 0 {
		return Digest{}, ErrBinding
	}
	digest, _, err := digestCanonical(chronology)
	return digest, err
}

type ReserveAccountingSeparation struct {
	ReserveDomain            string `json:"reserveDomain"`
	ReceivableDomain         string `json:"receivableDomain"`
	Separate                 bool   `json:"separate"`
	ClaimBurnedOrTransferred bool   `json:"claimBurnedOrTransferred"`
}

type MordantRecourseAttestation struct {
	SchemaVersion               string                      `json:"schemaVersion"`
	ProtectionBindingDigest     Digest                      `json:"protectionBindingDigest"`
	GovernedResultDigest        Digest                      `json:"governedResultDigest"`
	CaseID                      Digest                      `json:"caseId"`
	CleanverseAssetRecordDigest Digest                      `json:"cleanverseAssetRecordDigest"`
	SignedBoolean               bool                        `json:"signedBoolean"`
	RecourseRecordDigest        Digest                      `json:"recourseRecordDigest"`
	RecourseRefusal             string                      `json:"recourseRefusal"`
	HolderAllocationDigest      Digest                      `json:"holderAllocationDigest"`
	RecordDate                  string                      `json:"recordDate"`
	CureDeadline                *string                     `json:"cureDeadline"`
	FinalRecourseState          string                      `json:"finalRecourseState"`
	FinalIncidentState          string                      `json:"finalIncidentState"`
	ClockClass                  string                      `json:"clockClass"`
	SignedAtUnix                int64                       `json:"signedAtUnix"`
	SimulationAsOfUnix          *int64                      `json:"simulationAsOfUnix"`
	ChronologyDigest            Digest                      `json:"chronologyDigest"`
	OriginalReceivableState     string                      `json:"originalReceivableState"`
	ReserveAccountingSeparation ReserveAccountingSeparation `json:"reserveAccountingSeparation"`
	ExecutionClass              string                      `json:"executionClass"`
	DeploymentClass             string                      `json:"deploymentClass"`
	ReleaseClass                string                      `json:"releaseClass"`
	RecourseClass               string                      `json:"recourseClass"`
	ProductionIsolationProven   bool                        `json:"productionIsolationProven"`
	ProductClaim                string                      `json:"productClaim"`
	ReleaseAuthorityID          Digest                      `json:"releaseAuthorityId"`
	Signature                   []byte                      `json:"signature"`
}

func (attestation MordantRecourseAttestation) signingValue() MordantRecourseAttestation {
	attestation.Signature = nil
	return attestation
}

func (attestation MordantRecourseAttestation) Digest() (Digest, error) {
	digest, _, err := digestCanonical(attestation)
	return digest, err
}

func unixPointer(value int64) *int64 { return &value }

func recourseDigest(record RecourseRecord) Digest {
	encoded, _ := json.Marshal(record)
	return DigestBytes(encoded)
}

// canonicalProductChronology is reconstructed exclusively from verified
// signed/digest-bound artifacts. Participant and evaluator events deliberately
// have no timestamp because those artifacts provide no authoritative clock.
func canonicalProductChronology(
	authorization ProtectionAuthorization,
	manifest FHECaseManifest,
	artifact EvaluatedConflictArtifact,
	artifactDigest Digest,
	result GovernedConflictResult,
	resultDigest Digest,
	record *RecourseRecord,
	clockClass string,
	signedAtUnix int64,
) (ProductChronology, error) {
	recordDate, err := time.Parse(time.RFC3339Nano, authorization.Binding.HolderRecordDate)
	bindingDigest, bindingErr := manifest.Binding.Digest()
	if err != nil || bindingErr != nil || len(result.ParticipantArtifactDigests) != 2 || signedAtUnix < result.ReleasedAtUnix ||
		signedAtUnix > manifest.Binding.ExpiresAtUnix || artifactDigest != result.EvaluatedArtifactDigest {
		return ProductChronology{}, ErrBinding
	}
	events := []ProductChronologyEvent{
		{1, "PROTECTED_HOLDER_SNAPSHOT_FIXED", unixPointer(recordDate.Unix()), "PROTECTION_BINDING_RECORD_DATE", authorization.Digest},
		{2, "FHE_CASE_CREATED", unixPointer(manifest.Binding.CreatedAtUnix), "SIGNED_FHE_CASE_CLOCK", bindingDigest},
		{3, "PARTICIPANT_A_ARTIFACT_BOUND", nil, "CRYPTOGRAPHIC_ORDER_ONLY", result.ParticipantArtifactDigests[0]},
		{4, "PARTICIPANT_B_ARTIFACT_BOUND", nil, "CRYPTOGRAPHIC_ORDER_ONLY", result.ParticipantArtifactDigests[1]},
		{5, "FHE_EVALUATION_BOUND", nil, "CRYPTOGRAPHIC_ORDER_ONLY", artifactDigest},
		{6, "GOVERNED_RESULT_RELEASED", unixPointer(result.ReleasedAtUnix), "SIGNED_GOVERNED_RELEASE_CLOCK", resultDigest},
	}
	chronology := ProductChronology{
		SchemaVersion: ProductChronologySchema, ClockClass: clockClass, SignedAtUnix: signedAtUnix,
		RecordDate: authorization.Binding.HolderRecordDate, HolderAllocationDigest: authorization.Binding.HolderAllocationDigest,
	}
	if result.Conflict {
		if record == nil || validateCompleteRecourseRecord(*record, manifest.Binding, result, resultDigest,
			authorization.Binding.HolderRecordDate, authorization.Binding.HolderAllocationDigest) != nil {
			return ProductChronology{}, ErrBinding
		}
		recordDigest := recourseDigest(*record)
		events = append(events, ProductChronologyEvent{7, "RECOURSE_BOUND", unixPointer(record.BoundAtUnix), "DURABLE_RECOURSE_CLOCK", recordDigest})
		chronology.CureDeadlineUnix = unixPointer(record.CureDeadlineUnix)
		chronology.FinalIncidentState = "CONFLICT_CONFIRMED"
		if clockClass == ClockClassSimulatedProtocol {
			simulation := record.CureDeadlineUnix + 1
			chronology.SimulationAsOfUnix = unixPointer(simulation)
			chronology.FinalRecourseState = RecourseStateSimulated
			events = append(events, ProductChronologyEvent{8, "SIMULATED_CURE_WINDOW_COMPLETED", unixPointer(simulation), "SIMULATED_PROTOCOL_CLOCK", recordDigest})
		} else if clockClass == ClockClassRealObserved && signedAtUnix > record.CureDeadlineUnix {
			chronology.FinalRecourseState = RecourseStateAvailable
			events = append(events, ProductChronologyEvent{8, "CURE_WINDOW_COMPLETED", unixPointer(signedAtUnix), "REAL_OBSERVED_CLOCK", recordDigest})
		} else {
			return ProductChronology{}, ErrBinding
		}
	} else {
		if record != nil || clockClass != ClockClassRealObserved {
			return ProductChronology{}, ErrBinding
		}
		chronology.FinalIncidentState = "CLEARED"
		chronology.FinalRecourseState = RecourseStateRefused
		events = append(events, ProductChronologyEvent{7, "RECOURSE_REFUSED_BY_SIGNED_FALSE", unixPointer(result.ReleasedAtUnix), "SIGNED_GOVERNED_RELEASE_CLOCK", resultDigest})
	}
	chronology.Events = events
	if artifact.CaseID != result.CaseID || chronology.validateCanonicalOrder() != nil {
		return ProductChronology{}, ErrBinding
	}
	return chronology, nil
}

func (chronology ProductChronology) validateCanonicalOrder() error {
	if chronology.SchemaVersion != ProductChronologySchema || len(chronology.Events) == 0 {
		return ErrBinding
	}
	seen := make(map[string]bool, len(chronology.Events))
	var prior int64
	for index, event := range chronology.Events {
		if event.Ordinal != uint32(index+1) || event.Kind == "" || event.ClockSource == "" || !nonzero(event.EvidenceRef) || seen[event.Kind] {
			return ErrBinding
		}
		seen[event.Kind] = true
		if event.AtUnix != nil {
			if *event.AtUnix <= 0 || (prior != 0 && *event.AtUnix < prior) {
				return ErrBinding
			}
			prior = *event.AtUnix
		}
	}
	if chronology.ClockClass == ClockClassSimulatedProtocol {
		if chronology.SimulationAsOfUnix == nil || chronology.FinalRecourseState != RecourseStateSimulated {
			return ErrBinding
		}
	} else if chronology.ClockClass != ClockClassRealObserved || chronology.SimulationAsOfUnix != nil {
		return ErrBinding
	}
	return nil
}

func validateRecourseAttestation(
	attestation MordantRecourseAttestation,
	authorization ProtectionAuthorization,
	manifest FHECaseManifest,
	artifact EvaluatedConflictArtifact,
	artifactDigest Digest,
	result GovernedConflictResult,
	resultDigest Digest,
	record *RecourseRecord,
) error {
	zero := Digest{}
	expectedRecordDigest, expectedRefusal := zero, RecourseRefusalSignedFalse
	if record != nil {
		encoded, _ := json.Marshal(record)
		expectedRecordDigest, expectedRefusal = DigestBytes(encoded), RecourseRefusalNone
	}
	chronology, chronologyErr := canonicalProductChronology(
		authorization, manifest, artifact, artifactDigest, result, resultDigest, record, attestation.ClockClass, attestation.SignedAtUnix,
	)
	chronologyDigest, chronologyDigestErr := chronology.Digest()
	expectedClaim := RealObservedProductClaim
	if attestation.ClockClass == ClockClassSimulatedProtocol {
		expectedClaim = SimulatedProductClaim
	}
	if chronologyErr != nil || chronologyDigestErr != nil || attestation.SchemaVersion != ProtectionAttestationSchema || attestation.ProtectionBindingDigest != authorization.Digest ||
		attestation.GovernedResultDigest != resultDigest || attestation.CaseID != authorization.Binding.FHECaseID ||
		attestation.CleanverseAssetRecordDigest != authorization.Binding.CleanverseAssetRecordDigest ||
		attestation.SignedBoolean != result.Conflict || attestation.RecourseRecordDigest != expectedRecordDigest ||
		attestation.RecourseRefusal != expectedRefusal || attestation.HolderAllocationDigest != authorization.Binding.HolderAllocationDigest ||
		attestation.RecordDate != authorization.Binding.HolderRecordDate || attestation.ChronologyDigest != chronologyDigest ||
		attestation.ClockClass != chronology.ClockClass || attestation.SignedAtUnix != chronology.SignedAtUnix ||
		!sameOptionalInt64(attestation.SimulationAsOfUnix, chronology.SimulationAsOfUnix) ||
		attestation.FinalIncidentState != chronology.FinalIncidentState || attestation.FinalRecourseState != chronology.FinalRecourseState ||
		attestation.OriginalReceivableState != "OUTSTANDING_INTACT" ||
		attestation.ReserveAccountingSeparation != (ReserveAccountingSeparation{ReserveDomain: "PROTECTION", ReceivableDomain: "RECEIVABLE", Separate: true, ClaimBurnedOrTransferred: false}) ||
		attestation.ExecutionClass != EvidenceExecutionClass || attestation.DeploymentClass != EvidenceDeploymentClass ||
		attestation.ReleaseClass != EvidenceReleaseClass || attestation.RecourseClass != EvidenceRecourseClass ||
		attestation.ProductionIsolationProven || attestation.ProductClaim != expectedClaim ||
		attestation.ReleaseAuthorityID != result.ReleaseAuthorityID ||
		verifyCanonical(ed25519.PublicKey(result.ReleaseAuthorityPublicKey), "MordantRecourseAttestation/v2", attestation.signingValue(), attestation.Signature) != nil {
		return ErrBinding
	}
	if result.Conflict {
		if record == nil || (attestation.FinalRecourseState != RecourseStateAvailable && attestation.FinalRecourseState != RecourseStateSimulated) || attestation.CureDeadline == nil ||
			attestation.RecourseRefusal != RecourseRefusalNone {
			return ErrBinding
		}
		deadline, err := time.Parse(time.RFC3339Nano, *attestation.CureDeadline)
		if err != nil || deadline.Unix() != record.CureDeadlineUnix {
			return ErrBinding
		}
	} else if record != nil || attestation.FinalRecourseState != RecourseStateRefused || attestation.CureDeadline != nil ||
		attestation.RecourseRefusal != RecourseRefusalSignedFalse {
		return ErrBinding
	}
	return nil
}

func sameOptionalInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func loadProductAttestation(
	store *objectStore,
	authorization ProtectionAuthorization,
	manifest FHECaseManifest,
	artifact EvaluatedConflictArtifact,
	artifactDigest Digest,
	result GovernedConflictResult,
	resultDigest Digest,
	record *RecourseRecord,
) (MordantRecourseAttestation, error) {
	var attestation MordantRecourseAttestation
	if _, _, err := store.readJSON(productAttestationObject, &attestation); err != nil ||
		validateRecourseAttestation(attestation, authorization, manifest, artifact, artifactDigest, result, resultDigest, record) != nil {
		return MordantRecourseAttestation{}, ErrBinding
	}
	return attestation, nil
}

func CreateRecourseAttestation(publicRoot, privateRoot string) (MordantRecourseAttestation, error) {
	return createRecourseAttestation(publicRoot, privateRoot, "", time.Now)
}

// createRecourseAttestation exposes clock selection only to same-package tests.
// Production conflict evidence always uses the explicit simulated protocol
// clock; no caller can provide timestamps, chronology events, or final states.
func createRecourseAttestation(publicRoot, privateRoot, requestedClockClass string, clock func() time.Time) (MordantRecourseAttestation, error) {
	if clock == nil {
		return MordantRecourseAttestation{}, ErrBinding
	}
	publicStore, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	defer publicStore.close()
	manifest, err := loadCaseManifest(publicStore)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	authorization, err := loadProtectionAuthorization(publicStore, manifest.Binding)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	artifact, _, artifactDigest, err := loadEvaluatedArtifact(publicStore, manifest)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	authority, err := loadReleaseAuthority(publicStore, manifest)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	var result GovernedConflictResult
	resultBytes, _, err := publicStore.readJSON(publicResultObject, &result)
	if err != nil || verifyGovernedResult(result, manifest, artifact, authority) != nil {
		return MordantRecourseAttestation{}, ErrBinding
	}
	resultDigest := DigestBytes(resultBytes[:len(resultBytes)-1])
	record, err := loadValidatedRecourseRecord(publicStore, manifest.Binding, result, resultDigest, authorization)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	if publicStore.exists(productAttestationObject) {
		retained, err := loadProductAttestation(publicStore, authorization, manifest, artifact, artifactDigest, result, resultDigest, record)
		if err != nil || (requestedClockClass != "" && retained.ClockClass != requestedClockClass) {
			return MordantRecourseAttestation{}, ErrBinding
		}
		return retained, nil
	}
	clockClass := requestedClockClass
	if clockClass == "" {
		clockClass = ClockClassRealObserved
		if result.Conflict {
			clockClass = ClockClassSimulatedProtocol
		}
	}
	signedAtUnix := clock().UTC().Truncate(time.Second).Unix()
	chronology, err := canonicalProductChronology(
		authorization, manifest, artifact, artifactDigest, result, resultDigest, record, clockClass, signedAtUnix,
	)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	chronologyDigest, err := chronology.Digest()
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	var deadline *string
	if chronology.CureDeadlineUnix != nil {
		value := time.Unix(*chronology.CureDeadlineUnix, 0).UTC().Format(time.RFC3339)
		deadline = &value
	}
	privateStore, err := openObjectStore(privateRoot, PrivateCaseQuota, true)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	defer privateStore.close()
	var privateCase PrivateCaseManifest
	if _, _, err := privateStore.readJSON(privateCaseObject, &privateCase); err != nil || privateCase.SigningKey.Path != decryptorSigningKeyObject ||
		privateCase.CaseID != result.CaseID || privateCase.ReleaseAuthorityID != result.ReleaseAuthorityID {
		return MordantRecourseAttestation{}, ErrBinding
	}
	keyBytes, err := privateStore.read(privateCase.SigningKey, ed25519.PrivateKeySize)
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.PrivateKey(keyBytes).Public().(ed25519.PublicKey), result.ReleaseAuthorityPublicKey) {
		return MordantRecourseAttestation{}, ErrBinding
	}
	defer func() { clear(keyBytes) }()
	recordDigest, refusal := Digest{}, RecourseRefusalSignedFalse
	if record != nil {
		encoded, _ := json.Marshal(record)
		recordDigest, refusal = DigestBytes(encoded), RecourseRefusalNone
	}
	attestation := MordantRecourseAttestation{
		SchemaVersion: ProtectionAttestationSchema, ProtectionBindingDigest: authorization.Digest, GovernedResultDigest: resultDigest,
		CaseID: authorization.Binding.FHECaseID, CleanverseAssetRecordDigest: authorization.Binding.CleanverseAssetRecordDigest,
		SignedBoolean: result.Conflict, RecourseRecordDigest: recordDigest, RecourseRefusal: refusal,
		HolderAllocationDigest: authorization.Binding.HolderAllocationDigest, RecordDate: authorization.Binding.HolderRecordDate,
		CureDeadline: deadline, FinalRecourseState: chronology.FinalRecourseState, FinalIncidentState: chronology.FinalIncidentState,
		ClockClass: chronology.ClockClass, SignedAtUnix: chronology.SignedAtUnix, SimulationAsOfUnix: chronology.SimulationAsOfUnix,
		ChronologyDigest:            chronologyDigest,
		OriginalReceivableState:     "OUTSTANDING_INTACT",
		ReserveAccountingSeparation: ReserveAccountingSeparation{ReserveDomain: "PROTECTION", ReceivableDomain: "RECEIVABLE", Separate: true, ClaimBurnedOrTransferred: false},
		ExecutionClass:              EvidenceExecutionClass, DeploymentClass: EvidenceDeploymentClass, ReleaseClass: EvidenceReleaseClass,
		RecourseClass: EvidenceRecourseClass, ProductionIsolationProven: false,
		ProductClaim: func() string {
			if chronology.ClockClass == ClockClassSimulatedProtocol {
				return SimulatedProductClaim
			}
			return RealObservedProductClaim
		}(),
		ReleaseAuthorityID: result.ReleaseAuthorityID,
	}
	attestation.Signature, err = signCanonical(ed25519.PrivateKey(keyBytes), "MordantRecourseAttestation/v2", attestation.signingValue())
	if err != nil || validateRecourseAttestation(attestation, authorization, manifest, artifact, artifactDigest, result, resultDigest, record) != nil {
		return MordantRecourseAttestation{}, ErrBinding
	}
	if _, _, err := publicStore.createJSON(productAttestationObject, attestation); err != nil {
		return MordantRecourseAttestation{}, err
	}
	return attestation, nil
}

func LoadProductRecourseAttestation(publicRoot string) (MordantRecourseAttestation, error) {
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	defer store.close()
	manifest, err := loadCaseManifest(store)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	authorization, err := loadProtectionAuthorization(store, manifest.Binding)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	artifact, _, artifactDigest, err := loadEvaluatedArtifact(store, manifest)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	authority, err := loadReleaseAuthority(store, manifest)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	var result GovernedConflictResult
	resultBytes, _, err := store.readJSON(publicResultObject, &result)
	if err != nil || verifyGovernedResult(result, manifest, artifact, authority) != nil {
		return MordantRecourseAttestation{}, ErrBinding
	}
	resultDigest := DigestBytes(resultBytes[:len(resultBytes)-1])
	record, err := loadValidatedRecourseRecord(store, manifest.Binding, result, resultDigest, authorization)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	return loadProductAttestation(store, authorization, manifest, artifact, artifactDigest, result, resultDigest, record)
}

// LoadCanonicalProductChronology returns the single canonical chronology
// committed by the retained attestation. It never reads caller-supplied event
// data and independently reconstructs every field from verified artifacts.
func LoadCanonicalProductChronology(publicRoot string) (ProductChronology, error) {
	attestation, err := LoadProductRecourseAttestation(publicRoot)
	if err != nil {
		return ProductChronology{}, err
	}
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return ProductChronology{}, err
	}
	defer store.close()
	manifest, err := loadCaseManifest(store)
	if err != nil {
		return ProductChronology{}, err
	}
	authorization, err := loadProtectionAuthorization(store, manifest.Binding)
	if err != nil {
		return ProductChronology{}, err
	}
	artifact, _, artifactDigest, err := loadEvaluatedArtifact(store, manifest)
	if err != nil {
		return ProductChronology{}, err
	}
	authority, err := loadReleaseAuthority(store, manifest)
	if err != nil {
		return ProductChronology{}, err
	}
	var result GovernedConflictResult
	resultBytes, _, err := store.readJSON(publicResultObject, &result)
	if err != nil || verifyGovernedResult(result, manifest, artifact, authority) != nil {
		return ProductChronology{}, ErrBinding
	}
	resultDigest := DigestBytes(resultBytes[:len(resultBytes)-1])
	record, err := loadValidatedRecourseRecord(store, manifest.Binding, result, resultDigest, authorization)
	if err != nil {
		return ProductChronology{}, err
	}
	chronology, err := canonicalProductChronology(
		authorization, manifest, artifact, artifactDigest, result, resultDigest, record,
		attestation.ClockClass, attestation.SignedAtUnix,
	)
	if err != nil {
		return ProductChronology{}, err
	}
	digest, err := chronology.Digest()
	if err != nil || digest != attestation.ChronologyDigest {
		return ProductChronology{}, ErrBinding
	}
	return chronology, nil
}

func sameProtectionAuthorization(left, right ProtectionAuthorization) bool {
	leftBytes, _ := json.Marshal(left)
	rightBytes, _ := json.Marshal(right)
	return slices.Equal(leftBytes, rightBytes)
}
