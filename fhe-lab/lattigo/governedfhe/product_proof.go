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
	ProtectionBindingSchema     = "mordant.protection-binding/1"
	ProtectionAttestationSchema = "mordant.recourse-attestation/1"
	ProtectionService           = "Conflicting Pledge Protection"
	ProtectionServiceVersion    = uint32(1)
	ProtectionPolicyVersion     = uint32(1)
	ProtectionFixtureClass      = "SYNTHETIC_HACKATHON_FIXTURE"
	ProductClaimIdentifier      = "mordant.conflicting-pledge-protection/governed-fhe-mvp-v1"
	ProductClaim                = ProductClaimIdentifier
	RecourseRefusalNone         = "NONE"
	RecourseRefusalSignedFalse  = "SIGNED_RESULT_FALSE"
	RecourseStateAvailable      = "AVAILABLE"
	RecourseStateRefused        = "REFUSED"
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
	SchemaVersion               string                    `json:"schemaVersion"`
	CleanverseAssetRecordDigest Digest                    `json:"cleanverseAssetRecordDigest"`
	ProtectionService           string                    `json:"protectionService"`
	ProtectionServiceVersion    uint32                    `json:"protectionServiceVersion"`
	PolicyID                    Digest                    `json:"policyId"`
	PolicyVersion               uint32                    `json:"policyVersion"`
	ProductScenario             string                    `json:"productScenario"`
	FixtureClassification       string                    `json:"fixtureClassification"`
	ProtectedAmount             ProductAmount             `json:"protectedAmount"`
	ReserveBasisPoints          uint32                    `json:"reserveBasisPoints"`
	ReserveAmount               ProductAmount             `json:"reserveAmount"`
	HolderRecordDate            string                    `json:"holderRecordDate"`
	HolderSnapshot              []ProductHolderAllocation `json:"holderSnapshot"`
	HolderAllocationDigest      Digest                    `json:"holderAllocationDigest"`
	CaseNonce                   Digest                    `json:"caseNonce"`
	FHECaseID                   Digest                    `json:"fheCaseId"`
	GovernedReleaseMode         string                    `json:"governedReleaseMode"`
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
	if policyErr != nil || allocationErr != nil || caseErr != nil ||
		binding.SchemaVersion != ProtectionBindingSchema || binding.ProtectionService != ProtectionService ||
		binding.ProtectionServiceVersion != ProtectionServiceVersion || binding.PolicyID != policy ||
		binding.PolicyVersion != ProtectionPolicyVersion ||
		(binding.ProductScenario != "conflict" && binding.ProductScenario != "no-conflict") ||
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
	Ordinal        uint32 `json:"ordinal"`
	Kind           string `json:"kind"`
	At             string `json:"at"`
	Label          string `json:"label"`
	Classification string `json:"classification"`
	EvidenceRef    Digest `json:"evidenceRef"`
}

type ProductChronology struct {
	RecordDate             string                   `json:"recordDate"`
	HolderAllocationDigest Digest                   `json:"holderAllocationDigest"`
	CureDeadline           *string                  `json:"cureDeadline"`
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

func validateChronology(chronology ProductChronology, binding MordantProtectionBinding, result GovernedConflictResult, record *RecourseRecord) (Digest, *string, string, error) {
	if chronology.RecordDate != binding.HolderRecordDate || chronology.HolderAllocationDigest != binding.HolderAllocationDigest {
		return Digest{}, nil, "", ErrBinding
	}
	if len(result.ParticipantArtifactDigests) != 2 {
		return Digest{}, nil, "", ErrBinding
	}
	resultDigest, err := result.Digest()
	if err != nil {
		return Digest{}, nil, "", err
	}
	type expectedEvent struct {
		kind, label, classification string
		evidenceRef                 Digest
	}
	expected := []expectedEvent{
		{"PROTECTION_ACTIVATED", "Mordant protection activated for the canonical Cleanverse asset", "LOCAL_EXECUTION", binding.CleanverseAssetRecordDigest},
		{"HOLDER_SNAPSHOT_RECORDED", "Record-date holder allocation fixed at 60 / 40 and reserve held separately", "PROTOCOL_DOUBLE", binding.HolderAllocationDigest},
		{"PARTICIPANT_A_ENCRYPTED_PLEDGE_RECEIVED", "Participant A encrypted pledge received", "LOCAL_EXECUTION", result.ParticipantArtifactDigests[0]},
		{"PARTICIPANT_B_ENCRYPTED_PLEDGE_RECEIVED", "Participant B encrypted pledge received", "LOCAL_EXECUTION", result.ParticipantArtifactDigests[1]},
		{"FHE_EVALUATION_COMPLETE", "Fixed N15 BGV conflict circuit evaluated without an evaluator decryption key", "LOCAL_EXECUTION", result.EvaluatedArtifactDigest},
		{"GOVERNED_RECOMPUTATION_VERIFIED", "Governed decryptor independently recomputed the fixed circuit", "LOCAL_EXECUTION", result.ResultCiphertextDigest},
	}
	if result.Conflict {
		expected = append(expected,
			expectedEvent{"SIGNED_CONFLICT_CONFIRMED", "Signed Boolean confirmed a conflicting pledge", "LOCAL_EXECUTION", resultDigest},
			expectedEvent{"CURE_WINDOW_OPENED", "Record-date holders remain fixed while the cure / dispute window runs", "PROTOCOL_DOUBLE", binding.HolderAllocationDigest},
			expectedEvent{"RECOURSE_AVAILABLE_AFTER_CURE", "Local chronology reached the cure deadline; governed recourse is available", "PROTOCOL_DOUBLE", resultDigest},
		)
	} else {
		expected = append(expected,
			expectedEvent{"SIGNED_CONFLICT_CLEARED", "Signed Boolean cleared the conflicting-pledge check", "LOCAL_EXECUTION", resultDigest},
			expectedEvent{"RECOURSE_REFUSED", "A signed false result cannot open conflicting-pledge recourse", "PROTOCOL_DOUBLE", resultDigest},
		)
	}
	if len(chronology.Events) != len(expected) {
		return Digest{}, nil, "", ErrBinding
	}
	var prior time.Time
	for index, event := range chronology.Events {
		parsed, err := time.Parse(time.RFC3339Nano, event.At)
		want := expected[index]
		if err != nil || event.Ordinal != uint32(index+1) || event.Kind != want.kind || event.Label != want.label ||
			event.Classification != want.classification || event.EvidenceRef != want.evidenceRef ||
			!nonzero(event.EvidenceRef) || (!prior.IsZero() && parsed.Before(prior)) {
			return Digest{}, nil, "", ErrBinding
		}
		prior = parsed
	}
	var deadline *string
	state := RecourseStateRefused
	if result.Conflict {
		if record == nil || chronology.CureDeadline == nil {
			return Digest{}, nil, "", ErrBinding
		}
		parsed, err := time.Parse(time.RFC3339Nano, *chronology.CureDeadline)
		if err != nil || parsed.Unix() != record.CureDeadlineUnix || prior.Unix() <= record.CureDeadlineUnix {
			return Digest{}, nil, "", ErrBinding
		}
		deadline, state = chronology.CureDeadline, RecourseStateAvailable
	} else if chronology.CureDeadline != nil || record != nil {
		return Digest{}, nil, "", ErrBinding
	}
	digest, err := chronology.Digest()
	return digest, deadline, state, err
}

func sameOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func validateRecourseAttestation(attestation MordantRecourseAttestation, authorization ProtectionAuthorization, result GovernedConflictResult, resultDigest Digest, record *RecourseRecord) error {
	zero := Digest{}
	expectedRecordDigest, expectedRefusal := zero, RecourseRefusalSignedFalse
	if record != nil {
		encoded, _ := json.Marshal(record)
		expectedRecordDigest, expectedRefusal = DigestBytes(encoded), RecourseRefusalNone
	}
	if attestation.SchemaVersion != ProtectionAttestationSchema || attestation.ProtectionBindingDigest != authorization.Digest ||
		attestation.GovernedResultDigest != resultDigest || attestation.CaseID != authorization.Binding.FHECaseID ||
		attestation.CleanverseAssetRecordDigest != authorization.Binding.CleanverseAssetRecordDigest ||
		attestation.SignedBoolean != result.Conflict || attestation.RecourseRecordDigest != expectedRecordDigest ||
		attestation.RecourseRefusal != expectedRefusal || attestation.HolderAllocationDigest != authorization.Binding.HolderAllocationDigest ||
		attestation.RecordDate != authorization.Binding.HolderRecordDate || !nonzero(attestation.ChronologyDigest) ||
		attestation.OriginalReceivableState != "OUTSTANDING_INTACT" ||
		attestation.ReserveAccountingSeparation != (ReserveAccountingSeparation{ReserveDomain: "PROTECTION", ReceivableDomain: "RECEIVABLE", Separate: true, ClaimBurnedOrTransferred: false}) ||
		attestation.ExecutionClass != EvidenceExecutionClass || attestation.DeploymentClass != EvidenceDeploymentClass ||
		attestation.ReleaseClass != EvidenceReleaseClass || attestation.RecourseClass != EvidenceRecourseClass ||
		attestation.ProductionIsolationProven || attestation.ProductClaim != ProductClaimIdentifier ||
		attestation.ReleaseAuthorityID != result.ReleaseAuthorityID ||
		verifyCanonical(ed25519.PublicKey(result.ReleaseAuthorityPublicKey), "MordantRecourseAttestation/v1", attestation.signingValue(), attestation.Signature) != nil {
		return ErrBinding
	}
	if result.Conflict {
		if record == nil || attestation.FinalRecourseState != RecourseStateAvailable || attestation.CureDeadline == nil ||
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

func loadProductAttestation(store *objectStore, authorization ProtectionAuthorization, result GovernedConflictResult, resultDigest Digest, record *RecourseRecord) (MordantRecourseAttestation, error) {
	var attestation MordantRecourseAttestation
	if _, _, err := store.readJSON(productAttestationObject, &attestation); err != nil ||
		validateRecourseAttestation(attestation, authorization, result, resultDigest, record) != nil {
		return MordantRecourseAttestation{}, ErrBinding
	}
	return attestation, nil
}

func CreateRecourseAttestation(publicRoot, privateRoot string, chronology ProductChronology) (MordantRecourseAttestation, error) {
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
	artifact, _, _, err := loadEvaluatedArtifact(publicStore, manifest)
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
	var record *RecourseRecord
	if publicStore.exists(recourseRecordObject) {
		var candidate RecourseRecord
		if _, _, err := publicStore.readJSON(recourseRecordObject, &candidate); err != nil ||
			validateCompleteRecourseRecord(candidate, manifest.Binding, result, resultDigest, authorization.Binding.HolderRecordDate, authorization.Binding.HolderAllocationDigest) != nil {
			return MordantRecourseAttestation{}, ErrRecourse
		}
		record = &candidate
	}
	chronologyDigest, deadline, state, err := validateChronology(chronology, authorization.Binding, result, record)
	if err != nil {
		return MordantRecourseAttestation{}, err
	}
	if publicStore.exists(productAttestationObject) {
		retained, err := loadProductAttestation(publicStore, authorization, result, resultDigest, record)
		if err != nil || retained.ChronologyDigest != chronologyDigest ||
			retained.FinalRecourseState != state || !sameOptionalString(retained.CureDeadline, deadline) {
			return MordantRecourseAttestation{}, ErrBinding
		}
		return retained, nil
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
		CureDeadline: deadline, FinalRecourseState: state, ChronologyDigest: chronologyDigest,
		OriginalReceivableState:     "OUTSTANDING_INTACT",
		ReserveAccountingSeparation: ReserveAccountingSeparation{ReserveDomain: "PROTECTION", ReceivableDomain: "RECEIVABLE", Separate: true, ClaimBurnedOrTransferred: false},
		ExecutionClass:              EvidenceExecutionClass, DeploymentClass: EvidenceDeploymentClass, ReleaseClass: EvidenceReleaseClass,
		RecourseClass: EvidenceRecourseClass, ProductionIsolationProven: false, ProductClaim: ProductClaimIdentifier,
		ReleaseAuthorityID: result.ReleaseAuthorityID,
	}
	attestation.Signature, err = signCanonical(ed25519.PrivateKey(keyBytes), "MordantRecourseAttestation/v1", attestation.signingValue())
	if err != nil || validateRecourseAttestation(attestation, authorization, result, resultDigest, record) != nil {
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
	artifact, _, _, err := loadEvaluatedArtifact(store, manifest)
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
	var record *RecourseRecord
	if store.exists(recourseRecordObject) {
		var candidate RecourseRecord
		if _, _, err := store.readJSON(recourseRecordObject, &candidate); err != nil ||
			validateCompleteRecourseRecord(candidate, manifest.Binding, result, resultDigest, authorization.Binding.HolderRecordDate, authorization.Binding.HolderAllocationDigest) != nil {
			return MordantRecourseAttestation{}, ErrRecourse
		}
		record = &candidate
	}
	return loadProductAttestation(store, authorization, result, resultDigest, record)
}

func sameProtectionAuthorization(left, right ProtectionAuthorization) bool {
	leftBytes, _ := json.Marshal(left)
	rightBytes, _ := json.Marshal(right)
	return slices.Equal(leftBytes, rightBytes)
}
