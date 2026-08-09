package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"
)

// This file is an explicitly experimental orchestration layer. It deliberately
// reuses the retained case, protection, ciphertext and result schemas rather
// than introducing a second governed-FHE protocol.
const (
	ParticipantOriginatedCeremonyRequestSchema    = "mordant.participant-originated-ceremony-request/1"
	ParticipantOriginatedCeremonySignaturesSchema = "mordant.participant-originated-ceremony-signatures/1"
	ParticipantOriginatedClientBundleSchema       = "mordant.participant-originated-client-bundle/1"
	participantOriginatedClientBundleObject       = "participant-originated-client-bundle.json"
	participantOriginatedCeremonyRequestAObject   = "participant-originated-ceremony-request-a.json"
	participantOriginatedCeremonyRequestBObject   = "participant-originated-ceremony-request-b.json"
	participantOriginatedCeremonyApprovalAObject  = "participant-originated-ceremony-approval-a.json"
	participantOriginatedCeremonyApprovalBObject  = "participant-originated-ceremony-approval-b.json"
)

var ErrParticipantOriginated = errors.New("participant-originated experiment rejected")

// ParticipantOriginatedFoundationOptions differs from
// ProductAuthorizedCreateOptions in one security-critical respect: it accepts
// only the public participant identities already present in CaseSpec. No
// participant artifact-signing private key crosses this boundary.
type ParticipantOriginatedFoundationOptions struct {
	CreateCaseOptions
	ProtectionBinding MordantProtectionBinding
}

func CreateParticipantOriginatedFoundation(options ParticipantOriginatedFoundationOptions) (FHECaseBinding, KeyGenerationReport, Digest, error) {
	var zero Digest
	if options.ProtectionBinding.Validate() != nil || options.Spec.CaseID != options.ProtectionBinding.FHECaseID ||
		options.Spec.AssetIdentity != options.ProtectionBinding.CleanverseAssetRecordDigest ||
		options.Spec.PolicyID != options.ProtectionBinding.PolicyID || options.Spec.CaseNonce != options.ProtectionBinding.CaseNonce {
		return FHECaseBinding{}, KeyGenerationReport{}, zero, ErrParticipantOriginated
	}
	binding, report, err := CreateCase(options.CreateCaseOptions)
	if err != nil {
		return FHECaseBinding{}, report, zero, err
	}
	protectionDigest, err := options.ProtectionBinding.Digest()
	if err != nil {
		return FHECaseBinding{}, report, zero, err
	}
	store, err := openObjectStore(options.PublicRoot, PublicCaseQuota, false)
	if err != nil {
		return FHECaseBinding{}, report, zero, err
	}
	defer store.close()
	if _, _, err := store.createJSON(protectionBindingObject, options.ProtectionBinding); err != nil {
		return FHECaseBinding{}, report, zero, err
	}
	return binding, report, protectionDigest, nil
}

// ParticipantOriginatedCeremonyRequest is the bounded object a participant
// reviews locally before producing the two retained signatures. The extra
// source/client pins are experimental evidence fields; the existing case and
// protection signatures themselves remain byte-for-byte unchanged.
type ParticipantOriginatedCeremonyRequest struct {
	SchemaVersion               string                   `json:"schemaVersion"`
	RunID                       string                   `json:"runId"`
	Role                        string                   `json:"role"`
	CaseBinding                 FHECaseBinding           `json:"caseBinding"`
	CaseBindingDigest           Digest                   `json:"caseBindingDigest"`
	ProtectionBinding           MordantProtectionBinding `json:"protectionBinding"`
	ProtectionBindingDigest     Digest                   `json:"protectionBindingDigest"`
	ExpectedSourceDigest        Digest                   `json:"expectedSourceDigest"`
	ExpectedBuildManifestDigest Digest                   `json:"expectedBuildManifestDigest"`
	ExpectedClientBinaryDigest  Digest                   `json:"expectedClientBinaryDigest"`
}

func (r ParticipantOriginatedCeremonyRequest) Digest() (Digest, error) {
	if r.validate() != nil {
		return Digest{}, ErrParticipantOriginated
	}
	digest, _, err := digestCanonical(r)
	return digest, err
}

func validParticipantOriginatedRunID(runID string) bool {
	if len(runID) == 0 || len(runID) > 128 {
		return false
	}
	for _, value := range []byte(runID) {
		if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
			(value >= '0' && value <= '9') || value == '-' || value == '_' || value == '.' {
			continue
		}
		return false
	}
	return true
}

func (r ParticipantOriginatedCeremonyRequest) validate() error {
	caseDigest, caseErr := r.CaseBinding.Digest()
	protectionDigest, protectionErr := r.ProtectionBinding.Digest()
	if r.SchemaVersion != ParticipantOriginatedCeremonyRequestSchema || !validParticipantOriginatedRunID(r.RunID) ||
		r.CaseBinding.validate() != nil || caseErr != nil || caseDigest != r.CaseBindingDigest ||
		protectionErr != nil || protectionDigest != r.ProtectionBindingDigest ||
		!bindingMatchesFHE(r.ProtectionBinding, r.CaseBinding) ||
		!nonzero(r.ExpectedSourceDigest, r.ExpectedBuildManifestDigest, r.ExpectedClientBinaryDigest) {
		return ErrParticipantOriginated
	}
	identity, err := expectedParticipant(r.CaseBinding, r.Role)
	if err != nil || identity.Role != r.Role {
		return ErrParticipantOriginated
	}
	return nil
}

func loadParticipantOriginatedProtectionBinding(store *objectStore, binding FHECaseBinding) (MordantProtectionBinding, Digest, error) {
	var protection MordantProtectionBinding
	if _, _, err := store.readJSON(protectionBindingObject, &protection); err != nil || protection.Validate() != nil ||
		!bindingMatchesFHE(protection, binding) {
		return protection, Digest{}, ErrParticipantOriginated
	}
	digest, err := protection.Digest()
	return protection, digest, err
}

func buildParticipantOriginatedCeremonyRequest(store *objectStore, runID, role string, sourceDigest, buildManifestDigest, clientBinaryDigest Digest) (ParticipantOriginatedCeremonyRequest, error) {
	binding, _, err := loadCaseFoundation(store)
	if err != nil {
		return ParticipantOriginatedCeremonyRequest{}, err
	}
	protection, protectionDigest, err := loadParticipantOriginatedProtectionBinding(store, binding)
	if err != nil {
		return ParticipantOriginatedCeremonyRequest{}, err
	}
	bindingDigest, err := binding.Digest()
	if err != nil {
		return ParticipantOriginatedCeremonyRequest{}, err
	}
	request := ParticipantOriginatedCeremonyRequest{
		SchemaVersion: ParticipantOriginatedCeremonyRequestSchema, RunID: runID, Role: role,
		CaseBinding: binding, CaseBindingDigest: bindingDigest, ProtectionBinding: protection,
		ProtectionBindingDigest: protectionDigest, ExpectedSourceDigest: sourceDigest,
		ExpectedBuildManifestDigest: buildManifestDigest, ExpectedClientBinaryDigest: clientBinaryDigest,
	}
	if request.validate() != nil {
		return ParticipantOriginatedCeremonyRequest{}, ErrParticipantOriginated
	}
	return request, nil
}

func BuildParticipantOriginatedCeremonyRequest(publicRoot, runID, role string, sourceDigest, buildManifestDigest, clientBinaryDigest Digest) (ParticipantOriginatedCeremonyRequest, error) {
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return ParticipantOriginatedCeremonyRequest{}, err
	}
	defer store.close()
	return buildParticipantOriginatedCeremonyRequest(store, runID, role, sourceDigest, buildManifestDigest, clientBinaryDigest)
}

type ParticipantOriginatedCeremonySignatures struct {
	SchemaVersion              string                      `json:"schemaVersion"`
	RequestDigest              Digest                      `json:"requestDigest"`
	Role                       string                      `json:"role"`
	ParticipantID              Digest                      `json:"participantId"`
	CaseBindingSignature       ParticipantBindingSignature `json:"caseBindingSignature"`
	ProtectionBindingSignature ProtectionBindingSignature  `json:"protectionBindingSignature"`
	Signature                  []byte                      `json:"signature"`
}

func (s ParticipantOriginatedCeremonySignatures) signingValue() ParticipantOriginatedCeremonySignatures {
	s.Signature = nil
	return s
}

func signParticipantCaseBinding(identity ParticipantIdentity, key ed25519.PrivateKey, digest Digest) (ParticipantBindingSignature, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), identity.SigningPublicKey) {
		return ParticipantBindingSignature{}, ErrParticipantOriginated
	}
	signature := ParticipantBindingSignature{Role: identity.Role, ParticipantID: identity.ID, BindingDigest: digest}
	value := struct {
		Role          string `json:"role"`
		ParticipantID Digest `json:"participantId"`
		BindingDigest Digest `json:"bindingDigest"`
	}{signature.Role, signature.ParticipantID, signature.BindingDigest}
	encoded, err := signCanonical(key, "MordantFHECaseBindingSignature/v1", value)
	if err != nil {
		return ParticipantBindingSignature{}, err
	}
	signature.Signature = encoded
	return signature, nil
}

func SignParticipantOriginatedCeremony(request ParticipantOriginatedCeremonyRequest, signingKey ed25519.PrivateKey, now time.Time) (ParticipantOriginatedCeremonySignatures, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if request.validate() != nil || now.Unix() < request.CaseBinding.CreatedAtUnix || now.Unix() >= request.CaseBinding.ExpiresAtUnix {
		return ParticipantOriginatedCeremonySignatures{}, ErrParticipantOriginated
	}
	identity, err := expectedParticipant(request.CaseBinding, request.Role)
	if err != nil || len(signingKey) != ed25519.PrivateKeySize || !bytes.Equal(signingKey.Public().(ed25519.PublicKey), identity.SigningPublicKey) {
		return ParticipantOriginatedCeremonySignatures{}, ErrParticipantOriginated
	}
	requestDigest, err := request.Digest()
	if err != nil {
		return ParticipantOriginatedCeremonySignatures{}, err
	}
	caseSignature, err := signParticipantCaseBinding(identity, signingKey, request.CaseBindingDigest)
	if err != nil {
		return ParticipantOriginatedCeremonySignatures{}, err
	}
	protectionSignature, err := signProtectionBinding(identity, signingKey, request.ProtectionBindingDigest)
	if err != nil {
		return ParticipantOriginatedCeremonySignatures{}, err
	}
	signed := ParticipantOriginatedCeremonySignatures{
		SchemaVersion: ParticipantOriginatedCeremonySignaturesSchema, RequestDigest: requestDigest,
		Role: identity.Role, ParticipantID: identity.ID, CaseBindingSignature: caseSignature,
		ProtectionBindingSignature: protectionSignature,
	}
	signed.Signature, err = signCanonical(signingKey, "MordantParticipantOriginatedCeremony/v1", signed.signingValue())
	if err != nil {
		return ParticipantOriginatedCeremonySignatures{}, err
	}
	return signed, nil
}

func participantOriginatedCeremonyObjectNames(role string) (requestName, approvalName string, err error) {
	switch role {
	case RoleA:
		return participantOriginatedCeremonyRequestAObject, participantOriginatedCeremonyApprovalAObject, nil
	case RoleB:
		return participantOriginatedCeremonyRequestBObject, participantOriginatedCeremonyApprovalBObject, nil
	default:
		return "", "", ErrParticipantOriginated
	}
}

func participantOriginatedCeremonyAllowedNames() map[string]bool {
	return map[string]bool{
		participantOriginatedCeremonyRequestAObject:  true,
		participantOriginatedCeremonyRequestBObject:  true,
		participantOriginatedCeremonyApprovalAObject: true,
		participantOriginatedCeremonyApprovalBObject: true,
	}
}

func verifyParticipantOriginatedCeremonyApproval(request ParticipantOriginatedCeremonyRequest, signed ParticipantOriginatedCeremonySignatures) error {
	if request.validate() != nil {
		return ErrParticipantOriginated
	}
	requestDigest, err := request.Digest()
	if err != nil || signed.SchemaVersion != ParticipantOriginatedCeremonySignaturesSchema ||
		signed.RequestDigest != requestDigest || signed.Role != request.Role {
		return ErrParticipantOriginated
	}
	identity, err := expectedParticipant(request.CaseBinding, request.Role)
	if err != nil || signed.ParticipantID != identity.ID ||
		verifyBindingSignature(request.CaseBinding, signed.CaseBindingSignature, identity) != nil ||
		verifyProtectionSignature(signed.ProtectionBindingSignature, identity, request.ProtectionBindingDigest) != nil ||
		verifyCanonical(ed25519.PublicKey(identity.SigningPublicKey), "MordantParticipantOriginatedCeremony/v1", signed.signingValue(), signed.Signature) != nil {
		return ErrParticipantOriginated
	}
	return nil
}

func participantOriginatedCeremonyRequestsMatch(a, b ParticipantOriginatedCeremonyRequest) bool {
	return a.Role == RoleA && b.Role == RoleB && a.RunID == b.RunID && a.CaseBindingDigest == b.CaseBindingDigest &&
		a.ProtectionBindingDigest == b.ProtectionBindingDigest && a.ExpectedSourceDigest == b.ExpectedSourceDigest &&
		a.ExpectedBuildManifestDigest == b.ExpectedBuildManifestDigest && a.ExpectedClientBinaryDigest == b.ExpectedClientBinaryDigest
}

func createCanonicalOrVerify(store *objectStore, name string, value any) (ObjectRef, error) {
	encoded, err := marshalCanonical(value)
	if err != nil {
		return ObjectRef{}, err
	}
	if store.exists(name) {
		existing, ref, err := store.readNamed(name, maxManifestBytes)
		if err != nil || !bytes.Equal(existing, encoded) {
			return ObjectRef{}, ErrParticipantOriginated
		}
		return ref, nil
	}
	return store.create(name, encoded)
}

// ImportParticipantOriginatedCeremony verifies the participant-local envelope,
// retains that exact outer approval in a separate coordinator-only ceremony
// root, then publishes only the two existing role-specific signature objects
// to the governed public root. Exact retries are byte-checked.
func ImportParticipantOriginatedCeremony(publicRoot, ceremonyRoot string, request ParticipantOriginatedCeremonyRequest, signed ParticipantOriginatedCeremonySignatures) error {
	if request.validate() != nil || !rootsDisjoint(publicRoot, ceremonyRoot) {
		return ErrParticipantOriginated
	}
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return err
	}
	defer store.close()
	current, err := buildParticipantOriginatedCeremonyRequest(store, request.RunID, request.Role, request.ExpectedSourceDigest,
		request.ExpectedBuildManifestDigest, request.ExpectedClientBinaryDigest)
	if err != nil {
		return err
	}
	currentDigest, _ := current.Digest()
	requestDigest, _ := request.Digest()
	if currentDigest != requestDigest || verifyParticipantOriginatedCeremonyApproval(request, signed) != nil {
		return ErrParticipantOriginated
	}
	identity, err := expectedParticipant(current.CaseBinding, current.Role)
	if err != nil || signed.ParticipantID != identity.ID {
		return ErrParticipantOriginated
	}
	ceremony, err := openObjectStore(ceremonyRoot, PrivateCaseQuota, true)
	if err != nil {
		return err
	}
	defer ceremony.close()
	if ceremony.rejectUnknown(participantOriginatedCeremonyAllowedNames()) != nil {
		return ErrParticipantOriginated
	}
	otherRole := RoleA
	if request.Role == RoleA {
		otherRole = RoleB
	}
	otherRequestName, _, _ := participantOriginatedCeremonyObjectNames(otherRole)
	if ceremony.exists(otherRequestName) {
		var other ParticipantOriginatedCeremonyRequest
		if _, _, err := ceremony.readJSON(otherRequestName, &other); err != nil {
			return err
		}
		requestA, requestB := request, other
		if request.Role == RoleB {
			requestA, requestB = other, request
		}
		if !participantOriginatedCeremonyRequestsMatch(requestA, requestB) {
			return ErrParticipantOriginated
		}
	}
	requestName, approvalName, _ := participantOriginatedCeremonyObjectNames(request.Role)
	if _, err := createCanonicalOrVerify(ceremony, requestName, request); err != nil {
		return err
	}
	if _, err := createCanonicalOrVerify(ceremony, approvalName, signed); err != nil {
		return err
	}
	bindingName, _, _, err := participantFiles(current.Role)
	if err != nil {
		return err
	}
	protectionName := protectionSignatureAObject
	if current.Role == RoleB {
		protectionName = protectionSignatureBObject
	}
	if _, err := createCanonicalOrVerify(store, bindingName, signed.CaseBindingSignature); err != nil {
		return err
	}
	if _, err := createCanonicalOrVerify(store, protectionName, signed.ProtectionBindingSignature); err != nil {
		return err
	}
	return nil
}

type participantOriginatedRetainedCeremony struct {
	RequestA  ParticipantOriginatedCeremonyRequest
	ApprovalA ParticipantOriginatedCeremonySignatures
	RequestB  ParticipantOriginatedCeremonyRequest
	ApprovalB ParticipantOriginatedCeremonySignatures
}

func loadParticipantOriginatedRetainedCeremony(ceremony, public *objectStore) (participantOriginatedRetainedCeremony, error) {
	var retained participantOriginatedRetainedCeremony
	if ceremony.rejectUnknown(participantOriginatedCeremonyAllowedNames()) != nil {
		return retained, ErrParticipantOriginated
	}
	for _, entry := range []struct {
		name  string
		value any
	}{
		{participantOriginatedCeremonyRequestAObject, &retained.RequestA},
		{participantOriginatedCeremonyApprovalAObject, &retained.ApprovalA},
		{participantOriginatedCeremonyRequestBObject, &retained.RequestB},
		{participantOriginatedCeremonyApprovalBObject, &retained.ApprovalB},
	} {
		if _, _, err := ceremony.readJSON(entry.name, entry.value); err != nil {
			return retained, err
		}
	}
	if !participantOriginatedCeremonyRequestsMatch(retained.RequestA, retained.RequestB) ||
		verifyParticipantOriginatedCeremonyApproval(retained.RequestA, retained.ApprovalA) != nil ||
		verifyParticipantOriginatedCeremonyApproval(retained.RequestB, retained.ApprovalB) != nil {
		return retained, ErrParticipantOriginated
	}
	for _, request := range []ParticipantOriginatedCeremonyRequest{retained.RequestA, retained.RequestB} {
		current, err := buildParticipantOriginatedCeremonyRequest(public, request.RunID, request.Role,
			request.ExpectedSourceDigest, request.ExpectedBuildManifestDigest, request.ExpectedClientBinaryDigest)
		if err != nil {
			return retained, err
		}
		currentDigest, _ := current.Digest()
		retainedDigest, _ := request.Digest()
		if currentDigest != retainedDigest {
			return retained, ErrParticipantOriginated
		}
	}
	return retained, nil
}

type participantOriginatedBundleObjectSpec struct {
	name    string
	maximum int64
}

var participantOriginatedBundleObjectSpecs = []participantOriginatedBundleObjectSpec{
	{parametersObject, 1 << 20},
	{publicKeyObject, 64 << 20},
	{caseCryptoObject, maxManifestBytes},
	{caseBindingObject, maxManifestBytes},
	{bindingSignatureAObject, maxManifestBytes},
	{bindingSignatureBObject, maxManifestBytes},
	{caseManifestObject, maxManifestBytes},
	{protectionBindingObject, maxManifestBytes},
	{protectionSignatureAObject, maxManifestBytes},
	{protectionSignatureBObject, maxManifestBytes},
	{releaseAuthorityObject, maxManifestBytes},
}

// ParticipantOriginatedClientBundle is a thin, role-specific client package.
// It intentionally omits the ~315 MB evaluation-key bytes: their exact manifest
// digest remains participant-signed, while encryption needs only parameters and
// the public key copied alongside this manifest.
type ParticipantOriginatedClientBundle struct {
	SchemaVersion               string                                  `json:"schemaVersion"`
	RunID                       string                                  `json:"runId"`
	Role                        string                                  `json:"role"`
	CaseID                      Digest                                  `json:"caseId"`
	AssetIdentity               Digest                                  `json:"assetIdentity"`
	PolicyID                    Digest                                  `json:"policyId"`
	PolicyVersion               uint32                                  `json:"policyVersion"`
	CircuitID                   string                                  `json:"circuitId"`
	CircuitVersion              uint32                                  `json:"circuitVersion"`
	CircuitDigest               Digest                                  `json:"circuitDigest"`
	ParameterProfile            string                                  `json:"parameterProfile"`
	ParameterFingerprint        Digest                                  `json:"parameterFingerprint"`
	FHEPublicKeyDigest          Digest                                  `json:"fhePublicKeyDigest"`
	ParticipantA                ParticipantIdentity                     `json:"participantA"`
	ParticipantB                ParticipantIdentity                     `json:"participantB"`
	CaseBindingDigest           Digest                                  `json:"caseBindingDigest"`
	CaseManifestDigest          Digest                                  `json:"caseManifestDigest"`
	ProtectionBindingDigest     Digest                                  `json:"protectionBindingDigest"`
	ReleaseMode                 string                                  `json:"releaseMode"`
	ReleaseAuthorityID          Digest                                  `json:"releaseAuthorityId"`
	ReleaseAuthorityPublicKey   []byte                                  `json:"releaseAuthorityPublicKey"`
	KeygenProvenance            Digest                                  `json:"keygenProvenance"`
	CreatedAtUnix               int64                                   `json:"createdAtUnix"`
	ExpiresAtUnix               int64                                   `json:"expiresAtUnix"`
	ExpectedSourceDigest        Digest                                  `json:"expectedSourceDigest"`
	ExpectedBuildManifestDigest Digest                                  `json:"expectedBuildManifestDigest"`
	ExpectedClientBinaryDigest  Digest                                  `json:"expectedClientBinaryDigest"`
	CeremonyRequestA            ParticipantOriginatedCeremonyRequest    `json:"ceremonyRequestA"`
	CeremonyApprovalA           ParticipantOriginatedCeremonySignatures `json:"ceremonyApprovalA"`
	CeremonyRequestB            ParticipantOriginatedCeremonyRequest    `json:"ceremonyRequestB"`
	CeremonyApprovalB           ParticipantOriginatedCeremonySignatures `json:"ceremonyApprovalB"`
	Objects                     []ObjectRef                             `json:"objects"`
}

func (b ParticipantOriginatedClientBundle) Digest() (Digest, error) {
	if b.SchemaVersion != ParticipantOriginatedClientBundleSchema {
		return Digest{}, ErrParticipantOriginated
	}
	digest, _, err := digestCanonical(b)
	return digest, err
}

type ParticipantOriginatedBundleExpectations struct {
	RunID                       string
	Role                        string
	CaseID                      Digest
	AssetIdentity               Digest
	ExpectedSourceDigest        Digest
	ExpectedBuildManifestDigest Digest
	ExpectedClientBinaryDigest  Digest
	Now                         time.Time
}

func participantIdentityEqual(left, right ParticipantIdentity) bool {
	return left.ID == right.ID && left.Role == right.Role && bytes.Equal(left.SigningPublicKey, right.SigningPublicKey)
}

func verifyParticipantOriginatedBundleCeremony(bundle ParticipantOriginatedClientBundle, bindingDigest, protectionDigest Digest) error {
	requestA, requestB := bundle.CeremonyRequestA, bundle.CeremonyRequestB
	if !participantOriginatedCeremonyRequestsMatch(requestA, requestB) ||
		verifyParticipantOriginatedCeremonyApproval(requestA, bundle.CeremonyApprovalA) != nil ||
		verifyParticipantOriginatedCeremonyApproval(requestB, bundle.CeremonyApprovalB) != nil ||
		requestA.RunID != bundle.RunID || requestA.CaseBindingDigest != bindingDigest ||
		requestA.ProtectionBindingDigest != protectionDigest || requestA.ExpectedSourceDigest != bundle.ExpectedSourceDigest ||
		requestA.ExpectedBuildManifestDigest != bundle.ExpectedBuildManifestDigest ||
		requestA.ExpectedClientBinaryDigest != bundle.ExpectedClientBinaryDigest {
		return ErrParticipantOriginated
	}
	return nil
}

func bundleAllowedNames() map[string]bool {
	allowed := map[string]bool{participantOriginatedClientBundleObject: true}
	for _, spec := range participantOriginatedBundleObjectSpecs {
		allowed[spec.name] = true
	}
	return allowed
}

func ExportParticipantOriginatedClientBundle(publicRoot, ceremonyRoot, bundleRoot, role string) (ParticipantOriginatedClientBundle, Digest, error) {
	if !rootsDisjoint(publicRoot, ceremonyRoot) || !rootsDisjoint(publicRoot, bundleRoot) ||
		!rootsDisjoint(ceremonyRoot, bundleRoot) {
		return ParticipantOriginatedClientBundle{}, Digest{}, ErrParticipantOriginated
	}
	source, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	defer source.close()
	ceremony, err := openObjectStore(ceremonyRoot, PrivateCaseQuota, true)
	if err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	defer ceremony.close()
	retained, err := loadParticipantOriginatedRetainedCeremony(ceremony, source)
	if err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	runID := retained.RequestA.RunID
	sourceDigest := retained.RequestA.ExpectedSourceDigest
	buildManifestDigest := retained.RequestA.ExpectedBuildManifestDigest
	clientBinaryDigest := retained.RequestA.ExpectedClientBinaryDigest
	manifest, err := loadCaseManifest(source)
	if err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	if _, err := expectedParticipant(manifest.Binding, role); err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	authorization, err := loadProtectionAuthorization(source, manifest.Binding)
	if err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	authority, err := loadReleaseAuthority(source, manifest)
	if err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	destination, err := openObjectStore(bundleRoot, PublicCaseQuota, false)
	if err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	defer destination.close()
	if names, _ := destination.names(); len(names) != 0 {
		return ParticipantOriginatedClientBundle{}, Digest{}, ErrStore
	}
	objects := make([]ObjectRef, 0, len(participantOriginatedBundleObjectSpecs))
	for _, spec := range participantOriginatedBundleObjectSpecs {
		data, sourceRef, err := source.readNamed(spec.name, spec.maximum)
		if err != nil {
			return ParticipantOriginatedClientBundle{}, Digest{}, err
		}
		created, err := destination.create(spec.name, data)
		if err != nil || created != sourceRef {
			return ParticipantOriginatedClientBundle{}, Digest{}, ErrArtifact
		}
		objects = append(objects, created)
	}
	bindingDigest, _ := manifest.Binding.Digest()
	manifestDigest, _ := manifest.Digest()
	bundle := ParticipantOriginatedClientBundle{
		SchemaVersion: ParticipantOriginatedClientBundleSchema, RunID: runID, Role: role,
		CaseID: manifest.Binding.CaseID, AssetIdentity: manifest.Binding.AssetIdentity,
		PolicyID: manifest.Binding.PolicyID, PolicyVersion: manifest.Binding.PolicyVersion,
		CircuitID: manifest.Binding.CircuitID, CircuitVersion: manifest.Binding.CircuitVersion,
		CircuitDigest: manifest.Binding.CircuitDigest, ParameterProfile: manifest.Binding.ParameterProfile,
		ParameterFingerprint: manifest.Binding.ParameterFingerprint, FHEPublicKeyDigest: manifest.Binding.PublicKeyDigest,
		ParticipantA: manifest.Binding.ParticipantA, ParticipantB: manifest.Binding.ParticipantB,
		CaseBindingDigest: bindingDigest, CaseManifestDigest: manifestDigest,
		ProtectionBindingDigest: authorization.Digest, ReleaseMode: manifest.Binding.ReleaseMode,
		ReleaseAuthorityID:        manifest.Binding.ReleaseAuthorityID,
		ReleaseAuthorityPublicKey: append([]byte(nil), manifest.Binding.ReleaseAuthorityPublicKey...),
		KeygenProvenance:          authority.SourceProvenance, CreatedAtUnix: manifest.Binding.CreatedAtUnix,
		ExpiresAtUnix: manifest.Binding.ExpiresAtUnix, ExpectedSourceDigest: sourceDigest,
		ExpectedBuildManifestDigest: buildManifestDigest, ExpectedClientBinaryDigest: clientBinaryDigest,
		CeremonyRequestA: retained.RequestA, CeremonyApprovalA: retained.ApprovalA,
		CeremonyRequestB: retained.RequestB, CeremonyApprovalB: retained.ApprovalB, Objects: objects,
	}
	if _, _, err := destination.createJSON(participantOriginatedClientBundleObject, bundle); err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	digest, err := bundle.Digest()
	return bundle, digest, err
}

type verifiedParticipantOriginatedBundle struct {
	bundle        ParticipantOriginatedClientBundle
	manifest      FHECaseManifest
	authorization ProtectionAuthorization
	authority     ReleaseAuthorityManifest
}

func verifyParticipantOriginatedClientBundleStore(store *objectStore, expected ParticipantOriginatedBundleExpectations) (verifiedParticipantOriginatedBundle, error) {
	var verified verifiedParticipantOriginatedBundle
	if expected.Now.IsZero() {
		expected.Now = time.Now().UTC()
	}
	if !validParticipantOriginatedRunID(expected.RunID) || !nonzero(expected.CaseID, expected.AssetIdentity,
		expected.ExpectedSourceDigest, expected.ExpectedBuildManifestDigest, expected.ExpectedClientBinaryDigest) ||
		store.rejectUnknown(bundleAllowedNames()) != nil {
		return verified, ErrParticipantOriginated
	}
	if _, _, err := store.readJSON(participantOriginatedClientBundleObject, &verified.bundle); err != nil {
		return verified, err
	}
	verified.manifest, _ = loadCaseManifest(store)
	if verified.manifest.SchemaVersion != CaseManifestSchema {
		return verified, ErrParticipantOriginated
	}
	var err error
	verified.authorization, err = loadProtectionAuthorization(store, verified.manifest.Binding)
	if err != nil {
		return verified, err
	}
	verified.authority, err = loadReleaseAuthority(store, verified.manifest)
	if err != nil {
		return verified, err
	}
	if _, _, err := loadPublicEncryptionMaterial(store, verified.manifest.Crypto); err != nil {
		return verified, err
	}
	binding := verified.manifest.Binding
	bindingDigest, _ := binding.Digest()
	manifestDigest, _ := verified.manifest.Digest()
	bundle := verified.bundle
	if bundle.SchemaVersion != ParticipantOriginatedClientBundleSchema || bundle.RunID != expected.RunID ||
		bundle.Role != expected.Role || bundle.CaseID != expected.CaseID || bundle.AssetIdentity != expected.AssetIdentity ||
		bundle.ExpectedSourceDigest != expected.ExpectedSourceDigest ||
		bundle.ExpectedBuildManifestDigest != expected.ExpectedBuildManifestDigest ||
		bundle.ExpectedClientBinaryDigest != expected.ExpectedClientBinaryDigest ||
		bundle.CaseID != binding.CaseID || bundle.AssetIdentity != binding.AssetIdentity || bundle.PolicyID != binding.PolicyID ||
		bundle.PolicyVersion != binding.PolicyVersion || bundle.CircuitID != binding.CircuitID || bundle.CircuitVersion != binding.CircuitVersion ||
		bundle.CircuitDigest != binding.CircuitDigest || bundle.ParameterProfile != binding.ParameterProfile ||
		bundle.ParameterFingerprint != binding.ParameterFingerprint || bundle.FHEPublicKeyDigest != binding.PublicKeyDigest ||
		!participantIdentityEqual(bundle.ParticipantA, binding.ParticipantA) || !participantIdentityEqual(bundle.ParticipantB, binding.ParticipantB) ||
		bundle.CaseBindingDigest != bindingDigest || bundle.CaseManifestDigest != manifestDigest ||
		bundle.ProtectionBindingDigest != verified.authorization.Digest || bundle.ReleaseMode != binding.ReleaseMode ||
		bundle.ReleaseAuthorityID != binding.ReleaseAuthorityID ||
		!bytes.Equal(bundle.ReleaseAuthorityPublicKey, binding.ReleaseAuthorityPublicKey) ||
		bundle.KeygenProvenance != verified.authority.SourceProvenance || bundle.CreatedAtUnix != binding.CreatedAtUnix ||
		bundle.ExpiresAtUnix != binding.ExpiresAtUnix || expected.Now.Unix() < binding.CreatedAtUnix || expected.Now.Unix() >= binding.ExpiresAtUnix ||
		!nonzero(bundle.ExpectedSourceDigest, bundle.ExpectedBuildManifestDigest, bundle.ExpectedClientBinaryDigest) {
		return verified, ErrParticipantOriginated
	}
	if verifyParticipantOriginatedBundleCeremony(bundle, bindingDigest, verified.authorization.Digest) != nil {
		return verified, ErrParticipantOriginated
	}
	if _, err := expectedParticipant(binding, bundle.Role); err != nil || len(bundle.Objects) != len(participantOriginatedBundleObjectSpecs) {
		return verified, ErrParticipantOriginated
	}
	actualObjects := make([]ObjectRef, len(participantOriginatedBundleObjectSpecs))
	for index, spec := range participantOriginatedBundleObjectSpecs {
		_, ref, err := store.readNamed(spec.name, spec.maximum)
		if err != nil || bundle.Objects[index] != ref {
			return verified, ErrParticipantOriginated
		}
		actualObjects[index] = ref
	}
	if !slices.Equal(bundle.Objects, actualObjects) {
		return verified, ErrParticipantOriginated
	}
	return verified, nil
}

func VerifyParticipantOriginatedClientBundle(bundleRoot string, expected ParticipantOriginatedBundleExpectations) (ParticipantOriginatedClientBundle, Digest, error) {
	store, err := openObjectStore(bundleRoot, PublicCaseQuota, false)
	if err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	defer store.close()
	verified, err := verifyParticipantOriginatedClientBundleStore(store, expected)
	if err != nil {
		return ParticipantOriginatedClientBundle{}, Digest{}, err
	}
	digest, err := verified.bundle.Digest()
	return verified.bundle, digest, err
}

// FinalizeParticipantOriginatedCase deliberately delegates both decisions to
// the retained verifiers. It adds no alternate signature or manifest semantics.
func FinalizeParticipantOriginatedCase(publicRoot string) (FHECaseManifest, error) {
	if _, err := VerifyProtectionAuthorization(publicRoot); err != nil {
		return FHECaseManifest{}, err
	}
	return FinalizeCase(publicRoot)
}

func participantOriginatedBundleManifestName() string { return participantOriginatedClientBundleObject }

func participantOriginatedBundleObjectNames() []string {
	names := make([]string, 0, len(participantOriginatedBundleObjectSpecs)+1)
	for _, spec := range participantOriginatedBundleObjectSpecs {
		names = append(names, spec.name)
	}
	return append(names, participantOriginatedClientBundleObject)
}

func participantOriginatedBundleContainsEvaluationKeyBytes(names []string) bool {
	for _, name := range names {
		if name == relinearizationKeyObject {
			return true
		}
		for index := range rotationSteps {
			if name == galoisObject(index) {
				return true
			}
		}
	}
	return false
}

func assertParticipantOriginatedBundleThin(names []string) error {
	if participantOriginatedBundleContainsEvaluationKeyBytes(names) {
		return fmt.Errorf("%w: evaluation key bytes in client bundle", ErrParticipantOriginated)
	}
	return nil
}
