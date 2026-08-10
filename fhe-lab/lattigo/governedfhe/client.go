package governedfhe

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	fhe "mordant.dev/fhe-lab/lattigo"
)

type ParticipantSubmissionOptions struct {
	PublicRoot      string
	Role            string
	SigningKey      ed25519.PrivateKey
	Pledge          fhe.PlainPledge
	SubmissionNonce Digest
	ExpiresAtUnix   int64
	Now             time.Time
}

type SubmissionReport struct {
	Duration        time.Duration `json:"duration"`
	CiphertextBytes int64         `json:"ciphertextBytes"`
	ArtifactBytes   int64         `json:"artifactBytes"`
	EnrollmentBytes int64         `json:"enrollmentBytes"`
}

func loadPublicEncryptionMaterial(store *objectStore, cryptoManifest CaseCryptoManifest) (bgv.Parameters, *rlwe.PublicKey, error) {
	var params bgv.Parameters
	parameterBytes, err := store.read(cryptoManifest.Parameters, 1<<20)
	if err != nil || params.UnmarshalBinary(parameterBytes) != nil || ValidateParameters(params) != nil {
		return params, nil, ErrArtifact
	}
	canonicalParameters, err := params.MarshalBinary()
	if err != nil || DigestBytes(canonicalParameters) != cryptoManifest.Parameters.Digest {
		return params, nil, ErrArtifact
	}
	publicBytes, err := store.read(cryptoManifest.PublicKey, 64<<20)
	if err != nil {
		return params, nil, err
	}
	publicKey := rlwe.NewPublicKey(params)
	if publicKey.UnmarshalBinary(publicBytes) != nil {
		return params, nil, ErrArtifact
	}
	canonicalPublic, err := publicKey.MarshalBinary()
	if err != nil || DigestBytes(canonicalPublic) != cryptoManifest.PublicKey.Digest {
		return params, nil, ErrArtifact
	}
	return params, publicKey, nil
}

func participantFiles(role string) (signatureName, ciphertextName, manifestName string, err error) {
	switch role {
	case RoleA:
		return bindingSignatureAObject, submissionAObject, submissionAManifest, nil
	case RoleB:
		return bindingSignatureBObject, submissionBObject, submissionBManifest, nil
	default:
		return "", "", "", ErrBinding
	}
}

func SubmitParticipant(options ParticipantSubmissionOptions) (EncryptedParticipantArtifact, SubmissionReport, error) {
	started := time.Now()
	var report SubmissionReport
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	if len(options.SigningKey) != ed25519.PrivateKeySize || !nonzero(options.SubmissionNonce) {
		return EncryptedParticipantArtifact{}, report, ErrBinding
	}
	store, err := openObjectStore(options.PublicRoot, PublicCaseQuota, false)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	defer store.close()
	binding, cryptoManifest, err := loadCaseFoundation(store)
	if err != nil || options.Now.Unix() < binding.CreatedAtUnix || options.Now.Unix() > binding.ExpiresAtUnix ||
		options.ExpiresAtUnix <= options.Now.Unix() || options.ExpiresAtUnix > binding.ExpiresAtUnix {
		return EncryptedParticipantArtifact{}, report, ErrBinding
	}
	identity, err := expectedParticipant(binding, options.Role)
	if err != nil || !ed25519.PublicKey(options.SigningKey.Public().(ed25519.PublicKey)).Equal(ed25519.PublicKey(identity.SigningPublicKey)) {
		return EncryptedParticipantArtifact{}, report, ErrBinding
	}
	signatureName, ciphertextName, manifestName, err := participantFiles(options.Role)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	bindingDigest, err := binding.Digest()
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	bindingSignature := ParticipantBindingSignature{Role: options.Role, ParticipantID: identity.ID, BindingDigest: bindingDigest}
	signatureValue := struct {
		Role          string `json:"role"`
		ParticipantID Digest `json:"participantId"`
		BindingDigest Digest `json:"bindingDigest"`
	}{bindingSignature.Role, bindingSignature.ParticipantID, bindingSignature.BindingDigest}
	bindingSignature.Signature, err = signCanonical(options.SigningKey, "MordantFHECaseBindingSignature/v1", signatureValue)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	if _, _, err := store.createJSON(signatureName, bindingSignature); err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}

	params, publicKey, err := loadPublicEncryptionMaterial(store, cryptoManifest)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	client, expectedCustody, err := caseExternalClient(params, publicKey, binding.ReleaseMode)
	if err != nil || client.CustodyModel() != expectedCustody || Digest(client.KeyIDBytes()) != binding.PublicKeyDigest ||
		Digest(client.ParameterFingerprint()) != binding.ParameterFingerprint {
		return EncryptedParticipantArtifact{}, report, ErrBinding
	}
	cipherPledge, _, err := client.EncryptPledgeForMode(options.Pledge, fhe.IdentityFullFHE256)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, fmt.Errorf("encrypt participant: %w", err)
	}
	ciphertextBytes, err := cipherPledge.MarshalBinary()
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	ciphertextRef, err := store.create(ciphertextName, ciphertextBytes)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	components, err := componentRefs(cipherPledge)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	artifact := EncryptedParticipantArtifact{
		SchemaVersion: ParticipantArtifactSchema, CaseBindingDigest: bindingDigest, CaseID: binding.CaseID,
		AssetIdentity: binding.AssetIdentity, ParticipantID: identity.ID, ParticipantRole: identity.Role,
		PublicKeyDigest: binding.PublicKeyDigest, ParameterProfile: binding.ParameterProfile,
		ParameterFingerprint: binding.ParameterFingerprint, CircuitDigest: binding.CircuitDigest, InputSchema: binding.InputSchema,
		CiphertextObject: ciphertextRef, Components: components, SubmissionNonce: options.SubmissionNonce, ExpiresAtUnix: options.ExpiresAtUnix,
	}
	artifact.Signature, err = signCanonical(options.SigningKey, "MordantEncryptedParticipantArtifact/v1", artifact.signingValue())
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	artifactRef, artifactBytes, err := store.createJSON(manifestName, artifact)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	// The participant enrolls its own ciphertext into the bilateral session with
	// the same key that just signed the artifact. Issuance is not optional: a
	// submission the release boundary cannot pair is a submission that can never
	// be released, so failing here is better than failing at release.
	enrollmentName, err := enrollmentObjectForRole(identity.Role)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	circuitInputs, err := ParticipantCircuitSideDigest(cipherPledge)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	enrollment, err := IssueParticipantEnrollmentV5(IssueParticipantEnrollmentV5Options{
		Binding: binding, Artifact: artifact, Role: identity.Role,
		CircuitInputsDigest: circuitInputs, SigningKey: options.SigningKey,
	})
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	enrollmentRef, _, err := store.createJSON(enrollmentName, enrollment)
	if err != nil {
		return EncryptedParticipantArtifact{}, report, err
	}
	report.Duration = time.Since(started)
	report.CiphertextBytes = ciphertextRef.Length
	report.ArtifactBytes = artifactRef.Length
	report.EnrollmentBytes = enrollmentRef.Length
	_ = artifactBytes
	return artifact, report, nil
}

func componentRefs(pledge *fhe.CipherPledge) ([]CiphertextComponentRef, error) {
	if pledge == nil || pledge.ReceivableIDBits == nil {
		return nil, ErrArtifact
	}
	components := participantCiphertextComponents(pledge)
	result := make([]CiphertextComponentRef, len(components))
	for index, component := range components {
		if component.ciphertext == nil {
			return nil, ErrArtifact
		}
		encoded, err := component.ciphertext.MarshalBinary()
		if err != nil {
			return nil, err
		}
		result[index] = CiphertextComponentRef{Name: component.name, Digest: DigestBytes(encoded), Length: int64(len(encoded))}
	}
	return result, nil
}
