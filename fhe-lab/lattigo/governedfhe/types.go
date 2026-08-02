package governedfhe

import (
	"crypto/ed25519"
	"fmt"
	"slices"

	fhe "mordant.dev/fhe-lab/lattigo"
)

const (
	RoleA = "PARTICIPANT_A"
	RoleB = "PARTICIPANT_B"
)

type ObjectRef struct {
	Path   string `json:"path"`
	Digest Digest `json:"sha256"`
	Length int64  `json:"length"`
}

func (r ObjectRef) validate(expectedPath string, maximum int64) error {
	if r.Path != expectedPath || !nonzero(r.Digest) || r.Length <= 0 || r.Length > maximum {
		return ErrArtifact
	}
	return nil
}

type ParticipantIdentity struct {
	ID               Digest `json:"id"`
	Role             string `json:"role"`
	SigningPublicKey []byte `json:"signingPublicKey"`
}

func (i ParticipantIdentity) validate(role string) error {
	if !nonzero(i.ID) || i.Role != role || len(i.SigningPublicKey) != ed25519.PublicKeySize {
		return ErrBinding
	}
	return nil
}

type CaseSpec struct {
	CaseID        Digest              `json:"caseId"`
	AssetIdentity Digest              `json:"assetIdentity"`
	PolicyID      Digest              `json:"policyId"`
	ParticipantA  ParticipantIdentity `json:"participantA"`
	ParticipantB  ParticipantIdentity `json:"participantB"`
	CaseNonce     Digest              `json:"caseNonce"`
	CreatedAtUnix int64               `json:"createdAtUnix"`
	ExpiresAtUnix int64               `json:"expiresAtUnix"`
}

func (s CaseSpec) validate() error {
	if !nonzero(s.CaseID, s.AssetIdentity, s.PolicyID, s.CaseNonce) || s.CreatedAtUnix <= 0 || s.ExpiresAtUnix <= s.CreatedAtUnix ||
		s.ParticipantA.validate(RoleA) != nil || s.ParticipantB.validate(RoleB) != nil || s.ParticipantA.ID == s.ParticipantB.ID ||
		slices.Equal(s.ParticipantA.SigningPublicKey, s.ParticipantB.SigningPublicKey) {
		return ErrBinding
	}
	return nil
}

type GaloisKeyRef struct {
	Index   uint32    `json:"index"`
	Step    int       `json:"step"`
	Element uint64    `json:"element"`
	Object  ObjectRef `json:"object"`
}

type EvaluationKeyManifest struct {
	RelinearizationKey ObjectRef      `json:"relinearizationKey"`
	GaloisKeys         []GaloisKeyRef `json:"galoisKeys"`
}

func (m EvaluationKeyManifest) Digest() (Digest, error) {
	digest, _, err := digestCanonical(m)
	return digest, err
}

type FHECaseBinding struct {
	SchemaVersion               string              `json:"schemaVersion"`
	CaseID                      Digest              `json:"caseId"`
	AssetIdentity               Digest              `json:"assetIdentity"`
	ServiceID                   string              `json:"serviceId"`
	ServiceVersion              uint32              `json:"serviceVersion"`
	PolicyID                    Digest              `json:"policyId"`
	PolicyVersion               uint32              `json:"policyVersion"`
	CircuitID                   string              `json:"circuitId"`
	CircuitVersion              uint32              `json:"circuitVersion"`
	CircuitDigest               Digest              `json:"circuitDigest"`
	ParameterProfile            string              `json:"parameterProfile"`
	ParameterFingerprint        Digest              `json:"parameterFingerprint"`
	PublicKeyDigest             Digest              `json:"publicKeyDigest"`
	EvaluationKeyManifestDigest Digest              `json:"evaluationKeyManifestDigest"`
	ParticipantA                ParticipantIdentity `json:"participantA"`
	ParticipantB                ParticipantIdentity `json:"participantB"`
	ParticipantOrder            []Digest            `json:"participantOrder"`
	InputSchema                 string              `json:"inputSchema"`
	ResultSchema                string              `json:"resultSchema"`
	ReleaseMode                 string              `json:"releaseMode"`
	ReleaseAuthorityID          Digest              `json:"releaseAuthorityId"`
	ReleaseAuthorityPublicKey   []byte              `json:"releaseAuthorityPublicKey"`
	CaseNonce                   Digest              `json:"caseNonce"`
	CreatedAtUnix               int64               `json:"createdAtUnix"`
	ExpiresAtUnix               int64               `json:"expiresAtUnix"`
}

func (b FHECaseBinding) Digest() (Digest, error) {
	digest, _, err := digestCanonical(b)
	return digest, err
}

func (b FHECaseBinding) validate() error {
	expectedFingerprint, err := ParameterFingerprint()
	if err != nil || b.SchemaVersion != CaseBindingSchema || b.ServiceID != ServiceID || b.ServiceVersion != ServiceVersion ||
		b.PolicyVersion != fhe.PolicyVersion || b.CircuitID != CircuitID || b.CircuitVersion != fhe.CircuitV5Version ||
		b.CircuitDigest != FixedCircuitDigest() || b.ParameterProfile != ParameterProfile || b.ParameterFingerprint != expectedFingerprint ||
		b.InputSchema != InputSchema || b.ResultSchema != ResultSchema || !nonzero(b.CaseID, b.AssetIdentity, b.PolicyID, b.PublicKeyDigest, b.EvaluationKeyManifestDigest, b.CaseNonce) ||
		b.ReleaseMode != ReleaseModeGovernedDecryptor || !nonzero(b.ReleaseAuthorityID) || len(b.ReleaseAuthorityPublicKey) != ed25519.PublicKeySize ||
		releaseAuthorityIdentity(b.ReleaseMode, ed25519.PublicKey(b.ReleaseAuthorityPublicKey)) != b.ReleaseAuthorityID ||
		b.ParticipantA.validate(RoleA) != nil || b.ParticipantB.validate(RoleB) != nil || len(b.ParticipantOrder) != 2 ||
		b.ParticipantA.ID == b.ParticipantB.ID || slices.Equal(b.ParticipantA.SigningPublicKey, b.ParticipantB.SigningPublicKey) ||
		b.ParticipantOrder[0] != b.ParticipantA.ID || b.ParticipantOrder[1] != b.ParticipantB.ID || b.CreatedAtUnix <= 0 || b.ExpiresAtUnix <= b.CreatedAtUnix {
		return ErrBinding
	}
	return nil
}

type CaseCryptoManifest struct {
	SchemaVersion  string                `json:"schemaVersion"`
	Parameters     ObjectRef             `json:"parameters"`
	PublicKey      ObjectRef             `json:"publicKey"`
	EvaluationKeys EvaluationKeyManifest `json:"evaluationKeys"`
}

type ParticipantBindingSignature struct {
	Role          string `json:"role"`
	ParticipantID Digest `json:"participantId"`
	BindingDigest Digest `json:"bindingDigest"`
	Signature     []byte `json:"signature"`
}

type FHECaseManifest struct {
	SchemaVersion string                      `json:"schemaVersion"`
	Binding       FHECaseBinding              `json:"binding"`
	Crypto        CaseCryptoManifest          `json:"crypto"`
	SignatureA    ParticipantBindingSignature `json:"signatureA"`
	SignatureB    ParticipantBindingSignature `json:"signatureB"`
}

func (m FHECaseManifest) Digest() (Digest, error) {
	digest, _, err := digestCanonical(m)
	return digest, err
}

type CiphertextComponentRef struct {
	Name   string `json:"name"`
	Digest Digest `json:"sha256"`
	Length int64  `json:"length"`
}

type EncryptedParticipantArtifact struct {
	SchemaVersion        string                   `json:"schemaVersion"`
	CaseBindingDigest    Digest                   `json:"caseBindingDigest"`
	CaseID               Digest                   `json:"caseId"`
	AssetIdentity        Digest                   `json:"assetIdentity"`
	ParticipantID        Digest                   `json:"participantId"`
	ParticipantRole      string                   `json:"participantRole"`
	PublicKeyDigest      Digest                   `json:"publicKeyDigest"`
	ParameterProfile     string                   `json:"parameterProfile"`
	ParameterFingerprint Digest                   `json:"parameterFingerprint"`
	CircuitDigest        Digest                   `json:"circuitDigest"`
	InputSchema          string                   `json:"inputSchema"`
	CiphertextObject     ObjectRef                `json:"ciphertextObject"`
	Components           []CiphertextComponentRef `json:"components"`
	SubmissionNonce      Digest                   `json:"submissionNonce"`
	ExpiresAtUnix        int64                    `json:"expiresAtUnix"`
	Signature            []byte                   `json:"signature"`
}

func (a EncryptedParticipantArtifact) signingValue() EncryptedParticipantArtifact {
	a.Signature = nil
	return a
}

func (a EncryptedParticipantArtifact) Digest() (Digest, error) {
	digest, _, err := digestCanonical(a)
	return digest, err
}

type EvaluatedConflictArtifact struct {
	SchemaVersion              string    `json:"schemaVersion"`
	CaseID                     Digest    `json:"caseId"`
	CaseBindingDigest          Digest    `json:"caseBindingDigest"`
	AssetIdentity              Digest    `json:"assetIdentity"`
	ParticipantArtifactDigests []Digest  `json:"participantArtifactDigests"`
	PublicKeyDigest            Digest    `json:"publicKeyDigest"`
	ParameterProfile           string    `json:"parameterProfile"`
	ParameterFingerprint       Digest    `json:"parameterFingerprint"`
	CircuitID                  string    `json:"circuitId"`
	CircuitVersion             uint32    `json:"circuitVersion"`
	CircuitDigest              Digest    `json:"circuitDigest"`
	ResultCiphertext           ObjectRef `json:"resultCiphertext"`
	ResultCiphertextCommitment Digest    `json:"resultCiphertextCommitment"`
	OutputSchema               string    `json:"outputSchema"`
	OutputSlot                 uint32    `json:"outputSlot"`
	EvaluatorProvenance        Digest    `json:"evaluatorProvenance"`
	EvaluatedAtUnix            int64     `json:"evaluatedAtUnix"`
}

func (a EvaluatedConflictArtifact) Digest() (Digest, error) {
	digest, _, err := digestCanonical(a)
	return digest, err
}

type ReleaseAuthorityManifest struct {
	SchemaVersion     string `json:"schemaVersion"`
	CaseID            Digest `json:"caseId"`
	CaseBindingDigest Digest `json:"caseBindingDigest"`
	ReleaseMode       string `json:"releaseMode"`
	AuthorityID       Digest `json:"authorityId"`
	SigningPublicKey  []byte `json:"signingPublicKey"`
	SourceProvenance  Digest `json:"sourceProvenance"`
	Signature         []byte `json:"signature"`
}

func (a ReleaseAuthorityManifest) signingValue() ReleaseAuthorityManifest {
	a.Signature = nil
	return a
}

func knownReleaseMode(mode string) bool {
	return mode == ReleaseModeGovernedDecryptor
}

func releaseAuthorityIdentity(mode string, publicKey ed25519.PublicKey) Digest {
	value := append([]byte("MordantReleaseAuthorityIdentity/v1\x00"), []byte(mode)...)
	value = append(value, 0)
	value = append(value, publicKey...)
	return DigestBytes(value)
}

type GovernedConflictResult struct {
	SchemaVersion              string   `json:"schemaVersion"`
	CaseID                     Digest   `json:"caseId"`
	CaseBindingDigest          Digest   `json:"caseBindingDigest"`
	AssetIdentity              Digest   `json:"assetIdentity"`
	ServiceID                  string   `json:"serviceId"`
	ServiceVersion             uint32   `json:"serviceVersion"`
	PolicyID                   Digest   `json:"policyId"`
	PolicyVersion              uint32   `json:"policyVersion"`
	CircuitID                  string   `json:"circuitId"`
	CircuitVersion             uint32   `json:"circuitVersion"`
	CircuitDigest              Digest   `json:"circuitDigest"`
	ParameterProfile           string   `json:"parameterProfile"`
	ParameterFingerprint       Digest   `json:"parameterFingerprint"`
	ParticipantArtifactDigests []Digest `json:"participantArtifactDigests"`
	EvaluatedArtifactDigest    Digest   `json:"evaluatedArtifactDigest"`
	ResultCiphertextDigest     Digest   `json:"resultCiphertextDigest"`
	ResultCiphertextCommitment Digest   `json:"resultCiphertextCommitment"`
	Conflict                   bool     `json:"conflict"`
	ReleaseOrdinal             uint32   `json:"releaseOrdinal"`
	ReleaseMode                string   `json:"releaseMode"`
	ReleaseAuthorityID         Digest   `json:"releaseAuthorityId"`
	ReleaseAuthorityPublicKey  []byte   `json:"releaseAuthorityPublicKey"`
	ReleasedAtUnix             int64    `json:"releasedAtUnix"`
	SourceProvenance           Digest   `json:"sourceProvenance"`
	Signature                  []byte   `json:"signature"`
}

// TrustedRecoursePins is emitted by the trusted release service over its
// authenticated local control channel. The recourse adapter compares every
// field against the signed result instead of accepting result-selected pins.
type TrustedRecoursePins struct {
	ParticipantArtifactDigestA       Digest `json:"participantArtifactDigestA"`
	ParticipantArtifactDigestB       Digest `json:"participantArtifactDigestB"`
	EvaluatedArtifactDigest          Digest `json:"evaluatedArtifactDigest"`
	RecomputedResultCiphertextDigest Digest `json:"recomputedResultCiphertextDigest"`
	ResultCiphertextCommitment       Digest `json:"resultCiphertextCommitment"`
	DecryptorProvenance              Digest `json:"decryptorProvenance"`
	ReleaseMode                      string `json:"releaseMode"`
	ReleaseAuthorityID               Digest `json:"releaseAuthorityId"`
}

func (r GovernedConflictResult) signingValue() GovernedConflictResult {
	r.Signature = nil
	return r
}

func (r GovernedConflictResult) Digest() (Digest, error) {
	digest, _, err := digestCanonical(r)
	return digest, err
}

// FixedConflictReleaser is the single replaceable release boundary. A future
// threshold-2of3-v1 implementation can satisfy this interface without changing
// participant, evaluator, result or recourse types.
type FixedConflictReleaser interface {
	ReleaseFixedConflict(EvaluatedConflictArtifact) (GovernedConflictResult, []byte, error)
}

type RecourseRecord struct {
	SchemaVersion            string `json:"schemaVersion"`
	CaseID                   Digest `json:"caseId"`
	CaseBindingDigest        Digest `json:"caseBindingDigest"`
	AssetIdentity            Digest `json:"assetIdentity"`
	PolicyID                 Digest `json:"policyId"`
	PolicyVersion            uint32 `json:"policyVersion"`
	ResultDigest             Digest `json:"resultDigest"`
	ReleaseMode              string `json:"releaseMode"`
	ReleaseAuthorityID       Digest `json:"releaseAuthorityId"`
	RecordDateUnix           int64  `json:"recordDateUnix"`
	BoundAtUnix              int64  `json:"boundAtUnix"`
	CureDeadlineUnix         int64  `json:"cureDeadlineUnix"`
	ReserveBasisPoints       uint32 `json:"reserveBasisPoints"`
	HolderAllocationDigest   Digest `json:"holderAllocationDigest"`
	OriginalReceivableIntact bool   `json:"originalReceivableIntact"`
	Open                     bool   `json:"open"`
}

type PrivateCaseManifest struct {
	SchemaVersion      string    `json:"schemaVersion"`
	CaseID             Digest    `json:"caseId"`
	CaseBindingDigest  Digest    `json:"caseBindingDigest"`
	SecretKey          ObjectRef `json:"secretKey"`
	SigningKey         ObjectRef `json:"signingKey"`
	ReleaseAuthorityID Digest    `json:"releaseAuthorityId"`
}

func assertDigestSlice(values []Digest, count int) error {
	if len(values) != count {
		return ErrBinding
	}
	for _, value := range values {
		if !nonzero(value) {
			return ErrBinding
		}
	}
	return nil
}

func expectedParticipant(binding FHECaseBinding, role string) (ParticipantIdentity, error) {
	switch role {
	case RoleA:
		return binding.ParticipantA, nil
	case RoleB:
		return binding.ParticipantB, nil
	default:
		return ParticipantIdentity{}, fmt.Errorf("%w: participant role", ErrBinding)
	}
}
