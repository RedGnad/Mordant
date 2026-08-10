package governedfhe

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
)

// V5 enrollments on the product path.
//
// A V5 enrollment is the per-ciphertext statement the release boundary relies
// on: this exact ciphertext, from this participant, belongs to this bilateral
// session, and is only pairable with the counterparty this participant named.
// Pairing two enrollments is external audit finding H-01's gate, and until now
// the product had no object carrying it.
//
// Three properties are deliberate.
//
// The issuer is the participant, using the key the case binding already
// admitted for its role. No administrative issuer is introduced: the truth an
// enrollment asserts is a fact about one participant's own submission, and both
// participants already signed the case binding that names those keys. The
// release-side trust store is therefore derived from the signed binding rather
// than configured.
//
// The stored record carries the signature and the facts needed to audit it by
// eye, but never a re-serialization of the signed structure. The enrollment is
// a pure function of the case binding, the participant artifact, the role and
// the issuance time, so it is re-derived from the store on every read and the
// signature is checked against that re-derivation. A parallel wire encoding of
// a signed cryptographic struct could drift from the struct it claims to
// encode; a re-derivation cannot.
//
// Issuance fails closed for an asset with no deployed case adapter, because
// AuthorizationClaim.Vault is an EVM address inside an EIP-712-shaped type
// string. Filling it with a truncated digest would put a value that is not an
// address into a signed field that says it is one.
const (
	// EnrollmentV5Schema versions the stored record, not the signed enrollment.
	// The signed structure is fhe.CiphertextEnrollmentV5 and is versioned there.
	EnrollmentV5Schema = "mordant.fhe-participant-enrollment-v5/1"

	enrollmentAObject = "participant-enrollment-a.json"
	enrollmentBObject = "participant-enrollment-b.json"

	enrollmentInputCommitmentDomain = "MordantEnrollmentInputCommitment/v1\x00"
	enrollmentGovernanceDomain      = "MordantEnrollmentGovernanceRecord/v1\x00"
	enrollmentRoleDomain            = "MordantEnrollmentRole/v1\x00"
	enrollmentNullifierDomain       = "MordantEnrollmentSessionNullifier/v1\x00"

	// This profile has no authorization-rotation or submission-budget authority,
	// so there is no epoch to read. Both sides are pinned to 1 and the release
	// boundary refuses any other value rather than accepting a number whose
	// provenance it cannot state.
	enrollmentAuthorizationEpoch    uint32 = 1
	enrollmentSubmissionBudgetEpoch uint32 = 1
)

// ErrEnrollmentV5 reports a participant enrollment that could not be issued,
// re-derived, or verified against the case it claims to belong to.
var ErrEnrollmentV5 = errors.New("participant enrollment v5")

// deployedCaseAdapters maps an asset identity to the case adapter that consumes
// a governed release for it.
//
// The single entry is the hardened case adapter deployed to Monad testnet
// (chain 10143) at block 51559582. Its runtime code hash and every immutable
// were read back from the chain: assetIdentityDigest, parameterFingerprint and
// circuitHash on the contract equal the values this package computes, so the
// adapter and the FHE case describe the same asset, parameters and circuit.
//
// The table is keyed by asset because the adapter binds assetIdentityDigest as
// an immutable. A second asset requires a second deployment, and until that
// deployment exists this package refuses to issue enrollments for it.
var deployedCaseAdapters = map[string]string{
	"sha256:7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c": "0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1",
}

// DeployedCaseAdapterAssets lists the assets a case adapter has been deployed
// for. A case for any other asset cannot be enrolled and cannot settle.
func DeployedCaseAdapterAssets() []Digest {
	assets := make([]Digest, 0, len(deployedCaseAdapters))
	for encoded := range deployedCaseAdapters {
		raw, err := hex.DecodeString(strings.TrimPrefix(encoded, "sha256:"))
		if err != nil || len(raw) != 32 {
			continue
		}
		assets = append(assets, Digest(raw))
	}
	return assets
}

// SettlementVaultForAsset returns the deployed case adapter for an asset.
func SettlementVaultForAsset(assetIdentity Digest) ([20]byte, error) {
	var vault [20]byte
	encoded, deployed := deployedCaseAdapters[assetIdentity.String()]
	if !deployed {
		return vault, fmt.Errorf("%w: no deployed case adapter for asset %s", ErrEnrollmentV5, assetIdentity)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
	if err != nil || len(raw) != len(vault) {
		return vault, fmt.Errorf("%w: malformed case adapter address", ErrEnrollmentV5)
	}
	copy(vault[:], raw)
	return vault, nil
}

func enrollmentObjectForRole(role string) (string, error) {
	switch role {
	case RoleA:
		return enrollmentAObject, nil
	case RoleB:
		return enrollmentBObject, nil
	default:
		return "", fmt.Errorf("%w: unknown role %q", ErrEnrollmentV5, role)
	}
}

// enrollmentSlotForRole is the V5 input slot. PairEnrollmentsV5 requires exactly
// slot 0 then slot 1, in the participant order the binding fixes.
func enrollmentSlotForRole(role string) (uint8, error) {
	switch role {
	case RoleA:
		return 0, nil
	case RoleB:
		return 1, nil
	default:
		return 0, fmt.Errorf("%w: unknown role %q", ErrEnrollmentV5, role)
	}
}

func enrollmentRoleDigest(role string) [32]byte {
	return [32]byte(DigestBytes([]byte(enrollmentRoleDomain + role)))
}

// ParticipantEnrollmentV5 is the stored record.
//
// Every field except the signature is re-derived from the case binding and the
// participant artifact when the record is read, and a mismatch is refused. The
// fields are present so the record is auditable on its own, not because they are
// trusted.
type ParticipantEnrollmentV5 struct {
	SchemaVersion string `json:"schemaVersion"`
	Role          string `json:"role"`

	CaseID            Digest `json:"caseId"`
	CaseBindingDigest Digest `json:"caseBindingDigest"`
	ParticipantID     Digest `json:"participantId"`
	ArtifactDigest    Digest `json:"artifactDigest"`
	CiphertextDigest  Digest `json:"ciphertextDigest"`
	// The keccak-256 CircuitSideDigestV5 over this side's three circuit inputs,
	// hex with an 0x prefix. This is the value inside the signature; the object
	// digest above is the stored submission and is recorded for audit only.
	CircuitInputsDigest string `json:"circuitInputsDigest"`

	// The deployed case adapter this participant consents to settle against,
	// as a checksum-free lowercase hex address.
	SettlementVault string `json:"settlementVault"`

	IssuedAtUnix   int64 `json:"issuedAtUnix"`
	ValidUntilUnix int64 `json:"validUntilUnix"`

	// The keccak-256 signing digest of the enrollment, hex with an 0x prefix.
	// It is not a sha256 Digest and is deliberately not typed as one.
	EnrollmentSigningDigest string `json:"enrollmentSigningDigest"`

	Signature []byte `json:"signature"`
}

// EnrollmentCaseFacts is the part of a case an enrollment is derived from.
//
// It is deliberately the intersection of what the two producers hold. The
// coordinator reads the signed FHECaseBinding; a direct participant only ever
// receives its ceremony bundle, which is a strict subset. Deriving from the
// intersection means both sides compute the same enrollment from independent
// documents, and neither needs a document it was not meant to have.
//
// CaseNonce is deliberately absent: it is in the binding but not in the bundle,
// and the session nullifier is derived from the binding digest instead.
type EnrollmentCaseFacts struct {
	CaseID               Digest
	AssetIdentity        Digest
	PolicyID             Digest
	PolicyVersion        uint32
	CircuitVersion       uint32
	CircuitDigest        Digest
	ParameterFingerprint Digest
	PublicKeyDigest      Digest
	CaseBindingDigest    Digest
	ParticipantA         ParticipantIdentity
	ParticipantB         ParticipantIdentity
	CreatedAtUnix        int64
	ExpiresAtUnix        int64
}

func (f EnrollmentCaseFacts) validate() error {
	if !nonzero(f.CaseID, f.AssetIdentity, f.PolicyID, f.CircuitDigest, f.ParameterFingerprint, f.PublicKeyDigest, f.CaseBindingDigest) ||
		f.PolicyVersion != fhe.PolicyVersion || f.CircuitVersion != fhe.CircuitV5Version ||
		f.ParticipantA.validate(RoleA) != nil || f.ParticipantB.validate(RoleB) != nil ||
		f.ParticipantA.ID == f.ParticipantB.ID ||
		f.CreatedAtUnix <= 0 || f.ExpiresAtUnix <= f.CreatedAtUnix {
		return fmt.Errorf("%w: incomplete case facts", ErrEnrollmentV5)
	}
	return nil
}

// EnrollmentCaseFactsFromBinding is the coordinator's view.
func EnrollmentCaseFactsFromBinding(binding FHECaseBinding) (EnrollmentCaseFacts, error) {
	var facts EnrollmentCaseFacts
	if err := binding.validate(); err != nil {
		return facts, err
	}
	bindingDigest, err := binding.Digest()
	if err != nil {
		return facts, err
	}
	facts = EnrollmentCaseFacts{
		CaseID: binding.CaseID, AssetIdentity: binding.AssetIdentity,
		PolicyID: binding.PolicyID, PolicyVersion: binding.PolicyVersion,
		CircuitVersion: binding.CircuitVersion, CircuitDigest: binding.CircuitDigest,
		ParameterFingerprint: binding.ParameterFingerprint, PublicKeyDigest: binding.PublicKeyDigest,
		CaseBindingDigest: bindingDigest,
		ParticipantA:      binding.ParticipantA, ParticipantB: binding.ParticipantB,
		CreatedAtUnix: binding.CreatedAtUnix, ExpiresAtUnix: binding.ExpiresAtUnix,
	}
	return facts, facts.validate()
}

// EnrollmentCaseFactsFromBundle is the direct participant's view. For one case
// it must produce exactly the value EnrollmentCaseFactsFromBinding produces.
func EnrollmentCaseFactsFromBundle(bundle ParticipantOriginatedClientBundle) (EnrollmentCaseFacts, error) {
	facts := EnrollmentCaseFacts{
		CaseID: bundle.CaseID, AssetIdentity: bundle.AssetIdentity,
		PolicyID: bundle.PolicyID, PolicyVersion: bundle.PolicyVersion,
		CircuitVersion: bundle.CircuitVersion, CircuitDigest: bundle.CircuitDigest,
		ParameterFingerprint: bundle.ParameterFingerprint, PublicKeyDigest: bundle.FHEPublicKeyDigest,
		CaseBindingDigest: bundle.CaseBindingDigest,
		ParticipantA:      bundle.ParticipantA, ParticipantB: bundle.ParticipantB,
		CreatedAtUnix: bundle.CreatedAtUnix, ExpiresAtUnix: bundle.ExpiresAtUnix,
	}
	return facts, facts.validate()
}

// buildParticipantEnrollmentV5 is the single derivation. Issuance and
// verification both go through it, so a record can never be accepted under a
// different construction than the one that was signed.
func buildParticipantEnrollmentV5(
	facts EnrollmentCaseFacts,
	artifact EncryptedParticipantArtifact,
	artifactDigest Digest,
	role string,
	circuitInputs [32]byte,
) (fhe.CiphertextEnrollmentV5, error) {
	var enrollment fhe.CiphertextEnrollmentV5

	if err := facts.validate(); err != nil {
		return enrollment, err
	}
	own, counterparty := facts.ParticipantA, facts.ParticipantB
	if role == RoleB {
		own, counterparty = facts.ParticipantB, facts.ParticipantA
	}
	slot, err := enrollmentSlotForRole(role)
	if err != nil {
		return enrollment, err
	}
	vault, err := SettlementVaultForAsset(facts.AssetIdentity)
	if err != nil {
		return enrollment, err
	}

	// The artifact must belong to this case, this role and this participant, and
	// its digest must be the one the caller resolved. Nothing below is trusted
	// from the artifact until these hold.
	if artifact.CaseID != facts.CaseID || artifact.CaseBindingDigest != facts.CaseBindingDigest ||
		artifact.ParticipantRole != role || artifact.ParticipantID != own.ID ||
		artifact.PublicKeyDigest != facts.PublicKeyDigest ||
		artifact.ParameterFingerprint != facts.ParameterFingerprint ||
		artifact.CircuitDigest != facts.CircuitDigest ||
		!nonzero(artifactDigest, artifact.SubmissionNonce, artifact.CiphertextObject.Digest) ||
		circuitInputs == ([32]byte{}) {
		return enrollment, fmt.Errorf("%w: artifact does not bind this case and role", ErrEnrollmentV5)
	}
	// An enrollment may not outlive the session that authorizes it, and the
	// issuer window registered at the release boundary is the session window.
	//
	// IssuedAt is the session's creation time rather than a wall-clock reading.
	// The enrollment is then a pure function of the case and the artifact, so the
	// participant and the coordinator derive the same bytes without agreeing on a
	// clock, and no issuance timestamp has to travel. When the participant signed
	// is recorded by the artifact and the import journal, which is where it
	// belongs.
	if artifact.ExpiresAtUnix <= 0 || artifact.ExpiresAtUnix > facts.ExpiresAtUnix ||
		artifact.ExpiresAtUnix <= facts.CreatedAtUnix {
		return enrollment, fmt.Errorf("%w: enrollment window escapes the case window", ErrEnrollmentV5)
	}

	// A provider-independent commitment to this side's input identity, built
	// only from material the participant already signed.
	inputCommitment := DigestBytes(append(append(
		[]byte(enrollmentInputCommitmentDomain),
		concatDigests(facts.CaseID, enrollmentRoleDigest(role), artifact.CiphertextObject.Digest, artifact.SubmissionNonce)...,
	), circuitInputs[:]...))
	// Which admitted key governs this side, bound to the bilaterally signed
	// binding that admitted it.
	governanceRecord := DigestBytes(append(append(
		[]byte(enrollmentGovernanceDomain),
		concatDigests(facts.CaseBindingDigest, own.ID)...,
	), own.SigningPublicKey...))

	claim := fhe.AuthorizationClaim{
		SubjectCommitment: [32]byte(own.ID),
		Role:              enrollmentRoleDigest(role),
		Vault:             vault,
		PolicyID:          [32]byte(facts.PolicyID),
		PolicyVersion:     facts.PolicyVersion,
		ValidUntil:        uint64(facts.ExpiresAtUnix),
		Nonce:             uint256FromDigest(artifact.SubmissionNonce),
	}
	authorizationCommitment, err := fhe.EnrollmentAuthorizationCommitment(claim, [32]byte(facts.PublicKeyDigest))
	if err != nil {
		return enrollment, fmt.Errorf("%w: %v", ErrEnrollmentV5, err)
	}

	return fhe.CiphertextEnrollmentV5{
		Version: fhe.EnrollmentV5Version,
		Binding: fhe.SessionBindingV5{
			// The session is the bilaterally signed case binding. It is admitted
			// on chain at settlement, when the adapter consumes a result carrying
			// this digest, and not before the FHE runs.
			SessionCommitment: [32]byte(facts.CaseBindingDigest),
			// V5 separates the on-chain commitment from a salt-independent
			// nullifier because a salted commitment hides which intent it is. The
			// case binding digest carries no salt, so the two would carry the same
			// information; the nullifier is derived from it under its own domain.
			// It therefore does not add double-submission detection beyond the
			// session commitment, and this profile does not claim that it does.
			SessionNullifier:            [32]byte(DigestBytes(append([]byte(enrollmentNullifierDomain), facts.CaseBindingDigest[:]...))),
			OwnScopeCommitment:          [32]byte(own.ID),
			CounterpartyScopeCommitment: [32]byte(counterparty.ID),
			GovernanceRecord:            [32]byte(governanceRecord),
			SourceRecordCommitment:      [32]byte(artifactDigest),
			AuthorizationEpoch:          enrollmentAuthorizationEpoch,
			SubmissionBudgetEpoch:       enrollmentSubmissionBudgetEpoch,
			InputSlot:                   slot,
		},
		CircuitVersion: facts.CircuitVersion,
		// Exactly the three ciphertexts the circuit reads for this side, in fixed
		// order, and nothing else.
		//
		// The stored submission object also carries amount and obligation
		// ciphertexts the circuit never reads, so its digest cannot answer the
		// question a release operator has to answer: are these the inputs this
		// enrollment authorized me to evaluate? Binding the whole object here
		// would leave the operator trusting whoever extracted the circuit inputs
		// from it.
		CiphertextDigest:        circuitInputs,
		InputCommitment:         [32]byte(inputCommitment),
		KeyID:                   [32]byte(facts.PublicKeyDigest),
		ParameterFingerprint:    [32]byte(facts.ParameterFingerprint),
		PolicyID:                [32]byte(facts.PolicyID),
		PolicyVersion:           facts.PolicyVersion,
		IdentityMode:            fhe.IdentityFullFHE256,
		AuthorizationClaim:      claim,
		AuthorizationCommitment: authorizationCommitment,
		// The issuer is this role's own admitted key. SignEnrollmentV5 derives the
		// same value from the private key it is given, so a signature produced by
		// any other key fails against this re-derivation rather than being
		// accepted under a different issuer.
		IssuerKeyID: [32]byte(DigestBytes(own.SigningPublicKey)),
		IssuedAt:    uint64(facts.CreatedAtUnix),
		ValidUntil:  uint64(artifact.ExpiresAtUnix),
		Nonce:       [32]byte(artifact.SubmissionNonce),
	}, nil
}

func concatDigests(values ...Digest) []byte {
	encoded := make([]byte, 0, len(values)*32)
	for _, value := range values {
		encoded = append(encoded, value[:]...)
	}
	return encoded
}

func uint256FromDigest(value Digest) fhe.Uint256 {
	var word fhe.Uint256
	for limb := 0; limb < 4; limb++ {
		var accumulator uint64
		for index := 0; index < 8; index++ {
			accumulator = accumulator<<8 | uint64(value[limb*8+index])
		}
		word[limb] = accumulator
	}
	return word
}

// assembleEnrollmentRecord is the one place a stored record is built. Both the
// coordinator path (which signs here) and the direct participant path (which
// brings a signature produced on its own machine) go through it, and it refuses
// a signature that does not verify against the re-derived enrollment.
func assembleEnrollmentRecord(
	facts EnrollmentCaseFacts,
	artifact EncryptedParticipantArtifact,
	artifactDigest Digest,
	role string,
	circuitInputs [32]byte,
	signature []byte,
) (ParticipantEnrollmentV5, error) {
	var record ParticipantEnrollmentV5
	enrollment, err := buildParticipantEnrollmentV5(facts, artifact, artifactDigest, role, circuitInputs)
	if err != nil {
		return record, err
	}
	identity := facts.ParticipantA
	if role == RoleB {
		identity = facts.ParticipantB
	}
	signingDigest := enrollment.SigningDigest()
	if len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(identity.SigningPublicKey), signingDigest[:], signature) {
		return record, fmt.Errorf("%w: signature is not from the key admitted for role %s", ErrEnrollmentV5, role)
	}
	vault, err := SettlementVaultForAsset(facts.AssetIdentity)
	if err != nil {
		return record, err
	}
	return ParticipantEnrollmentV5{
		SchemaVersion:           EnrollmentV5Schema,
		Role:                    role,
		CaseID:                  facts.CaseID,
		CaseBindingDigest:       facts.CaseBindingDigest,
		ParticipantID:           identity.ID,
		ArtifactDigest:          artifactDigest,
		CiphertextDigest:        artifact.CiphertextObject.Digest,
		CircuitInputsDigest:     "0x" + hex.EncodeToString(circuitInputs[:]),
		SettlementVault:         "0x" + hex.EncodeToString(vault[:]),
		IssuedAtUnix:            facts.CreatedAtUnix,
		ValidUntilUnix:          artifact.ExpiresAtUnix,
		EnrollmentSigningDigest: "0x" + hex.EncodeToString(signingDigest[:]),
		Signature:               append([]byte(nil), signature...),
	}, nil
}

// SignParticipantEnrollmentV5 produces the participant's signature over its own
// enrollment. A direct participant calls this on its own machine, where the key
// lives, and ships only the resulting signature.
func SignParticipantEnrollmentV5(
	facts EnrollmentCaseFacts,
	artifact EncryptedParticipantArtifact,
	role string,
	circuitInputs [32]byte,
	signingKey ed25519.PrivateKey,
) ([]byte, error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: participant signing key required", ErrEnrollmentV5)
	}
	artifactDigest, err := artifact.Digest()
	if err != nil {
		return nil, err
	}
	enrollment, err := buildParticipantEnrollmentV5(facts, artifact, artifactDigest, role, circuitInputs)
	if err != nil {
		return nil, err
	}
	signed, err := fhe.SignEnrollmentV5(enrollment, signingKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnrollmentV5, err)
	}
	return append([]byte(nil), signed.Signature[:]...), nil
}

// IssueParticipantEnrollmentV5Options is the coordinator-path issuance input.
type IssueParticipantEnrollmentV5Options struct {
	Binding  FHECaseBinding
	Artifact EncryptedParticipantArtifact
	Role     string
	// CircuitInputsDigest is CircuitSideDigestV5 over this side's three circuit
	// ciphertexts. It is what the enrollment actually authorizes.
	CircuitInputsDigest [32]byte
	SigningKey          ed25519.PrivateKey
}

// IssueParticipantEnrollmentV5 signs and assembles one side's enrollment where
// the participant key is present in-process.
func IssueParticipantEnrollmentV5(options IssueParticipantEnrollmentV5Options) (ParticipantEnrollmentV5, error) {
	var record ParticipantEnrollmentV5
	facts, err := EnrollmentCaseFactsFromBinding(options.Binding)
	if err != nil {
		return record, err
	}
	signature, err := SignParticipantEnrollmentV5(facts, options.Artifact, options.Role, options.CircuitInputsDigest, options.SigningKey)
	if err != nil {
		return record, err
	}
	artifactDigest, err := options.Artifact.Digest()
	if err != nil {
		return record, err
	}
	return assembleEnrollmentRecord(facts, options.Artifact, artifactDigest, options.Role, options.CircuitInputsDigest, signature)
}

// AdoptParticipantEnrollmentV5 assembles the stored record from a signature the
// participant produced elsewhere. The signature is the only thing trusted from
// the caller, and it is checked against a local re-derivation before the record
// exists.
func AdoptParticipantEnrollmentV5(
	facts EnrollmentCaseFacts,
	artifact EncryptedParticipantArtifact,
	artifactDigest Digest,
	role string,
	circuitInputs [32]byte,
	signature []byte,
) (ParticipantEnrollmentV5, error) {
	return assembleEnrollmentRecord(facts, artifact, artifactDigest, role, circuitInputs, signature)
}

// reconstructParticipantEnrollmentV5 re-derives the signed enrollment from the
// case and the artifact, and checks the stored record describes exactly that
// derivation. The record's own fields are never used as inputs.
func reconstructParticipantEnrollmentV5(
	facts EnrollmentCaseFacts,
	artifact EncryptedParticipantArtifact,
	artifactDigest Digest,
	role string,
	circuitInputs [32]byte,
	record ParticipantEnrollmentV5,
) (*fhe.SignedCiphertextEnrollmentV5, error) {
	if record.SchemaVersion != EnrollmentV5Schema || record.Role != role {
		return nil, fmt.Errorf("%w: malformed enrollment record", ErrEnrollmentV5)
	}
	// Rebuilding the record from the store's own copies of the case and the
	// artifact, then comparing every field, refuses an edited record even where
	// the edit would not have changed the signature.
	rebuilt, err := assembleEnrollmentRecord(facts, artifact, artifactDigest, role, circuitInputs, record.Signature)
	if err != nil {
		return nil, err
	}
	if rebuilt.IssuedAtUnix != record.IssuedAtUnix || rebuilt.CaseID != record.CaseID || rebuilt.CaseBindingDigest != record.CaseBindingDigest ||
		rebuilt.ParticipantID != record.ParticipantID || rebuilt.ArtifactDigest != record.ArtifactDigest ||
		rebuilt.CiphertextDigest != record.CiphertextDigest || rebuilt.CircuitInputsDigest != record.CircuitInputsDigest ||
		rebuilt.SettlementVault != record.SettlementVault ||
		rebuilt.ValidUntilUnix != record.ValidUntilUnix ||
		rebuilt.EnrollmentSigningDigest != record.EnrollmentSigningDigest {
		return nil, fmt.Errorf("%w: enrollment record does not match its re-derivation", ErrEnrollmentV5)
	}
	enrollment, err := buildParticipantEnrollmentV5(facts, artifact, artifactDigest, role, circuitInputs)
	if err != nil {
		return nil, err
	}
	signed := &fhe.SignedCiphertextEnrollmentV5{Enrollment: enrollment}
	copy(signed.Signature[:], record.Signature)
	return signed, nil
}

// RegisterCaseEnrollmentIssuers derives a runtime's enrollment trust store from
// the signed case binding.
//
// It is exported because every runtime that will verify an enrollment does this
// for itself: the coordinator, and each coalition operator on its own evaluator.
// An operator that was handed a trust store instead of deriving one would be
// trusting whoever handed it over, which is the opposite of what an independent
// operator is for.
//
// Each participant is an issuer for its own side only, for exactly the session
// window the binding fixes.
func RegisterCaseEnrollmentIssuers(runtime *fhe.Runtime, binding FHECaseBinding) error {
	if runtime == nil {
		return fmt.Errorf("%w: runtime required", ErrEnrollmentV5)
	}
	facts, err := EnrollmentCaseFactsFromBinding(binding)
	if err != nil {
		return err
	}
	validFrom := time.Unix(facts.CreatedAtUnix, 0).UTC()
	validUntil := time.Unix(facts.ExpiresAtUnix, 0).UTC()
	for _, identity := range []ParticipantIdentity{facts.ParticipantA, facts.ParticipantB} {
		if _, err := runtime.RegisterEnrollmentIssuer(ed25519.PublicKey(identity.SigningPublicKey), validFrom, validUntil); err != nil {
			return fmt.Errorf("%w: %v", ErrEnrollmentV5, err)
		}
	}
	return nil
}

// CaseEnrollmentsV5 is the verified two-sided authorization for one case.
type CaseEnrollmentsV5 struct {
	Paired          fhe.PairedEnrollmentsV5
	SettlementVault [20]byte
	RecordA         ParticipantEnrollmentV5
	RecordB         ParticipantEnrollmentV5
	// The re-derived signed enrollments. The coalition operators verify these
	// again for themselves; they are carried here so the coordinator does not
	// re-derive them a second time from the same store.
	SignedA *fhe.SignedCiphertextEnrollmentV5
	SignedB *fhe.SignedCiphertextEnrollmentV5
}

// verifyCaseEnrollmentsV5 is the release-side gate.
//
// It derives the issuer trust store from the case binding both participants
// signed, verifies each enrollment against that store, and then pairs them.
// Pairing is the H-01 check: two enrollments from different sessions cannot
// satisfy it in both directions.
//
// The runtime is the public evaluation runtime the decryptor already builds to
// recompute the circuit. It holds no secret key, and this function reads none.
func verifyCaseEnrollmentsV5(
	runtime *fhe.Runtime,
	binding FHECaseBinding,
	participants validatedFreshParticipants,
	recordA, recordB ParticipantEnrollmentV5,
	now time.Time,
) (CaseEnrollmentsV5, error) {
	var verified CaseEnrollmentsV5
	if runtime == nil {
		return verified, fmt.Errorf("%w: evaluation runtime required", ErrEnrollmentV5)
	}
	facts, err := EnrollmentCaseFactsFromBinding(binding)
	if err != nil {
		return verified, err
	}
	// The digests are recomputed from the ciphertexts this case actually holds,
	// never read from the records.
	sideA, err := ParticipantCircuitSideDigest(participants.pledgeA)
	if err != nil {
		return verified, fmt.Errorf("participant A: %w", err)
	}
	sideB, err := ParticipantCircuitSideDigest(participants.pledgeB)
	if err != nil {
		return verified, fmt.Errorf("participant B: %w", err)
	}
	signedA, err := reconstructParticipantEnrollmentV5(facts, participants.artifactA, participants.digestA, RoleA, sideA, recordA)
	if err != nil {
		return verified, fmt.Errorf("participant A: %w", err)
	}
	signedB, err := reconstructParticipantEnrollmentV5(facts, participants.artifactB, participants.digestB, RoleB, sideB, recordB)
	if err != nil {
		return verified, fmt.Errorf("participant B: %w", err)
	}

	if err := RegisterCaseEnrollmentIssuers(runtime, binding); err != nil {
		return verified, err
	}
	// An enrollment must be signed by the key admitted for its own role, so a
	// participant cannot enroll the counterparty's ciphertext under its own key.
	if err := requireIssuerIsRoleKey(signedA, facts.ParticipantA); err != nil {
		return verified, err
	}
	if err := requireIssuerIsRoleKey(signedB, facts.ParticipantB); err != nil {
		return verified, err
	}
	if _, err := runtime.VerifyEnrollmentV5(signedA, now); err != nil {
		return verified, fmt.Errorf("%w: participant A: %v", ErrEnrollmentV5, err)
	}
	if _, err := runtime.VerifyEnrollmentV5(signedB, now); err != nil {
		return verified, fmt.Errorf("%w: participant B: %v", ErrEnrollmentV5, err)
	}

	paired, err := fhe.PairEnrollmentsV5(signedA, signedB)
	if err != nil {
		return verified, fmt.Errorf("%w: %v", ErrEnrollmentV5, err)
	}
	// Both sides must have consented to the same settlement venue. V5 binds the
	// vault into each signature but does not compare the two, because at that
	// layer a pair may legitimately span venues. Here it may not.
	vaultA := signedA.Enrollment.AuthorizationClaim.Vault
	if vaultA != signedB.Enrollment.AuthorizationClaim.Vault {
		return verified, fmt.Errorf("%w: participants named different settlement vaults", ErrEnrollmentV5)
	}
	// The pair must authorize the ciphertexts this case actually holds, in the
	// participant order the binding fixes.
	if paired.SessionCommitment != [32]byte(facts.CaseBindingDigest) ||
		paired.CiphertextDigestA != sideA || paired.CiphertextDigestB != sideB ||
		paired.ScopeCommitmentA != [32]byte(facts.ParticipantA.ID) ||
		paired.ScopeCommitmentB != [32]byte(facts.ParticipantB.ID) {
		return verified, fmt.Errorf("%w: paired enrollments do not authorize this case", ErrEnrollmentV5)
	}
	return CaseEnrollmentsV5{
		Paired: paired, SettlementVault: vaultA,
		RecordA: recordA, RecordB: recordB, SignedA: signedA, SignedB: signedB,
	}, nil
}

func requireIssuerIsRoleKey(signed *fhe.SignedCiphertextEnrollmentV5, identity ParticipantIdentity) error {
	expected := DigestBytes(identity.SigningPublicKey)
	if signed.Enrollment.IssuerKeyID != [32]byte(expected) {
		return fmt.Errorf("%w: enrollment for role %s was not issued by that role's admitted key", ErrEnrollmentV5, identity.Role)
	}
	return nil
}

// loadCaseEnrollmentsV5 reads both stored records.
func loadCaseEnrollmentsV5(store *objectStore) (ParticipantEnrollmentV5, ParticipantEnrollmentV5, error) {
	var recordA, recordB ParticipantEnrollmentV5
	if _, _, err := store.readJSON(enrollmentAObject, &recordA); err != nil {
		return recordA, recordB, fmt.Errorf("%w: participant A record: %v", ErrEnrollmentV5, err)
	}
	if _, _, err := store.readJSON(enrollmentBObject, &recordB); err != nil {
		return recordA, recordB, fmt.Errorf("%w: participant B record: %v", ErrEnrollmentV5, err)
	}
	return recordA, recordB, nil
}

// ParticipantCircuitSideDigest commits to exactly the three ciphertexts the
// circuit reads for one side. It is the value an enrollment binds, so that a
// release operator can check the inputs it was handed against the authorization
// it was given rather than trusting the coordinator's extraction.
func ParticipantCircuitSideDigest(pledge *fhe.CipherPledge) ([32]byte, error) {
	if pledge == nil {
		return [32]byte{}, fmt.Errorf("%w: no ciphertext", ErrEnrollmentV5)
	}
	digest, err := fhe.CircuitSideDigestV5(pledge.PolicyBits, pledge.CurrencyBits, pledge.ReceivableIDBits)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrEnrollmentV5, err)
	}
	return digest, nil
}
