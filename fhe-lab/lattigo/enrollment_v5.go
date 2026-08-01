package lattigospike

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"
)

const (
	// EnrollmentV5Version is the enrollment schema that carries a session
	// binding. A V1 enrollment is not upgradable to it: the missing fields are
	// exactly the ones that were unauthenticated, so accepting a V1 enrollment
	// under V5 rules would reintroduce finding H-01.
	EnrollmentV5Version uint16 = 5

	enrollmentV5Domain      = "MordantCiphertextEnrollment/v5"
	sessionBindingV5Domain  = "MordantSessionBinding/v5"
	releaseDescriptorDomain = "MordantReleaseDescriptor/v5"
)

var (
	// ErrEnrollmentNotBound reports an enrollment that carries no usable
	// session binding.
	ErrEnrollmentNotBound = errors.New("enrollment carries no session binding")
	// ErrEnrollmentsNotPaired reports two enrollments that do not cross-certify
	// each other as the two halves of one bilateral session.
	ErrEnrollmentsNotPaired = errors.New("enrollments are not two halves of one session")
)

// SessionBindingV5 is the correction to external audit finding H-01.
//
// In V4 an enrollment authenticated a ciphertext against a policy and a vault,
// and nothing else. Two enrollments issued for two entirely different sessions
// shared that public context, so the evaluator could pair any A with any B and
// both issuer signatures still verified. The pairing was chosen by the
// evaluator and attested by nobody.
//
// Here each side names the session it belongs to AND the counterparty scope it
// expects. The two enrollments therefore cross-certify: A is only pairable with
// a B whose own scope is the counterparty scope A named, and vice versa. There
// is no pair of enrollments from different sessions that satisfies both
// directions.
type SessionBindingV5 struct {
	// The opaque commitment published on chain before any FHE ran.
	SessionCommitment [32]byte
	// The salt-independent one-shot identity of the signed intent.
	SessionNullifier [32]byte
	// This side's scope, and the scope this side expects to be compared against.
	OwnScopeCommitment          [32]byte
	CounterpartyScopeCommitment [32]byte
	// This side's governance authorization and opaque source record.
	GovernanceRecord       [32]byte
	SourceRecordCommitment [32]byte
	// Epochs are bound so a rotation invalidates enrollments rather than
	// silently widening what an old signature authorizes.
	AuthorizationEpoch    uint32
	SubmissionBudgetEpoch uint32
	// 0 or 1. Which side of the comparison this ciphertext occupies.
	InputSlot uint8
}

func (binding SessionBindingV5) validate() error {
	zero := [32]byte{}
	if binding.SessionCommitment == zero || binding.SessionNullifier == zero ||
		binding.OwnScopeCommitment == zero || binding.CounterpartyScopeCommitment == zero ||
		binding.GovernanceRecord == zero || binding.SourceRecordCommitment == zero ||
		binding.AuthorizationEpoch == 0 || binding.SubmissionBudgetEpoch == 0 ||
		binding.InputSlot > 1 {
		return ErrEnrollmentNotBound
	}
	// A side that names itself as its own counterparty is comparing a receivable
	// against itself under two identities.
	if binding.OwnScopeCommitment == binding.CounterpartyScopeCommitment {
		return ErrEnrollmentNotBound
	}
	return nil
}

// Digest is the binding's contribution to the enrollment signature. It is also
// what the release descriptor and the operators re-derive independently.
func (binding SessionBindingV5) Digest() [32]byte {
	encoded := make([]byte, 0, 32*9)
	domain := legacyKeccak([]byte(sessionBindingV5Domain))
	encoded = append(encoded, domain[:]...)
	encoded = append(encoded, binding.SessionCommitment[:]...)
	encoded = append(encoded, binding.SessionNullifier[:]...)
	encoded = append(encoded, binding.OwnScopeCommitment[:]...)
	encoded = append(encoded, binding.CounterpartyScopeCommitment[:]...)
	encoded = append(encoded, binding.GovernanceRecord[:]...)
	encoded = append(encoded, binding.SourceRecordCommitment[:]...)
	encoded = append(encoded, uint32Word(binding.AuthorizationEpoch)...)
	encoded = append(encoded, uint32Word(binding.SubmissionBudgetEpoch)...)
	encoded = append(encoded, uint8Word(binding.InputSlot)...)
	return legacyKeccak(encoded)
}

// CiphertextEnrollmentV5 is the issuer statement accepted at the V5 evaluator
// boundary. Everything the evaluator will later rely on is inside the signature.
type CiphertextEnrollmentV5 struct {
	Version uint16
	Binding SessionBindingV5
	// The circuit this enrollment consents to. An operator that recomputes a
	// different circuit version refuses to release.
	CircuitVersion uint32
	// The exact ciphertext, and the provider-independent input commitment the
	// on-chain result will carry.
	CiphertextDigest [32]byte
	InputCommitment  [32]byte

	KeyID                [32]byte
	ParameterFingerprint [32]byte
	PolicyID             [32]byte
	PolicyVersion        uint32
	IdentityMode         IdentityMode

	AuthorizationClaim      AuthorizationClaim
	AuthorizationCommitment [32]byte

	IssuerKeyID [32]byte
	IssuedAt    uint64
	ValidUntil  uint64
	Nonce       [32]byte
}

type SignedCiphertextEnrollmentV5 struct {
	Enrollment CiphertextEnrollmentV5
	Signature  [ed25519.SignatureSize]byte
}

func (enrollment CiphertextEnrollmentV5) validate() error {
	zero := [32]byte{}
	if enrollment.Version != EnrollmentV5Version {
		return ErrMalformedEnrollment
	}
	if err := enrollment.Binding.validate(); err != nil {
		return err
	}
	if enrollment.CircuitVersion != CircuitV5Version {
		return ErrMalformedEnrollment
	}
	if enrollment.CiphertextDigest == zero || enrollment.InputCommitment == zero ||
		enrollment.KeyID == zero || enrollment.ParameterFingerprint == zero ||
		enrollment.PolicyID == zero || enrollment.PolicyVersion != PolicyVersion ||
		enrollment.AuthorizationCommitment == zero || enrollment.IssuerKeyID == zero ||
		enrollment.IssuedAt == 0 || enrollment.ValidUntil == 0 ||
		enrollment.IssuedAt > enrollment.ValidUntil || enrollment.Nonce == zero {
		return ErrMalformedEnrollment
	}
	// V5 always compares the strict identifier under FHE. Mode A compared a
	// public commitment, which is what made the identity join-able off-chain.
	if enrollment.IdentityMode != IdentityFullFHE256 {
		return ErrMalformedEnrollment
	}
	claim := enrollment.AuthorizationClaim
	if claim.SubjectCommitment == zero || claim.Role == zero || claim.Vault == ([20]byte{}) ||
		claim.PolicyID != enrollment.PolicyID || claim.PolicyVersion != enrollment.PolicyVersion ||
		claim.ValidUntil == 0 || claim.ValidUntil < enrollment.ValidUntil {
		return ErrUnauthorizedIngress
	}
	return nil
}

// SigningDigest uses the same fixed-width, big-endian, domain-separated
// encoding as V1, so there is no JSON or map-ordering ambiguity at the trust
// boundary.
func (enrollment CiphertextEnrollmentV5) SigningDigest() [32]byte {
	encoded := make([]byte, 0, 32*24)
	domain := legacyKeccak([]byte(enrollmentV5Domain))
	bindingDigest := enrollment.Binding.Digest()
	encoded = append(encoded, domain[:]...)
	encoded = append(encoded, uint16Word(enrollment.Version)...)
	encoded = append(encoded, bindingDigest[:]...)
	encoded = append(encoded, uint32Word(enrollment.CircuitVersion)...)
	encoded = append(encoded, enrollment.CiphertextDigest[:]...)
	encoded = append(encoded, enrollment.InputCommitment[:]...)
	encoded = append(encoded, enrollment.KeyID[:]...)
	encoded = append(encoded, enrollment.ParameterFingerprint[:]...)
	encoded = append(encoded, enrollment.PolicyID[:]...)
	encoded = append(encoded, uint32Word(enrollment.PolicyVersion)...)
	encoded = append(encoded, identityModeWord(enrollment.IdentityMode)...)
	claim := enrollment.AuthorizationClaim
	encoded = append(encoded, claim.SubjectCommitment[:]...)
	encoded = append(encoded, claim.Role[:]...)
	encoded = append(encoded, addressWord(claim.Vault)...)
	encoded = append(encoded, claim.PolicyID[:]...)
	encoded = append(encoded, uint32Word(claim.PolicyVersion)...)
	encoded = append(encoded, uint64Word(claim.ValidUntil)...)
	encoded = append(encoded, uint256Word(claim.Nonce)...)
	encoded = append(encoded, enrollment.AuthorizationCommitment[:]...)
	encoded = append(encoded, enrollment.IssuerKeyID[:]...)
	encoded = append(encoded, uint64Word(enrollment.IssuedAt)...)
	encoded = append(encoded, uint64Word(enrollment.ValidUntil)...)
	encoded = append(encoded, enrollment.Nonce[:]...)
	return legacyKeccak(encoded)
}

// SignEnrollmentV5 is used by the authorized ingress issuer once it has checked
// the private source facts and the authorization claim.
func SignEnrollmentV5(enrollment CiphertextEnrollmentV5, issuerPrivateKey ed25519.PrivateKey) (*SignedCiphertextEnrollmentV5, error) {
	if len(issuerPrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrMalformedEnrollment
	}
	publicKey, ok := issuerPrivateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrMalformedEnrollment
	}
	enrollment.Version = EnrollmentV5Version
	enrollment.CircuitVersion = CircuitV5Version
	enrollment.IssuerKeyID = sha256.Sum256(publicKey)
	if err := enrollment.validate(); err != nil {
		return nil, err
	}
	digest := enrollment.SigningDigest()
	signed := &SignedCiphertextEnrollmentV5{Enrollment: enrollment}
	copy(signed.Signature[:], ed25519.Sign(issuerPrivateKey, digest[:]))
	return signed, nil
}

// PairedEnrollmentsV5 is the verified two-sided authorization for one session.
type PairedEnrollmentsV5 struct {
	SessionCommitment [32]byte
	SessionNullifier  [32]byte
	EnrollmentDigestA [32]byte
	EnrollmentDigestB [32]byte
	ScopeCommitmentA  [32]byte
	ScopeCommitmentB  [32]byte
	InputCommitmentA  [32]byte
	InputCommitmentB  [32]byte
	CiphertextDigestA [32]byte
	CiphertextDigestB [32]byte
}

// PairEnrollmentsV5 checks that two signed enrollments are the two halves of
// one bilateral session, and nothing weaker.
//
// This is the H-01 gate. Every clause below is a way two enrollments from
// different sessions could otherwise have been paired by the evaluator.
func PairEnrollmentsV5(a, b *SignedCiphertextEnrollmentV5) (PairedEnrollmentsV5, error) {
	var paired PairedEnrollmentsV5
	if a == nil || b == nil {
		return paired, ErrMalformedEnrollment
	}
	left, right := a.Enrollment, b.Enrollment
	if err := left.validate(); err != nil {
		return paired, err
	}
	if err := right.validate(); err != nil {
		return paired, err
	}

	lb, rb := left.Binding, right.Binding
	// Same session, by commitment and by the salt-independent nullifier.
	if lb.SessionCommitment != rb.SessionCommitment || lb.SessionNullifier != rb.SessionNullifier {
		return paired, ErrEnrollmentsNotPaired
	}
	// Cross-certification. Each side must be the counterparty the other named.
	if lb.OwnScopeCommitment != rb.CounterpartyScopeCommitment ||
		rb.OwnScopeCommitment != lb.CounterpartyScopeCommitment {
		return paired, ErrEnrollmentsNotPaired
	}
	// Two distinct sides, two distinct governance records, two distinct sources.
	if lb.OwnScopeCommitment == rb.OwnScopeCommitment ||
		lb.GovernanceRecord == rb.GovernanceRecord ||
		lb.SourceRecordCommitment == rb.SourceRecordCommitment {
		return paired, ErrEnrollmentsNotPaired
	}
	// Exactly slots 0 and 1, in that order.
	if lb.InputSlot != 0 || rb.InputSlot != 1 {
		return paired, ErrEnrollmentsNotPaired
	}
	// One epoch pair for the whole session; a rotation between the two
	// enrollments invalidates the session rather than being averaged over.
	if lb.AuthorizationEpoch != rb.AuthorizationEpoch ||
		lb.SubmissionBudgetEpoch != rb.SubmissionBudgetEpoch {
		return paired, ErrEnrollmentsNotPaired
	}
	// One key epoch, one parameter set, one circuit, one policy.
	if left.KeyID != right.KeyID || left.ParameterFingerprint != right.ParameterFingerprint ||
		left.CircuitVersion != right.CircuitVersion || left.PolicyID != right.PolicyID ||
		left.PolicyVersion != right.PolicyVersion || left.IdentityMode != right.IdentityMode {
		return paired, ErrEnrollmentsNotPaired
	}
	// Two different ciphertexts, two different issuer nonces. Equality here
	// means one input was submitted twice under two identities.
	if subtle.ConstantTimeCompare(left.CiphertextDigest[:], right.CiphertextDigest[:]) == 1 ||
		left.Nonce == right.Nonce || left.InputCommitment == right.InputCommitment {
		return paired, ErrEnrollmentReplay
	}

	digestA := left.SigningDigest()
	digestB := right.SigningDigest()
	if digestA == digestB {
		return paired, ErrEnrollmentReplay
	}
	return PairedEnrollmentsV5{
		SessionCommitment: lb.SessionCommitment,
		SessionNullifier:  lb.SessionNullifier,
		EnrollmentDigestA: digestA,
		EnrollmentDigestB: digestB,
		ScopeCommitmentA:  lb.OwnScopeCommitment,
		ScopeCommitmentB:  rb.OwnScopeCommitment,
		InputCommitmentA:  left.InputCommitment,
		InputCommitmentB:  right.InputCommitment,
		CiphertextDigestA: left.CiphertextDigest,
		CiphertextDigestB: right.CiphertextDigest,
	}, nil
}

// VerifyEnrollmentV5 checks one enrollment's issuer signature and validity
// window against the runtime's trust store.
func (r *Runtime) VerifyEnrollmentV5(signed *SignedCiphertextEnrollmentV5, now time.Time) ([32]byte, error) {
	var zero [32]byte
	if signed == nil {
		return zero, ErrMalformedEnrollment
	}
	enrollment := signed.Enrollment
	if err := enrollment.validate(); err != nil {
		return zero, err
	}
	if enrollment.KeyID != r.keyIDBytes || enrollment.ParameterFingerprint != r.parameterFingerprint {
		return zero, ErrWrongKeyID
	}
	nowUnix := now.Unix()
	if nowUnix < 0 || uint64(nowUnix) < enrollment.IssuedAt || uint64(nowUnix) > enrollment.ValidUntil {
		return zero, ErrExpired
	}
	authorizationCommitment, err := enrollmentAuthorizationCommitment(enrollment.AuthorizationClaim, r.keyIDBytes)
	if err != nil || subtle.ConstantTimeCompare(authorizationCommitment[:], enrollment.AuthorizationCommitment[:]) != 1 {
		return zero, ErrUnauthorizedIngress
	}

	r.issuerMu.RLock()
	issuer, exists := r.trustedIssuers[enrollment.IssuerKeyID]
	r.issuerMu.RUnlock()
	if !exists {
		return zero, ErrUnknownIssuer
	}
	if issuer.revoked {
		return zero, ErrRevokedIssuer
	}
	if enrollment.IssuedAt < issuer.validFrom || enrollment.ValidUntil > issuer.validUntil ||
		uint64(nowUnix) < issuer.validFrom || uint64(nowUnix) > issuer.validUntil {
		return zero, ErrExpired
	}
	digest := enrollment.SigningDigest()
	if !ed25519.Verify(issuer.publicKey, digest[:], signed.Signature[:]) {
		return zero, ErrInvalidSignature
	}
	return digest, nil
}

// ReleaseDescriptorV5 is what a quorum of operators signs, and the only thing
// that authorizes a decryption share.
//
// It binds both enrollment digests, so an operator can verify that the pair it
// is being asked to release for is the pair the issuer actually authorized, and
// binds the recomputed output digest, so it cannot be pointed at a ciphertext
// the operator did not compute itself.
type ReleaseDescriptorV5 struct {
	SessionCommitment    [32]byte
	SessionNullifier     [32]byte
	EnrollmentDigestA    [32]byte
	EnrollmentDigestB    [32]byte
	InputsDigest         [32]byte
	OutputsDigest        [32]byte
	CircuitVersion       uint32
	KeyID                [32]byte
	ParameterFingerprint [32]byte
	PolicyID             [32]byte
	PolicyVersion        uint32
	ExpiresAt            uint64
}

func (descriptor ReleaseDescriptorV5) validate() error {
	zero := [32]byte{}
	if descriptor.SessionCommitment == zero || descriptor.SessionNullifier == zero ||
		descriptor.EnrollmentDigestA == zero || descriptor.EnrollmentDigestB == zero ||
		descriptor.EnrollmentDigestA == descriptor.EnrollmentDigestB ||
		descriptor.InputsDigest == zero || descriptor.OutputsDigest == zero ||
		descriptor.CircuitVersion != CircuitV5Version || descriptor.KeyID == zero ||
		descriptor.ParameterFingerprint == zero || descriptor.PolicyID == zero ||
		descriptor.PolicyVersion != PolicyVersion || descriptor.ExpiresAt == 0 {
		return ErrMalformedEnrollment
	}
	return nil
}

// Digest is the value operators compare and sign. Two descriptors that differ
// in any bound field are different releases.
func (descriptor ReleaseDescriptorV5) Digest() ([32]byte, error) {
	if err := descriptor.validate(); err != nil {
		return [32]byte{}, err
	}
	encoded := make([]byte, 0, 32*13)
	domain := legacyKeccak([]byte(releaseDescriptorDomain))
	encoded = append(encoded, domain[:]...)
	encoded = append(encoded, descriptor.SessionCommitment[:]...)
	encoded = append(encoded, descriptor.SessionNullifier[:]...)
	encoded = append(encoded, descriptor.EnrollmentDigestA[:]...)
	encoded = append(encoded, descriptor.EnrollmentDigestB[:]...)
	encoded = append(encoded, descriptor.InputsDigest[:]...)
	encoded = append(encoded, descriptor.OutputsDigest[:]...)
	encoded = append(encoded, uint32Word(descriptor.CircuitVersion)...)
	encoded = append(encoded, descriptor.KeyID[:]...)
	encoded = append(encoded, descriptor.ParameterFingerprint[:]...)
	encoded = append(encoded, descriptor.PolicyID[:]...)
	encoded = append(encoded, uint32Word(descriptor.PolicyVersion)...)
	encoded = append(encoded, uint64Word(descriptor.ExpiresAt)...)
	return legacyKeccak(encoded), nil
}
