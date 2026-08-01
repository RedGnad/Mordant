package lattigospike

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"time"
)

const (
	EnrollmentVersion uint16 = 1
	enrollmentDomain         = "MordantCiphertextEnrollment/v1"
)

type issuerRecord struct {
	publicKey  ed25519.PublicKey
	validFrom  uint64
	validUntil uint64
	revoked    bool
}

// CiphertextEnrollment is the canonical issuer statement accepted at the
// evaluator boundary. It binds one exact ciphertext to the evaluator key,
// policy, provider-neutral input context and submitter authorization claim.
// IssuedAt and ValidUntil are Unix seconds.
type CiphertextEnrollment struct {
	Version                 uint16
	CiphertextDigest        [32]byte
	KeyID                   [32]byte
	ParameterFingerprint    [32]byte
	PolicyVersion           uint32
	IdentityMode            IdentityMode
	InputContext            InputCommitmentContext
	AuthorizationClaim      AuthorizationClaim
	AuthorizationCommitment [32]byte
	IssuerKeyID             [32]byte
	IssuedAt                uint64
	ValidUntil              uint64
	Nonce                   [32]byte
}

type SignedCiphertextEnrollment struct {
	Enrollment CiphertextEnrollment
	Signature  [ed25519.SignatureSize]byte
}

// RegisterEnrollmentIssuer adds a bounded Ed25519 issuer key to the
// evaluator's trust store. The returned ID is sha256(publicKey). A revoked key
// cannot be silently re-enabled by registering it again on the same runtime.
func (r *Runtime) RegisterEnrollmentIssuer(publicKey ed25519.PublicKey, validFrom, validUntil time.Time) ([32]byte, error) {
	var zero [32]byte
	if len(publicKey) != ed25519.PublicKeySize || validFrom.Unix() < 0 || validUntil.Unix() < 0 || !validFrom.Before(validUntil) {
		return zero, ErrUnknownIssuer
	}
	keyID := sha256.Sum256(publicKey)
	r.issuerMu.Lock()
	defer r.issuerMu.Unlock()
	if current, exists := r.trustedIssuers[keyID]; exists && current.revoked {
		return zero, ErrRevokedIssuer
	}
	keyCopy := append(ed25519.PublicKey(nil), publicKey...)
	r.trustedIssuers[keyID] = issuerRecord{
		publicKey:  keyCopy,
		validFrom:  uint64(validFrom.Unix()),
		validUntil: uint64(validUntil.Unix()),
	}
	return keyID, nil
}

func (r *Runtime) RevokeEnrollmentIssuer(keyID [32]byte) error {
	r.issuerMu.Lock()
	defer r.issuerMu.Unlock()
	record, exists := r.trustedIssuers[keyID]
	if !exists {
		return ErrUnknownIssuer
	}
	record.revoked = true
	r.trustedIssuers[keyID] = record
	return nil
}

// SignCiphertextEnrollment is intended for the authorized ingress issuer,
// after it has validated the private source facts and authorization claim. The
// evaluator does not accept a client-provided authorization Boolean.
func SignCiphertextEnrollment(
	client *ExternalClient,
	pledge *CipherPledge,
	mode IdentityMode,
	context InputCommitmentContext,
	claim AuthorizationClaim,
	issuedAt, validUntil time.Time,
	nonce [32]byte,
	issuerPrivateKey ed25519.PrivateKey,
) (*SignedCiphertextEnrollment, error) {
	if client == nil || pledge == nil || len(issuerPrivateKey) != ed25519.PrivateKeySize || issuedAt.Unix() < 0 || validUntil.Unix() < 0 || issuedAt.After(validUntil) || nonce == ([32]byte{}) {
		return nil, ErrMalformedEnrollment
	}
	if pledge.KeyID != client.KeyID() || pledge.ParameterFingerprint != client.ParameterFingerprint() || context.PolicyVersion != PolicyVersion {
		return nil, ErrWrongKeyID
	}
	if (mode == IdentityPublicCommitment && pledge.ReceivableIDBits != nil) || (mode == IdentityFullFHE256 && pledge.ReceivableIDBits == nil) {
		return nil, ErrMalformedEnrollment
	}
	publicKey, ok := issuerPrivateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrMalformedEnrollment
	}
	authorizationCommitment, err := client.SubmitterAuthorizationCommitment(claim)
	if err != nil || authorizationCommitment != pledge.AuthorizationCommitment {
		return nil, ErrUnauthorizedIngress
	}
	ciphertextDigest, err := cipherPledgeDigestBytes(pledge)
	if err != nil {
		return nil, ErrMalformedEnrollment
	}
	enrollment := CiphertextEnrollment{
		Version:                 EnrollmentVersion,
		CiphertextDigest:        ciphertextDigest,
		KeyID:                   client.KeyIDBytes(),
		ParameterFingerprint:    client.ParameterFingerprint(),
		PolicyVersion:           context.PolicyVersion,
		IdentityMode:            mode,
		InputContext:            context,
		AuthorizationClaim:      claim,
		AuthorizationCommitment: authorizationCommitment,
		IssuerKeyID:             sha256.Sum256(publicKey),
		IssuedAt:                uint64(issuedAt.Unix()),
		ValidUntil:              uint64(validUntil.Unix()),
		Nonce:                   nonce,
	}
	if err := validateEnrollmentShape(enrollment); err != nil {
		return nil, err
	}
	digest := enrollmentSigningDigest(enrollment)
	signed := &SignedCiphertextEnrollment{Enrollment: enrollment}
	copy(signed.Signature[:], ed25519.Sign(issuerPrivateKey, digest[:]))
	return signed, nil
}

func validateEnrollmentShape(enrollment CiphertextEnrollment) error {
	zero32 := [32]byte{}
	if enrollment.Version != EnrollmentVersion || enrollment.CiphertextDigest == zero32 || enrollment.KeyID == zero32 || enrollment.ParameterFingerprint == zero32 || enrollment.PolicyVersion != PolicyVersion || enrollment.AuthorizationCommitment == zero32 || enrollment.IssuerKeyID == zero32 || enrollment.IssuedAt == 0 || enrollment.ValidUntil == 0 || enrollment.IssuedAt > enrollment.ValidUntil || enrollment.Nonce == zero32 {
		return ErrMalformedEnrollment
	}
	if enrollment.IdentityMode != IdentityPublicCommitment && enrollment.IdentityMode != IdentityFullFHE256 {
		return ErrMalformedEnrollment
	}
	context := enrollment.InputContext
	claim := enrollment.AuthorizationClaim
	if context.ChainID == (Uint256{}) || context.Vault == ([20]byte{}) || context.PolicyID == zero32 || context.PolicyVersion != enrollment.PolicyVersion || context.InputSlot > 1 {
		return ErrMalformedEnrollment
	}
	if claim.SubjectCommitment == zero32 || claim.Role == zero32 || claim.Vault != context.Vault || claim.PolicyID != context.PolicyID || claim.PolicyVersion != enrollment.PolicyVersion || claim.ValidUntil == 0 || claim.ValidUntil < enrollment.ValidUntil {
		return ErrUnauthorizedIngress
	}
	return nil
}

func enrollmentSigningDigest(enrollment CiphertextEnrollment) [32]byte {
	// Every field uses a fixed-width, big-endian encoding. The identity mode is
	// represented by a single stable discriminator rather than a free-form
	// string, eliminating JSON and map-order ambiguity at the trust boundary.
	encoded := make([]byte, 0, 32*22)
	domain := legacyKeccak([]byte(enrollmentDomain))
	encoded = append(encoded, domain[:]...)
	encoded = append(encoded, uint16Word(enrollment.Version)...)
	encoded = append(encoded, enrollment.CiphertextDigest[:]...)
	encoded = append(encoded, enrollment.KeyID[:]...)
	encoded = append(encoded, enrollment.ParameterFingerprint[:]...)
	encoded = append(encoded, uint32Word(enrollment.PolicyVersion)...)
	encoded = append(encoded, identityModeWord(enrollment.IdentityMode)...)
	context := enrollment.InputContext
	encoded = append(encoded, uint256Word(context.ChainID)...)
	encoded = append(encoded, addressWord(context.Vault)...)
	encoded = append(encoded, context.PolicyID[:]...)
	encoded = append(encoded, uint32Word(context.PolicyVersion)...)
	encoded = append(encoded, uint8Word(context.InputSlot)...)
	encoded = append(encoded, uint256Word(context.ClientNonce)...)
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

func uint16Word(value uint16) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint16(word[30:], value)
	return word
}

func identityModeWord(mode IdentityMode) []byte {
	word := make([]byte, 32)
	switch mode {
	case IdentityPublicCommitment:
		word[31] = 1
	case IdentityFullFHE256:
		word[31] = 2
	}
	return word
}

func (r *Runtime) verifyExternalEnrollment(pledge *CipherPledge, signed *SignedCiphertextEnrollment, request EvaluationRequest, expectedSlot uint8, now time.Time) ([32]byte, error) {
	var zero [32]byte
	if signed == nil {
		return zero, ErrMalformedEnrollment
	}
	enrollment := signed.Enrollment
	if err := validateEnrollmentShape(enrollment); err != nil {
		return zero, err
	}
	if enrollment.KeyID != r.keyIDBytes || enrollment.ParameterFingerprint != r.parameterFingerprint || pledge.KeyID != r.keyID || pledge.ParameterFingerprint != r.parameterFingerprint {
		return zero, ErrWrongKeyID
	}
	if enrollment.PolicyVersion != request.PolicyVersion || enrollment.IdentityMode != request.IdentityMode || enrollment.InputContext.PolicyVersion != request.PolicyVersion || enrollment.InputContext.InputSlot != expectedSlot {
		return zero, ErrWrongPolicy
	}
	if request.ValidUntil.Unix() < 0 || uint64(request.ValidUntil.Unix()) > enrollment.ValidUntil {
		return zero, ErrExpired
	}
	nowUnix := now.Unix()
	if nowUnix < 0 || uint64(nowUnix) < enrollment.IssuedAt || uint64(nowUnix) > enrollment.ValidUntil {
		return zero, ErrExpired
	}
	ciphertextDigest, err := cipherPledgeDigestBytes(pledge)
	if err != nil {
		return zero, ErrMalformedEnrollment
	}
	if subtle.ConstantTimeCompare(ciphertextDigest[:], enrollment.CiphertextDigest[:]) != 1 {
		return zero, ErrMalformedEnrollment
	}
	authorizationCommitment, err := enrollmentAuthorizationCommitment(enrollment.AuthorizationClaim, r.keyIDBytes)
	if err != nil || subtle.ConstantTimeCompare(authorizationCommitment[:], enrollment.AuthorizationCommitment[:]) != 1 || subtle.ConstantTimeCompare(authorizationCommitment[:], pledge.AuthorizationCommitment[:]) != 1 {
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
	if enrollment.IssuedAt < issuer.validFrom || enrollment.ValidUntil > issuer.validUntil || uint64(nowUnix) < issuer.validFrom || uint64(nowUnix) > issuer.validUntil {
		return zero, ErrExpired
	}
	digest := enrollmentSigningDigest(enrollment)
	if !ed25519.Verify(issuer.publicKey, digest[:], signed.Signature[:]) {
		return zero, ErrInvalidSignature
	}
	return digest, nil
}

func enrollmentAuthorizationCommitment(claim AuthorizationClaim, keyID [32]byte) ([32]byte, error) {
	var zero [32]byte
	if keyID == zero || claim.SubjectCommitment == zero || claim.Role == zero || claim.Vault == ([20]byte{}) || claim.PolicyID == zero || claim.PolicyVersion != PolicyVersion || claim.ValidUntil == 0 {
		return zero, ErrUnauthorizedIngress
	}
	typeHash := legacyKeccak([]byte(SubmitterAuthorizationType))
	encoded := make([]byte, 0, 9*32)
	encoded = append(encoded, typeHash[:]...)
	encoded = append(encoded, claim.SubjectCommitment[:]...)
	encoded = append(encoded, claim.Role[:]...)
	encoded = append(encoded, addressWord(claim.Vault)...)
	encoded = append(encoded, claim.PolicyID[:]...)
	encoded = append(encoded, uint32Word(claim.PolicyVersion)...)
	encoded = append(encoded, keyID[:]...)
	encoded = append(encoded, uint64Word(claim.ValidUntil)...)
	encoded = append(encoded, uint256Word(claim.Nonce)...)
	return legacyKeccak(encoded), nil
}

func sameEnrollmentContext(a, b CiphertextEnrollment) bool {
	return a.InputContext.ChainID == b.InputContext.ChainID &&
		a.InputContext.Vault == b.InputContext.Vault &&
		a.InputContext.PolicyID == b.InputContext.PolicyID &&
		a.InputContext.PolicyVersion == b.InputContext.PolicyVersion
}

func (r *Runtime) externalEnrollmentIDs(request EvaluationRequest, now time.Time) ([][32]byte, error) {
	hasA, hasB := request.EnrollmentA != nil, request.EnrollmentB != nil
	if !hasA && !hasB {
		return nil, nil
	}
	if !hasA || !hasB {
		return nil, ErrMalformedEnrollment
	}
	if !sameEnrollmentContext(request.EnrollmentA.Enrollment, request.EnrollmentB.Enrollment) {
		return nil, ErrMalformedEnrollment
	}
	idA, err := r.verifyExternalEnrollment(request.A, request.EnrollmentA, request, 0, now)
	if err != nil {
		return nil, err
	}
	idB, err := r.verifyExternalEnrollment(request.B, request.EnrollmentB, request, 1, now)
	if err != nil {
		return nil, err
	}
	if idA == idB {
		return nil, ErrEnrollmentReplay
	}
	return [][32]byte{idA, idB}, nil
}

func (r *Runtime) reserveRequest(nonce [32]byte, enrollmentIDs [][32]byte) error {
	r.nonceMu.Lock()
	defer r.nonceMu.Unlock()
	if _, exists := r.usedNonce[nonce]; exists {
		return ErrReplay
	}
	for _, id := range enrollmentIDs {
		if _, exists := r.usedEnrollments[id]; exists {
			return ErrEnrollmentReplay
		}
	}
	r.usedNonce[nonce] = struct{}{}
	for _, id := range enrollmentIDs {
		r.usedEnrollments[id] = struct{}{}
	}
	return nil
}
