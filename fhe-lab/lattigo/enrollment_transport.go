package lattigospike

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	signedEnrollmentMagic = "MCE1"
	// The enrollment wire format is deliberately fixed-width. This gives the
	// gateway and evaluator one canonical byte representation and lets the
	// decoder reject truncation and extension before allocating anything.
	signedEnrollmentWireSize = 4 + 2 + 32 + 32 + 32 + 4 + 1 +
		32 + 20 + 32 + 4 + 1 + 32 +
		32 + 32 + 20 + 32 + 4 + 8 + 32 +
		32 + 32 + 8 + 8 + 32 + 64
)

// MarshalBinary encodes a signed ciphertext enrollment in its canonical,
// versioned fixed-width transport representation. The signed statement is
// validated structurally before it crosses the process boundary; signature
// and issuer trust are verified by Runtime at evaluation time.
func (signed SignedCiphertextEnrollment) MarshalBinary() ([]byte, error) {
	if err := validateEnrollmentShape(signed.Enrollment); err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.Grow(signedEnrollmentWireSize)
	out.WriteString(signedEnrollmentMagic)
	enrollment := signed.Enrollment
	writeEnrollmentUint(&out, enrollment.Version)
	out.Write(enrollment.CiphertextDigest[:])
	out.Write(enrollment.KeyID[:])
	out.Write(enrollment.ParameterFingerprint[:])
	writeEnrollmentUint(&out, enrollment.PolicyVersion)
	mode, err := identityModeDiscriminator(enrollment.IdentityMode)
	if err != nil {
		return nil, err
	}
	out.WriteByte(mode)
	writeUint256(&out, enrollment.InputContext.ChainID)
	out.Write(enrollment.InputContext.Vault[:])
	out.Write(enrollment.InputContext.PolicyID[:])
	writeEnrollmentUint(&out, enrollment.InputContext.PolicyVersion)
	out.WriteByte(enrollment.InputContext.InputSlot)
	writeUint256(&out, enrollment.InputContext.ClientNonce)
	out.Write(enrollment.AuthorizationClaim.SubjectCommitment[:])
	out.Write(enrollment.AuthorizationClaim.Role[:])
	out.Write(enrollment.AuthorizationClaim.Vault[:])
	out.Write(enrollment.AuthorizationClaim.PolicyID[:])
	writeEnrollmentUint(&out, enrollment.AuthorizationClaim.PolicyVersion)
	writeEnrollmentUint(&out, enrollment.AuthorizationClaim.ValidUntil)
	writeUint256(&out, enrollment.AuthorizationClaim.Nonce)
	out.Write(enrollment.AuthorizationCommitment[:])
	out.Write(enrollment.IssuerKeyID[:])
	writeEnrollmentUint(&out, enrollment.IssuedAt)
	writeEnrollmentUint(&out, enrollment.ValidUntil)
	out.Write(enrollment.Nonce[:])
	out.Write(signed.Signature[:])
	if out.Len() != signedEnrollmentWireSize {
		return nil, fmt.Errorf("%w: invalid enrollment wire length", ErrMalformedEnrollment)
	}
	return out.Bytes(), nil
}

// UnmarshalSignedCiphertextEnrollment decodes only the exact canonical wire
// size. It rejects unknown identity-mode discriminators, malformed fields,
// truncation and trailing bytes. Cryptographic trust is intentionally checked
// later against the Runtime issuer registry and the exact CipherPledge.
func UnmarshalSignedCiphertextEnrollment(data []byte) (*SignedCiphertextEnrollment, error) {
	if len(data) != signedEnrollmentWireSize {
		return nil, fmt.Errorf("%w: invalid enrollment wire size", ErrMalformedEnrollment)
	}
	reader := bytes.NewReader(data)
	magic := make([]byte, len(signedEnrollmentMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != signedEnrollmentMagic {
		return nil, fmt.Errorf("%w: invalid enrollment wire header", ErrMalformedEnrollment)
	}

	signed := new(SignedCiphertextEnrollment)
	enrollment := &signed.Enrollment
	if err := readEnrollmentUint(reader, &enrollment.Version); err != nil ||
		readEnrollmentExact(reader, enrollment.CiphertextDigest[:]) != nil ||
		readEnrollmentExact(reader, enrollment.KeyID[:]) != nil ||
		readEnrollmentExact(reader, enrollment.ParameterFingerprint[:]) != nil ||
		readEnrollmentUint(reader, &enrollment.PolicyVersion) != nil {
		return nil, fmt.Errorf("%w: truncated enrollment header", ErrMalformedEnrollment)
	}
	mode, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("%w: truncated enrollment identity mode", ErrMalformedEnrollment)
	}
	enrollment.IdentityMode, err = identityModeFromDiscriminator(mode)
	if err != nil {
		return nil, err
	}
	if err := readUint256(reader, &enrollment.InputContext.ChainID); err != nil ||
		readEnrollmentExact(reader, enrollment.InputContext.Vault[:]) != nil ||
		readEnrollmentExact(reader, enrollment.InputContext.PolicyID[:]) != nil ||
		readEnrollmentUint(reader, &enrollment.InputContext.PolicyVersion) != nil {
		return nil, fmt.Errorf("%w: truncated enrollment input context", ErrMalformedEnrollment)
	}
	inputSlot, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("%w: truncated enrollment input slot", ErrMalformedEnrollment)
	}
	enrollment.InputContext.InputSlot = inputSlot
	if err := readUint256(reader, &enrollment.InputContext.ClientNonce); err != nil ||
		readEnrollmentExact(reader, enrollment.AuthorizationClaim.SubjectCommitment[:]) != nil ||
		readEnrollmentExact(reader, enrollment.AuthorizationClaim.Role[:]) != nil ||
		readEnrollmentExact(reader, enrollment.AuthorizationClaim.Vault[:]) != nil ||
		readEnrollmentExact(reader, enrollment.AuthorizationClaim.PolicyID[:]) != nil ||
		readEnrollmentUint(reader, &enrollment.AuthorizationClaim.PolicyVersion) != nil ||
		readEnrollmentUint(reader, &enrollment.AuthorizationClaim.ValidUntil) != nil ||
		readUint256(reader, &enrollment.AuthorizationClaim.Nonce) != nil {
		return nil, fmt.Errorf("%w: truncated enrollment authorization claim", ErrMalformedEnrollment)
	}
	if readEnrollmentExact(reader, enrollment.AuthorizationCommitment[:]) != nil ||
		readEnrollmentExact(reader, enrollment.IssuerKeyID[:]) != nil ||
		readEnrollmentUint(reader, &enrollment.IssuedAt) != nil ||
		readEnrollmentUint(reader, &enrollment.ValidUntil) != nil ||
		readEnrollmentExact(reader, enrollment.Nonce[:]) != nil ||
		readEnrollmentExact(reader, signed.Signature[:]) != nil || reader.Len() != 0 {
		return nil, fmt.Errorf("%w: truncated or trailing enrollment payload", ErrMalformedEnrollment)
	}
	if err := validateEnrollmentShape(*enrollment); err != nil {
		return nil, err
	}
	return signed, nil
}

// VerifiedExternalInputCommitments verifies the complete signed binding of
// both externally encrypted pledges and derives their public commitments only
// from the contexts carried inside those signed enrollments. It performs no
// nonce/enrollment reservation and is therefore safe for deterministic
// preflight, durable logging and result construction before Evaluate commits
// the one-shot request.
func (r *Runtime) VerifiedExternalInputCommitments(request EvaluationRequest, now time.Time) ([32]byte, [32]byte, error) {
	var zero [32]byte
	if request.A == nil || request.B == nil || request.EnrollmentA == nil || request.EnrollmentB == nil || request.KeyID != r.keyID {
		return zero, zero, ErrMalformedEnrollment
	}
	ids, err := r.externalEnrollmentIDs(request, now)
	if err != nil {
		return zero, zero, err
	}
	if len(ids) != 2 {
		return zero, zero, ErrMalformedEnrollment
	}
	commitmentA, err := r.CanonicalInputCommitment(request.A, request.EnrollmentA.Enrollment.InputContext)
	if err != nil {
		return zero, zero, err
	}
	commitmentB, err := r.CanonicalInputCommitment(request.B, request.EnrollmentB.Enrollment.InputContext)
	if err != nil {
		return zero, zero, err
	}
	return commitmentA, commitmentB, nil
}

func identityModeDiscriminator(mode IdentityMode) (byte, error) {
	switch mode {
	case IdentityPublicCommitment:
		return 1, nil
	case IdentityFullFHE256:
		return 2, nil
	default:
		return 0, ErrMalformedEnrollment
	}
}

func identityModeFromDiscriminator(value byte) (IdentityMode, error) {
	switch value {
	case 1:
		return IdentityPublicCommitment, nil
	case 2:
		return IdentityFullFHE256, nil
	default:
		return "", ErrMalformedEnrollment
	}
}

func writeUint256(out *bytes.Buffer, value Uint256) {
	for _, limb := range value {
		writeEnrollmentUint(out, limb)
	}
}

func readUint256(reader *bytes.Reader, value *Uint256) error {
	for index := range value {
		if err := readEnrollmentUint(reader, &value[index]); err != nil {
			return err
		}
	}
	return nil
}

func writeEnrollmentUint[T uint16 | uint32 | uint64](out *bytes.Buffer, value T) {
	_ = binary.Write(out, binary.BigEndian, value)
}

func readEnrollmentUint[T uint16 | uint32 | uint64](reader *bytes.Reader, value *T) error {
	return binary.Read(reader, binary.BigEndian, value)
}

func readEnrollmentExact(reader *bytes.Reader, target []byte) error {
	_, err := io.ReadFull(reader, target)
	return err
}
