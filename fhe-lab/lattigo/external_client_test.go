package lattigospike

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestExternalClientEncryptsAndSignedEnrollmentsEvaluate(t *testing.T) {
	runtime := sharedTestRuntime(t)
	material, err := runtime.ExportPublicEncryptionMaterial()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewExternalClient(material)
	if err != nil {
		t.Fatal(err)
	}
	if client.KeyID() != runtime.KeyID() || client.KeyIDBytes() != runtime.KeyIDBytes() || client.ParameterFingerprint() != runtime.ParameterFingerprint() {
		t.Fatal("imported client key metadata differs from evaluator")
	}

	now := time.Unix(1_800_000_000, 0)
	issuerPrivateKey := deterministicIssuerKey("external-enrollment-issuer")
	issuerPublicKey := issuerPrivateKey.Public().(ed25519.PublicKey)
	issuerID, err := runtime.RegisterEnrollmentIssuer(issuerPublicKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if issuerID != sha256.Sum256(issuerPublicKey) {
		t.Fatal("issuer key id is not bound to the public key")
	}

	a, b := fixturePair("external-client")
	contextA, contextB := enrollmentContexts()
	claimA := enrollmentClaim("a", contextA, uint64(now.Add(10*time.Minute).Unix()), 11)
	claimB := enrollmentClaim("b", contextB, uint64(now.Add(10*time.Minute).Unix()), 12)
	a.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claimA)
	if err != nil {
		t.Fatal(err)
	}
	b.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claimB)
	if err != nil {
		t.Fatal(err)
	}
	encA, _, err := client.EncryptPledge(a)
	if err != nil {
		t.Fatal(err)
	}
	encB, _, err := client.EncryptPledge(b)
	if err != nil {
		t.Fatal(err)
	}

	// External encryption cannot populate the evaluator's lab-only issuance
	// registry. Even with lab grants, omitting signed enrollments stays closed.
	if err := runtime.GrantIngress(a.AuthorizationCommitment, PolicyVersion, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := runtime.GrantIngress(b.AuthorizationCommitment, PolicyVersion, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	withoutEnrollments := fixtureRequest(runtime, "external-without-enrollment", encA, encB, now)
	if _, _, err := runtime.Evaluate(withoutEnrollments, now); !errors.Is(err, ErrCiphertextNotIssued) {
		t.Fatalf("external ciphertext bypassed enrollment: %v", err)
	}

	enrollmentA := signTestEnrollment(t, client, encA, contextA, claimA, now, 21, issuerPrivateKey)
	enrollmentB := signTestEnrollment(t, client, encB, contextB, claimB, now, 22, issuerPrivateKey)
	request := fixtureRequest(runtime, "external-valid", encA, encB, now)
	request.EnrollmentA, request.EnrollmentB = enrollmentA, enrollmentB
	decision, _, err := runtime.Evaluate(request, now)
	if err != nil {
		t.Fatalf("external evaluation failed: %v", err)
	}
	confirmed, _, err := runtime.DecryptThresholdWithCoalition(decision, 0, 2)
	if err != nil || !confirmed {
		t.Fatalf("wrong external evaluation result: confirmed=%t err=%v", confirmed, err)
	}

	// A new request nonce cannot make the same signed enrollment reusable.
	replay := request
	replay.Nonce = sha256.Sum256([]byte("new-request-nonce-same-enrollments"))
	if _, _, err := runtime.Evaluate(replay, now); !errors.Is(err, ErrEnrollmentReplay) {
		t.Fatalf("expected enrollment replay rejection, got %v", err)
	}
}

func TestExternalEnrollmentFailuresAreFailClosed(t *testing.T) {
	runtime := sharedTestRuntime(t)
	material, err := runtime.ExportPublicEncryptionMaterial()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewExternalClient(material)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_010_000, 0)
	issuerPrivateKey := deterministicIssuerKey("failure-test-issuer")
	if _, err := runtime.RegisterEnrollmentIssuer(issuerPrivateKey.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	a, b := fixturePair("external-failures")
	contextA, contextB := enrollmentContexts()
	claimA := enrollmentClaim("failure-a", contextA, uint64(now.Add(10*time.Minute).Unix()), 31)
	claimB := enrollmentClaim("failure-b", contextB, uint64(now.Add(10*time.Minute).Unix()), 32)
	a.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claimA)
	if err != nil {
		t.Fatal(err)
	}
	b.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claimB)
	if err != nil {
		t.Fatal(err)
	}
	encA, _, err := client.EncryptPledge(a)
	if err != nil {
		t.Fatal(err)
	}
	encB, _, err := client.EncryptPledge(b)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentA := signTestEnrollment(t, client, encA, contextA, claimA, now, 41, issuerPrivateKey)
	enrollmentB := signTestEnrollment(t, client, encB, contextB, claimB, now, 42, issuerPrivateKey)
	base := fixtureRequest(runtime, "external-failure-base", encA, encB, now)
	base.EnrollmentA, base.EnrollmentB = enrollmentA, enrollmentB

	t.Run("one_enrollment_missing", func(t *testing.T) {
		request := base
		request.EnrollmentB = nil
		assertEvaluationError(t, runtime, request, now, ErrMalformedEnrollment)
	})

	t.Run("tampered_signature", func(t *testing.T) {
		request := base
		tampered := *enrollmentA
		tampered.Signature[0] ^= 0x80
		request.EnrollmentA = &tampered
		assertEvaluationError(t, runtime, request, now, ErrInvalidSignature)
	})

	t.Run("ciphertext_digest_mismatch", func(t *testing.T) {
		request := base
		tampered, err := cloneCipherPledge(encA)
		if err != nil {
			t.Fatal(err)
		}
		tampered.PrivateMetadataCommitment[0] ^= 0x80
		request.A = tampered
		assertEvaluationError(t, runtime, request, now, ErrMalformedEnrollment)
	})

	t.Run("input_context_mismatch", func(t *testing.T) {
		request := base
		tampered := *enrollmentB
		tampered.Enrollment.InputContext.ChainID[3]++
		request.EnrollmentB = &tampered
		assertEvaluationError(t, runtime, request, now, ErrMalformedEnrollment)
	})

	t.Run("unknown_issuer", func(t *testing.T) {
		unknownKey := deterministicIssuerKey("unknown-issuer")
		request := base
		request.EnrollmentA = signTestEnrollment(t, client, encA, contextA, claimA, now, 43, unknownKey)
		assertEvaluationError(t, runtime, request, now, ErrUnknownIssuer)
	})

	t.Run("revoked_issuer", func(t *testing.T) {
		revokedKey := deterministicIssuerKey("revoked-issuer")
		revokedID, err := runtime.RegisterEnrollmentIssuer(revokedKey.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.RevokeEnrollmentIssuer(revokedID); err != nil {
			t.Fatal(err)
		}
		request := base
		request.EnrollmentA = signTestEnrollment(t, client, encA, contextA, claimA, now, 44, revokedKey)
		assertEvaluationError(t, runtime, request, now, ErrRevokedIssuer)
	})

	t.Run("expired_enrollment", func(t *testing.T) {
		request := base
		expired, err := SignCiphertextEnrollment(client, encA, IdentityPublicCommitment, contextA, claimA, now.Add(-2*time.Minute), now.Add(-time.Minute), nonce32(45), issuerPrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		request.EnrollmentA = expired
		assertEvaluationError(t, runtime, request, now, ErrExpired)
	})

	// All failed preflight cases leave the valid enrollments unconsumed.
	if _, _, err := runtime.Evaluate(base, now); err != nil {
		t.Fatalf("failed preflight consumed valid enrollment: %v", err)
	}
}

func TestPublicEncryptionMaterialRejectsTampering(t *testing.T) {
	runtime := sharedTestRuntime(t)
	material, err := runtime.ExportPublicEncryptionMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if len(material) == 0 || len(material) >= 16<<20 {
		t.Fatalf("public bundle has implausible size: %d", len(material))
	}
	if _, err := NewExternalClient(material[:len(material)/2]); !errors.Is(err, ErrWrongKeyID) {
		t.Fatalf("truncated public material accepted: %v", err)
	}
	tampered := append([]byte(nil), material...)
	// Key ID metadata immediately follows the magic and variable-length name.
	keyIDLength := int(tampered[len(publicMaterialMagic)])<<8 | int(tampered[len(publicMaterialMagic)+1])
	keyDigestOffset := len(publicMaterialMagic) + 2 + keyIDLength
	tampered[keyDigestOffset] ^= 0x80
	if _, err := NewExternalClient(tampered); !errors.Is(err, ErrWrongKeyID) {
		t.Fatalf("relabeled public material accepted: %v", err)
	}
}

func enrollmentContexts() (InputCommitmentContext, InputCommitmentContext) {
	base := InputCommitmentContext{
		ChainID:       Uint256{0, 0, 0, 31_337},
		Vault:         filled20(0x41),
		PolicyID:      filled32(0x42),
		PolicyVersion: PolicyVersion,
		ClientNonce:   Uint256{0, 0, 0, 101},
	}
	a, b := base, base
	a.InputSlot = 0
	b.InputSlot = 1
	b.ClientNonce = Uint256{0, 0, 0, 102}
	return a, b
}

func enrollmentClaim(label string, context InputCommitmentContext, validUntil uint64, nonce uint64) AuthorizationClaim {
	return AuthorizationClaim{
		SubjectCommitment: sha256.Sum256([]byte("subject-" + label)),
		Role:              sha256.Sum256([]byte("role-" + label)),
		Vault:             context.Vault,
		PolicyID:          context.PolicyID,
		PolicyVersion:     context.PolicyVersion,
		ValidUntil:        validUntil,
		Nonce:             Uint256{0, 0, 0, nonce},
	}
}

func signTestEnrollment(t *testing.T, client *ExternalClient, pledge *CipherPledge, context InputCommitmentContext, claim AuthorizationClaim, now time.Time, nonce uint64, privateKey ed25519.PrivateKey) *SignedCiphertextEnrollment {
	t.Helper()
	signed, err := SignCiphertextEnrollment(client, pledge, IdentityPublicCommitment, context, claim, now.Add(-time.Minute), now.Add(5*time.Minute), nonce32(nonce), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func deterministicIssuerKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func nonce32(value uint64) (out [32]byte) {
	out[24] = byte(value >> 56)
	out[25] = byte(value >> 48)
	out[26] = byte(value >> 40)
	out[27] = byte(value >> 32)
	out[28] = byte(value >> 24)
	out[29] = byte(value >> 16)
	out[30] = byte(value >> 8)
	out[31] = byte(value)
	return out
}

func assertEvaluationError(t *testing.T, runtime *Runtime, request EvaluationRequest, now time.Time, expected error) {
	t.Helper()
	request.Nonce = sha256.Sum256([]byte(t.Name()))
	if _, _, err := runtime.Evaluate(request, now); !errors.Is(err, expected) {
		t.Fatalf("expected %v, got %v", expected, err)
	}
}
