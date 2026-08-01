package lattigospike

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestSignedCiphertextEnrollmentBinaryRoundTripIsStrict(t *testing.T) {
	_, _, _, signedA, _ := externalEnrollmentTransportFixture(t)
	wire, err := signedA.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != signedEnrollmentWireSize {
		t.Fatalf("wire length=%d want=%d", len(wire), signedEnrollmentWireSize)
	}
	decoded, err := UnmarshalSignedCiphertextEnrollment(wire)
	if err != nil {
		t.Fatal(err)
	}
	if *decoded != *signedA {
		t.Fatal("canonical enrollment round-trip changed signed fields")
	}
	reencoded, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if string(reencoded) != string(wire) {
		t.Fatal("enrollment encoding is not deterministic")
	}

	for cut := 0; cut < len(wire); cut++ {
		if _, err := UnmarshalSignedCiphertextEnrollment(wire[:cut]); !errors.Is(err, ErrMalformedEnrollment) {
			t.Fatalf("truncation at byte %d accepted: %v", cut, err)
		}
	}
	trailing := append(append([]byte(nil), wire...), 0)
	if _, err := UnmarshalSignedCiphertextEnrollment(trailing); !errors.Is(err, ErrMalformedEnrollment) {
		t.Fatalf("trailing byte accepted: %v", err)
	}

	badMagic := append([]byte(nil), wire...)
	badMagic[0] ^= 0x80
	if _, err := UnmarshalSignedCiphertextEnrollment(badMagic); !errors.Is(err, ErrMalformedEnrollment) {
		t.Fatalf("bad magic accepted: %v", err)
	}
	badMode := append([]byte(nil), wire...)
	const modeOffset = 4 + 2 + 32 + 32 + 32 + 4
	badMode[modeOffset] = 0xff
	if _, err := UnmarshalSignedCiphertextEnrollment(badMode); !errors.Is(err, ErrMalformedEnrollment) {
		t.Fatalf("unknown identity mode accepted: %v", err)
	}
}

func TestVerifiedExternalInputCommitmentsUseSignedContextsWithoutConsumption(t *testing.T) {
	runtime, client, request, signedA, signedB := externalEnrollmentTransportFixture(t)
	now := request.ValidUntil.Add(-2 * time.Minute)

	expectedA, err := client.CanonicalInputCommitment(request.A, signedA.Enrollment.InputContext)
	if err != nil {
		t.Fatal(err)
	}
	expectedB, err := client.CanonicalInputCommitment(request.B, signedB.Enrollment.InputContext)
	if err != nil {
		t.Fatal(err)
	}
	gotA, gotB, err := runtime.VerifiedExternalInputCommitments(request, now)
	if err != nil {
		t.Fatal(err)
	}
	if gotA != expectedA || gotB != expectedB {
		t.Fatal("runtime did not derive commitments from signed input contexts")
	}
	// Preflight is repeatable and does not reserve either enrollment.
	if againA, againB, err := runtime.VerifiedExternalInputCommitments(request, now); err != nil || againA != gotA || againB != gotB {
		t.Fatalf("repeatable preflight failed: %v", err)
	}
	if _, _, err := runtime.Evaluate(request, now); err != nil {
		t.Fatalf("preflight consumed an enrollment: %v", err)
	}
}

func TestVerifiedExternalInputCommitmentsRejectTampering(t *testing.T) {
	runtime, _, request, signedA, _ := externalEnrollmentTransportFixture(t)
	now := request.ValidUntil.Add(-2 * time.Minute)

	tamperedContext := *signedA
	tamperedContext.Enrollment.InputContext.ClientNonce[3]++
	request.EnrollmentA = &tamperedContext
	if _, _, err := runtime.VerifiedExternalInputCommitments(request, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered signed context accepted: %v", err)
	}

	request.EnrollmentA = signedA
	tamperedPledge, err := cloneCipherPledge(request.A)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPledge.PrivateMetadataCommitment[0] ^= 0x80
	request.A = tamperedPledge
	if _, _, err := runtime.VerifiedExternalInputCommitments(request, now); !errors.Is(err, ErrMalformedEnrollment) {
		t.Fatalf("pledge not bound to enrollment accepted: %v", err)
	}
}

func externalEnrollmentTransportFixture(t *testing.T) (*Runtime, *ExternalClient, EvaluationRequest, *SignedCiphertextEnrollment, *SignedCiphertextEnrollment) {
	t.Helper()
	runtime := sharedTestRuntime(t)
	material, err := runtime.ExportPublicEncryptionMaterial()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewExternalClient(material)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_020_000, 0)
	issuerPrivateKey := deterministicIssuerKey("enrollment-transport-issuer")
	if _, err := runtime.RegisterEnrollmentIssuer(issuerPrivateKey.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	a, b := fixturePair("enrollment-transport")
	contextA, contextB := enrollmentContexts()
	claimA := enrollmentClaim("transport-a", contextA, uint64(now.Add(10*time.Minute).Unix()), 71)
	claimB := enrollmentClaim("transport-b", contextB, uint64(now.Add(10*time.Minute).Unix()), 72)
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
	signedA := signTestEnrollment(t, client, encA, contextA, claimA, now, 73, issuerPrivateKey)
	signedB := signTestEnrollment(t, client, encB, contextB, claimB, now, 74, issuerPrivateKey)
	request := fixtureRequest(runtime, "enrollment-transport-request", encA, encB, now)
	request.EnrollmentA = signedA
	request.EnrollmentB = signedB
	return runtime, client, request, signedA, signedB
}
