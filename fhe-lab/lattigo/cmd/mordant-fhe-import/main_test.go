package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

func repeatedDigest(value byte) governedfhe.Digest {
	var digest governedfhe.Digest
	for index := range digest {
		digest[index] = value
	}
	return digest
}

func repeatedHex(value string) string { return "0x" + strings.Repeat(value, 64) }

func validImportRequest() participantImportRequest {
	return participantImportRequest{
		SchemaVersion: participantImportRequestSchema, Role: "PARTICIPANT_A",
		CaseID: repeatedHex("1"), AssetIdentity: repeatedHex("2"), CaseBindingDigest: repeatedHex("3"),
		SigningKeyDigest: repeatedHex("4"), BundleDigest: repeatedHex("5"), EncryptionIntentDigest: repeatedHex("6"),
		ClaimCommitment: repeatedHex("7"), SubmissionNonce: repeatedHex("8"), ArtifactDigest: repeatedHex("9"),
		CiphertextDigest: repeatedHex("a"), CiphertextObjectLength: 1024,
		FinalEncryptedAdmissionDigest: repeatedHex("b"),
		EnrollmentSignature:           "0x" + strings.Repeat("c", 128),
		ArtifactObject:                governedfhe.ObjectRef{Path: "submission-a.json", Digest: repeatedDigest(0xcc), Length: 512},
		CiphertextObject:              governedfhe.ObjectRef{Path: "submission-a.bin", Digest: repeatedDigest(0xaa), Length: 1024},
	}
}

func TestImportRequestKeepsSemanticAndTransportArtifactDigestsDistinct(t *testing.T) {
	request := validImportRequest()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeImportRequest(append(encoded, '\n'))
	if err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if decoded.ArtifactDigest != request.ArtifactDigest || decoded.ArtifactObject.Digest != request.ArtifactObject.Digest ||
		decoded.ArtifactDigest == "0x"+strings.TrimPrefix(decoded.ArtifactObject.Digest.String(), "sha256:") {
		t.Fatal("semantic artifact digest was conflated with exact manifest-object digest")
	}
}

func TestImportRequestRejectsRawClaimsExtrasAndTransportSubstitutions(t *testing.T) {
	request := validImportRequest()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{
		`,"activeFrom":100}`, `,"activeUntil":400}`, `,"claim":{"activeFrom":100}}`,
		`,"salt":"` + repeatedHex("d") + `"}`, `,"participantSigningPrivateKey":"secret"}`,
	} {
		candidate := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(extra)...)
		if _, err := decodeImportRequest(candidate); err == nil {
			t.Fatalf("forbidden request member accepted: %s", extra)
		}
	}

	wrongLength := request
	wrongLength.CiphertextObjectLength++
	wrongLengthJSON, _ := json.Marshal(wrongLength)
	if _, err := decodeImportRequest(wrongLengthJSON); err == nil {
		t.Fatal("Phase-2 ciphertext length mismatch accepted")
	}

	traversal := request
	traversal.ArtifactObject.Path = "../submission-a.json"
	traversalJSON, _ := json.Marshal(traversal)
	if _, err := decodeImportRequest(traversalJSON); err == nil {
		t.Fatal("artifact path traversal accepted")
	}

	pretty := &bytes.Buffer{}
	if err := json.Indent(pretty, encoded, "", "  "); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeImportRequest(pretty.Bytes()); err == nil {
		t.Fatal("non-canonical import JSON accepted")
	}
}

func TestStageObjectKindIsServerSelectedFromTheExactRequest(t *testing.T) {
	request := validImportRequest()
	kind, ref, err := stageObjectSelection(request, "artifact-manifest")
	if err != nil || kind != governedfhe.ParticipantOriginatedStageManifest || ref != request.ArtifactObject {
		t.Fatalf("manifest selection mismatch: %s %+v %v", kind, ref, err)
	}
	kind, ref, err = stageObjectSelection(request, "ciphertext")
	if err != nil || kind != governedfhe.ParticipantOriginatedStageCiphertext || ref != request.CiphertextObject {
		t.Fatalf("ciphertext selection mismatch: %s %+v %v", kind, ref, err)
	}
	if _, _, err := stageObjectSelection(request, "../ciphertext"); err == nil {
		t.Fatal("arbitrary object kind accepted")
	}
}

func TestReconcileSkipsExpiredPreverifyAndBindsExactRequestRefs(t *testing.T) {
	request := validImportRequest()
	preverifyCalls := 0
	publishCalls := 0
	reconcileCalls := 0
	expired := errors.New("artifact expired at retry time")
	report, err := executeImportPublication(
		request,
		governedfhe.ParticipantOriginatedPublicationOptions{},
		true,
		func() error { preverifyCalls++; return expired },
		func(governedfhe.ParticipantOriginatedPublicationOptions) (governedfhe.ParticipantOriginatedImportReport, error) {
			publishCalls++
			return governedfhe.ParticipantOriginatedImportReport{}, nil
		},
		func(governedfhe.ParticipantOriginatedPublicationOptions) (governedfhe.ParticipantOriginatedImportReport, error) {
			reconcileCalls++
			return governedfhe.ParticipantOriginatedImportReport{
				ArtifactObject: request.ArtifactObject, CiphertextObject: request.CiphertextObject, Reconciled: true,
			}, nil
		},
	)
	if err != nil || !report.Reconciled || preverifyCalls != 0 || publishCalls != 0 || reconcileCalls != 1 {
		t.Fatalf("post-expiry reconciliation path: %+v pre=%d publish=%d reconcile=%d err=%v", report, preverifyCalls, publishCalls, reconcileCalls, err)
	}

	wrong := request.ArtifactObject
	wrong.Digest = repeatedDigest(0xdd)
	_, err = executeImportPublication(
		request,
		governedfhe.ParticipantOriginatedPublicationOptions{},
		true,
		func() error { return nil },
		func(governedfhe.ParticipantOriginatedPublicationOptions) (governedfhe.ParticipantOriginatedImportReport, error) {
			return governedfhe.ParticipantOriginatedImportReport{}, nil
		},
		func(governedfhe.ParticipantOriginatedPublicationOptions) (governedfhe.ParticipantOriginatedImportReport, error) {
			return governedfhe.ParticipantOriginatedImportReport{ArtifactObject: wrong, CiphertextObject: request.CiphertextObject}, nil
		},
	)
	if !errors.Is(err, governedfhe.ErrParticipantImportMismatch) {
		t.Fatalf("reconciliation accepted another manifest ref: %v", err)
	}
}

// A participant enrollment is what lets the release boundary pair a submission,
// so a request that carries no enrollment signature describes a submission that
// could never be released. It is refused at the transport boundary rather than
// much later.
func TestImportRequestRequiresAnEnrollmentSignature(t *testing.T) {
	for _, supplied := range []struct {
		name  string
		value string
	}{
		{"absent", ""},
		{"truncated", "0x" + strings.Repeat("c", 126)},
		{"not_hex", "0x" + strings.Repeat("z", 128)},
		{"upper_case", "0x" + strings.Repeat("C", 128)},
	} {
		t.Run(supplied.name, func(t *testing.T) {
			request := validImportRequest()
			request.EnrollmentSignature = supplied.value
			encoded, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeImportRequest(append(encoded, '\n')); err == nil {
				t.Fatal("a request with no usable enrollment signature was accepted")
			}
		})
	}
}
