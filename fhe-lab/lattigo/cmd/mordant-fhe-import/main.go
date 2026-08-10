// Command mordant-fhe-import is the standalone coordinator boundary for the
// qualified native-CLI participant-originated profile. It accepts only public authorization
// facts and encrypted object streams; no pledge preimage or participant secret
// is represented by its request schema.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

const (
	// v2 adds the required enrollmentSignature. A v1 request carries no
	// enrollment, and a submission with no enrollment can never be released, so
	// it is rejected by version rather than by a confusing field error.
	participantImportRequestSchema = "mordant.participant-originated-import-request/2"
	maximumArtifactManifestBytes   = int64(4 << 20)
	maximumParticipantCipherBytes  = int64(192 << 20)
)

var importBytes32 = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
var importSignature = regexp.MustCompile(`^0x[0-9a-f]{128}$`)

// participantImportRequest is an internal coordinator request created only
// after the EIP-712 chain has verified. encryptedArtifactDigest is the SHA-256
// of semantic canonical JSON without its storage newline; ArtifactObject is a
// separate exact-byte transport reference and must never be substituted for it.
type participantImportRequest struct {
	SchemaVersion                 string `json:"schemaVersion"`
	Role                          string `json:"role"`
	CaseID                        string `json:"fheCaseId"`
	AssetIdentity                 string `json:"assetIdentityDigest"`
	CaseBindingDigest             string `json:"caseBindingDigest"`
	SigningKeyDigest              string `json:"participantSigningKeyDigest"`
	BundleDigest                  string `json:"clientBundleDigest"`
	EncryptionIntentDigest        string `json:"encryptionIntentDigest"`
	ClaimCommitment               string `json:"claimCommitment"`
	SubmissionNonce               string `json:"submissionNonce"`
	ArtifactDigest                string `json:"encryptedArtifactDigest"`
	CiphertextDigest              string `json:"ciphertextObjectDigest"`
	CiphertextObjectLength        int64  `json:"ciphertextObjectLength"`
	FinalEncryptedAdmissionDigest string `json:"finalEncryptedAdmissionDigest"`
	// The participant's signature over its own V5 enrollment, produced on the
	// participant's machine. Publication re-derives the enrollment locally and
	// refuses a signature that does not verify against it.
	EnrollmentSignature string                `json:"enrollmentSignature"`
	ArtifactObject      governedfhe.ObjectRef `json:"artifactObject"`
	CiphertextObject    governedfhe.ObjectRef `json:"ciphertextObject"`
}

func main() {
	mode := flag.String("mode", "", "stage-object, verify, publish, or reconcile")
	requestPath := flag.String("request", "", "absolute canonical participant import request JSON")
	publicRoot := flag.String("public-root", "", "absolute immutable public case root")
	quarantineRoot := flag.String("quarantine-root", "", "absolute create-only quarantine root")
	journalRoot := flag.String("journal-root", "", "absolute private import journal root")
	objectKind := flag.String("object-kind", "", "artifact-manifest or ciphertext; stage-object only")
	flag.Parse()
	if !filepath.IsAbs(*requestPath) {
		fail(fmt.Errorf("-request must be absolute"))
	}
	request, err := readImportRequest(*requestPath)
	if err != nil {
		fail(err)
	}
	switch *mode {
	case "stage-object":
		runStageObject(request, *quarantineRoot, *objectKind, os.Stdin)
	case "verify":
		runVerify(request, *publicRoot, *quarantineRoot)
	case "publish":
		runPublish(request, *publicRoot, *quarantineRoot, *journalRoot, false)
	case "reconcile":
		runPublish(request, *publicRoot, *quarantineRoot, *journalRoot, true)
	default:
		fail(fmt.Errorf("unsupported or missing -mode"))
	}
}

func runStageObject(request participantImportRequest, quarantineRoot, objectKind string, reader io.Reader) {
	if !filepath.IsAbs(quarantineRoot) || reader == nil {
		fail(fmt.Errorf("stage-object requires absolute -quarantine-root and a raw stdin stream"))
	}
	kind, expected, err := stageObjectSelection(request, objectKind)
	if err != nil {
		fail(err)
	}
	ref, err := governedfhe.StageParticipantOriginatedObject(governedfhe.ParticipantOriginatedStageObjectOptions{
		QuarantineRoot: quarantineRoot, Role: request.Role, Kind: kind, Expected: expected, Reader: reader,
	})
	if err != nil {
		fail(err)
	}
	writeJSON(struct {
		SchemaVersion string                                           `json:"schemaVersion"`
		Role          string                                           `json:"role"`
		Kind          governedfhe.ParticipantOriginatedStageObjectKind `json:"kind"`
		Object        governedfhe.ObjectRef                            `json:"object"`
	}{"mordant.participant-originated-import-stage-object-result/1", request.Role, kind, ref})
}

func stageObjectSelection(request participantImportRequest, objectKind string) (governedfhe.ParticipantOriginatedStageObjectKind, governedfhe.ObjectRef, error) {
	switch objectKind {
	case "artifact-manifest":
		return governedfhe.ParticipantOriginatedStageManifest, request.ArtifactObject, nil
	case "ciphertext":
		return governedfhe.ParticipantOriginatedStageCiphertext, request.CiphertextObject, nil
	default:
		return "", governedfhe.ObjectRef{}, fmt.Errorf("-object-kind must be artifact-manifest or ciphertext")
	}
}

func runVerify(request participantImportRequest, publicRoot, quarantineRoot string) {
	if !allAbsolute(publicRoot, quarantineRoot) {
		fail(fmt.Errorf("verify requires absolute -public-root and -quarantine-root"))
	}
	now := time.Now().UTC()
	verification, err := verifyExactRequest(request, publicRoot, quarantineRoot, now)
	if err != nil {
		fail(err)
	}
	writeJSON(struct {
		SchemaVersion string                                                `json:"schemaVersion"`
		Verification  governedfhe.ParticipantOriginatedArtifactVerification `json:"verification"`
	}{"mordant.participant-originated-import-verification-result/1", verification})
}

func runPublish(request participantImportRequest, publicRoot, quarantineRoot, journalRoot string, reconcile bool) {
	if !allAbsolute(publicRoot, quarantineRoot, journalRoot) {
		fail(fmt.Errorf("publish/reconcile requires absolute -public-root, -quarantine-root, and -journal-root"))
	}
	now := time.Now().UTC()
	options := governedfhe.ParticipantOriginatedPublicationOptions{
		PublicRoot: publicRoot, QuarantineRoot: quarantineRoot, JournalRoot: journalRoot,
		Expected: request.expected(now), Now: now,
	}
	report, err := executeImportPublication(
		request, options, reconcile,
		func() error {
			_, err := verifyExactRequest(request, publicRoot, quarantineRoot, now)
			return err
		},
		governedfhe.PublishParticipantOriginatedArtifact,
		governedfhe.ReconcileParticipantOriginatedImport,
	)
	if err != nil {
		fail(err)
	}
	schema := "mordant.participant-originated-import-publication-result/1"
	if reconcile {
		schema = "mordant.participant-originated-import-reconciliation-result/1"
	}
	writeJSON(struct {
		SchemaVersion string                                        `json:"schemaVersion"`
		Report        governedfhe.ParticipantOriginatedImportReport `json:"report"`
	}{schema, report})
}

type participantImportPublication func(governedfhe.ParticipantOriginatedPublicationOptions) (governedfhe.ParticipantOriginatedImportReport, error)

func executeImportPublication(
	request participantImportRequest,
	options governedfhe.ParticipantOriginatedPublicationOptions,
	reconcile bool,
	preverify func() error,
	publish participantImportPublication,
	reconcileExact participantImportPublication,
) (governedfhe.ParticipantOriginatedImportReport, error) {
	if preverify == nil || publish == nil || reconcileExact == nil {
		return governedfhe.ParticipantOriginatedImportReport{}, governedfhe.ErrParticipantImportMismatch
	}
	if !reconcile {
		// New publication remains bound to current time at the CLI boundary;
		// the core independently repeats the same fresh verification.
		if err := preverify(); err != nil {
			return governedfhe.ParticipantOriginatedImportReport{}, err
		}
		return publish(options)
	}
	// Reconciliation deliberately skips current-time preverification. The core
	// verifies against the durable admission instant, then this boundary binds
	// the recovered exact-byte references back to the authenticated request.
	report, err := reconcileExact(options)
	if err != nil {
		return report, err
	}
	if report.ArtifactObject != request.ArtifactObject || report.CiphertextObject != request.CiphertextObject ||
		report.CiphertextObject.Length != request.CiphertextObjectLength {
		return governedfhe.ParticipantOriginatedImportReport{}, governedfhe.ErrParticipantImportMismatch
	}
	return report, nil
}

func verifyExactRequest(request participantImportRequest, publicRoot, quarantineRoot string, now time.Time) (governedfhe.ParticipantOriginatedArtifactVerification, error) {
	verification, err := governedfhe.VerifyStagedParticipantOriginatedArtifact(governedfhe.ParticipantOriginatedVerificationOptions{
		PublicRoot: publicRoot, QuarantineRoot: quarantineRoot, Expected: request.expected(now),
	})
	if err != nil {
		return verification, err
	}
	if verification.ArtifactObject != request.ArtifactObject || verification.CiphertextObject != request.CiphertextObject ||
		verification.CiphertextObject.Length != request.CiphertextObjectLength {
		return verification, governedfhe.ErrParticipantImportMismatch
	}
	return verification, nil
}

func (request participantImportRequest) expected(now time.Time) governedfhe.ParticipantOriginatedArtifactExpectations {
	return governedfhe.ParticipantOriginatedArtifactExpectations{
		Role: request.Role, CaseID: mustDigest0x(request.CaseID), AssetIdentity: mustDigest0x(request.AssetIdentity),
		CaseBindingDigest: mustDigest0x(request.CaseBindingDigest), SigningKeyDigest: mustDigest0x(request.SigningKeyDigest),
		BundleDigest: mustDigest0x(request.BundleDigest), EncryptionIntentDigest: mustAuthorizationDigest(request.EncryptionIntentDigest),
		ClaimCommitment: mustDigest0x(request.ClaimCommitment), SubmissionNonce: mustDigest0x(request.SubmissionNonce),
		ArtifactDigest: mustDigest0x(request.ArtifactDigest), CiphertextDigest: mustDigest0x(request.CiphertextDigest),
		FinalEncryptedAdmissionDigest: mustAuthorizationDigest(request.FinalEncryptedAdmissionDigest),
		EnrollmentSignature:           mustSignature0x(request.EnrollmentSignature), Now: now,
	}
}

func readImportRequest(path string) (participantImportRequest, error) {
	var request participantImportRequest
	data, err := os.ReadFile(path)
	if err != nil {
		return request, err
	}
	return decodeImportRequest(data)
}

func decodeImportRequest(data []byte) (participantImportRequest, error) {
	var request participantImportRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, fmt.Errorf("invalid import request JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return request, fmt.Errorf("trailing import request JSON")
	}
	canonical, err := json.Marshal(request)
	if err != nil {
		return request, err
	}
	withNewline := append(append([]byte(nil), canonical...), '\n')
	if !bytes.Equal(data, canonical) && !bytes.Equal(data, withNewline) {
		return request, fmt.Errorf("import request JSON is not canonical")
	}
	if err := request.validate(); err != nil {
		return request, err
	}
	return request, nil
}

func (request participantImportRequest) validate() error {
	if request.SchemaVersion != participantImportRequestSchema ||
		(request.Role != "PARTICIPANT_A" && request.Role != "PARTICIPANT_B") ||
		request.CiphertextObjectLength <= 0 || request.CiphertextObjectLength > maximumParticipantCipherBytes {
		return fmt.Errorf("invalid participant import request")
	}
	for _, value := range []string{
		request.CaseID, request.AssetIdentity, request.CaseBindingDigest, request.SigningKeyDigest,
		request.BundleDigest, request.EncryptionIntentDigest, request.ClaimCommitment, request.SubmissionNonce,
		request.ArtifactDigest, request.CiphertextDigest, request.FinalEncryptedAdmissionDigest,
	} {
		decoded, err := digestBytes0x(value)
		if err != nil || decoded == ([32]byte{}) {
			return fmt.Errorf("invalid participant import bytes32")
		}
	}
	if _, err := signatureBytes0x(request.EnrollmentSignature); err != nil {
		return fmt.Errorf("invalid participant enrollment signature")
	}
	artifactName, ciphertextName := "submission-a.json", "submission-a.bin"
	if request.Role == "PARTICIPANT_B" {
		artifactName, ciphertextName = "submission-b.json", "submission-b.bin"
	}
	if request.ArtifactObject.Path != artifactName || request.ArtifactObject.Digest == (governedfhe.Digest{}) ||
		request.ArtifactObject.Length <= 0 || request.ArtifactObject.Length > maximumArtifactManifestBytes ||
		request.CiphertextObject.Path != ciphertextName || request.CiphertextObject.Digest == (governedfhe.Digest{}) ||
		request.CiphertextObject.Length != request.CiphertextObjectLength ||
		request.CiphertextObject.Length > maximumParticipantCipherBytes ||
		request.CiphertextObject.Digest != mustDigest0x(request.CiphertextDigest) {
		return fmt.Errorf("import transport references do not match the authorization")
	}
	return nil
}

func signatureBytes0x(value string) ([]byte, error) {
	if !importSignature.MatchString(value) {
		return nil, fmt.Errorf("ed25519 signature must use exact lower-case 0x encoding")
	}
	decoded, err := hex.DecodeString(value[2:])
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid ed25519 signature")
	}
	return decoded, nil
}

func mustSignature0x(value string) []byte {
	decoded, err := signatureBytes0x(value)
	if err != nil {
		panic("validated import signature became invalid")
	}
	return decoded
}

func digestBytes0x(value string) ([32]byte, error) {
	var result [32]byte
	if !importBytes32.MatchString(value) {
		return result, fmt.Errorf("bytes32 must use exact lower-case 0x encoding")
	}
	decoded, err := hex.DecodeString(value[2:])
	if err != nil || len(decoded) != len(result) {
		return result, fmt.Errorf("invalid bytes32")
	}
	copy(result[:], decoded)
	return result, nil
}

func mustDigest0x(value string) governedfhe.Digest {
	decoded, err := digestBytes0x(value)
	if err != nil {
		panic("validated import digest became invalid")
	}
	return governedfhe.Digest(decoded)
}

func mustAuthorizationDigest(value string) governedfhe.ParticipantOriginatedAuthorizationDigest {
	decoded, err := digestBytes0x(value)
	if err != nil {
		panic("validated authorization digest became invalid")
	}
	return governedfhe.ParticipantOriginatedAuthorizationDigest(decoded)
}

func allAbsolute(paths ...string) bool {
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return false
		}
	}
	return true
}

func writeJSON(value any) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-import: %v\n", err)
	os.Exit(1)
}
