package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

const (
	defaultKeygenMode                     = "create"
	participantCeremonyRequestInputSchema = "mordant.participant-originated-ceremony-request-input/1"
)

type participantFoundationSpec struct {
	governedfhe.CaseSpec
	ProtectionBinding governedfhe.MordantProtectionBinding `json:"protectionBinding"`
}

// participantCeremonyRequestInput contains only public pins. In particular it
// has no participant private-key field and is safe to retain as coordinator
// evidence.
type participantCeremonyRequestInput struct {
	SchemaVersion               string             `json:"schemaVersion"`
	RunID                       string             `json:"runId"`
	Role                        string             `json:"role"`
	ExpectedSourceDigest        governedfhe.Digest `json:"expectedSourceDigest"`
	ExpectedBuildManifestDigest governedfhe.Digest `json:"expectedBuildManifestDigest"`
	ExpectedClientBinaryDigest  governedfhe.Digest `json:"expectedClientBinaryDigest"`
}

func main() {
	mode := flag.String("mode", defaultKeygenMode, "create, finalize, participant-foundation, participant-ceremony-request, participant-ceremony-import, participant-finalize, or participant-bundle-export")
	publicRoot := flag.String("public-root", "", "absolute public case root")
	privateRoot := flag.String("private-root", "", "absolute private decryptor root")
	ceremonyRoot := flag.String("ceremony-root", "", "absolute private coordinator ceremony journal root")
	bundleRoot := flag.String("bundle-root", "", "absolute create-only participant bundle root")
	specPath := flag.String("spec", "", "canonical case specification JSON")
	requestPath := flag.String("request", "", "canonical participant ceremony request input or signed request JSON")
	approvalPath := flag.String("approval", "", "canonical participant ceremony approval JSON")
	role := flag.String("role", "", "PARTICIPANT_A or PARTICIPANT_B")
	participantAKey := flag.String("participant-a-key", "", "participant A Ed25519 private-key file")
	participantBKey := flag.String("participant-b-key", "", "participant B Ed25519 private-key file")
	flag.Parse()
	if *publicRoot == "" {
		fail(fmt.Errorf("-public-root is required"))
	}
	switch *mode {
	case "create":
		runManagedCreate(*publicRoot, *privateRoot, *specPath, *participantAKey, *participantBKey)
	case "finalize":
		runManagedFinalize(*publicRoot)
	case "participant-foundation":
		if err := rejectParticipantFoundationPrivateKeys(*participantAKey, *participantBKey); err != nil {
			fail(err)
		}
		runParticipantFoundation(*publicRoot, *privateRoot, *specPath)
	case "participant-ceremony-request":
		runParticipantCeremonyRequest(*publicRoot, *requestPath)
	case "participant-ceremony-import":
		runParticipantCeremonyImport(*publicRoot, *ceremonyRoot, *requestPath, *approvalPath)
	case "participant-finalize":
		runParticipantFinalize(*publicRoot)
	case "participant-bundle-export":
		runParticipantBundleExport(*publicRoot, *ceremonyRoot, *bundleRoot, *role)
	default:
		fail(fmt.Errorf("unsupported mode"))
	}
}

func rejectParticipantFoundationPrivateKeys(participantAKey, participantBKey string) error {
	if participantAKey != "" || participantBKey != "" {
		return fmt.Errorf("participant-foundation accepts public keys in -spec only; participant private-key flags are forbidden")
	}
	return nil
}

func runManagedCreate(publicRoot, privateRoot, specPath, participantAKey, participantBKey string) {
	if privateRoot == "" || specPath == "" || participantAKey == "" || participantBKey == "" {
		fail(fmt.Errorf("create requires -private-root, -spec, and both participant keys"))
	}
	data, err := os.ReadFile(specPath)
	if err != nil {
		fail(err)
	}
	var spec participantFoundationSpec
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		fail(err)
	}
	provenance, err := governedfhe.ExecutableDigest()
	if err != nil {
		fail(err)
	}
	keyA := readParticipantKey(participantAKey)
	keyB := readParticipantKey(participantBKey)
	defer clear(keyA)
	defer clear(keyB)
	binding, report, authorization, err := governedfhe.CreateProductAuthorizedCase(governedfhe.ProductAuthorizedCreateOptions{
		CreateCaseOptions: governedfhe.CreateCaseOptions{
			PublicRoot: publicRoot, PrivateRoot: privateRoot, Spec: spec.CaseSpec, SourceProvenance: provenance,
		},
		ProtectionBinding:      spec.ProtectionBinding,
		ParticipantASigningKey: ed25519.PrivateKey(keyA),
		ParticipantBSigningKey: ed25519.PrivateKey(keyB),
	})
	if err != nil {
		fail(err)
	}
	digest, _ := binding.Digest()
	writeJSON(struct {
		BindingDigest           governedfhe.Digest              `json:"bindingDigest"`
		ProtectionBindingDigest governedfhe.Digest              `json:"protectionBindingDigest"`
		DurationNanos           int64                           `json:"durationNanos"`
		Report                  governedfhe.KeyGenerationReport `json:"report"`
	}{digest, authorization.Digest, report.Duration.Nanoseconds(), report})
}

func runManagedFinalize(publicRoot string) {
	if _, err := governedfhe.VerifyProtectionAuthorization(publicRoot); err != nil {
		fail(err)
	}
	manifest, err := governedfhe.FinalizeCase(publicRoot)
	if err != nil {
		fail(err)
	}
	digest, _ := manifest.Digest()
	writeJSON(struct {
		ManifestDigest governedfhe.Digest `json:"manifestDigest"`
	}{digest})
}

func runParticipantFoundation(publicRoot, privateRoot, specPath string) {
	if !filepath.IsAbs(privateRoot) || !filepath.IsAbs(specPath) {
		fail(fmt.Errorf("participant-foundation requires absolute -private-root and -spec"))
	}
	var spec participantFoundationSpec
	readCanonicalJSON(specPath, &spec)
	provenance, err := governedfhe.ExecutableDigest()
	if err != nil {
		fail(err)
	}
	binding, report, protectionDigest, err := governedfhe.CreateParticipantOriginatedFoundation(
		governedfhe.ParticipantOriginatedFoundationOptions{
			CreateCaseOptions: governedfhe.CreateCaseOptions{
				PublicRoot: publicRoot, PrivateRoot: privateRoot, Spec: spec.CaseSpec, SourceProvenance: provenance,
			},
			ProtectionBinding: spec.ProtectionBinding,
		},
	)
	if err != nil {
		fail(err)
	}
	bindingDigest, _ := binding.Digest()
	writeJSON(struct {
		SchemaVersion           string                          `json:"schemaVersion"`
		BindingDigest           governedfhe.Digest              `json:"bindingDigest"`
		ProtectionBindingDigest governedfhe.Digest              `json:"protectionBindingDigest"`
		DurationNanos           int64                           `json:"durationNanos"`
		Report                  governedfhe.KeyGenerationReport `json:"report"`
	}{"mordant.participant-originated-foundation-result/1", bindingDigest, protectionDigest, report.Duration.Nanoseconds(), report})
}

func runParticipantCeremonyRequest(publicRoot, requestPath string) {
	if !filepath.IsAbs(requestPath) {
		fail(fmt.Errorf("participant-ceremony-request requires absolute -request"))
	}
	var input participantCeremonyRequestInput
	readCanonicalJSON(requestPath, &input)
	if input.SchemaVersion != participantCeremonyRequestInputSchema {
		fail(fmt.Errorf("unsupported participant ceremony request input schema"))
	}
	request, err := governedfhe.BuildParticipantOriginatedCeremonyRequest(
		publicRoot,
		input.RunID,
		input.Role,
		input.ExpectedSourceDigest,
		input.ExpectedBuildManifestDigest,
		input.ExpectedClientBinaryDigest,
	)
	if err != nil {
		fail(err)
	}
	// The direct schema object is written so it can be passed byte-for-byte to
	// the participant signing command.
	writeJSON(request)
}

func runParticipantCeremonyImport(publicRoot, ceremonyRoot, requestPath, approvalPath string) {
	if !filepath.IsAbs(ceremonyRoot) || !filepath.IsAbs(requestPath) || !filepath.IsAbs(approvalPath) {
		fail(fmt.Errorf("participant-ceremony-import requires absolute -ceremony-root, -request, and -approval"))
	}
	var request governedfhe.ParticipantOriginatedCeremonyRequest
	var approval governedfhe.ParticipantOriginatedCeremonySignatures
	readCanonicalJSON(requestPath, &request)
	readCanonicalJSON(approvalPath, &approval)
	if err := governedfhe.ImportParticipantOriginatedCeremony(publicRoot, ceremonyRoot, request, approval); err != nil {
		fail(err)
	}
	requestDigest, _ := request.Digest()
	writeJSON(struct {
		SchemaVersion string             `json:"schemaVersion"`
		Role          string             `json:"role"`
		RequestDigest governedfhe.Digest `json:"requestDigest"`
	}{"mordant.participant-originated-ceremony-import-result/1", request.Role, requestDigest})
}

func runParticipantFinalize(publicRoot string) {
	manifest, err := governedfhe.FinalizeParticipantOriginatedCase(publicRoot)
	if err != nil {
		fail(err)
	}
	digest, _ := manifest.Digest()
	writeJSON(struct {
		SchemaVersion  string             `json:"schemaVersion"`
		ManifestDigest governedfhe.Digest `json:"manifestDigest"`
	}{"mordant.participant-originated-finalize-result/1", digest})
}

func runParticipantBundleExport(publicRoot, ceremonyRoot, bundleRoot, role string) {
	if !filepath.IsAbs(ceremonyRoot) || !filepath.IsAbs(bundleRoot) || role == "" {
		fail(fmt.Errorf("participant-bundle-export requires absolute -ceremony-root, absolute -bundle-root, and -role"))
	}
	bundle, digest, err := governedfhe.ExportParticipantOriginatedClientBundle(publicRoot, ceremonyRoot, bundleRoot, role)
	if err != nil {
		fail(err)
	}
	writeJSON(struct {
		SchemaVersion string             `json:"schemaVersion"`
		RunID         string             `json:"runId"`
		Role          string             `json:"role"`
		BundleDigest  governedfhe.Digest `json:"bundleDigest"`
	}{"mordant.participant-originated-bundle-export-result/1", bundle.RunID, bundle.Role, digest})
}

func readCanonicalJSON(path string, target any) {
	data, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	if err := decodeCanonicalJSON(data, target); err != nil {
		fail(err)
	}
}

func decodeCanonicalJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid canonical JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("invalid canonical JSON: trailing value")
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	withNewline := append(append([]byte(nil), canonical...), '\n')
	if !bytes.Equal(data, canonical) && !bytes.Equal(data, withNewline) {
		return fmt.Errorf("input JSON is not canonical")
	}
	return nil
}

func readParticipantKey(path string) []byte {
	key, err := os.ReadFile(path)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		fail(fmt.Errorf("invalid participant signing key"))
	}
	return key
}

func writeJSON(value any) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-keygen: %v\n", err)
	os.Exit(1)
}
