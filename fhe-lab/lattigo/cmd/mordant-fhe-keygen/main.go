package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

func main() {
	mode := flag.String("mode", "create", "create or finalize")
	publicRoot := flag.String("public-root", "", "absolute public case root")
	privateRoot := flag.String("private-root", "", "absolute private decryptor root")
	specPath := flag.String("spec", "", "canonical case specification JSON")
	participantAKey := flag.String("participant-a-key", "", "participant A Ed25519 private-key file")
	participantBKey := flag.String("participant-b-key", "", "participant B Ed25519 private-key file")
	flag.Parse()
	if *publicRoot == "" {
		fail(fmt.Errorf("-public-root is required"))
	}
	switch *mode {
	case "create":
		if *privateRoot == "" || *specPath == "" || *participantAKey == "" || *participantBKey == "" {
			fail(fmt.Errorf("create requires -private-root, -spec, and both participant keys"))
		}
		data, err := os.ReadFile(*specPath)
		if err != nil {
			fail(err)
		}
		var spec struct {
			governedfhe.CaseSpec
			ProtectionBinding governedfhe.MordantProtectionBinding `json:"protectionBinding"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&spec); err != nil {
			fail(err)
		}
		provenance, err := governedfhe.ExecutableDigest()
		if err != nil {
			fail(err)
		}
		keyA := readParticipantKey(*participantAKey)
		keyB := readParticipantKey(*participantBKey)
		defer clear(keyA)
		defer clear(keyB)
		binding, report, authorization, err := governedfhe.CreateProductAuthorizedCase(governedfhe.ProductAuthorizedCreateOptions{
			CreateCaseOptions: governedfhe.CreateCaseOptions{
				PublicRoot: *publicRoot, PrivateRoot: *privateRoot, Spec: spec.CaseSpec, SourceProvenance: provenance,
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
	case "finalize":
		if _, err := governedfhe.VerifyProtectionAuthorization(*publicRoot); err != nil {
			fail(err)
		}
		manifest, err := governedfhe.FinalizeCase(*publicRoot)
		if err != nil {
			fail(err)
		}
		digest, _ := manifest.Digest()
		writeJSON(struct {
			ManifestDigest governedfhe.Digest `json:"manifestDigest"`
		}{digest})
	default:
		fail(fmt.Errorf("unsupported mode"))
	}
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
