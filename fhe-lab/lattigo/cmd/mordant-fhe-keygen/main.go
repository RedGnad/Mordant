package main

import (
	"bytes"
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
	flag.Parse()
	if *publicRoot == "" {
		fail(fmt.Errorf("-public-root is required"))
	}
	switch *mode {
	case "create":
		if *privateRoot == "" || *specPath == "" {
			fail(fmt.Errorf("create requires -private-root and -spec"))
		}
		data, err := os.ReadFile(*specPath)
		if err != nil {
			fail(err)
		}
		var spec governedfhe.CaseSpec
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&spec); err != nil {
			fail(err)
		}
		provenance, err := governedfhe.ExecutableDigest()
		if err != nil {
			fail(err)
		}
		binding, report, err := governedfhe.CreateCase(governedfhe.CreateCaseOptions{
			PublicRoot: *publicRoot, PrivateRoot: *privateRoot, Spec: spec, SourceProvenance: provenance,
		})
		if err != nil {
			fail(err)
		}
		digest, _ := binding.Digest()
		writeJSON(struct {
			BindingDigest governedfhe.Digest `json:"bindingDigest"`
			DurationNanos int64              `json:"durationNanos"`
		}{digest, report.Duration.Nanoseconds()})
	case "finalize":
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

func writeJSON(value any) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-keygen: %v\n", err)
	os.Exit(1)
}
