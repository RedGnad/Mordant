// Command mordant-fhe-evaluator evaluates only IdentityFullFHE256 from the
// immutable public case root. Its configuration has deliberately no secret-key
// or private-root field.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

func main() {
	publicRoot := flag.String("public-root", "", "absolute immutable public case root")
	flag.Parse()
	if *publicRoot == "" {
		fail(fmt.Errorf("-public-root is required"))
	}
	provenance, err := governedfhe.ExecutableDigest()
	if err != nil {
		fail(err)
	}
	artifact, report, err := governedfhe.EvaluateFixedConflict(governedfhe.EvaluatorConfig{
		PublicRoot: *publicRoot, Provenance: provenance, Now: time.Now().UTC(),
	})
	if err != nil {
		fail(err)
	}
	digest, err := artifact.Digest()
	if err != nil {
		fail(err)
	}
	output := struct {
		ArtifactDigest governedfhe.Digest `json:"artifactDigest"`
		DurationNanos  int64              `json:"durationNanos"`
		ResultBytes    int64              `json:"resultBytes"`
		ArtifactBytes  int64              `json:"artifactBytes"`
	}{digest, report.Duration.Nanoseconds(), report.ResultCiphertextBytes, report.ArtifactBytes}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-evaluator: %v\n", err)
	os.Exit(1)
}
