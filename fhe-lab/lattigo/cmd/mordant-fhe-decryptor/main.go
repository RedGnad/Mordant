// Command mordant-fhe-decryptor exposes only the fixed governed Boolean
// release. It takes roots, never an arbitrary ciphertext path or output slot.
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
	privateRoot := flag.String("private-root", "", "absolute private decryptor root")
	flag.Parse()
	if *publicRoot == "" || *privateRoot == "" {
		fail(fmt.Errorf("-public-root and -private-root are required"))
	}
	provenance, err := governedfhe.ExecutableDigest()
	if err != nil {
		fail(err)
	}
	artifact, err := governedfhe.LoadEvaluatedConflictArtifact(*publicRoot)
	if err != nil {
		fail(err)
	}
	decryptor, err := governedfhe.NewGovernedDecryptor(governedfhe.GovernedDecryptorConfig{
		PublicRoot: *publicRoot, PrivateRoot: *privateRoot, Provenance: provenance, Now: time.Now().UTC(),
	})
	if err != nil {
		fail(err)
	}
	defer decryptor.Close()
	result, encoded, report, err := decryptor.ReleaseWithReport(artifact)
	if err != nil {
		fail(err)
	}
	digest, err := result.Digest()
	if err != nil {
		fail(err)
	}
	output := struct {
		ResultDigest  governedfhe.Digest              `json:"resultDigest"`
		Conflict      bool                            `json:"conflict"`
		ReleaseMode   string                          `json:"releaseMode"`
		DurationNanos int64                           `json:"durationNanos"`
		ResultBytes   int64                           `json:"resultBytes"`
		ExactRetry    bool                            `json:"exactRetry"`
		TrustedPins   governedfhe.TrustedRecoursePins `json:"trustedRecoursePins"`
	}{digest, result.Conflict, result.ReleaseMode, report.Duration.Nanoseconds(), int64(len(encoded)), report.ExactRetry, report.Pins}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-decryptor: %v\n", err)
	os.Exit(1)
}
