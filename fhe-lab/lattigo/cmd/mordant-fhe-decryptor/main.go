// Command mordant-fhe-decryptor exposes only the two fixed Boolean releases: the
// governed one, and the coalition one. It takes roots, never an arbitrary
// ciphertext path or output slot.
//
// Which release runs is named by the caller rather than inferred from the case,
// and both library paths refuse the case they were not built for. A coalition
// case generated no secret key, so a governed release against it has nothing to
// open; naming the mode makes that a refusal at the door instead of a failure
// half way through a release.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

// operatorRoots collects a repeatable -operator-root flag, one sealed bundle per
// root. Named one at a time so a path containing a delimiter cannot silently
// become two roots.
type operatorRoots []string

func (r *operatorRoots) String() string { return fmt.Sprint(*r) }

func (r *operatorRoots) Set(value string) error {
	if value == "" {
		return fmt.Errorf("an operator root cannot be empty")
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("an operator root must be absolute")
	}
	for _, existing := range *r {
		if existing == value {
			return fmt.Errorf("operator root %q was named twice", value)
		}
	}
	*r = append(*r, value)
	return nil
}

func main() {
	publicRoot := flag.String("public-root", "", "absolute immutable public case root")
	privateRoot := flag.String("private-root", "", "absolute private decryptor root")
	releaseMode := flag.String("release-mode", "", "empty for the governed decryptor, or "+governedfhe.ReleaseModeCoalitionV5)
	ledgerRoot := flag.String("ledger-root", "", "absolute root for the coalition operators' one-shot session ledgers")
	var operators operatorRoots
	flag.Var(&operators, "operator-root", "absolute root of one coalition operator bundle; repeat once per operator")
	flag.Parse()
	if *publicRoot == "" {
		fail(fmt.Errorf("-public-root is required"))
	}
	if *releaseMode == governedfhe.ReleaseModeCoalitionV5 {
		runCoalitionRelease(*publicRoot, *ledgerRoot, operators)
		return
	}
	if *releaseMode != "" {
		fail(fmt.Errorf("unsupported -release-mode"))
	}
	if len(operators) != 0 || *ledgerRoot != "" {
		fail(fmt.Errorf("-operator-root and -ledger-root belong to a coalition release; pass -release-mode %s", governedfhe.ReleaseModeCoalitionV5))
	}
	if *privateRoot == "" {
		fail(fmt.Errorf("-private-root is required"))
	}
	if _, err := governedfhe.VerifyProtectionAuthorization(*publicRoot); err != nil {
		fail(err)
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

// runCoalitionRelease releases the two bits through the operator quorum. No
// secret key is opened, because a coalition case never generated one.
//
// The two bits are reported separately rather than folded into one conflict
// answer. They are not the same fact: PolicyConflict is only meaningful where
// SameEconomicAsset holds, and a caller that receives a single Boolean cannot
// tell "different receivables" from "same receivable, no policy conflict".
func runCoalitionRelease(publicRoot, ledgerRoot string, operators operatorRoots) {
	if ledgerRoot == "" {
		fail(fmt.Errorf("a coalition release requires -ledger-root"))
	}
	if len(operators) < int(governedfhe.CoalitionThreshold) {
		fail(fmt.Errorf("a coalition release needs at least %d -operator-root values, got %d", governedfhe.CoalitionThreshold, len(operators)))
	}
	if _, err := governedfhe.VerifyProtectionAuthorization(publicRoot); err != nil {
		fail(err)
	}
	provenance, err := governedfhe.ExecutableDigest()
	if err != nil {
		fail(err)
	}
	artifact, err := governedfhe.LoadEvaluatedConflictArtifact(publicRoot)
	if err != nil {
		fail(err)
	}
	decryptor, err := governedfhe.NewCoalitionDecryptor(governedfhe.CoalitionDecryptorConfig{
		PublicRoot: publicRoot, OperatorRoots: operators, LedgerRoot: ledgerRoot,
		Provenance: provenance, Now: time.Now().UTC(),
	})
	if err != nil {
		fail(err)
	}
	defer decryptor.Close()
	started := time.Now()
	result, encoded, err := decryptor.Release(artifact)
	if err != nil {
		fail(err)
	}
	elapsed := time.Since(started)
	digest, err := result.Digest()
	if err != nil {
		fail(err)
	}
	output := struct {
		ResultDigest            governedfhe.Digest `json:"resultDigest"`
		SameEconomicAsset       bool               `json:"sameEconomicAsset"`
		PolicyConflict          bool               `json:"policyConflict"`
		ReleaseMode             string             `json:"releaseMode"`
		ReleaseAuthorityID      governedfhe.Digest `json:"releaseAuthorityId"`
		Threshold               uint16             `json:"threshold"`
		Coalition               []uint64           `json:"coalition"`
		OperatorTopology        string             `json:"operatorTopology"`
		RecomputedByAllOfQuorum bool               `json:"recomputedByAllOfQuorum"`
		DurationNanos           int64              `json:"durationNanos"`
		ResultBytes             int64              `json:"resultBytes"`
	}{
		digest, result.SameEconomicAsset, result.PolicyConflict, result.ReleaseMode, result.ReleaseAuthorityID,
		result.Threshold, result.Coalition, result.OperatorTopology, result.RecomputedByAllOfQuorum,
		elapsed.Nanoseconds(), int64(len(encoded)),
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-decryptor: %v\n", err)
	os.Exit(1)
}
