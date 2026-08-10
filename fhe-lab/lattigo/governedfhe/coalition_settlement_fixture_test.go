package governedfhe

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/sha3"
)

// Emits the settlement-relevant facts of a real coalition release so the
// on-chain adapter test consumes what the spine actually produced rather than
// synthetic digests.
//
// It is gated behind an environment variable because it writes outside the test
// tree, and because the settlement test must be able to state which run its
// fixture came from. Regenerate with:
//
//	MORDANT_COALITION_FIXTURE_OUT=<abs path> go test -run TestEmitCoalitionSettlementFixture ./governedfhe/
type CoalitionSettlementFixture struct {
	SchemaVersion              string   `json:"schemaVersion"`
	CaseID                     string   `json:"fheCaseId"`
	CaseBindingDigest          string   `json:"caseBindingDigest"`
	AssetIdentityDigest        string   `json:"assetIdentityDigest"`
	CoalitionResultDigest      string   `json:"coalitionResultDigest"`
	ReleaseTranscript          string   `json:"releaseTranscript"`
	ParticipantArtifactDigestA string   `json:"participantArtifactDigestA"`
	ParticipantArtifactDigestB string   `json:"participantArtifactDigestB"`
	CoalitionAuthorityID       string   `json:"coalitionAuthorityId"`
	ServingQuorum              uint16   `json:"servingQuorum"`
	Coalition                  []uint64 `json:"coalition"`
	ReleaseMode                string   `json:"releaseMode"`
	CircuitDigest              string   `json:"circuitDigest"`
	ParameterFingerprint       string   `json:"parameterFingerprint"`
	SameEconomicAsset          bool     `json:"sameEconomicAsset"`
	PolicyConflict             bool     `json:"policyConflict"`
	OperatorTopology           string   `json:"operatorTopology"`
}

func TestEmitCoalitionSettlementFixture(t *testing.T) {
	destination := os.Getenv("MORDANT_COALITION_FIXTURE_OUT")
	if destination == "" {
		t.Skip("set MORDANT_COALITION_FIXTURE_OUT to regenerate the settlement fixture")
	}
	if !filepath.IsAbs(destination) {
		t.Fatal("MORDANT_COALITION_FIXTURE_OUT must be absolute")
	}

	fixture := newCoalitionFixture(t, true)
	result, err := fixture.release(t, fixture.operatorRoots)
	if err != nil {
		t.Fatalf("coalition release: %v", err)
	}
	// The release authority of a coalition case is the digest of its published
	// threshold manifest. Read it back from the case rather than recomputing it,
	// so the fixture carries what the case actually committed to.
	raw, err := os.ReadFile(filepath.Join(fixture.publicRoot, thresholdManifestObject))
	if err != nil {
		t.Fatal(err)
	}
	var manifest CoalitionThresholdManifest
	if decodeStrict(raw, &manifest) != nil {
		t.Fatal("threshold manifest must decode")
	}
	authority, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if authority != result.ReleaseAuthorityID {
		t.Fatalf("the released result names %s as its authority, the manifest digests to %s",
			result.ReleaseAuthorityID, authority)
	}
	resultDigest, err := result.Digest()
	if err != nil {
		t.Fatal(err)
	}

	emitted := CoalitionSettlementFixture{
		SchemaVersion:              "mordant.coalition-settlement-fixture/1",
		CaseID:                     hexOfDigest(result.CaseID),
		CaseBindingDigest:          hexOfDigest(result.CaseBindingDigest),
		AssetIdentityDigest:        hexOfDigest(result.AssetIdentity),
		CoalitionResultDigest:      hexOfDigest(resultDigest),
		ReleaseTranscript:          result.ReleaseTranscript,
		ParticipantArtifactDigestA: hexOfDigest(result.ParticipantArtifactDigests[0]),
		ParticipantArtifactDigestB: hexOfDigest(result.ParticipantArtifactDigests[1]),
		CoalitionAuthorityID:       hexOfDigest(result.ReleaseAuthorityID),
		ServingQuorum:              result.Threshold,
		Coalition:                  result.Coalition,
		ReleaseMode:                keccakTextHex(result.ReleaseMode),
		CircuitDigest:              hexOfDigest(result.CircuitDigest),
		ParameterFingerprint:       hexOfDigest(result.ParameterFingerprint),
		SameEconomicAsset:          result.SameEconomicAsset,
		PolicyConflict:             result.PolicyConflict,
		OperatorTopology:           result.OperatorTopology,
	}
	encoded, err := json.MarshalIndent(emitted, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote coalition settlement fixture to %s", destination)
}

func hexOfDigest(value Digest) string {
	return "0x" + value.String()[len("sha256:"):]
}

// keccakTextHex is how the adapter encodes a release mode: the EVM pins
// keccak256 of the mode string, so the fixture carries the same encoding rather
// than the string.
func keccakTextHex(text string) string {
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte(text))
	return "0x" + hex.EncodeToString(hash.Sum(nil))
}
