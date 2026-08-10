package governedfhe

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	// The two identities the case binding publishes. The canonical scenario needs
	// them because a V2 admission names the exact key the case will accept
	// enrollments from.
	ParticipantA CoalitionFixtureIdentity `json:"participantA"`
	ParticipantB CoalitionFixtureIdentity `json:"participantB"`
}

type CoalitionFixtureIdentity struct {
	ID               string `json:"id"`
	Role             string `json:"role"`
	SigningPublicKey string `json:"signingPublicKey"`
}

func TestEmitCoalitionSettlementFixture(t *testing.T) {
	destination := os.Getenv("MORDANT_COALITION_FIXTURE_OUT")
	if destination == "" {
		t.Skip("set MORDANT_COALITION_FIXTURE_OUT to regenerate the settlement fixture")
	}
	if !filepath.IsAbs(destination) {
		t.Fatal("MORDANT_COALITION_FIXTURE_OUT must be absolute")
	}

	conflicting := os.Getenv("MORDANT_COALITION_FIXTURE_BRANCH") != "no-conflict"
	fixture := newCoalitionFixture(t, conflicting)
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
		ParticipantA: CoalitionFixtureIdentity{
			ID: fixture.manifest.Binding.ParticipantA.ID.String(), Role: RoleA,
			SigningPublicKey: base64.StdEncoding.EncodeToString(fixture.manifest.Binding.ParticipantA.SigningPublicKey),
		},
		ParticipantB: CoalitionFixtureIdentity{
			ID: fixture.manifest.Binding.ParticipantB.ID.String(), Role: RoleB,
			SigningPublicKey: base64.StdEncoding.EncodeToString(fixture.manifest.Binding.ParticipantB.SigningPublicKey),
		},
	}
	encoded, err := json.MarshalIndent(emitted, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	// The evidence the settlement authority verifies: the published manifest and
	// the released result, exactly as the case holds them. Emitted verbatim so
	// the TypeScript verifier is exercised against real bytes rather than a
	// re-serialization.
	resultBytes, err := os.ReadFile(filepath.Join(fixture.publicRoot, coalitionResultObject))
	if err != nil {
		t.Fatal(err)
	}
	evidence := map[string]json.RawMessage{
		"thresholdManifest": json.RawMessage(raw),
		"coalitionResult":   json.RawMessage(resultBytes),
	}
	evidenceEncoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(filepath.Dir(destination), "coalition-evidence.json")
	if err := os.WriteFile(evidencePath, append(evidenceEncoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	// A Solidity library of the same values, so the on-chain test consumes them
	// without reading a file. Foundry only grants filesystem access through
	// foundry.toml, and that file is a frozen source: the reviewed build
	// configuration of the contracts must not drift to make a test convenient.
	solidity := fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Generated from a real 2-of-3 coalition release of the Go spine. Do not edit by hand.
///
/// Regenerate with:
///   MORDANT_COALITION_FIXTURE_OUT=<abs path to test/fixtures/coalition-settlement.json> ///     go test -run TestEmitCoalitionSettlementFixture ./governedfhe/
library CoalitionSettlementFixture {
    bytes32 internal constant FHE_CASE_ID =
        %s;
    bytes32 internal constant CASE_BINDING_DIGEST =
        %s;
    bytes32 internal constant ASSET_IDENTITY_DIGEST =
        %s;
    bytes32 internal constant COALITION_RESULT_DIGEST =
        %s;
    bytes32 internal constant RELEASE_TRANSCRIPT =
        %s;
    bytes32 internal constant PARTICIPANT_ARTIFACT_DIGEST_A =
        %s;
    bytes32 internal constant PARTICIPANT_ARTIFACT_DIGEST_B =
        %s;
    bytes32 internal constant COALITION_AUTHORITY_ID =
        %s;
    bytes32 internal constant RELEASE_MODE =
        %s;
    bytes32 internal constant CIRCUIT_DIGEST =
        %s;
    bytes32 internal constant PARAMETER_FINGERPRINT =
        %s;
    uint16 internal constant SERVING_QUORUM = %d;
    bool internal constant SAME_ECONOMIC_ASSET = %t;
    bool internal constant POLICY_CONFLICT = %t;
}
`,
		emitted.CaseID, emitted.CaseBindingDigest, emitted.AssetIdentityDigest, emitted.CoalitionResultDigest,
		emitted.ReleaseTranscript, emitted.ParticipantArtifactDigestA, emitted.ParticipantArtifactDigestB,
		emitted.CoalitionAuthorityID, emitted.ReleaseMode, emitted.CircuitDigest, emitted.ParameterFingerprint,
		emitted.ServingQuorum, emitted.SameEconomicAsset, emitted.PolicyConflict)
	solidityPath := filepath.Join(filepath.Dir(destination), "CoalitionSettlementFixture.sol")
	if err := os.WriteFile(solidityPath, []byte(solidity), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote coalition settlement fixture to %s, evidence to %s and %s", destination, evidencePath, solidityPath)
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
