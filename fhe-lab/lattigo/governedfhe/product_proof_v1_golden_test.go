package governedfhe

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// Golden vectors copied verbatim from the published A8 conflict envelope
// (docs/evidence/conflicting-pledge-protection/conflict.json). They are the
// backward-compatibility contract: introducing the V2 custom authorization must
// not move a single byte, digest or signature of this retained V1 material.
const a8ConflictBindingJSON = `{"schemaVersion":"mordant.protection-binding/1","cleanverseAssetRecordDigest":"sha256:7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c","protectionService":"Conflicting Pledge Protection","protectionServiceVersion":1,"policyId":"sha256:a9e039b95a56043532bcc1d7a8c1bb0086fc64d50adcb35ff54f54ee59fb6e65","policyVersion":1,"productScenario":"conflict","fixtureClassification":"SYNTHETIC_HACKATHON_FIXTURE","protectedAmount":{"asset":"aUSDC","minorUnits":"100000000"},"reserveBasisPoints":1000,"reserveAmount":{"asset":"aUSDC","minorUnits":"10000000"},"holderRecordDate":"2026-08-03T14:48:49.163Z","holderSnapshot":[{"holderId":"HOLDER_A","protectedUnits":"60000000","allocationBps":6000},{"holderId":"HOLDER_B","protectedUnits":"40000000","allocationBps":4000}],"holderAllocationDigest":"sha256:3c700c3f10343766c466e959ca65d6906c8811fababec08c8e6c4f31b3700b83","caseNonce":"sha256:b0ebed0f839dfc2b9bed641dcbbba51c2761e85f63d9ac05090c8ac1af46b87c","fheCaseId":"sha256:806de678d14adbde33a0048d244389d3404b6c45d0c71163e2fd5a283c60828e","governedReleaseMode":"governed-decryptor-v1"}`

const (
	a8ConflictBindingDigest = "sha256:62f96cd7b03f82f087643d9d6e09e0a90c2b28b93d6780e50b8fbbd4aaa4aa52"
	a8ConflictFHECaseID     = "sha256:806de678d14adbde33a0048d244389d3404b6c45d0c71163e2fd5a283c60828e"
)

type a8Participant struct {
	role      string
	id        string
	publicKey string
	signature string
}

var a8Participants = []a8Participant{
	{
		role:      "PARTICIPANT_A",
		id:        "sha256:058956fd989c2119ab3513b697cfebc81625ee18f7e4c874879566eb438e912c",
		publicKey: "H+ZKHA9qgTl5r6y0TujwZsgRGCDxD9j3gFC7nj6pED4=",
		signature: "Bwqr0XvOhfyLsYl/IHAh07/XSLgjEoDlcsB7kB64gWlkrIqwiL2iyFV9ydTzrmR8c0k4TLLrQ/zhKJV+1NI2Cw==",
	},
	{
		role:      "PARTICIPANT_B",
		id:        "sha256:23a27d5d379544dbb486e4b762ae43787b5282e5e16b5c673a07ba0a15928140",
		publicKey: "tiKC9lZqCo+d37gMLAosH6fYnUYeAENuDKWwr3GbfiY=",
		signature: "7Z5uLLRH2+t/eUJb4FqQDrRVuIiget8zvD1FMS/O8u0pXdEmNBrVV/OLfUjPcAgRbYPmth8KAHg25SCMXXGbBQ==",
	},
}

func a8Binding(t *testing.T) MordantProtectionBinding {
	t.Helper()
	var binding MordantProtectionBinding
	if err := json.Unmarshal([]byte(a8ConflictBindingJSON), &binding); err != nil {
		t.Fatalf("retained A8 V1 binding must decode: %v", err)
	}
	return binding
}

// The retained V1 binding must marshal back to exactly the same bytes. This is
// what protects every existing participant signature and the published A8
// envelopes from any V2 struct change.
func TestV1GoldenBindingMarshalsToIdenticalBytes(t *testing.T) {
	encoded, err := json.Marshal(a8Binding(t))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(encoded) != a8ConflictBindingJSON {
		t.Fatalf("V1 canonical bytes changed\n want: %s\n got : %s", a8ConflictBindingJSON, string(encoded))
	}
}

func TestV1GoldenBindingDigestUnchanged(t *testing.T) {
	digest, err := a8Binding(t).Digest()
	if err != nil {
		t.Fatalf("retained A8 V1 binding must validate and digest: %v", err)
	}
	if got := digest.String(); got != a8ConflictBindingDigest {
		t.Fatalf("V1 binding digest changed\n want: %s\n got : %s", a8ConflictBindingDigest, got)
	}
}

func TestV1GoldenFHECaseIDUnchanged(t *testing.T) {
	binding := a8Binding(t)
	allocation, err := protectionHolderAllocationDigest(binding)
	if err != nil {
		t.Fatalf("holder allocation digest: %v", err)
	}
	caseID, err := protectionFHECaseID(binding, allocation)
	if err != nil {
		t.Fatalf("case id: %v", err)
	}
	if got := caseID.String(); got != a8ConflictFHECaseID {
		t.Fatalf("V1 FHECaseID derivation changed\n want: %s\n got : %s", a8ConflictFHECaseID, got)
	}
}

// The two retained participant signatures over the V1 binding digest must still
// verify. If the digest moved, this fails, which is the hard stop condition.
func TestV1GoldenParticipantSignaturesStillVerify(t *testing.T) {
	digest, err := a8Binding(t).Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	for _, entry := range a8Participants {
		var participantID Digest
		if err := participantID.UnmarshalText([]byte(entry.id)); err != nil {
			t.Fatalf("%s participant id: %v", entry.role, err)
		}
		publicKey, err := base64.StdEncoding.DecodeString(entry.publicKey)
		if err != nil {
			t.Fatalf("%s public key: %v", entry.role, err)
		}
		rawSignature, err := base64.StdEncoding.DecodeString(entry.signature)
		if err != nil {
			t.Fatalf("%s signature: %v", entry.role, err)
		}
		identity := ParticipantIdentity{ID: participantID, Role: entry.role, SigningPublicKey: publicKey}
		signature := ProtectionBindingSignature{
			Role:                    entry.role,
			ParticipantID:           participantID,
			ProtectionBindingDigest: digest,
			Signature:               rawSignature,
		}
		if err := verifyProtectionSignature(signature, identity, digest); err != nil {
			t.Fatalf("%s retained V1 signature no longer verifies: %v", entry.role, err)
		}
	}
}
