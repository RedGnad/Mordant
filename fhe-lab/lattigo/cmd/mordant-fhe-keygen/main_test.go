package main

import (
	"encoding/json"
	"testing"

	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

func TestManagedKeygenRemainsDefaultAndParticipantFoundationRejectsPrivateKeys(t *testing.T) {
	if defaultKeygenMode != "create" {
		t.Fatalf("managed keygen default changed to %q", defaultKeygenMode)
	}
	if err := rejectParticipantFoundationPrivateKeys("", ""); err != nil {
		t.Fatalf("public-key-only foundation rejected empty private-key flags: %v", err)
	}
	if err := rejectParticipantFoundationPrivateKeys("/private/a", ""); err == nil {
		t.Fatal("participant foundation accepted participant A private-key path")
	}
	if err := rejectParticipantFoundationPrivateKeys("", "/private/b"); err == nil {
		t.Fatal("participant foundation accepted participant B private-key path")
	}
}

func TestCeremonyRequestInputIsCanonicalAndRejectsSecretExtras(t *testing.T) {
	request := participantCeremonyRequestInput{
		SchemaVersion: participantCeremonyRequestInputSchema, RunID: "8a44f9e0-20d7-4ca3-8762-82bcbfc648af",
		Role: "PARTICIPANT_A", ExpectedSourceDigest: keygenTestDigest(0x11),
		ExpectedBuildManifestDigest: keygenTestDigest(0x22), ExpectedClientBinaryDigest: keygenTestDigest(0x33),
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeCanonicalJSON(append(encoded, '\n'), &participantCeremonyRequestInput{}); err != nil {
		t.Fatalf("canonical ceremony request input rejected: %v", err)
	}
	for _, extra := range []string{`,"participantSigningPrivateKey":"secret"}`, `,"claim":{"activeFrom":1}}`, `,"salt":"secret"}`} {
		candidate := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(extra)...)
		if err := decodeCanonicalJSON(candidate, &participantCeremonyRequestInput{}); err == nil {
			t.Fatalf("forbidden ceremony input member accepted: %s", extra)
		}
	}
}

func keygenTestDigest(value byte) governedfhe.Digest {
	var digest governedfhe.Digest
	for index := range digest {
		digest[index] = value
	}
	return digest
}
