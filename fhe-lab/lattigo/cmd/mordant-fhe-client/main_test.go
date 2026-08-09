package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParticipantSigningKeyCreationIsPrivateAndCreateOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "participant-signing-key.bin")
	secret := bytes.Repeat([]byte{0x5a}, 64)
	if err := createLocalSecret(path, secret); err != nil {
		t.Fatalf("create local secret: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected key mode: %v", info.Mode())
	}
	if err := createLocalSecret(path, bytes.Repeat([]byte{0x33}, 64)); err == nil {
		t.Fatal("existing participant key was overwritten")
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, secret) {
		t.Fatalf("create-only key changed: %v", err)
	}
}

func TestParticipantKeygenResultNeverContainsThePrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "participant-signing-key.bin")
	result, err := generateParticipantSigningKey(path)
	if err != nil {
		t.Fatalf("participant keygen: %v", err)
	}
	privateKey, err := os.ReadFile(path)
	if err != nil || len(privateKey) != 64 {
		t.Fatalf("read participant private key: %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		privateKey,
		[]byte(hex.EncodeToString(privateKey)),
		[]byte(base64.StdEncoding.EncodeToString(privateKey)),
	} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatal("participant key-generation stdout schema contains private key material")
		}
	}
	if !strings.HasPrefix(result.ParticipantSigningPublicKey, "0x") ||
		!strings.HasPrefix(result.ParticipantSigningKeyDigest, "0x") {
		t.Fatal("key generation did not return Phase-0-ready public values")
	}
	if _, err := generateParticipantSigningKey(path); err == nil {
		t.Fatal("participant keygen overwrote an existing private key")
	}
}

func TestParticipantLocalPledgeRequiresCanonicalZeroFullFHECommitment(t *testing.T) {
	hex32 := func(value string) string { return "0x" + strings.Repeat(value, 64) }
	input := participantLocalPledge{
		SchemaVersion: participantLocalPledgeSchema,
		ActiveFrom:    100, ActiveUntil: 400, Amount: [4]uint64{0, 0, 0, 100_000_000},
		Currency: hex32("1"), ObligationID: hex32("2"), ReceivableID: hex32("3"), Exclusive: true,
		ReceivableCommitment: hex32("0"),
	}
	if _, err := participantPledgeFromInput(input); err != nil {
		t.Fatalf("canonical full-FHE pledge rejected: %v", err)
	}
	input.ReceivableCommitment = hex32("4")
	if _, err := participantPledgeFromInput(input); err == nil {
		t.Fatal("nonzero full-FHE receivableCommitment accepted")
	}
}

func TestPreparationRequestRejectsClaimPreimagesSaltsAndPrivateKeys(t *testing.T) {
	request := participantPreparationRequest{
		SchemaVersion:          participantPreparationRequestSchema,
		ClientBundleDigest:     "0x" + string(bytes.Repeat([]byte{'1'}, 64)),
		ClaimCommitment:        "0x" + string(bytes.Repeat([]byte{'2'}, 64)),
		EncryptionIntentDigest: "0x" + string(bytes.Repeat([]byte{'3'}, 64)),
		SubmissionNonce:        "0x" + string(bytes.Repeat([]byte{'4'}, 64)),
		ExpiresAtUnix:          1_900_000_000,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeCanonicalJSON(append(encoded, '\n'), &participantPreparationRequest{}); err != nil {
		t.Fatalf("canonical preparation request rejected: %v", err)
	}
	for _, extra := range []string{
		`,"activeFrom":100}`, `,"activeUntil":400}`, `,"claim":{"activeFrom":100}}`,
		`,"salt":"secret"}`, `,"participantSigningPrivateKey":"secret"}`,
	} {
		candidate := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(extra)...)
		if err := decodeCanonicalJSON(candidate, &participantPreparationRequest{}); err == nil {
			t.Fatalf("forbidden preparation member accepted: %s", extra)
		}
	}
}

func TestManagedSubmissionRemainsTheDefaultInputProfile(t *testing.T) {
	if defaultClientMode != "submit" {
		t.Fatalf("managed default mode changed to %q", defaultClientMode)
	}
	legacy := []byte(`{"activeFrom":100,"activeUntil":400,"amount":[0,0,0,1],"currency":"0x01","obligationId":"0x02","receivableId":"0x03","exclusive":true,"authorizationCommitment":"0x04","privateMetadataCommitment":"0x05"}`)
	var input pledgeInput
	decoder := json.NewDecoder(bytes.NewReader(legacy))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatalf("retained managed pledge shape no longer decodes: %v", err)
	}
	if input.AuthorizationCommitment != "0x04" || input.PrivateMetadataCommitment != "0x05" {
		t.Fatal("managed commitment fields changed")
	}
}
