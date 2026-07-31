package lattigospike

import (
	"encoding/hex"
	"testing"
)

func TestCanonicalInputCommitmentMatchesViemReference(t *testing.T) {
	chainID := Uint256{0, 0, 0, 31_337}
	vault := filled20(0x11)
	policyID := decode32(t, "bd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540")
	keyID := filled32(0xd0)
	ciphertextDigest := filled32(0xaa)
	authorizationCommitment := filled32(0xbb)
	receivableLinkCommitment := filled32(0xcc)
	clientNonce := Uint256{0, 0, 0, 7}

	observed := canonicalInputCommitmentWords(chainID, vault, policyID, 1, keyID, 0, ciphertextDigest, authorizationCommitment, receivableLinkCommitment, clientNonce)
	expected := decode32(t, "5bbc116f1ed84b59f8c604fc0d1b17582c09e230bd2b56a54e01373bbb70ed37")
	if observed != expected {
		t.Fatalf("Solidity ABI commitment mismatch: observed=%x expected=%x", observed, expected)
	}
}

func TestCanonicalInputCommitmentBindsSlotAndCiphertext(t *testing.T) {
	runtime := sharedTestRuntime(t)
	a, _ := fixturePair("canonical-input")
	pledge, _, err := runtime.EncryptPledge(a)
	if err != nil {
		t.Fatal(err)
	}
	base := InputCommitmentContext{
		ChainID:       Uint256{0, 0, 0, 31_337},
		Vault:         filled20(0x11),
		PolicyID:      decode32(t, "bd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540"),
		PolicyVersion: PolicyVersion,
		InputSlot:     0,
		ClientNonce:   Uint256{0, 0, 0, 7},
	}
	commitmentA, err := runtime.CanonicalInputCommitment(pledge, base)
	if err != nil {
		t.Fatal(err)
	}
	base.InputSlot = 1
	commitmentB, err := runtime.CanonicalInputCommitment(pledge, base)
	if err != nil {
		t.Fatal(err)
	}
	if commitmentA == commitmentB {
		t.Fatal("input slot was not bound into canonical commitment")
	}
}

func TestResultCommitmentMatchesSharedViemVector(t *testing.T) {
	result := PublicPolicyResultCore{
		ChainID:                 Uint256{0, 0, 0, 31_337},
		Vault:                   filled20(0x11),
		PolicyID:                decode32(t, "bd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540"),
		PolicyVersion:           1,
		InputCommitmentA:        decode32(t, "82118156ab9ee2b2c4f500e0ef4ce6e1dd35ebad13421fd5f4ccb78b941f6725"),
		InputCommitmentB:        decode32(t, "9dc2a7820edf7ac4700c85d114c655081bd799e9104de27e2fff0de7092a07fb"),
		ConflictConfirmed:       true,
		ResponsibleRole:         decode32(t, "e4e507c0331021261ae219c736aa71977a41f814117a0ea4f6bd31faf50d2674"),
		CureDeadline:            2_000_003_600,
		Nonce:                   Uint256{0, 0, 0, 7},
		ValidUntil:              2_000_000_300,
		ProviderProofCommitment: decode32(t, "af499d1fbecbe6f8582ae6a77073eefc800f5087a53e00d2df9b7dbe5f917e76"),
	}
	observed, err := ResultCommitment(result)
	if err != nil {
		t.Fatal(err)
	}
	expected := decode32(t, "ecfea1abebee6c34d75d1803d63de9295e3eeb0cfa4aff1285e7c731fb221f13")
	if observed != expected {
		t.Fatalf("result commitment mismatch: observed=%x expected=%x", observed, expected)
	}
}

func TestResultCommitmentV3BindsConsumerWithoutConsequences(t *testing.T) {
	base := PublicPolicyResultV3Core{
		ChainID: Uint256{0, 0, 0, 10_143}, Consumer: filled20(0x22), Vault: filled20(0x11),
		PolicyID: filled32(0x33), PolicyVersion: PolicyVersion, InputCommitmentA: filled32(0x44),
		InputCommitmentB: filled32(0x55), ConflictConfirmed: true, Nonce: Uint256{0, 0, 0, 9},
		ValidUntil: 2_000_000_000, ProviderProofCommitment: filled32(0x66),
	}
	first, err := ResultCommitmentV3(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Consumer = filled20(0x77)
	second, err := ResultCommitmentV3(base)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("consumer was not bound into V3 result commitment")
	}
}

func TestProviderProofCommitmentMatchesSharedViemVector(t *testing.T) {
	proof := ProviderProof{
		ResultCiphertextCommitment:    filled32(0x11),
		ThresholdTranscriptCommitment: filled32(0x22),
		ThresholdSessionID:            filled32(0x33),
		ThresholdKeyCommitment:        filled32(0x44),
		PolicyCircuitCommitment:       filled32(0x55),
	}
	observed, err := ProviderProofCommitment(proof)
	if err != nil {
		t.Fatal(err)
	}
	expected := decode32(t, "af499d1fbecbe6f8582ae6a77073eefc800f5087a53e00d2df9b7dbe5f917e76")
	if observed != expected {
		t.Fatalf("provider proof commitment mismatch: observed=%x expected=%x", observed, expected)
	}
}

func decode32(t *testing.T, value string) (out [32]byte) {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) {
		t.Fatalf("invalid bytes32 test vector")
	}
	copy(out[:], decoded)
	return
}

func filled32(value byte) (out [32]byte) {
	for i := range out {
		out[i] = value
	}
	return
}

func filled20(value byte) (out [20]byte) {
	for i := range out {
		out[i] = value
	}
	return
}
