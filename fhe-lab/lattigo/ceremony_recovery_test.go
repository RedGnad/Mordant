package lattigospike

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

func restoreCeremonyState(t *testing.T, state *CeremonyOperatorState, key ed25519.PrivateKey) *CeremonyOperatorState {
	t.Helper()
	encoded, err := state.MarshalPrivateRecoveryState()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreCeremonyOperatorState(state.params, state.roster, state.Point(), key, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return restored
}

func TestCeremonyPrivateRecoveryPreservesOneShotMaterial(t *testing.T) {
	params := ceremonyParameters(t)
	roster, keys, operators := newSetupFixture(t)
	original := operators[0]

	// Recovery before any exchange retains the exact already-sampled
	// contribution instead of sampling a second one under the ceremony ID.
	restored := restoreCeremonyState(t, original, keys[0])
	if restored.CRSContribution() != original.CRSContribution() {
		t.Fatal("recovery regenerated the CRS contribution")
	}

	exchangeCRS(t, operators)
	restored = restoreCeremonyState(t, original, keys[0])
	originalShare, err := original.PrivateShareFor(2)
	if err != nil {
		t.Fatal(err)
	}
	restoredShare, err := restored.PrivateShareFor(2)
	if err != nil {
		t.Fatal(err)
	}
	originalWire, err := originalShare.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restoredWire, err := restoredShare.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalWire, restoredWire) {
		t.Fatal("recovery regenerated a private re-share")
	}
	if _, err := restored.PrivateShareFor(2); !errors.Is(err, ErrCeremonyReplay) {
		t.Fatalf("recovered emitted-set allowed duplicate private re-share: %v", err)
	}

	// Finish the private exchange, using the original operator's persisted wire
	// for point 2 and its normal one-shot output for every other recipient.
	for senderIndex, sender := range operators {
		for _, recipient := range operators {
			var share CeremonyPrivateShare
			if senderIndex == 0 && recipient.Point() == 2 {
				share = originalShare
			} else {
				share, err = sender.PrivateShareFor(recipient.Point())
				if err != nil {
					t.Fatalf("private share %d->%d: %v", sender.Point(), recipient.Point(), err)
				}
			}
			if err := recipient.AcceptPrivateShare(share); err != nil {
				t.Fatalf("accept private share %d->%d: %v", sender.Point(), recipient.Point(), err)
			}
		}
	}
	for _, operator := range operators {
		if err := operator.SealThresholdShare(); err != nil {
			t.Fatal(err)
		}
	}

	// The common CRS stream is reconstructed at the exact protocol boundary and
	// the operator can continue exactly once. Public shares include fresh
	// protocol noise, so their exact wire is made durable by the surrounding
	// ledger (tested separately) at the same time as the post-operation state.
	restored = restoreCeremonyState(t, original, keys[0])
	restoredPublic, err := restored.PublicKeyShare()
	if err != nil || len(restoredPublic) == 0 {
		t.Fatal(err)
	}
	if _, err := restored.PublicKeyShare(); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("recovered state repeated the public-key round: %v", err)
	}

	// A snapshot is cryptographically and operationally bound to the exact
	// roster, ceremony identifier, point, signing key and parameter set.
	encoded, err := original.MarshalPrivateRecoveryState()
	if err != nil {
		t.Fatal(err)
	}
	differentCeremony := roster
	differentCeremony.CeremonyID = sha256.Sum256([]byte("different-ceremony"))
	if _, err := RestoreCeremonyOperatorState(params, differentCeremony, 1, keys[0], encoded); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("state crossed ceremony identifiers: %v", err)
	}
	if _, err := RestoreCeremonyOperatorState(params, roster, 2, keys[1], encoded); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("state crossed operator identities: %v", err)
	}
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreCeremonyOperatorState(params, roster, 1, wrongKey, encoded); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("state accepted an unpinned signing key: %v", err)
	}
}

func TestCeremonyPrivateRecoveryRejectsInvalidHeader(t *testing.T) {
	_, keys, operators := newSetupFixture(t)
	encoded, err := operators[0].MarshalPrivateRecoveryState()
	if err != nil {
		t.Fatal(err)
	}
	encoded[0] ^= 0x80
	if _, err := RestoreCeremonyOperatorState(operators[0].params, operators[0].roster, 1, keys[0], encoded); err == nil {
		t.Fatal("corrupted private recovery state was accepted")
	}
}

func TestEveryCanonicalCeremonyManifestByteIsSignedByAllOperators(t *testing.T) {
	params := ceremonyParameters(t)
	keys := make([]ed25519.PrivateKey, 3)
	for index := range keys {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[index] = key
	}
	roster := newCeremonyRoster(t, params, keys)
	digests := CeremonyKeyDigests{
		CRSCommitment: sha256.Sum256([]byte("crs")), PublicKeyCommitment: sha256.Sum256([]byte("pk")),
		RelinearizationKeyDigest: sha256.Sum256([]byte("relin")), GaloisKeyCommitment: sha256.Sum256([]byte("galois")),
		PolicyCircuitCommitment: sha256.Sum256([]byte("policy")),
	}
	statement := MarshalCeremonyManifestStatement(roster, digests)
	digest := sha256.Sum256(statement)
	if digest != CeremonyManifestDigest(roster, digests) {
		t.Fatal("public manifest statement differs from the existing V4 signature preimage")
	}
	signatures := make([][]byte, len(keys))
	for index, key := range keys {
		signatures[index] = ed25519.Sign(key, digest[:])
		if !ed25519.Verify(key.Public().(ed25519.PublicKey), digest[:], signatures[index]) {
			t.Fatalf("operator %d original signature failed", index+1)
		}
	}
	for offset := range statement {
		mutated := append([]byte(nil), statement...)
		mutated[offset] ^= 1
		mutatedDigest := sha256.Sum256(mutated)
		for index, key := range keys {
			if ed25519.Verify(key.Public().(ed25519.PublicKey), mutatedDigest[:], signatures[index]) {
				t.Fatalf("operator %d signature survived mutation at byte %d", index+1, offset)
			}
		}
	}
}

func TestCeremonyRecoveryRetainsRelinEphemeralThroughoutGaloisRound(t *testing.T) {
	_, keys, operators := newSetupFixture(t)
	exchangeCRS(t, operators)
	for _, sender := range operators {
		for _, recipient := range operators {
			share, err := sender.PrivateShareFor(recipient.Point())
			if err != nil {
				t.Fatal(err)
			}
			if err := recipient.AcceptPrivateShare(share); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, operator := range operators {
		if err := operator.SealThresholdShare(); err != nil {
			t.Fatal(err)
		}
	}
	operator := operators[0]
	if _, err := operator.PublicKeyShare(); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.RelinearizationShareRoundOne(); err != nil {
		t.Fatal(err)
	}
	// Round two retains this ephemeral until final Seal. Model the exact
	// post-round-two phase boundary; relinRoundOne is not consumed by Galois.
	operator.round = roundGalois
	restored := restoreCeremonyState(t, operator, keys[0])
	if restored.round != roundGalois || restored.ephemeral == nil {
		t.Fatal("recovery discarded the relin ephemeral needed until final seal")
	}
}
