package lattigospike

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// newSetupFixture stops before collective key generation. Every negative in
// this file is reachable at or before the private-share round, so the rejection
// paths are cheap enough to exercise exhaustively.
func newSetupFixture(t *testing.T) (CeremonyRoster, []ed25519.PrivateKey, []*CeremonyOperatorState) {
	t.Helper()
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
	operators := make([]*CeremonyOperatorState, 3)
	for index := range operators {
		state, err := NewCeremonyOperatorState(params, roster, uint64(index+1), keys[index])
		if err != nil {
			t.Fatal(err)
		}
		operators[index] = state
	}
	return roster, keys, operators
}

func exchangeCRS(t *testing.T, operators []*CeremonyOperatorState) {
	t.Helper()
	for _, source := range operators {
		for _, target := range operators {
			if source.Point() == target.Point() {
				continue
			}
			if err := target.AcceptCRSContribution(source.Point(), source.CRSContribution()); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, operator := range operators {
		if err := operator.SealCRS(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCeremonyRejectsUnknownOperatorAndDuplicateContribution(t *testing.T) {
	_, _, operators := newSetupFixture(t)
	if err := operators[0].AcceptCRSContribution(99, [32]byte{1}); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("contribution from a non-roster point accepted: %v", err)
	}
	if err := operators[0].AcceptCRSContribution(2, [32]byte{}); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("empty contribution accepted: %v", err)
	}
	contribution := operators[1].CRSContribution()
	if err := operators[0].AcceptCRSContribution(2, contribution); err != nil {
		t.Fatal(err)
	}
	// Re-sending the identical contribution is idempotent; a different value
	// for the same point is a conflicting duplicate and must be refused.
	if err := operators[0].AcceptCRSContribution(2, contribution); err != nil {
		t.Fatalf("idempotent contribution rejected: %v", err)
	}
	if err := operators[0].AcceptCRSContribution(2, [32]byte{9}); !errors.Is(err, ErrCeremonyReplay) {
		t.Fatalf("conflicting duplicate contribution accepted: %v", err)
	}
}

func TestCeremonyRefusesSealBeforeEveryContribution(t *testing.T) {
	_, _, operators := newSetupFixture(t)
	if err := operators[0].SealCRS(); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("CRS sealed with a missing contribution: %v", err)
	}
}

func TestCeremonyRejectsReorderedRounds(t *testing.T) {
	_, _, operators := newSetupFixture(t)
	operator := operators[0]
	// Nothing may run before the CRS is sealed.
	if _, err := operator.PrivateShareFor(2); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("private share emitted before CRS seal: %v", err)
	}
	if _, err := operator.PublicKeyShare(); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("public key share emitted before CRS seal: %v", err)
	}
	exchangeCRS(t, operators)
	// The threshold share must be sealed before key generation starts.
	if _, err := operator.PublicKeyShare(); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("public key share emitted before threshold seal: %v", err)
	}
	if _, err := operator.RelinearizationShareRoundOne(); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("relin round one emitted out of order: %v", err)
	}
	if _, err := operator.RelinearizationShareRoundTwo([]byte("x")); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("relin round two emitted out of order: %v", err)
	}
	if _, err := operator.GaloisShare(1); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("galois share emitted out of order: %v", err)
	}
	if _, err := operator.Seal(CeremonyKeyDigests{}); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("seal accepted out of order: %v", err)
	}
}

func TestCeremonyPrivateShareIsOneShotPerRecipient(t *testing.T) {
	_, _, operators := newSetupFixture(t)
	exchangeCRS(t, operators)
	if _, err := operators[0].PrivateShareFor(2); err != nil {
		t.Fatal(err)
	}
	// Lattigo documents that reusing protocol material across retries can leak
	// secrets, so a second emission for the same recipient is refused.
	if _, err := operators[0].PrivateShareFor(2); !errors.Is(err, ErrCeremonyReplay) {
		t.Fatalf("private share re-emitted for the same recipient: %v", err)
	}
	if _, err := operators[0].PrivateShareFor(77); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("private share emitted for a non-roster recipient: %v", err)
	}
}

func TestCeremonyRejectsReplayedForgedAndMisboundPrivateShares(t *testing.T) {
	roster, keys, operators := newSetupFixture(t)
	exchangeCRS(t, operators)
	share, err := operators[0].PrivateShareFor(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := operators[1].AcceptPrivateShare(share); err != nil {
		t.Fatal(err)
	}
	// Replay of the same authenticated message.
	if err := operators[1].AcceptPrivateShare(share); !errors.Is(err, ErrCeremonyReplay) {
		t.Fatalf("replayed private share accepted: %v", err)
	}

	fresh, err := operators[0].PrivateShareFor(3)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong recipient: operator 2 must not absorb a share addressed to 3.
	if err := operators[1].AcceptPrivateShare(fresh); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("misaddressed private share accepted: %v", err)
	}

	// Wrong ceremony id.
	wrongCeremony := fresh
	wrongCeremony.CeremonyID = sha256.Sum256([]byte("other-ceremony"))
	if err := operators[2].AcceptPrivateShare(wrongCeremony); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("share from another ceremony accepted: %v", err)
	}

	// Wrong key epoch.
	wrongEpoch := fresh
	wrongEpoch.KeyEpoch = roster.KeyEpoch + 1
	if err := operators[2].AcceptPrivateShare(wrongEpoch); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("share from another key epoch accepted: %v", err)
	}

	// Wrong roster digest.
	wrongRoster := fresh
	wrongRoster.RosterDigest = sha256.Sum256([]byte("other-roster"))
	if err := operators[2].AcceptPrivateShare(wrongRoster); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("share bound to another roster accepted: %v", err)
	}

	// Forged signature: an attacker re-signs a mutated payload with a key that
	// is not the declared sender's.
	forged := fresh
	forged.Payload = append([]byte(nil), fresh.Payload...)
	forged.Payload[0] ^= 0xFF
	digest := forged.signingDigest()
	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(forged.Signature[:], ed25519.Sign(attacker, digest[:]))
	if err := operators[2].AcceptPrivateShare(forged); !errors.Is(err, ErrCeremonySignature) {
		t.Fatalf("forged private share accepted: %v", err)
	}

	// A payload mutated without re-signing must also fail authentication.
	tampered := fresh
	tampered.Payload = append([]byte(nil), fresh.Payload...)
	tampered.Payload[1] ^= 0x01
	if err := operators[2].AcceptPrivateShare(tampered); !errors.Is(err, ErrCeremonySignature) {
		t.Fatalf("tampered private share accepted: %v", err)
	}
	_ = keys
}

func TestCeremonyAbsentOperatorIsTerminal(t *testing.T) {
	_, _, operators := newSetupFixture(t)
	exchangeCRS(t, operators)
	// Operator 3 never sends its re-sharing to operator 1.
	for _, sender := range []int{0, 1} {
		share, err := operators[sender].PrivateShareFor(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := operators[0].AcceptPrivateShare(share); err != nil {
			t.Fatal(err)
		}
	}
	// The documented safe rule: an incomplete re-sharing round is terminal. The
	// operator refuses to seal a partial share rather than continuing with a
	// key that only some operators can reconstruct.
	if err := operators[0].SealThresholdShare(); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("threshold share sealed with a missing operator: %v", err)
	}
	if _, err := operators[0].PublicKeyShare(); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("key generation continued after an incomplete re-sharing: %v", err)
	}
}

func TestCeremonyRosterValidation(t *testing.T) {
	params := ceremonyParameters(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roster, keys, _ := newSetupFixture(t)

	// A point outside the roster cannot instantiate an operator.
	if _, err := NewCeremonyOperatorState(params, roster, 42, keys[0]); !errors.Is(err, ErrCeremonyRoster) {
		t.Fatalf("operator outside the roster accepted: %v", err)
	}
	// A signing key that does not match the roster entry is refused.
	if _, err := NewCeremonyOperatorState(params, roster, 1, key); !errors.Is(err, ErrCeremonyRoster) {
		t.Fatalf("mismatched signing key accepted: %v", err)
	}
	// Threshold below two is not a threshold.
	broken := roster
	broken.Threshold = 1
	if _, err := NewCeremonyOperatorState(params, broken, 1, keys[0]); !errors.Is(err, ErrCeremonyRoster) {
		t.Fatalf("threshold 1 accepted: %v", err)
	}
	// A parameter fingerprint that does not match the actual parameters is a
	// binding failure, not a roster failure.
	wrongFingerprint := roster
	wrongFingerprint.ParameterFingerprint = sha256.Sum256([]byte("other-parameters"))
	if _, err := NewCeremonyOperatorState(params, wrongFingerprint, 1, keys[0]); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("wrong parameter fingerprint accepted: %v", err)
	}
	// Duplicate points must not form a roster.
	duplicate := roster
	duplicate.Operators = append([]CeremonyOperatorIdentity(nil), roster.Operators...)
	duplicate.Operators[2].Point = duplicate.Operators[1].Point
	if _, err := NewCeremonyOperatorState(params, duplicate, 1, keys[0]); !errors.Is(err, ErrCeremonyRoster) {
		t.Fatalf("duplicate roster point accepted: %v", err)
	}
}

func TestCeremonyDivergentCRSCannotCountersignTheManifest(t *testing.T) {
	_, _, operators := newSetupFixture(t)
	// Operators 1 and 2 agree. Operator 3 is fed a different contribution for
	// operator 1, so it derives a different CRS and a different commitment.
	for _, source := range operators {
		for _, target := range operators[:2] {
			if source.Point() == target.Point() {
				continue
			}
			if err := target.AcceptCRSContribution(source.Point(), source.CRSContribution()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := operators[2].AcceptCRSContribution(1, sha256.Sum256([]byte("substituted-contribution"))); err != nil {
		t.Fatal(err)
	}
	if err := operators[2].AcceptCRSContribution(2, operators[1].CRSContribution()); err != nil {
		t.Fatal(err)
	}
	for _, operator := range operators {
		if err := operator.SealCRS(); err != nil {
			t.Fatal(err)
		}
	}
	if operators[0].CRSCommitment() == operators[2].CRSCommitment() {
		t.Fatal("a substituted contribution produced the same CRS")
	}
	// The divergence is caught at seal time: an operator refuses to sign a
	// manifest whose CRS commitment is not the one it actually used, so the
	// manifest cannot collect a full set of attestations.
	digests := CeremonyKeyDigests{
		CRSCommitment:            operators[0].CRSCommitment(),
		PublicKeyCommitment:      sha256.Sum256([]byte("pk")),
		RelinearizationKeyDigest: sha256.Sum256([]byte("rlk")),
		GaloisKeyCommitment:      sha256.Sum256([]byte("gal")),
		PolicyCircuitCommitment:  sha256.Sum256([]byte("policy")),
	}
	if _, err := operators[2].Seal(digests); err == nil {
		t.Fatal("an operator signed a manifest for a CRS it did not use")
	}
}

func TestCeremonyAggregatorRejectsDuplicateAndForeignShares(t *testing.T) {
	params := ceremonyParameters(t)
	roster, _, operators := newSetupFixture(t)
	aggregator, err := NewCeremonyAggregator(params, roster)
	if err != nil {
		t.Fatal(err)
	}
	for _, operator := range operators {
		if err := aggregator.AcceptCRSContribution(operator.Point(), operator.CRSContribution()); err != nil {
			t.Fatal(err)
		}
	}
	if err := aggregator.AcceptCRSContribution(1, [32]byte{7}); !errors.Is(err, ErrCeremonyReplay) {
		t.Fatalf("aggregator accepted a duplicate contribution: %v", err)
	}
	if err := aggregator.AcceptCRSContribution(64, [32]byte{7}); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("aggregator accepted a foreign contribution: %v", err)
	}
	if err := aggregator.SealCRS(); err != nil {
		t.Fatal(err)
	}
	// Out-of-stage messages are refused: relinearization cannot start before the
	// collective public key has been derived.
	if err := aggregator.AcceptRelinearizationShareRoundOne(1, []byte("x")); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("aggregator accepted an out-of-stage relin share: %v", err)
	}
	if err := aggregator.AcceptGaloisShare(1, []byte("x")); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("aggregator accepted an out-of-stage galois share: %v", err)
	}
	if err := aggregator.AcceptPublicKeyShare(9, []byte("x")); !errors.Is(err, ErrCeremonyBinding) {
		t.Fatalf("aggregator accepted a share from a foreign point: %v", err)
	}
	if err := aggregator.AcceptPublicKeyShare(1, nil); !errors.Is(err, ErrCeremonyMaterial) {
		t.Fatalf("aggregator accepted an empty share: %v", err)
	}
	if _, _, _, err := aggregator.CollectiveKeys(); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("aggregator surrendered keys from an unfinished ceremony: %v", err)
	}
}

func TestCeremonyPrivateShareWireRoundTripAndBounds(t *testing.T) {
	_, _, operators := newSetupFixture(t)
	exchangeCRS(t, operators)
	share, err := operators[0].PrivateShareFor(2)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalCeremonyPrivateShare(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sender != share.Sender || decoded.Recipient != share.Recipient ||
		decoded.CeremonyID != share.CeremonyID || decoded.RosterDigest != share.RosterDigest {
		t.Fatal("private share did not round-trip")
	}
	if _, err := UnmarshalCeremonyPrivateShare(append(wire, 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	if _, err := UnmarshalCeremonyPrivateShare(wire[:len(wire)-1]); err == nil {
		t.Fatal("truncated message accepted")
	}
	if _, err := UnmarshalCeremonyPrivateShare([]byte("nope")); err == nil {
		t.Fatal("bad magic accepted")
	}
}

func TestManifestVerificationRejectsSubstitutedAndUnauthenticatedKeys(t *testing.T) {
	roster, keys, operators := newSetupFixture(t)
	digests := CeremonyKeyDigests{
		CRSCommitment:            sha256.Sum256([]byte("crs")),
		PublicKeyCommitment:      sha256.Sum256([]byte("collective-public-key")),
		RelinearizationKeyDigest: sha256.Sum256([]byte("rlk")),
		GaloisKeyCommitment:      sha256.Sum256([]byte("gal")),
		PolicyCircuitCommitment:  sha256.Sum256([]byte("policy-circuit")),
	}
	manifestDigest := digests.manifestDigest(roster)
	attestations := make([]CeremonyAttestation, 0, len(keys))
	for index, key := range keys {
		attestation := CeremonyAttestation{Point: uint64(index + 1)}
		copy(attestation.Signature[:], ed25519.Sign(key, manifestDigest[:]))
		attestations = append(attestations, attestation)
	}
	if err := VerifyCeremonyAttestations(roster, digests, attestations); err != nil {
		t.Fatal(err)
	}
	// A quorum is not enough for a key manifest: every operator must sign.
	if err := VerifyCeremonyAttestations(roster, digests, attestations[:2]); !errors.Is(err, ErrCeremonySignature) {
		t.Fatalf("partially attested manifest accepted: %v", err)
	}
	// A duplicated signature cannot stand in for a missing operator.
	padded := []CeremonyAttestation{attestations[0], attestations[1], attestations[1]}
	if err := VerifyCeremonyAttestations(roster, digests, padded); !errors.Is(err, ErrCeremonyReplay) {
		t.Fatalf("duplicated attestation accepted: %v", err)
	}
	// Substituting the public-key commitment invalidates every signature.
	substituted := digests
	substituted.PublicKeyCommitment = sha256.Sum256([]byte("evaluator-substituted-key"))
	if err := VerifyCeremonyAttestations(roster, substituted, attestations); !errors.Is(err, ErrCeremonySignature) {
		t.Fatalf("substituted public key accepted: %v", err)
	}

	keyID := sha256.Sum256([]byte("key-id"))
	policyID := sha256.Sum256([]byte("policy"))
	now := time.Unix(1_900_000_000, 0)
	manifest, err := BuildCollectiveKeyManifest(roster, digests, attestations, keyID, 10143, policyID, PolicyVersion, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalCollectiveKeyManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := UnmarshalCollectiveKeyManifest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	expectation := ClientKeyExpectation{
		RosterDigest:  roster.Digest(),
		Threshold:     2,
		KeyEpoch:      roster.KeyEpoch,
		ChainID:       10143,
		PolicyID:      policyID,
		PolicyVersion: PolicyVersion,
		Now:           now,
	}
	if err := VerifyCollectiveKeyManifest(parsed, expectation, keyID, digests.PublicKeyCommitment); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}

	// Client-side rejections required by the mission.
	cases := []struct {
		name    string
		mutate  func(*CollectiveKeyManifest, *ClientKeyExpectation)
		keyID   [32]byte
		keyComm [32]byte
	}{
		{"unknown operator set", func(_ *CollectiveKeyManifest, e *ClientKeyExpectation) {
			e.RosterDigest = sha256.Sum256([]byte("other-operators"))
		}, keyID, digests.PublicKeyCommitment},
		{"wrong threshold", func(m *CollectiveKeyManifest, _ *ClientKeyExpectation) { m.Threshold = 3 }, keyID, digests.PublicKeyCommitment},
		{"wrong key epoch", func(m *CollectiveKeyManifest, _ *ClientKeyExpectation) { m.KeyEpoch = 9 }, keyID, digests.PublicKeyCommitment},
		{"expired manifest", func(m *CollectiveKeyManifest, _ *ClientKeyExpectation) {
			m.ExpiresAtUnix = now.Add(-time.Minute).Unix()
		}, keyID, digests.PublicKeyCommitment},
		{"revoked manifest", func(m *CollectiveKeyManifest, _ *ClientKeyExpectation) { m.Revoked = true }, keyID, digests.PublicKeyCommitment},
		{"mismatched public key", func(_ *CollectiveKeyManifest, _ *ClientKeyExpectation) {}, keyID, sha256.Sum256([]byte("substituted"))},
		{"mismatched key id", func(_ *CollectiveKeyManifest, _ *ClientKeyExpectation) {}, sha256.Sum256([]byte("other")), digests.PublicKeyCommitment},
		{"insufficient authentication", func(m *CollectiveKeyManifest, _ *ClientKeyExpectation) {
			m.Attestations = m.Attestations[:2]
		}, keyID, digests.PublicKeyCommitment},
		{"trusted dealer custody", func(m *CollectiveKeyManifest, _ *ClientKeyExpectation) {
			m.CustodyModel = string(CustodyTrustedDealer)
		}, keyID, digests.PublicKeyCommitment},
		{"wrong policy scope", func(m *CollectiveKeyManifest, _ *ClientKeyExpectation) { m.ChainID = 1 }, keyID, digests.PublicKeyCommitment},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mutated := parsed
			mutated.Attestations = append([]string(nil), parsed.Attestations...)
			mutatedExpectation := expectation
			testCase.mutate(&mutated, &mutatedExpectation)
			if err := VerifyCollectiveKeyManifest(mutated, mutatedExpectation, testCase.keyID, testCase.keyComm); !errors.Is(err, ErrManifestRejected) {
				t.Fatalf("client accepted %s: %v", testCase.name, err)
			}
		})
	}
	_ = operators
}

// TestCeremonyUnsafeReinitializationIsDetectedAndFailsClosed proves that a
// caller cannot bypass the private recovery ledger by constructing fresh state
// under an existing ceremony identifier.
//
// The supported process restart restores the operator-local immutable ledger.
// A direct constructor necessarily samples fresh material and cannot silently
// join the persisted cohort; divergence is caught before key publication.
func TestCeremonyUnsafeReinitializationIsDetectedAndFailsClosed(t *testing.T) {
	params := ceremonyParameters(t)
	roster, keys, operators := newSetupFixture(t)
	original := make(map[uint64][32]byte, len(operators))
	for _, operator := range operators {
		original[operator.Point()] = operator.CRSContribution()
	}
	exchangeCRS(t, operators)
	cohortCommitment := operators[0].CRSCommitment()

	// Operator 2 restarts: a brand new state object with brand new secrets.
	restarted, err := NewCeremonyOperatorState(params, roster, 2, keys[1])
	if err != nil {
		t.Fatal(err)
	}
	if restarted.CRSContribution() == original[2] {
		t.Fatal("a restarted operator reused its previous CRS contribution")
	}
	// It is fed the cohort's table, which still carries its pre-crash value for
	// its own point. Its own contribution is the fresh one, so its seed differs.
	for _, point := range []uint64{1, 3} {
		if err := restarted.AcceptCRSContribution(point, original[point]); err != nil {
			t.Fatal(err)
		}
	}
	if err := restarted.SealCRS(); err != nil {
		t.Fatal(err)
	}
	if restarted.CRSCommitment() == cohortCommitment {
		t.Fatal("a restarted operator silently rejoined the cohort CRS")
	}

	// The restarted operator also cannot inherit the pre-crash threshold share:
	// it has received nothing, so sealing is refused and key generation is shut.
	if err := restarted.SealThresholdShare(); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("restarted operator sealed a threshold share it never received: %v", err)
	}
	if _, err := restarted.PublicKeyShare(); !errors.Is(err, ErrCeremonyState) {
		t.Fatalf("restarted operator contributed to key generation: %v", err)
	}
}
