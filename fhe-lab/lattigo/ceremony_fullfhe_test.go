package lattigospike

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Mode B measurement.
//
// Private Conflict Discovery evaluates the 256-bit economic-asset equality under
// encryption (IdentityFullFHE256) instead of gating on a shared public
// receivable-link commitment (IdentityPublicCommitment). This test runs both
// modes against the same dealerless collective keys and records the delta, and
// it asserts the property that motivates the mode: the equality is decided
// homomorphically, so two pledges that name different assets produce a false
// result without either identifier ever being compared in the clear.
//
// It writes fhe-lab/privacy-v4/evidence/fullfhe-measurement.json.

type modeMeasurement struct {
	Mode                    string `json:"mode"`
	ClientEncryptMillis     int64  `json:"clientEncryptMillisPerPledge"`
	IdentityEncryptMillis   int64  `json:"identityEncryptMillisPerPledge"`
	EnvelopeBytes           int    `json:"envelopeBytesPerPledge"`
	IdentityCiphertextBytes int    `json:"identityCiphertextBytesPerPledge"`
	EvaluationMillis        int64  `json:"evaluationMillis"`
	IdentityEqualityMillis  int64  `json:"identityEqualityMillis"`
	MultiplicativeDepth     int    `json:"multiplicativeDepth"`
}

type fullFHEEvidence struct {
	SchemaVersion  string          `json:"schemaVersion"`
	LattigoVersion string          `json:"lattigoVersion"`
	CustodyModel   string          `json:"custodyModel"`
	Parameters     string          `json:"parameters"`
	Baseline       modeMeasurement `json:"modeA_IdentityPublicCommitment"`
	Private        modeMeasurement `json:"modeB_IdentityFullFHE256"`
	Delta          struct {
		EncryptMillisPerPledge int64 `json:"encryptMillisPerPledge"`
		EnvelopeBytesPerPledge int   `json:"envelopeBytesPerPledge"`
		EvaluationMillis       int64 `json:"evaluationMillis"`
		TotalTransportBytes    int   `json:"totalTransportBytesForTwoPledges"`
	} `json:"delta"`
	InformationHidden []string `json:"informationModeBHidesThatModeAReveals"`
	Assertions        []string `json:"assertions"`
}

func TestFullFHEIdentityEqualityUnderDealerlessKeys(t *testing.T) {
	fixture := runCeremony(t)

	// Both modes are exercised directly against the collective keys. The
	// enrollment layer is not involved: this measures the circuit and the
	// client, which is what the mode decision turns on.
	run := func(mode IdentityMode, label string, sameAsset bool) (modeMeasurement, bool) {
		material, err := fixture.runtime.ExportPublicEncryptionMaterial()
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewExternalClient(material)
		if err != nil {
			t.Fatal(err)
		}
		pledgeA, pledgeB := fixturePair(label)
		assetID := sha256.Sum256([]byte("mordant.v4.asset/" + label))
		pledgeA.ReceivableID = assetID
		if sameAsset {
			pledgeB.ReceivableID = assetID
		} else {
			pledgeB.ReceivableID = sha256.Sum256([]byte("mordant.v4.other/" + label))
		}
		if mode == IdentityFullFHE256 {
			pledgeA.ReceivableCommitment = [32]byte{}
			pledgeB.ReceivableCommitment = [32]byte{}
		}

		// The signed-enrollment path is the real ingress, so the measurement
		// reflects what a client actually pays.
		now := time.Unix(1_900_000_000, 0)
		issuerKey := deterministicIssuerKey("fullfhe-" + label)
		if _, err := fixture.runtime.RegisterEnrollmentIssuer(
			issuerKey.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour),
		); err != nil {
			t.Fatal(err)
		}
		contextA, contextB := enrollmentContexts()
		claimA := enrollmentClaim("a-"+label, contextA, uint64(now.Add(10*time.Minute).Unix()), fixture.nextNonce())
		claimB := enrollmentClaim("b-"+label, contextB, uint64(now.Add(10*time.Minute).Unix()), fixture.nextNonce())
		if pledgeA.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claimA); err != nil {
			t.Fatal(err)
		}
		if pledgeB.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claimB); err != nil {
			t.Fatal(err)
		}
		encA, metricsA, err := client.EncryptPledgeForMode(pledgeA, mode)
		if err != nil {
			t.Fatalf("%s encrypt A: %v", label, err)
		}
		encB, _, err := client.EncryptPledgeForMode(pledgeB, mode)
		if err != nil {
			t.Fatalf("%s encrypt B: %v", label, err)
		}
		authorizePair(t, fixture.runtime, pledgeA, pledgeB)
		request := fixtureRequest(fixture.runtime, label, encA, encB, now)
		request.IdentityMode = mode
		request.EnrollmentA = signModeEnrollment(t, client, encA, mode, contextA, claimA, now, fixture.nextNonce(), issuerKey)
		request.EnrollmentB = signModeEnrollment(t, client, encB, mode, contextB, claimB, now, fixture.nextNonce(), issuerKey)
		decision, evaluation, err := fixture.runtime.Evaluate(request, now)
		if err != nil {
			t.Fatalf("%s evaluate: %v", label, err)
		}
		inputA, inputB, err := fixture.runtime.VerifiedExternalInputCommitments(request, now)
		if err != nil {
			t.Fatalf("%s input commitments: %v", label, err)
		}
		confirmed, releaseErr := fixture.releaseWithCoalition(t, decision, inputA, inputB, 0, 1, label)
		if releaseErr != nil {
			t.Fatalf("%s release: %v", label, releaseErr)
		}
		return modeMeasurement{
			Mode:                    map[IdentityMode]string{IdentityPublicCommitment: "IdentityPublicCommitment", IdentityFullFHE256: "IdentityFullFHE256"}[mode],
			ClientEncryptMillis:     metricsA.Total.Milliseconds(),
			IdentityEncryptMillis:   metricsA.ReceivableIdentityBits.Milliseconds(),
			EnvelopeBytes:           metricsA.CiphertextBytes,
			IdentityCiphertextBytes: metricsA.IdentityCiphertextBytes,
			EvaluationMillis:        evaluation.Total.Milliseconds(),
			IdentityEqualityMillis:  evaluation.IdentityEquality.Milliseconds(),
			MultiplicativeDepth:     evaluation.MultiplicativeDepth,
		}, confirmed
	}

	baseline, baselineConfirmed := run(IdentityPublicCommitment, "modeA-same", true)
	if !baselineConfirmed {
		t.Fatal("Mode A did not confirm a conflict on the same asset")
	}
	private, privateConfirmed := run(IdentityFullFHE256, "modeB-same", true)
	if !privateConfirmed {
		t.Fatal("Mode B did not confirm a conflict when both identities match under encryption")
	}

	// The property that matters: with FullFHE the equality is decided under
	// encryption, so different economic assets yield false without any public
	// link and without either identifier being compared in the clear.
	_, mismatchConfirmed := run(IdentityFullFHE256, "modeB-different", false)
	if mismatchConfirmed {
		t.Fatal("Mode B confirmed a conflict for two different economic assets")
	}

	evidence := fullFHEEvidence{
		SchemaVersion:  "mordant.fullfhe-measurement/4",
		LattigoVersion: LattigoVersion,
		CustodyModel:   string(CustodyDealerlessCeremony),
		Parameters:     "BGV LogN=15, LogQ 12 primes, LogP 3 primes, t=65537 (unchanged)",
		Baseline:       baseline,
		Private:        private,
	}
	evidence.Delta.EncryptMillisPerPledge = private.ClientEncryptMillis - baseline.ClientEncryptMillis
	evidence.Delta.EnvelopeBytesPerPledge = private.EnvelopeBytes - baseline.EnvelopeBytes
	evidence.Delta.EvaluationMillis = private.EvaluationMillis - baseline.EvaluationMillis
	evidence.Delta.TotalTransportBytes = 2 * evidence.Delta.EnvelopeBytesPerPledge
	evidence.InformationHidden = []string{
		"Mode A requires both pledges to carry an identical public ReceivableCommitment, so the evaluator and anyone holding both envelopes learns the two submissions concern the same receivable before any policy runs.",
		"Mode B carries no receivable commitment at all (it must be zero) and decides the 256-bit economic-asset equality homomorphically, so same-asset linkage is never asserted in transport.",
		"Mode A's V3 enrollment additionally requires a cleartext shared vault address; Mode B's scope commitments name a portfolio, never a receivable.",
	}
	evidence.Assertions = []string{
		"same economic asset under FullFHE256 -> conflict confirmed",
		"different economic assets under FullFHE256 -> conflict refused, with no public link involved",
		"both modes evaluated under the same dealerless collective keys and released by a 2-of-3 coalition",
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("../privacy-v4/evidence", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../privacy-v4/evidence/fullfhe-measurement.json", append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("Mode A encrypt %dms envelope %dB eval %dms", baseline.ClientEncryptMillis, baseline.EnvelopeBytes, baseline.EvaluationMillis)
	t.Logf("Mode B encrypt %dms envelope %dB eval %dms (identity equality %dms, identity ct %dB)",
		private.ClientEncryptMillis, private.EnvelopeBytes, private.EvaluationMillis,
		private.IdentityEqualityMillis, private.IdentityCiphertextBytes)
}

// signModeEnrollment signs a ciphertext enrollment for an explicit identity mode.
func signModeEnrollment(t *testing.T, client *ExternalClient, pledge *CipherPledge, mode IdentityMode,
	context InputCommitmentContext, claim AuthorizationClaim, now time.Time, nonce uint64, key ed25519.PrivateKey,
) *SignedCiphertextEnrollment {
	t.Helper()
	signed, err := SignCiphertextEnrollment(client, pledge, mode, context, claim, now.Add(-time.Minute), now.Add(5*time.Minute), nonce32(nonce), key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
