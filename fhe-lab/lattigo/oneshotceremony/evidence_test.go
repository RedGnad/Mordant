package oneshotceremony

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestLocalNonAcceptanceEvidenceSample emits only public, test-only digests.
// It intentionally emits no topology attestation and cannot be represented as
// the later three-host acceptance run.
func TestLocalNonAcceptanceEvidenceSample(t *testing.T) {
	success := newFixture(t, "local-non-acceptance-evidence-success").runSuccess()
	publicBytes, err := success.bundle.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	unsignedBytes, err := success.bundle.Unsigned.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	publicSHA := sha256.Sum256(publicBytes)
	unsignedSHA := sha256.Sum256(unsignedBytes)
	contextBytes, err := success.fixture.context.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	contextSHA := sha256.Sum256(contextBytes)
	transcriptRoot := success.bundle.Unsigned.Transcript.Root(success.fixture.context)
	successHead := success.fixture.participants[0].Records()[len(success.fixture.participants[0].Records())-1].Digest()
	successCeremonyID := success.fixture.context.CeremonyID()
	t.Logf("classification=LOCAL_SINGLE_HOST_NON_ACCEPTANCE ceremonyId=%s keyId=%s context.sha256=%s unsigned-public-bundle.sha256=%s public-bundle.sha256=%s transcriptRoot=%s completedWitnessHead=%s",
		hex.EncodeToString(successCeremonyID[:]),
		hex.EncodeToString(success.bundle.Unsigned.KeyID[:]),
		hex.EncodeToString(contextSHA[:]),
		hex.EncodeToString(unsignedSHA[:]),
		hex.EncodeToString(publicSHA[:]),
		hex.EncodeToString(transcriptRoot[:]),
		hex.EncodeToString(successHead[:]))

	aborted := newFixture(t, "local-non-acceptance-evidence-abort")
	aborted.reserveAndStart()
	record := aborted.transition(PhaseAborted, digestLabel("test-only-operator-abandonment"), aborted.participants[:2])
	abortBytes, err := record.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	abortSHA := sha256.Sum256(abortBytes)
	abortCeremonyID := aborted.context.CeremonyID()
	abortHead := record.Digest()
	t.Logf("classification=LOCAL_SINGLE_HOST_NON_ACCEPTANCE abortCeremonyId=%s abortPhase=%d abortWitness.sha256=%s abortWitnessHead=%s signatures=%d privateBundleCreated=false",
		hex.EncodeToString(abortCeremonyID[:]),
		record.Statement.ToPhase,
		hex.EncodeToString(abortSHA[:]),
		hex.EncodeToString(abortHead[:]),
		len(record.Signatures))
}
