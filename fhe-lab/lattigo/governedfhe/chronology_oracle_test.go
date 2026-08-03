package governedfhe

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestChronologyOracleAndDurableInternalRecourseClock(t *testing.T) {
	fixture := newProductionFixture(t, true)
	artifact, _, err := EvaluateFixedConflict(EvaluatorConfig{
		PublicRoot: fixture.publicRoot, Provenance: testDigest("chronology/evaluator"), Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := NewGovernedDecryptor(GovernedDecryptorConfig{
		PublicRoot: fixture.publicRoot, PrivateRoot: fixture.privateRoot,
		Provenance: testDigest("chronology/decryptor"), Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, signedResult, err := decryptor.ReleaseFixedConflict(artifact)
	if closeErr := decryptor.Close(); err != nil || closeErr != nil {
		t.Fatalf("release=%v close=%v", err, closeErr)
	}
	config := RecourseAdapterConfig{
		RecordRoot: fixture.publicRoot, CaseManifest: fixture.manifest, ExpectedPins: recoursePinsForResult(result),
	}
	firstClock := time.Unix(result.ReleasedAtUnix+1, 0).UTC()
	first, err := adaptSignedResultToRecourse(config, signedResult, func() time.Time { return firstClock })
	if err != nil {
		t.Fatal(err)
	}
	clockPath := filepath.Join(fixture.publicRoot, recourseClockObject)
	clockBefore, err := os.ReadFile(clockPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(fixture.publicRoot, recourseRecordObject)); err != nil {
		t.Fatal(err)
	}
	secondClock := firstClock.Add(30 * time.Minute)
	recovered, err := adaptSignedResultToRecourse(config, signedResult, func() time.Time { return secondClock })
	if err != nil {
		t.Fatal(err)
	}
	clockAfter, err := os.ReadFile(clockPath)
	if err != nil {
		t.Fatal(err)
	}
	if first != recovered || first.BoundAtUnix != firstClock.Unix() || first.CureDeadlineUnix != first.BoundAtUnix+24*60*60 ||
		!bytes.Equal(clockBefore, clockAfter) {
		t.Fatal("recourse retry changed the signer-owned durable clock binding")
	}

	if _, err := createRecourseAttestation(
		fixture.publicRoot, fixture.privateRoot, ClockClassRealObserved,
		func() time.Time { return time.Unix(first.CureDeadlineUnix-1, 0) },
	); !errors.Is(err, ErrBinding) {
		t.Fatalf("real chronology before cure deadline accepted: %v", err)
	}
	attestation, err := createRecourseAttestation(
		fixture.publicRoot, fixture.privateRoot, ClockClassSimulatedProtocol,
		func() time.Time { return firstClock.Add(time.Minute) },
	)
	if err != nil {
		t.Fatal(err)
	}
	chronology, err := LoadCanonicalProductChronology(fixture.publicRoot)
	if err != nil {
		t.Fatal(err)
	}
	if attestation.ClockClass != ClockClassSimulatedProtocol || attestation.FinalRecourseState != RecourseStateSimulated ||
		attestation.SimulationAsOfUnix == nil || *attestation.SimulationAsOfUnix != first.CureDeadlineUnix+1 ||
		chronology.SimulationAsOfUnix == nil || *chronology.SimulationAsOfUnix != first.CureDeadlineUnix+1 ||
		chronology.Events[len(chronology.Events)-1].Kind != "SIMULATED_CURE_WINDOW_COMPLETED" {
		t.Fatal("simulated terminal chronology was not explicit and signer-derived")
	}
}
