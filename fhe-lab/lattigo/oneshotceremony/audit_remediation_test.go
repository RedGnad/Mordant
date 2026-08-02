package oneshotceremony

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAuditFailRemediations(t *testing.T) {
	result := newFixture(t, "audit-remediation-shared-success").runSuccess()

	t.Run("F-01 protocol coordinates reject every modulus-degenerate point and one share remains insufficient", func(t *testing.T) {
		points := operatorPoints(result.fixture.context.Operators)
		if err := validateShamirCoordinates(result.fixture.params, points); err != nil {
			t.Fatal(err)
		}
		for _, modulus := range append(slices.Clone(result.fixture.params.Q()), result.fixture.params.P()...) {
			for _, hostile := range [][]uint64{{0, 2, 3}, {1, 1, 3}, {1, 2, modulus}, {1, 2, modulus + 1}} {
				if err := validateShamirCoordinates(result.fixture.params, hostile); err == nil {
					t.Fatalf("hostile coordinates accepted for modulus %d: %v", modulus, hostile)
				}
			}
		}
		mutated := result.fixture.context
		mutated.Operators = slices.Clone(mutated.Operators)
		mutated.Operators[2].Point = result.fixture.params.Q()[0] + 1
		if _, err := NewContext(result.fixture.params, mutated); !errors.Is(err, ErrBinding) {
			t.Fatalf("coordinator-selected coordinate accepted: %v", err)
		}
		// runSuccess invokes the real Lattigo combiner and fails unless a single
		// active share is rejected before proving the two-share correspondence.
		if result.bundle.Unsigned.KeyID == ([32]byte{}) {
			t.Fatal("threshold correspondence probe did not execute")
		}
	})

	t.Run("F-02 completion depends on exact durable publication readback", func(t *testing.T) {
		canonical, err := result.bundle.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name   string
			mutate func(PublicationReceipt) PublicationReceipt
			write  []byte
		}{
			{"missing", func(r PublicationReceipt) PublicationReceipt {
				r.ObjectPath = filepath.Join(strictTempPath(t, "missing-publication"), "public.bundle")
				return r
			}, nil},
			{"replacement", func(r PublicationReceipt) PublicationReceipt { return r }, bytes.Repeat([]byte{0x5a}, len(canonical))},
			{"truncation", func(r PublicationReceipt) PublicationReceipt { return r }, canonical[:len(canonical)-1]},
			{"stale-digest", func(r PublicationReceipt) PublicationReceipt { r.BundleDigest = digestLabel("stale-bundle"); return r }, canonical},
			{"mismatched-readback-digest", func(r PublicationReceipt) PublicationReceipt {
				r.CanonicalBytesSHA256 = digestLabel("wrong-readback")
				return r
			}, canonical},
			{"wrong-ceremony", func(r PublicationReceipt) PublicationReceipt { r.CeremonyID = digestLabel("wrong-ceremony"); return r }, canonical},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				receipt := testCase.mutate(result.receipt)
				if testCase.write != nil {
					root := strictTempPath(t, "publication")
					if err := os.Mkdir(root, 0o700); err != nil {
						t.Fatal(err)
					}
					receipt.ObjectPath = filepath.Join(root, "public.bundle")
					if err := os.WriteFile(receipt.ObjectPath, testCase.write, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				replicas := auditReplicas(result.fixture)
				if err := VerifyPublishedCeremony(result.fixture.context, result.bundle, receipt, replicas...); err == nil {
					t.Fatal("publication drift still verified as completed")
				}
			})
		}
	})

	t.Run("F-03 reservation owns a deep immutable identity snapshot", func(t *testing.T) {
		fixture := newFixture(t, "audit-f03-identity")
		participant := fixture.participants[0]
		before := participant.ContextSnapshot()
		fixture.context.Operators[0].AdministratorID = "mutated-administrator"
		fixture.context.Operators[0].SigningPublicKey[0] ^= 0xff
		fixture.context.Operators[1].EncryptionPublicKey[0] ^= 0xff
		fixture.context.Operators[2].TransportCertFingerprint[0] ^= 0xff
		fixture.context.Operators[2].RuntimeBinaryDigest[0] ^= 0xff
		fixture.context.GaloisElements[0]++
		after := participant.ContextSnapshot()
		if before.ContextDigest() != after.ContextDigest() || before.CeremonyID() != after.CeremonyID() {
			t.Fatal("caller mutation changed participant identity")
		}
		after.Operators[0].AdministratorID = "accessor-mutation"
		after.GaloisElements[0]++
		if participant.ContextSnapshot().ContextDigest() != before.ContextDigest() {
			t.Fatal("context accessor returned mutable backing storage")
		}
		if err := participant.Reserve(fixture.heads()); err != nil {
			t.Fatal(err)
		}
		reservation, err := participant.Reservation()
		if err != nil {
			t.Fatal(err)
		}
		reservation.ContextSnapshot[0] ^= 0xff
		fresh, _ := participant.Reservation()
		parsed, err := ParseContext(fresh.ContextSnapshot)
		if err != nil || parsed.ContextDigest() != before.ContextDigest() {
			t.Fatal("reservation accessor exposed its canonical identity snapshot")
		}
	})

	t.Run("F-04 operator-local storage capability fixes paths and consumes the session", func(t *testing.T) {
		if result.fixture.context.AttemptOrdinal != MVPAttemptOrdinal {
			t.Fatal("MVP ordinal drift")
		}
		invalid := result.fixture.context
		invalid.AttemptOrdinal = 2
		if _, err := NewContext(result.fixture.params, invalid); !errors.Is(err, ErrBinding) {
			t.Fatalf("second MVP ordinal accepted: %v", err)
		}

		base := newFixture(t, "audit-f04-local-capability")
		base.reserveAndWitnessStart()
		alternate := OperatorLocalStorageConfig{
			StateRoot:       strictTempPath(t, "f04-coordinator-selected-alternate-root"),
			StorageIdentity: base.storage[0].storageID,
			Identity:        base.context.Operators[0],
			ProcessInstance: base.storageConfigs[0].ProcessInstance,
			BootSession:     base.storageConfigs[0].BootSession,
		}
		if _, err := OpenOperatorStorageCapability(alternate); !errors.Is(err, ErrBinding) {
			t.Fatalf("same identity reopened through caller-selected paths: %v", err)
		}

		candidate := base.context
		candidate.Nonce = digestLabel("f04-same-session-new-ceremony-id")
		context, err := NewContext(base.params, candidate)
		if err != nil {
			t.Fatal(err)
		}
		participants := make([]*Participant, PartyCount)
		for index := range participants {
			participants[index], err = NewParticipant(base.params, context, base.signingKeys[index], base.encryptionKey[index], base.storage[index], nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		heads := attestHeads(t, participants)
		for index, participant := range participants {
			if err := participant.Reserve(heads); !errors.Is(err, ErrReplay) {
				t.Fatalf("operator %d replayed consumed session through a new ceremony id: %v", index+1, err)
			}
		}
	})

	t.Run("F-05 event digest is independent of every quorum subset", func(t *testing.T) {
		context := result.fixture.context
		prefix := cloneWitnessChain(result.fixture.participants[0].Records()[:2])
		root := prefix[len(prefix)-1].Statement.TranscriptDigest
		reason := digestLabel("f05-canonical-abort")
		material := hashDomain("MordantOneShotAbortMaterial/v1", root[:], reason[:])
		statement, err := NewWitnessStatement(context, prefix, PhaseAborted, prefix[len(prefix)-1].Statement.Step, root, material, reason)
		if err != nil {
			t.Fatal(err)
		}
		subsets := [][2]int{{0, 1}, {0, 2}, {1, 2}}
		records := make([]WitnessRecord, len(subsets))
		for index, subset := range subsets {
			signatures := make([]WitnessSignature, 2)
			for signatureIndex, operatorIndex := range subset {
				signatures[signatureIndex], err = SignWitnessStatement(statement, uint64(operatorIndex+1), result.fixture.signingKeys[operatorIndex])
				if err != nil {
					t.Fatal(err)
				}
			}
			records[index], err = AssembleWitnessRecord(context, statement, []WitnessSignature{signatures[1], signatures[0]})
			if err != nil {
				t.Fatal(err)
			}
			if records[index].EventDigest() != records[0].EventDigest() {
				t.Fatal("quorum subset changed event digest")
			}
		}
		if records[0].AttestationDigest() == records[1].AttestationDigest() {
			t.Fatal("separate signature artifacts unexpectedly identical")
		}
		replicas := make([][]WitnessRecord, PartyCount)
		for index := range replicas {
			replicas[index] = append(cloneWitnessChain(prefix), records[index])
		}
		if err := VerifyCompatibleReplicaHeads(context, replicas[0], replicas...); err != nil {
			t.Fatalf("selective valid quorum views forked one event: %v", err)
		}
		store, err := openWitnessStore(strictTempPath(t, "f05-decisions"), strictTempPath(t, "f05-registry"))
		if err != nil {
			t.Fatal(err)
		}
		first := records[0].Signatures[0]
		if err := store.WriteDecision(context.CeremonyID(), statement.Sequence, statement.Digest(), first.Signature[:]); err != nil {
			t.Fatal(err)
		}
		conflicting := statement
		conflicting.ReasonDigest = digestLabel("f05-conflicting-reason")
		if err := store.WriteDecision(context.CeremonyID(), statement.Sequence, conflicting.Digest(), first.Signature[:]); !errors.Is(err, ErrReplay) {
			t.Fatalf("conflicting event decision accepted: %v", err)
		}
	})

	t.Run("F-06 three operator-signed current heads gate every cryptographic generation", func(t *testing.T) {
		fixture := newFixture(t, "audit-f06-partial-replication")
		fixture.reserveAndStart()
		heads := fixture.heads()
		commits := envelopes(t, fixture.participants, func(p *Participant) (SignedEnvelope, error) {
			return p.CRSCommitEnvelope(heads)
		})
		for _, participant := range fixture.participants {
			if err := participant.AcceptCRSCommitStage(commits); err != nil {
				t.Fatal(err)
			}
		}
		statement, err := fixture.participants[0].ProposedTransition(PhaseCRSCommitted, [32]byte{})
		if err != nil {
			t.Fatal(err)
		}
		heads = fixture.heads()
		signatures := make([]WitnessSignature, PartyCount)
		for index, participant := range fixture.participants {
			signatures[index], err = participant.SignTransition(statement, heads)
			if err != nil {
				t.Fatal(err)
			}
		}
		record, err := AssembleWitnessRecord(fixture.context, statement, signatures)
		if err != nil {
			t.Fatal(err)
		}
		for _, participant := range fixture.participants[:Threshold] {
			if err := participant.CommitTransition(record); err != nil {
				t.Fatal(err)
			}
		}

		divergent := attestHeads(t, fixture.participants)
		if divergent[0].Sequence != divergent[1].Sequence || divergent[2].Sequence == divergent[0].Sequence {
			t.Fatal("test did not persist the valid transition at exactly two operators")
		}
		copies := []ReplicaHeadAttestation{divergent[0], divergent[0], divergent[0]}
		if VerifyReplicaHeadAttestations(fixture.context, fixture.participants[0].Records(), copies) == nil {
			t.Fatal("three caller-supplied copies of one signed head were accepted")
		}
		if VerifyReplicaHeadAttestations(fixture.context, fixture.participants[0].Records(), divergent[:2]) == nil {
			t.Fatal("missing operator head was accepted")
		}
		envelope, err := fixture.participants[0].CRSRevealEnvelope(divergent)
		if err == nil || len(envelope.Payload) != 0 || fixture.participants[0].wasGenerated("crs-reveal") || !isZero32(fixture.participants[0].crsReveal) {
			t.Fatalf("divergent head produced cryptographic material: %v", err)
		}
		tombstone, err := fixture.stores[0].TerminalTombstone(fixture.context.CeremonyID())
		if err != nil || tombstone.Disposition != DispositionPoisoned {
			t.Fatalf("divergent generation did not poison durably: %v", err)
		}
	})

	t.Run("F-07 exact publication plus ABORTED still creates no private bundle authority", func(t *testing.T) {
		fixture := newFixture(t, "audit-f07-staged-abort")
		fixture.abortAfterStaging = true
		aborted := fixture.runSuccess()
		if len(aborted.sealed) != 0 || VerifyPublicationReceipt(aborted.receipt, aborted.bundle) != nil {
			t.Fatal("test did not reach an otherwise valid exact public publication without a private bundle")
		}
		for index, store := range fixture.stores {
			tombstone, err := store.TerminalTombstone(fixture.context.CeremonyID())
			entries, readErr := os.ReadDir(fixture.storage[index].completedRoot)
			if err != nil || tombstone.Disposition != DispositionAborted || readErr != nil || len(entries) != 0 || fixture.participants[index].hasThreshold {
				t.Fatalf("abort tombstone missing: %v", err)
			}
		}
	})

	t.Run("F-08 default package and command graph cannot reach recoverable code", func(t *testing.T) {
		moduleRoot := filepath.Clean("..")
		listed := auditCommand(t, moduleRoot, "go", "list", "./...")
		for _, obsolete := range []string{"cmd/ceremony-client", "cmd/ceremony-coordinator", "cmd/ceremony-evaluator", "cmd/ceremony-lab", "cmd/ceremony-operator"} {
			if strings.Contains(listed, obsolete) {
				t.Fatalf("default go list exposed %s", obsolete)
			}
		}
		dependencies := auditCommand(t, moduleRoot, "go", "list", "-deps", "./oneshotceremony")
		if strings.Contains(dependencies, "internal/thresholdnet") || strings.Contains(dependencies, "mordant.dev/fhe-lab/lattigo\n") {
			t.Fatal("one-shot package imports historical ceremony/recovery code")
		}
		for _, target := range []string{"./cmd/ceremony-client", "./cmd/ceremony-evaluator", "./cmd/ceremony-lab"} {
			command := exec.Command("go", "build", target)
			command.Dir = moduleRoot
			command.Env = append(os.Environ(), "GOCACHE="+strictTempPath(t, "go-cache-default-boundary"))
			if err := command.Run(); err == nil {
				t.Fatalf("default build exposed %s", target)
			}
		}
		for _, magic := range []string{"MCR1", "MCL1", "MCW1"} {
			if _, err := ParsePublicBundle([]byte(magic)); err == nil {
				t.Fatalf("historical format %s accepted", magic)
			}
		}
	})

	t.Run("F-09 startup-signed executable A cannot be replaced by clean binary B", func(t *testing.T) {
		moduleRoot := filepath.Clean("..")
		binary := filepath.Join(strictTempPath(t, "provenance-binary"), "oneshot-provenance")
		if err := os.Mkdir(filepath.Dir(binary), 0o700); err != nil {
			t.Fatal(err)
		}
		build := exec.Command("go", "build", "-o", binary, "./cmd/oneshot-provenance")
		build.Dir = moduleRoot
		build.Env = append(os.Environ(), "GOCACHE="+strictTempPath(t, "go-cache-provenance"))
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build provenance harness: %v: %s", err, output)
		}
		output, err := exec.Command(binary).Output()
		if err != nil {
			t.Fatal(err)
		}
		var emitted ExecutableProvenance
		if err := json.Unmarshal(output, &emitted); err != nil {
			t.Fatal(err)
		}
		bytesOnDisk, err := os.ReadFile(binary)
		if err != nil || emitted.ExecutableSHA256 != sha256.Sum256(bytesOnDisk) {
			t.Fatal("emitted provenance does not identify concrete executable bytes")
		}
		head := strings.TrimSpace(auditCommand(t, moduleRoot, "git", "rev-parse", "HEAD"))
		if emitted.SourceRevision != head || VerifyExecutableProvenance(emitted) != nil {
			t.Fatal("emitted provenance does not identify live VCS revision")
		}
		tampered := emitted
		tampered.ExecutableSHA256[0] ^= 0xff
		if VerifyExecutableProvenance(tampered) == nil {
			t.Fatal("synthetic executable digest qualified as verified provenance")
		}
		reservations := auditReservations(t, result.fixture)
		startupA := reservations[0].StartupProvenance
		if startupA.ExecutableSHA256 == emitted.ExecutableSHA256 {
			t.Fatal("substitution test did not produce distinct executables A and B")
		}
		manifest, err := BuildEvidenceManifest(result.fixture.context, result.bundle, result.receipt, auditReplicas(result.fixture), reservations)
		if err != nil {
			t.Fatal(err)
		}
		for _, retained := range manifest.Executables {
			if retained.Digest() != startupA.Digest() || retained.ExecutableSHA256 == emitted.ExecutableSHA256 {
				t.Fatal("evidence manifest did not consume the signed startup measurement from executable A")
			}
		}
		if manifest.BundleDigest != result.bundle.Digest() || manifest.PublicationReceipt != result.receipt.Digest() {
			t.Fatal("startup provenance manifest lost artifact bindings")
		}

		substitutedReservations := slices.Clone(reservations)
		substitutedReservations[0].StartupProvenance = emitted
		if _, err := BuildEvidenceManifest(result.fixture.context, result.bundle, result.receipt, auditReplicas(result.fixture), substitutedReservations); err == nil {
			t.Fatal("post-run evidence path substituted executable B for startup-measured executable A")
		}
		substitutedRoster := result.fixture.context
		substitutedRoster.Operators = slices.Clone(substitutedRoster.Operators)
		substitutedRoster.Operators[0].RuntimeBinaryDigest = emitted.ExecutableSHA256
		substitutedRoster.Operators[0].GoVersion = emitted.GoVersion
		substitutedRoster.Operators[0].OperatingSystem = emitted.OperatingSystem
		substitutedRoster.Operators[0].Architecture = emitted.Architecture
		if _, err := reservationSetDigest(substitutedRoster, reservations); err == nil {
			t.Fatal("roster substituted executable B after executable A signed its reservation")
		}
	})

	t.Run("F-10 one-time generation cannot be replayed with caller-selected storage paths", func(t *testing.T) {
		fixture := newFixture(t, "audit-f10-generation")
		fixture.reserveAndWitnessStart()
		heads := fixture.heads()
		var successes atomic.Int32
		var wait sync.WaitGroup
		for range 8 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				if fixture.participants[0].BeginSecrets(heads) == nil {
					successes.Add(1)
				}
			}()
		}
		wait.Wait()
		if successes.Load() != 1 {
			t.Fatalf("secret generation had %d authorized generators", successes.Load())
		}
		if err := fixture.stores[0].MarkGeneration(fixture.context, "begin-secrets"); !errors.Is(err, ErrReplay) {
			t.Fatalf("generation marker was reusable: %v", err)
		}
		alternate := OperatorLocalStorageConfig{
			StateRoot:       strictTempPath(t, "f10-restored-caller-path"),
			StorageIdentity: fixture.storage[0].storageID,
			Identity:        fixture.context.Operators[0],
			ProcessInstance: fixture.storageConfigs[0].ProcessInstance,
			BootSession:     fixture.storageConfigs[0].BootSession,
		}
		if _, err := OpenOperatorStorageCapability(alternate); !errors.Is(err, ErrBinding) {
			t.Fatalf("caller-selected witness/registry paths recreated generation authority: %v", err)
		}
	})
}

func TestF04F10SessionConsumptionPrecedesReservationCompletion(t *testing.T) {
	fixture := newFixture(t, "final-f04-f10-session-boundary")
	originalCeremonyID := fixture.context.CeremonyID()
	sessionBinding := fixture.context.SessionBindingDigest()
	heads := fixture.heads()

	for index, participant := range fixture.participants {
		if err := VerifyReplicaHeadAttestations(fixture.context, participant.Records(), heads); err != nil {
			t.Fatalf("operator %d heads were not valid: %v", index+1, err)
		}
		failurePath := filepath.Join(fixture.stores[index].root, "forced-pre-reservation-failure")
		if err := os.Mkdir(failurePath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := participant.Reserve(heads); !errors.Is(err, ErrPersistence) {
			t.Fatalf("operator %d did not fail after authenticated head validation: %v", index+1, err)
		}
		if participant.reserved || participant.secretKey != nil || participant.wasGenerated("begin-secrets") {
			t.Fatalf("operator %d completed reservation or generated secret material", index+1)
		}
		if err := os.Remove(failurePath); err != nil {
			t.Fatal(err)
		}
	}

	restartedStorage := make([]*OperatorStorageCapability, PartyCount)
	for index, config := range fixture.storageConfigs {
		var err error
		restartedStorage[index], err = OpenOperatorStorageCapability(config)
		if err != nil {
			t.Fatalf("operator %d ordinary storage restart: %v", index+1, err)
		}
	}
	restartedContextInput := fixture.context
	restartedContextInput.Nonce = digestLabel("final-f04-f10-new-nonce")
	restartedContext, err := NewContext(fixture.params, restartedContextInput)
	if err != nil {
		t.Fatal(err)
	}
	if restartedContext.CeremonyID() == originalCeremonyID || restartedContext.SessionBindingDigest() != sessionBinding {
		t.Fatal("regression did not preserve the session while changing CeremonyID")
	}

	restarted := make([]*Participant, PartyCount)
	for index := range restarted {
		restarted[index], err = NewParticipant(fixture.params, restartedContext, fixture.signingKeys[index], fixture.encryptionKey[index], restartedStorage[index], nil)
		if err != nil {
			t.Fatalf("operator %d ordinary participant restart: %v", index+1, err)
		}
	}
	restartedHeads := attestHeads(t, restarted)
	for index, participant := range restarted {
		if err := participant.Reserve(restartedHeads); !errors.Is(err, ErrReplay) {
			t.Fatalf("operator %d recreated reservation authority for consumed session: %v", index+1, err)
		}
		if err := participant.BeginSecrets(restartedHeads); !errors.Is(err, ErrState) {
			t.Fatalf("operator %d generated after rejected restart: %v", index+1, err)
		}
		if participant.secretKey != nil || participant.wasGenerated("begin-secrets") {
			t.Fatalf("operator %d retained generation authority after rejected restart", index+1)
		}
	}
}

func auditReplicas(fixture *ceremonyFixture) [][]WitnessRecord {
	return [][]WitnessRecord{fixture.participants[0].Records(), fixture.participants[1].Records(), fixture.participants[2].Records()}
}

func auditReservations(t *testing.T, fixture *ceremonyFixture) []AttemptReservation {
	t.Helper()
	reservations := make([]AttemptReservation, PartyCount)
	for index, participant := range fixture.participants {
		var err error
		reservations[index], err = participant.Reservation()
		if err != nil {
			t.Fatal(err)
		}
	}
	return reservations
}

func attestHeads(t *testing.T, participants []*Participant) []ReplicaHeadAttestation {
	t.Helper()
	heads := make([]ReplicaHeadAttestation, len(participants))
	for index, participant := range participants {
		var err error
		heads[index], err = participant.AttestReplicaHead()
		if err != nil {
			t.Fatal(err)
		}
	}
	return heads
}

func auditCommand(t *testing.T, directory, name string, arguments ...string) string {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GOCACHE="+strictTempPath(t, "go-cache-command"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(arguments, " "), err, output)
	}
	return string(output)
}
