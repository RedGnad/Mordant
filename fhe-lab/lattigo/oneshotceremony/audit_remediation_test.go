package oneshotceremony

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
		if err := participant.Reserve("f03-process", "f03-boot"); err != nil {
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

	t.Run("F-04 one durable reservation consumes one bilateral service session", func(t *testing.T) {
		if result.fixture.context.AttemptOrdinal != MVPAttemptOrdinal {
			t.Fatal("MVP ordinal drift")
		}
		invalid := result.fixture.context
		invalid.AttemptOrdinal = 2
		if _, err := NewContext(result.fixture.params, invalid); !errors.Is(err, ErrBinding) {
			t.Fatalf("second MVP ordinal accepted: %v", err)
		}

		base := newFixture(t, "audit-f04-concurrent")
		registryRoot := base.stores[0].registry.root
		const competitors = 12
		participants := make([]*Participant, competitors)
		for index := range participants {
			candidate := base.context
			candidate.Nonce = digestLabel(fmt.Sprintf("f04-concurrent-nonce-%d", index))
			context, err := NewContext(base.params, candidate)
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWitnessStore(strictTempPath(t, fmt.Sprintf("f04-witness-%d", index)), registryRoot)
			if err != nil {
				t.Fatal(err)
			}
			participants[index], err = NewParticipant(base.params, context, 1, base.signingKeys[0], base.encryptionKey[0], store, nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		var accepted atomic.Int32
		var wait sync.WaitGroup
		for index, participant := range participants {
			wait.Add(1)
			go func(index int, participant *Participant) {
				defer wait.Done()
				if participant.Reserve(fmt.Sprintf("process-%d", index), fmt.Sprintf("boot-%d", index)) == nil {
					accepted.Add(1)
				}
			}(index, participant)
		}
		wait.Wait()
		if accepted.Load() != 1 {
			t.Fatalf("concurrent reservations accepted %d winners", accepted.Load())
		}
		candidate := base.context
		candidate.Nonce = digestLabel("f04-restart-nonce")
		context, _ := NewContext(base.params, candidate)
		restored, err := OpenWitnessStore(strictTempPath(t, "f04-restored-witness-snapshot"), registryRoot)
		if err != nil {
			t.Fatal(err)
		}
		restarted, err := NewParticipant(base.params, context, 1, base.signingKeys[0], base.encryptionKey[0], restored, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.Reserve("restart", "restored-snapshot"); !errors.Is(err, ErrReplay) {
			t.Fatalf("restart/restored witness snapshot reopened consumed session: %v", err)
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
		store, err := OpenWitnessStore(strictTempPath(t, "f05-decisions"), strictTempPath(t, "f05-registry"))
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

	t.Run("F-06 every stale or partial replica head poisons continuation", func(t *testing.T) {
		records := result.fixture.participants[0].Records()
		for length := 1; length <= len(records); length++ {
			local := cloneWitnessChain(records[:length])
			replicas := [][]WitnessRecord{cloneWitnessChain(local), cloneWitnessChain(local), cloneWitnessChain(local[:length-1])}
			if err := VerifyCompatibleReplicaHeads(result.fixture.context, local, replicas...); err == nil {
				t.Fatalf("stale replica accepted at transition boundary %d", length)
			}
		}
		store, err := OpenWitnessStore(strictTempPath(t, "f06-atomic-witness"), strictTempPath(t, "f06-registry"))
		if err != nil {
			t.Fatal(err)
		}
		first := result.fixture.participants[0].Records()[0]
		abortStatement, err := NewWitnessStatement(result.fixture.context, nil, PhaseAborted, 0, result.fixture.context.ContextDigest(), digestLabel("f06-abort-material"), digestLabel("f06-abort"))
		if err != nil {
			t.Fatal(err)
		}
		abortSignatures := make([]WitnessSignature, Threshold)
		for index := range abortSignatures {
			abortSignatures[index], _ = SignWitnessStatement(abortStatement, uint64(index+1), result.fixture.signingKeys[index])
		}
		abortRecord, err := AssembleWitnessRecord(result.fixture.context, abortStatement, abortSignatures)
		if err != nil {
			t.Fatal(err)
		}
		var wins atomic.Int32
		var wait sync.WaitGroup
		for _, record := range []WitnessRecord{first, abortRecord} {
			wait.Add(1)
			go func(record WitnessRecord) {
				defer wait.Done()
				if store.Append(record) == nil {
					wins.Add(1)
				}
			}(record)
		}
		wait.Wait()
		if wins.Load() != 1 {
			t.Fatalf("compare-and-append accepted %d concurrent successors", wins.Load())
		}

		restart := newFixture(t, "audit-f06-restart-ambiguity")
		restart.reserveAndWitnessStart()
		if _, err := NewParticipant(restart.params, restart.context, 1, restart.signingKeys[0], restart.encryptionKey[0], restart.stores[0], nil); !errors.Is(err, ErrReplay) {
			t.Fatalf("ambiguous restart constructor accepted: %v", err)
		}
		tombstone, err := restart.stores[0].TerminalTombstone(restart.context.CeremonyID())
		if err != nil || tombstone.Disposition != DispositionPoisoned {
			t.Fatalf("ambiguous restart was not durably poisoned: %v", err)
		}
	})

	t.Run("F-07 staged private bytes are unusable after terminal abort", func(t *testing.T) {
		fixture := newFixture(t, "audit-f07-staged-abort")
		fixture.abortAfterStaging = true
		aborted := fixture.runSuccess()
		if len(aborted.sealed) != PartyCount {
			t.Fatal("test did not reach private staging")
		}
		for _, store := range fixture.stores[:Threshold] {
			tombstone, err := store.TerminalTombstone(fixture.context.CeremonyID())
			if err != nil || tombstone.Disposition != DispositionAborted {
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

	t.Run("F-09 retained provenance identifies the concrete binary and live VCS revision", func(t *testing.T) {
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
		manifest, err := BuildEvidenceManifest(result.fixture.context, result.bundle, result.receipt, auditReplicas(result.fixture), []string{binary, binary, binary})
		if err != nil {
			t.Fatal(err)
		}
		if manifest.ProvenanceVerified || manifest.BundleDigest != result.bundle.Digest() || manifest.PublicationReceipt != result.receipt.Digest() {
			t.Fatal("synthetic fixture provenance qualified or lost artifact bindings")
		}
	})

	t.Run("F-10 one-time randomness marker survives concurrency restart and witness snapshot restoration", func(t *testing.T) {
		fixture := newFixture(t, "audit-f10-generation")
		fixture.reserveAndWitnessStart()
		var successes atomic.Int32
		var wait sync.WaitGroup
		for range 8 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				if fixture.participants[0].BeginSecrets() == nil {
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
		candidate := fixture.context
		candidate.Nonce = digestLabel("f10-restored-nonce")
		context, _ := NewContext(fixture.params, candidate)
		restoredStore, err := OpenWitnessStore(strictTempPath(t, "f10-restored-witness"), fixture.stores[0].registry.root)
		if err != nil {
			t.Fatal(err)
		}
		restarted, err := NewParticipant(fixture.params, context, 1, fixture.signingKeys[0], fixture.encryptionKey[0], restoredStore, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.Reserve("restored-process", "restored-boot"); !errors.Is(err, ErrReplay) {
			t.Fatalf("restored snapshot regenerated session material: %v", err)
		}
	})
}

func auditReplicas(fixture *ceremonyFixture) [][]WitnessRecord {
	return [][]WitnessRecord{fixture.participants[0].Records(), fixture.participants[1].Records(), fixture.participants[2].Records()}
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
