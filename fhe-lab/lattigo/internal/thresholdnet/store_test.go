package thresholdnet

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestStoreEnforcesGlobalBindingAcrossSessionsAndCoalitions(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "ledger.db"))
	defer closeTestStore(t, store)

	binding := testID(0x10)
	first := Descriptor{
		SessionID:       testID(0x11),
		Binding:         binding,
		CoalitionDigest: testID(0x12),
	}
	record, err := store.Prepare(first)
	if err != nil {
		t.Fatalf("prepare first session: %v", err)
	}
	if record.State != StatePrepared || record.IsTerminal() {
		t.Fatalf("unexpected prepared record: %+v", record)
	}

	_, err = store.Prepare(Descriptor{
		SessionID:       testID(0x21),
		Binding:         binding,
		CoalitionDigest: testID(0x22),
	})
	if !errors.Is(err, ErrBindingConsumed) {
		t.Fatalf("new session and coalition bypassed binding lock: %v", err)
	}

	_, err = store.Prepare(Descriptor{
		SessionID:       first.SessionID,
		Binding:         testID(0x31),
		CoalitionDigest: testID(0x32),
	})
	if !errors.Is(err, ErrSessionExists) {
		t.Fatalf("reused session id was not rejected: %v", err)
	}

	byBinding, err := store.GetByBinding(binding)
	if err != nil {
		t.Fatalf("get by binding: %v", err)
	}
	if byBinding.SessionID != first.SessionID || byBinding.CoalitionDigest != first.CoalitionDigest {
		t.Fatalf("binding resolved to wrong record: %+v", byBinding)
	}
}

func TestStoreLifecycleAndTerminalStates(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "ledger.db"))
	defer closeTestStore(t, store)
	descriptor := testDescriptor(0x40)

	if _, err := store.Prepare(descriptor); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	committed, err := store.Commit(descriptor.SessionID)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if committed.State != StateCommitted {
		t.Fatalf("expected COMMITTED, got %s", committed.State)
	}
	if _, err := store.Commit(descriptor.SessionID); !errors.Is(err, ErrTerminal) {
		t.Fatalf("duplicate commit could authorize another generation: %v", err)
	}

	responseDigest := testID(0x44)
	generated, err := store.MarkGenerated(descriptor.SessionID, responseDigest)
	if err != nil {
		t.Fatalf("mark generated: %v", err)
	}
	if generated.State != StateGenerated || generated.ResponseDigest != responseDigest {
		t.Fatalf("unexpected generated record: %+v", generated)
	}
	if _, err := store.MarkReleased(descriptor.SessionID); err != nil {
		t.Fatalf("mark released: %v", err)
	}
	acked, err := store.MarkAcked(descriptor.SessionID)
	if err != nil {
		t.Fatalf("mark acked: %v", err)
	}
	if acked.State != StateAcked || !acked.IsTerminal() {
		t.Fatalf("unexpected acked record: %+v", acked)
	}
	if _, err := store.FailTerminal(descriptor.SessionID, FailureRelease); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal successful record was mutable: %v", err)
	}

	abortedDescriptor := testDescriptor(0x50)
	if _, err := store.Prepare(abortedDescriptor); err != nil {
		t.Fatalf("prepare abort case: %v", err)
	}
	aborted, err := store.AbortPrepared(abortedDescriptor.SessionID)
	if err != nil {
		t.Fatalf("abort prepared: %v", err)
	}
	if aborted.State != StateAbortedPrestart || aborted.FailureCode != FailureAbortedBeforeCommit || !aborted.IsTerminal() {
		t.Fatalf("unexpected aborted record: %+v", aborted)
	}
	if _, err := store.Prepare(Descriptor{
		SessionID:       testID(0x59),
		Binding:         abortedDescriptor.Binding,
		CoalitionDigest: testID(0x5a),
	}); !errors.Is(err, ErrBindingConsumed) {
		t.Fatalf("aborted binding was reusable: %v", err)
	}

	failedDescriptor := testDescriptor(0x60)
	if _, err := store.Prepare(failedDescriptor); err != nil {
		t.Fatalf("prepare failure case: %v", err)
	}
	if _, err := store.Commit(failedDescriptor.SessionID); err != nil {
		t.Fatalf("commit failure case: %v", err)
	}
	failed, err := store.FailTerminal(failedDescriptor.SessionID, FailureGeneration)
	if err != nil {
		t.Fatalf("mark terminal failure: %v", err)
	}
	if failed.State != StateFailedTerminal || failed.FailureCode != FailureGeneration || !failed.IsTerminal() {
		t.Fatalf("unexpected failed record: %+v", failed)
	}
}

func TestStoreRestartRecoveryIsFailClosedAfterCommit(t *testing.T) {
	phases := []struct {
		name    string
		advance func(*testing.T, *Store, Descriptor)
	}{
		{name: "committed", advance: func(t *testing.T, store *Store, descriptor Descriptor) {
			if _, err := store.Commit(descriptor.SessionID); err != nil {
				t.Fatalf("commit: %v", err)
			}
		}},
		{name: "generated", advance: func(t *testing.T, store *Store, descriptor Descriptor) {
			if _, err := store.Commit(descriptor.SessionID); err != nil {
				t.Fatalf("commit: %v", err)
			}
			if _, err := store.MarkGenerated(descriptor.SessionID, testID(0x81)); err != nil {
				t.Fatalf("mark generated: %v", err)
			}
		}},
		{name: "released", advance: func(t *testing.T, store *Store, descriptor Descriptor) {
			if _, err := store.Commit(descriptor.SessionID); err != nil {
				t.Fatalf("commit: %v", err)
			}
			if _, err := store.MarkGenerated(descriptor.SessionID, testID(0x82)); err != nil {
				t.Fatalf("mark generated: %v", err)
			}
			if _, err := store.MarkReleased(descriptor.SessionID); err != nil {
				t.Fatalf("mark released: %v", err)
			}
		}},
	}

	for index, phase := range phases {
		t.Run(phase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ledger.db")
			store := openTestStore(t, path)
			descriptor := testDescriptor(byte(0x70 + index*4))
			if _, err := store.Prepare(descriptor); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			phase.advance(t, store, descriptor)
			closeTestStore(t, store)

			reopened := openTestStore(t, path)
			defer closeTestStore(t, reopened)
			recovered, err := reopened.Get(descriptor.SessionID)
			if err != nil {
				t.Fatalf("get recovered session: %v", err)
			}
			if recovered.State != StateFailedTerminal || recovered.FailureCode != FailureRestartAfterCommit || !recovered.IsTerminal() {
				t.Fatalf("restart did not terminalize %s: %+v", phase.name, recovered)
			}
			if _, err := reopened.Commit(descriptor.SessionID); !errors.Is(err, ErrTerminal) {
				t.Fatalf("recovered session was retriable: %v", err)
			}
			if _, err := reopened.Prepare(Descriptor{
				SessionID:       testID(byte(0xa0 + index)),
				Binding:         descriptor.Binding,
				CoalitionDigest: testID(byte(0xb0 + index)),
			}); !errors.Is(err, ErrBindingConsumed) {
				t.Fatalf("new session/coalition bypassed recovered lock: %v", err)
			}
		})
	}
}

func TestStoreRestartPreservesPreparedAndAcked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	store := openTestStore(t, path)
	prepared := testDescriptor(0xc0)
	acked := testDescriptor(0xd0)
	if _, err := store.Prepare(prepared); err != nil {
		t.Fatalf("prepare pending session: %v", err)
	}
	if _, err := store.Prepare(acked); err != nil {
		t.Fatalf("prepare ack case: %v", err)
	}
	if _, err := store.Commit(acked.SessionID); err != nil {
		t.Fatalf("commit ack case: %v", err)
	}
	if _, err := store.MarkGenerated(acked.SessionID, testID(0xd4)); err != nil {
		t.Fatalf("generate ack case: %v", err)
	}
	if _, err := store.MarkReleased(acked.SessionID); err != nil {
		t.Fatalf("release ack case: %v", err)
	}
	if _, err := store.MarkAcked(acked.SessionID); err != nil {
		t.Fatalf("ack case: %v", err)
	}
	closeTestStore(t, store)

	reopened := openTestStore(t, path)
	defer closeTestStore(t, reopened)
	preparedRecord, err := reopened.Get(prepared.SessionID)
	if err != nil || preparedRecord.State != StatePrepared {
		t.Fatalf("PREPARED was not recoverable before crypto: record=%+v err=%v", preparedRecord, err)
	}
	if _, err := reopened.Commit(prepared.SessionID); err != nil {
		t.Fatalf("PREPARED could not cross commit barrier after restart: %v", err)
	}
	ackedRecord, err := reopened.Get(acked.SessionID)
	if err != nil || ackedRecord.State != StateAcked || !ackedRecord.IsTerminal() {
		t.Fatalf("ACKED was altered on restart: record=%+v err=%v", ackedRecord, err)
	}
}

func TestStoreSerializesConcurrentGlobalBindingReservations(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "ledger.db"))
	defer closeTestStore(t, store)
	binding := testID(0xe0)

	const contenders = 12
	var successes atomic.Int32
	var consumed atomic.Int32
	var unexpected atomic.Int32
	var wait sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < contenders; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, err := store.Prepare(Descriptor{
				SessionID:       testID(byte(index + 1)),
				Binding:         binding,
				CoalitionDigest: testID(byte(index + 21)),
			})
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrBindingConsumed):
				consumed.Add(1)
			default:
				unexpected.Add(1)
			}
		}(i)
	}
	close(start)
	wait.Wait()

	if successes.Load() != 1 || consumed.Load() != contenders-1 || unexpected.Load() != 0 {
		t.Fatalf("global reservation race: successes=%d consumed=%d unexpected=%d", successes.Load(), consumed.Load(), unexpected.Load())
	}
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return store
}

func closeTestStore(t *testing.T, store *Store) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
}

func testDescriptor(base byte) Descriptor {
	return Descriptor{
		SessionID:       testID(base),
		Binding:         testID(base + 1),
		CoalitionDigest: testID(base + 2),
	}
}

func testID(value byte) [32]byte {
	var id [32]byte
	for index := range id {
		id[index] = value
	}
	return id
}
