package lattigospike

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// These tests express external audit finding H-01 as behaviour that must now be
// impossible: pairing two enrollments that were never authorized as two halves
// of the same bilateral session, and re-running a session after a restart.

func label32(text string) [32]byte {
	return legacyKeccak([]byte(text))
}

type v5Fixture struct {
	issuerPrivate ed25519.PrivateKey
	sessionCommit [32]byte
	nullifier     [32]byte
	scopeA        [32]byte
	scopeB        [32]byte
	now           time.Time
}

func newV5Fixture(t *testing.T) v5Fixture {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return v5Fixture{
		issuerPrivate: private,
		sessionCommit: label32("session-commitment"),
		nullifier:     label32("session-nullifier"),
		scopeA:        label32("scope-a"),
		scopeB:        label32("scope-b"),
		now:           time.Unix(1_800_000_000, 0),
	}
}

// enrollment builds one side. Every caller-visible knob is a field an attacker
// would want to vary.
func (f v5Fixture) enrollment(side string, own, counterparty [32]byte, slot uint8) CiphertextEnrollmentV5 {
	claim := AuthorizationClaim{
		SubjectCommitment: label32("subject-" + side),
		Role:              label32("role"),
		Vault:             [20]byte{0xAA, 0xBB, 0xCC},
		PolicyID:          label32("policy"),
		PolicyVersion:     PolicyVersion,
		ValidUntil:        uint64(f.now.Add(72 * time.Hour).Unix()),
		Nonce:             Uint256{0, 0, 0, uint64(slot) + 1},
	}
	commitment, err := enrollmentAuthorizationCommitment(claim, label32("key-id"))
	if err != nil {
		panic(err)
	}
	return CiphertextEnrollmentV5{
		Version:        EnrollmentV5Version,
		CircuitVersion: CircuitV5Version,
		Binding: SessionBindingV5{
			SessionCommitment:           f.sessionCommit,
			SessionNullifier:            f.nullifier,
			OwnScopeCommitment:          own,
			CounterpartyScopeCommitment: counterparty,
			GovernanceRecord:            label32("governance-" + side),
			SourceRecordCommitment:      label32("source-" + side),
			AuthorizationEpoch:          7,
			SubmissionBudgetEpoch:       3,
			InputSlot:                   slot,
		},
		CiphertextDigest:        label32("ciphertext-" + side),
		InputCommitment:         label32("input-" + side),
		KeyID:                   label32("key-id"),
		ParameterFingerprint:    label32("parameters"),
		PolicyID:                label32("policy"),
		PolicyVersion:           PolicyVersion,
		IdentityMode:            IdentityFullFHE256,
		AuthorizationClaim:      claim,
		AuthorizationCommitment: commitment,
		IssuedAt:                uint64(f.now.Add(-time.Hour).Unix()),
		ValidUntil:              uint64(f.now.Add(24 * time.Hour).Unix()),
		Nonce:                   label32("nonce-" + side),
	}
}

func (f v5Fixture) sign(t *testing.T, enrollment CiphertextEnrollmentV5) *SignedCiphertextEnrollmentV5 {
	t.Helper()
	signed, err := SignEnrollmentV5(enrollment, f.issuerPrivate)
	if err != nil {
		t.Fatalf("sign enrollment: %v", err)
	}
	return signed
}

func (f v5Fixture) pair(t *testing.T) (*SignedCiphertextEnrollmentV5, *SignedCiphertextEnrollmentV5) {
	t.Helper()
	return f.sign(t, f.enrollment("a", f.scopeA, f.scopeB, 0)),
		f.sign(t, f.enrollment("b", f.scopeB, f.scopeA, 1))
}

func TestTwoCrossCertifiedEnrollmentsPair(t *testing.T) {
	fixture := newV5Fixture(t)
	a, b := fixture.pair(t)
	paired, err := PairEnrollmentsV5(a, b)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if paired.SessionCommitment != fixture.sessionCommit {
		t.Fatal("paired session commitment does not match")
	}
	if paired.EnrollmentDigestA == paired.EnrollmentDigestB {
		t.Fatal("the two enrollment digests collide")
	}
	if paired.ScopeCommitmentA != fixture.scopeA || paired.ScopeCommitmentB != fixture.scopeB {
		t.Fatal("paired scopes do not match the enrollments")
	}
}

// The V4 defect itself: two enrollments issued for different sessions shared
// the public policy context and could be paired by the evaluator alone.
func TestEnrollmentsFromDifferentSessionsDoNotPair(t *testing.T) {
	fixture := newV5Fixture(t)
	a, _ := fixture.pair(t)

	other := fixture
	other.sessionCommit = label32("a-different-session")
	_, b := other.pair(t)

	if _, err := PairEnrollmentsV5(a, b); !errors.Is(err, ErrEnrollmentsNotPaired) {
		t.Fatalf("expected ErrEnrollmentsNotPaired, got %v", err)
	}
}

func TestASharedSessionCommitmentWithADifferentNullifierDoesNotPair(t *testing.T) {
	fixture := newV5Fixture(t)
	a, _ := fixture.pair(t)
	side := fixture.enrollment("b", fixture.scopeB, fixture.scopeA, 1)
	side.Binding.SessionNullifier = label32("another-nullifier")
	b := fixture.sign(t, side)

	if _, err := PairEnrollmentsV5(a, b); !errors.Is(err, ErrEnrollmentsNotPaired) {
		t.Fatalf("expected ErrEnrollmentsNotPaired, got %v", err)
	}
}

// Cross-certification is what removes the evaluator's freedom to choose the
// pairing. B must be exactly the counterparty A named.
func TestASideThatIsNotTheNamedCounterpartyDoesNotPair(t *testing.T) {
	fixture := newV5Fixture(t)
	a := fixture.sign(t, fixture.enrollment("a", fixture.scopeA, fixture.scopeB, 0))
	// B is a real, correctly signed enrollment for this session, but its own
	// scope is not the one A consented to be compared against.
	side := fixture.enrollment("c", label32("scope-c"), fixture.scopeA, 1)
	b := fixture.sign(t, side)

	if _, err := PairEnrollmentsV5(a, b); !errors.Is(err, ErrEnrollmentsNotPaired) {
		t.Fatalf("expected ErrEnrollmentsNotPaired, got %v", err)
	}
}

func TestASideThatNamesItselfAsCounterpartyIsRefused(t *testing.T) {
	fixture := newV5Fixture(t)
	side := fixture.enrollment("a", fixture.scopeA, fixture.scopeA, 0)
	if _, err := SignEnrollmentV5(side, fixture.issuerPrivate); !errors.Is(err, ErrEnrollmentNotBound) {
		t.Fatalf("expected ErrEnrollmentNotBound, got %v", err)
	}
}

func TestBothSidesInTheSameSlotDoNotPair(t *testing.T) {
	fixture := newV5Fixture(t)
	a := fixture.sign(t, fixture.enrollment("a", fixture.scopeA, fixture.scopeB, 0))
	b := fixture.sign(t, fixture.enrollment("b", fixture.scopeB, fixture.scopeA, 0))
	if _, err := PairEnrollmentsV5(a, b); !errors.Is(err, ErrEnrollmentsNotPaired) {
		t.Fatalf("expected ErrEnrollmentsNotPaired, got %v", err)
	}
}

func TestARotatedEpochBetweenTheTwoEnrollmentsDoesNotPair(t *testing.T) {
	fixture := newV5Fixture(t)
	a := fixture.sign(t, fixture.enrollment("a", fixture.scopeA, fixture.scopeB, 0))
	side := fixture.enrollment("b", fixture.scopeB, fixture.scopeA, 1)
	side.Binding.AuthorizationEpoch = 8
	b := fixture.sign(t, side)
	if _, err := PairEnrollmentsV5(a, b); !errors.Is(err, ErrEnrollmentsNotPaired) {
		t.Fatalf("expected ErrEnrollmentsNotPaired, got %v", err)
	}
}

func TestABudgetEpochRotationDoesNotPair(t *testing.T) {
	fixture := newV5Fixture(t)
	a := fixture.sign(t, fixture.enrollment("a", fixture.scopeA, fixture.scopeB, 0))
	side := fixture.enrollment("b", fixture.scopeB, fixture.scopeA, 1)
	side.Binding.SubmissionBudgetEpoch = 4
	b := fixture.sign(t, side)
	if _, err := PairEnrollmentsV5(a, b); !errors.Is(err, ErrEnrollmentsNotPaired) {
		t.Fatalf("expected ErrEnrollmentsNotPaired, got %v", err)
	}
}

func TestOneCiphertextSubmittedAsBothSidesIsReplay(t *testing.T) {
	fixture := newV5Fixture(t)
	a := fixture.sign(t, fixture.enrollment("a", fixture.scopeA, fixture.scopeB, 0))
	side := fixture.enrollment("b", fixture.scopeB, fixture.scopeA, 1)
	side.CiphertextDigest = a.Enrollment.CiphertextDigest
	b := fixture.sign(t, side)
	if _, err := PairEnrollmentsV5(a, b); !errors.Is(err, ErrEnrollmentReplay) {
		t.Fatalf("expected ErrEnrollmentReplay, got %v", err)
	}
}

func TestAModeAEnrollmentIsRefusedUnderV5(t *testing.T) {
	// V5 always compares the strict identifier under FHE. Mode A compared a
	// public commitment, which is what made the identity join-able off-chain.
	fixture := newV5Fixture(t)
	side := fixture.enrollment("a", fixture.scopeA, fixture.scopeB, 0)
	side.IdentityMode = IdentityPublicCommitment
	if _, err := SignEnrollmentV5(side, fixture.issuerPrivate); !errors.Is(err, ErrMalformedEnrollment) {
		t.Fatalf("expected ErrMalformedEnrollment, got %v", err)
	}
}

func TestAnUnboundEnrollmentCannotBeSigned(t *testing.T) {
	fixture := newV5Fixture(t)
	for name, mutate := range map[string]func(*CiphertextEnrollmentV5){
		"no session commitment": func(e *CiphertextEnrollmentV5) { e.Binding.SessionCommitment = [32]byte{} },
		"no nullifier":          func(e *CiphertextEnrollmentV5) { e.Binding.SessionNullifier = [32]byte{} },
		"no counterparty":       func(e *CiphertextEnrollmentV5) { e.Binding.CounterpartyScopeCommitment = [32]byte{} },
		"no governance record":  func(e *CiphertextEnrollmentV5) { e.Binding.GovernanceRecord = [32]byte{} },
		"no source commitment":  func(e *CiphertextEnrollmentV5) { e.Binding.SourceRecordCommitment = [32]byte{} },
		"no authorization epoch": func(e *CiphertextEnrollmentV5) {
			e.Binding.AuthorizationEpoch = 0
		},
		"no budget epoch": func(e *CiphertextEnrollmentV5) { e.Binding.SubmissionBudgetEpoch = 0 },
		"slot out of range": func(e *CiphertextEnrollmentV5) {
			e.Binding.InputSlot = 2
		},
	} {
		t.Run(name, func(t *testing.T) {
			side := fixture.enrollment("a", fixture.scopeA, fixture.scopeB, 0)
			mutate(&side)
			if _, err := SignEnrollmentV5(side, fixture.issuerPrivate); !errors.Is(err, ErrEnrollmentNotBound) {
				t.Fatalf("expected ErrEnrollmentNotBound, got %v", err)
			}
		})
	}
}

// Every bound field must actually be inside the signature.
func TestTheSigningDigestCoversEveryBoundField(t *testing.T) {
	fixture := newV5Fixture(t)
	base := fixture.enrollment("a", fixture.scopeA, fixture.scopeB, 0)
	baseline := base.SigningDigest()

	mutations := map[string]func(*CiphertextEnrollmentV5){
		"session commitment":    func(e *CiphertextEnrollmentV5) { e.Binding.SessionCommitment = label32("x") },
		"session nullifier":     func(e *CiphertextEnrollmentV5) { e.Binding.SessionNullifier = label32("x") },
		"own scope":             func(e *CiphertextEnrollmentV5) { e.Binding.OwnScopeCommitment = label32("x") },
		"counterparty scope":    func(e *CiphertextEnrollmentV5) { e.Binding.CounterpartyScopeCommitment = label32("x") },
		"governance record":     func(e *CiphertextEnrollmentV5) { e.Binding.GovernanceRecord = label32("x") },
		"source commitment":     func(e *CiphertextEnrollmentV5) { e.Binding.SourceRecordCommitment = label32("x") },
		"authorization epoch":   func(e *CiphertextEnrollmentV5) { e.Binding.AuthorizationEpoch = 99 },
		"budget epoch":          func(e *CiphertextEnrollmentV5) { e.Binding.SubmissionBudgetEpoch = 99 },
		"input slot":            func(e *CiphertextEnrollmentV5) { e.Binding.InputSlot = 1 },
		"circuit version":       func(e *CiphertextEnrollmentV5) { e.CircuitVersion = 99 },
		"ciphertext digest":     func(e *CiphertextEnrollmentV5) { e.CiphertextDigest = label32("x") },
		"input commitment":      func(e *CiphertextEnrollmentV5) { e.InputCommitment = label32("x") },
		"key id":                func(e *CiphertextEnrollmentV5) { e.KeyID = label32("x") },
		"parameter fingerprint": func(e *CiphertextEnrollmentV5) { e.ParameterFingerprint = label32("x") },
		"policy id":             func(e *CiphertextEnrollmentV5) { e.PolicyID = label32("x") },
		"expiry":                func(e *CiphertextEnrollmentV5) { e.ValidUntil = e.ValidUntil + 1 },
		"nonce":                 func(e *CiphertextEnrollmentV5) { e.Nonce = label32("x") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := base
			mutate(&mutated)
			if mutated.SigningDigest() == baseline {
				t.Fatalf("%s is not covered by the signing digest", name)
			}
		})
	}
}

func TestReleaseDescriptorBindsBothEnrollmentDigests(t *testing.T) {
	fixture := newV5Fixture(t)
	a, b := fixture.pair(t)
	paired, err := PairEnrollmentsV5(a, b)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := ReleaseDescriptorV5{
		SessionCommitment:    paired.SessionCommitment,
		SessionNullifier:     paired.SessionNullifier,
		EnrollmentDigestA:    paired.EnrollmentDigestA,
		EnrollmentDigestB:    paired.EnrollmentDigestB,
		InputsDigest:         label32("inputs"),
		OutputsDigest:        label32("outputs"),
		CircuitVersion:       CircuitV5Version,
		RuntimeFingerprint:   label32("runtime"),
		KeyID:                label32("key-id"),
		ParameterFingerprint: label32("parameters"),
		PolicyID:             label32("policy"),
		PolicyVersion:        PolicyVersion,
		ExpiresAt:            uint64(fixture.now.Add(time.Hour).Unix()),
	}
	baseline, err := descriptor.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ReleaseDescriptorV5){
		"enrollment A":  func(d *ReleaseDescriptorV5) { d.EnrollmentDigestA = label32("x") },
		"enrollment B":  func(d *ReleaseDescriptorV5) { d.EnrollmentDigestB = label32("x") },
		"inputs":        func(d *ReleaseDescriptorV5) { d.InputsDigest = label32("x") },
		"outputs":       func(d *ReleaseDescriptorV5) { d.OutputsDigest = label32("x") },
		"session":       func(d *ReleaseDescriptorV5) { d.SessionCommitment = label32("x") },
		"key id":        func(d *ReleaseDescriptorV5) { d.KeyID = label32("x") },
		"expiry":        func(d *ReleaseDescriptorV5) { d.ExpiresAt++ },
		"runtime":       func(d *ReleaseDescriptorV5) { d.RuntimeFingerprint = label32("x") },
		"parameter set": func(d *ReleaseDescriptorV5) { d.ParameterFingerprint = label32("x") },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := descriptor
			mutate(&mutated)
			digest, err := mutated.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if digest == baseline {
				t.Fatalf("%s is not covered by the release descriptor digest", name)
			}
		})
	}

	// A descriptor whose two enrollment digests are equal is not a bilateral
	// release.
	degenerate := descriptor
	degenerate.EnrollmentDigestB = degenerate.EnrollmentDigestA
	if _, err := degenerate.Digest(); !errors.Is(err, ErrMalformedEnrollment) {
		t.Fatalf("expected ErrMalformedEnrollment, got %v", err)
	}
}

/* ------------------------------------------------------- durable one-shot */

func openLedger(t *testing.T, path string) *SessionLedger {
	t.Helper()
	ledger, err := OpenSessionLedger(path)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	return ledger
}

func TestASessionIsReservedExactlyOnce(t *testing.T) {
	fixture := newV5Fixture(t)
	a, b := fixture.pair(t)
	paired, err := PairEnrollmentsV5(a, b)
	if err != nil {
		t.Fatal(err)
	}
	ledger := openLedger(t, filepath.Join(t.TempDir(), "sessions.db"))
	if _, err := ledger.Reserve(paired, fixture.now); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	if _, err := ledger.Reserve(paired, fixture.now); !errors.Is(err, ErrSessionConsumed) {
		t.Fatalf("expected ErrSessionConsumed, got %v", err)
	}
}

// The whole point of finding H-01's second half: the V4 ledger was a Go map, so
// a restart forgot every session and a recorded request replayed cleanly.
func TestAReservedSessionSurvivesAnEvaluatorRestart(t *testing.T) {
	fixture := newV5Fixture(t)
	a, b := fixture.pair(t)
	paired, err := PairEnrollmentsV5(a, b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sessions.db")

	first, err := OpenSessionLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Reserve(paired, fixture.now); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// A brand new process would do exactly this.
	second := openLedger(t, path)
	if _, err := second.Reserve(paired, fixture.now); !errors.Is(err, ErrSessionConsumed) {
		t.Fatalf("session replayed after restart: %v", err)
	}
	record, err := second.Get(paired.SessionCommitment)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != SessionReserved {
		t.Fatalf("state %d survived incorrectly", record.State)
	}
}

// A resalted commitment is a different session commitment but the same
// nullifier, which is precisely the probing surface finding M-02 named.
func TestAResaltedSessionIsRefusedByItsNullifier(t *testing.T) {
	fixture := newV5Fixture(t)
	a, b := fixture.pair(t)
	paired, err := PairEnrollmentsV5(a, b)
	if err != nil {
		t.Fatal(err)
	}
	ledger := openLedger(t, filepath.Join(t.TempDir(), "sessions.db"))
	if _, err := ledger.Reserve(paired, fixture.now); err != nil {
		t.Fatal(err)
	}

	resalted := paired
	resalted.SessionCommitment = label32("resalted-commitment")
	resalted.EnrollmentDigestA = label32("fresh-a")
	resalted.EnrollmentDigestB = label32("fresh-b")
	if _, err := ledger.Reserve(resalted, fixture.now); !errors.Is(err, ErrSessionConsumed) {
		t.Fatalf("expected ErrSessionConsumed on nullifier, got %v", err)
	}
}

func TestAConsumedEnrollmentCannotJoinANewPair(t *testing.T) {
	fixture := newV5Fixture(t)
	a, b := fixture.pair(t)
	paired, err := PairEnrollmentsV5(a, b)
	if err != nil {
		t.Fatal(err)
	}
	ledger := openLedger(t, filepath.Join(t.TempDir(), "sessions.db"))
	if _, err := ledger.Reserve(paired, fixture.now); err != nil {
		t.Fatal(err)
	}

	// Everything fresh except side A's enrollment.
	recycled := paired
	recycled.SessionCommitment = label32("second-session")
	recycled.SessionNullifier = label32("second-nullifier")
	recycled.EnrollmentDigestB = label32("fresh-b")
	if _, err := ledger.Reserve(recycled, fixture.now); !errors.Is(err, ErrSessionConsumed) {
		t.Fatalf("expected ErrSessionConsumed on enrollment, got %v", err)
	}
}

func TestASessionIsReleasedAtMostOnce(t *testing.T) {
	fixture := newV5Fixture(t)
	a, b := fixture.pair(t)
	paired, err := PairEnrollmentsV5(a, b)
	if err != nil {
		t.Fatal(err)
	}
	ledger := openLedger(t, filepath.Join(t.TempDir(), "sessions.db"))
	if _, err := ledger.Reserve(paired, fixture.now); err != nil {
		t.Fatal(err)
	}
	outputs := label32("outputs")
	record, err := ledger.MarkReleased(paired.SessionCommitment, outputs, fixture.now)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if record.State != SessionReleased || record.OutputsDigest != outputs {
		t.Fatal("release did not record the recomputed output digest")
	}
	if _, err := ledger.MarkReleased(paired.SessionCommitment, outputs, fixture.now); !errors.Is(err, ErrSessionState) {
		t.Fatalf("expected ErrSessionState on second release, got %v", err)
	}
}

// An abandoned session spends its authorization. Otherwise a failed release is
// a free retry, and retries under one authorization are the probing surface.
func TestAnAbandonedSessionIsTerminal(t *testing.T) {
	fixture := newV5Fixture(t)
	a, b := fixture.pair(t)
	paired, err := PairEnrollmentsV5(a, b)
	if err != nil {
		t.Fatal(err)
	}
	ledger := openLedger(t, filepath.Join(t.TempDir(), "sessions.db"))
	if _, err := ledger.Reserve(paired, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.MarkFailed(paired.SessionCommitment, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.MarkReleased(paired.SessionCommitment, label32("outputs"), fixture.now); !errors.Is(err, ErrSessionState) {
		t.Fatalf("expected ErrSessionState, got %v", err)
	}
	if _, err := ledger.Reserve(paired, fixture.now); !errors.Is(err, ErrSessionConsumed) {
		t.Fatalf("expected ErrSessionConsumed, got %v", err)
	}
}

func TestReleasingAnUnknownSessionFails(t *testing.T) {
	ledger := openLedger(t, filepath.Join(t.TempDir(), "sessions.db"))
	if _, err := ledger.MarkReleased(label32("never-reserved"), label32("outputs"), time.Now()); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("expected ErrSessionUnknown, got %v", err)
	}
}
