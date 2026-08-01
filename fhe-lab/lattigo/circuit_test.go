package lattigospike

import (
	"crypto/sha256"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

var (
	testRuntimeOnce sync.Once
	testRuntime     *Runtime
	testRuntimeErr  error
)

func sharedTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	testRuntimeOnce.Do(func() {
		testRuntime, _, testRuntimeErr = NewRuntime()
	})
	if testRuntimeErr != nil {
		t.Fatalf("setup failed: %v", testRuntimeErr)
	}
	return testRuntime
}

// dedicatedTestRuntime is for tests that deliberately destroy runtime state,
// such as detaching the co-located threshold parties. Those tests must not run
// against the shared runtime: DetachThresholdParties is irreversible, so every
// later test in the package would lose the in-process coalition and fail with
// ErrInsufficientShare purely because of execution order.
func dedicatedTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	runtime, _, err := NewRuntime()
	if err != nil {
		t.Fatalf("dedicated setup failed: %v", err)
	}
	return runtime
}

func TestEncryptedPolicyCases(t *testing.T) {
	runtime := sharedTestRuntime(t)
	tests := []struct {
		name     string
		mutate   func(*PlainPledge, *PlainPledge)
		mode     IdentityMode
		expected bool
	}{
		{name: "overlap_true", expected: true},
		{name: "disjoint_false", mutate: func(a, b *PlainPledge) {
			b.ActiveFrom, b.ActiveUntil = 500, 600
		}},
		{name: "adjacent_false", mutate: func(a, b *PlainPledge) {
			a.ActiveFrom, a.ActiveUntil = 100, 200
			b.ActiveFrom, b.ActiveUntil = 200, 300
		}},
		{name: "currency_bytes32_false", mutate: func(a, b *PlainPledge) {
			b.Currency = sha256.Sum256([]byte("different-currency-code"))
		}},
		{name: "exclusive_false", mutate: func(a, b *PlainPledge) {
			b.Exclusive = false
		}},
		{name: "public_receivable_commitment_false", mutate: func(a, b *PlainPledge) {
			b.ReceivableCommitment = sha256.Sum256([]byte("another-public-salted-commitment"))
		}},
		{name: "uint64_max_boundary_true", mutate: func(a, b *PlainPledge) {
			a.ActiveFrom, a.ActiveUntil = math.MaxUint64-100, math.MaxUint64-20
			b.ActiveFrom, b.ActiveUntil = math.MaxUint64-80, math.MaxUint64-1
		}, expected: true},
		{name: "full_fhe_identity_true", mode: IdentityFullFHE256, expected: true},
		{name: "full_fhe_identity_false", mode: IdentityFullFHE256, mutate: func(a, b *PlainPledge) {
			b.ReceivableID = sha256.Sum256([]byte("different-private-receivable-id"))
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := fixturePair("policy-" + tt.name)
			if tt.mutate != nil {
				tt.mutate(&a, &b)
			}
			mode := tt.mode
			if mode == "" {
				mode = IdentityPublicCommitment
			}
			decision := evaluateFixture(t, runtime, "policy-"+tt.name, a, b, mode)
			observed, metrics, err := runtime.DecryptThresholdWithCoalition(decision, 1, 2)
			if err != nil {
				t.Fatalf("threshold decryption failed: %v", err)
			}
			if metrics.Participants != 2 || metrics.Threshold != 2 || metrics.ReceiverIndex != 1 || metrics.HelperIndex != 2 {
				t.Fatalf("unexpected threshold metadata: %+v", metrics)
			}
			if observed != tt.expected {
				t.Fatalf("wrong encrypted policy result: expected=%t observed=%t", tt.expected, observed)
			}
		})
	}
}

func TestEveryTwoOfThreeCoalitionDecrypts(t *testing.T) {
	runtime := sharedTestRuntime(t)
	coalitions := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, coalition := range coalitions {
		label := string(rune('a'+coalition[0])) + string(rune('a'+coalition[1]))
		t.Run(label, func(t *testing.T) {
			a, b := fixturePair("coalition-" + label)
			decision := evaluateFixture(t, runtime, "coalition-"+label, a, b, IdentityPublicCommitment)
			observed, metrics, err := runtime.DecryptThresholdWithCoalition(decision, coalition[0], coalition[1])
			if err != nil {
				t.Fatalf("coalition %v failed: %v", coalition, err)
			}
			if !observed || metrics.ReceiverIndex != coalition[0] || metrics.HelperIndex != coalition[1] {
				t.Fatalf("coalition %v returned wrong result or metadata: %+v", coalition, metrics)
			}
		})
	}
}

func TestOneShareFailsAndCiphertextAttemptIsTerminal(t *testing.T) {
	runtime := sharedTestRuntime(t)
	a, b := fixturePair("terminal-decrypt")
	decision := evaluateFixture(t, runtime, "terminal-decrypt", a, b, IdentityPublicCommitment)

	if _, _, err := runtime.DecryptThresholdWithCoalition(decision, 1, 1); !errors.Is(err, ErrInsufficientShare) {
		t.Fatalf("expected one-share rejection, got %v", err)
	}
	if observed, _, err := runtime.DecryptThresholdWithCoalition(decision, 0, 2); err != nil || !observed {
		t.Fatalf("preflight rejection must not consume the result: result=%t err=%v", observed, err)
	}
	copyWithNewNonce := *decision
	copyWithNewNonce.Nonce = sha256.Sum256([]byte("attacker-selected-new-nonce"))
	if _, _, err := runtime.DecryptThresholdWithCoalition(&copyWithNewNonce, 0, 2); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ciphertext-bound terminal rejection, got %v", err)
	}

	// The key-switch protocol consumes c1, not c0. An attacker must not obtain
	// another release by mutating c0 and recomputing the whole-ciphertext hash.
	copyWithChangedC0 := *decision
	copyWithChangedC0.Conflict = decision.Conflict.CopyNew()
	copyWithChangedC0.Conflict.Value[0].Coeffs[0][0] ^= 1
	changedCommitment, err := ciphertextCommitment(copyWithChangedC0.Conflict)
	if err != nil {
		t.Fatal(err)
	}
	copyWithChangedC0.ResultCiphertextCommitment = changedCommitment
	copyWithChangedC0.Nonce = sha256.Sum256([]byte("attacker-mutated-c0"))
	if _, _, err := runtime.DecryptThresholdWithCoalition(&copyWithChangedC0, 0, 2); !errors.Is(err, ErrReplay) {
		t.Fatalf("c0 mutation bypassed protocol-consumption guard: %v", err)
	}
}

func TestResultCiphertextCommitmentIsVerified(t *testing.T) {
	runtime := sharedTestRuntime(t)
	a, b := fixturePair("result-commitment")
	decision := evaluateFixture(t, runtime, "result-commitment", a, b, IdentityPublicCommitment)
	altered := *decision
	altered.ResultCiphertextCommitment[0] ^= 0xff
	if _, _, err := runtime.DecryptThresholdWithCoalition(&altered, 0, 1); !errors.Is(err, ErrMalformedPledge) {
		t.Fatalf("expected altered result commitment rejection, got %v", err)
	}
	if observed, _, err := runtime.DecryptThresholdWithCoalition(decision, 0, 1); err != nil || !observed {
		t.Fatalf("valid commitment should remain usable after preflight rejection: result=%t err=%v", observed, err)
	}
}

func TestEnvelopeFailuresAreHandled(t *testing.T) {
	runtime := sharedTestRuntime(t)
	a, b := fixturePair("invalid-envelope")
	a, b = normalizeForMode(a, b, IdentityPublicCommitment)
	authorizePair(t, runtime, a, b)
	encA, _, err := runtime.EncryptPledge(a)
	if err != nil {
		t.Fatal(err)
	}
	encB, _, err := runtime.EncryptPledge(b)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)

	tests := []struct {
		name   string
		mutate func(*EvaluationRequest)
		want   error
	}{
		{name: "wrong_request_key", mutate: func(r *EvaluationRequest) { r.KeyID = "internal-sha256:wrong" }, want: ErrWrongKeyID},
		{name: "wrong_embedded_key", mutate: func(r *EvaluationRequest) { r.A.KeyID = "internal-sha256:wrong" }, want: ErrWrongKeyID},
		{name: "wrong_parameter_fingerprint", mutate: func(r *EvaluationRequest) { r.B.ParameterFingerprint[0] ^= 0xff }, want: ErrWrongKeyID},
		{name: "wrong_policy", mutate: func(r *EvaluationRequest) { r.PolicyVersion++ }, want: ErrWrongPolicy},
		{name: "expired", mutate: func(r *EvaluationRequest) { r.ValidUntil = now.Add(-time.Nanosecond) }, want: ErrExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roundTripA, err := cloneCipherPledge(encA)
			if err != nil {
				t.Fatal(err)
			}
			roundTripB, err := cloneCipherPledge(encB)
			if err != nil {
				t.Fatal(err)
			}
			request := fixtureRequest(runtime, "envelope-"+tt.name, roundTripA, roundTripB, now)
			tt.mutate(&request)
			if _, _, err := runtime.Evaluate(request, now); !errors.Is(err, tt.want) {
				t.Fatalf("expected handled error %v, got %v", tt.want, err)
			}
		})
	}

	replay := fixtureRequest(runtime, "envelope-replay", encA, encB, now)
	if _, _, err := runtime.Evaluate(replay, now); err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	if _, _, err := runtime.Evaluate(replay, now); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected evaluation replay rejection, got %v", err)
	}
}

func TestCiphertextsFromAnotherRuntimeAreRejected(t *testing.T) {
	runtime := sharedTestRuntime(t)
	other, _, err := NewRuntime()
	if err != nil {
		t.Fatalf("second key setup failed: %v", err)
	}
	a, b := fixturePair("actual-wrong-key")
	encA, _, err := other.EncryptPledge(a)
	if err != nil {
		t.Fatal(err)
	}
	encB, _, err := other.EncryptPledge(b)
	if err != nil {
		t.Fatal(err)
	}
	authorizePair(t, runtime, a, b)
	now := time.Unix(1_800_000_000, 0)
	request := fixtureRequest(runtime, "actual-wrong-key", encA, encB, now)
	if _, _, err := runtime.Evaluate(request, now); !errors.Is(err, ErrWrongKeyID) {
		t.Fatalf("expected actual wrong-key ciphertext rejection, got %v", err)
	}

	// Relabeling provider metadata cannot turn a ciphertext created by another
	// runtime into one accepted by this harness. The process-local issuance
	// registry is an integration guard, not a proof of ciphertext well-formedness.
	encA.KeyID, encB.KeyID = runtime.keyID, runtime.keyID
	encA.ParameterFingerprint, encB.ParameterFingerprint = runtime.parameterFingerprint, runtime.parameterFingerprint
	forged := fixtureRequest(runtime, "actual-wrong-key-forged-metadata", encA, encB, now)
	if _, _, err := runtime.Evaluate(forged, now); !errors.Is(err, ErrCiphertextNotIssued) {
		t.Fatalf("expected relabeled wrong-runtime ciphertext rejection, got %v", err)
	}
}

func TestIngressAndIdentityModeFailures(t *testing.T) {
	runtime := sharedTestRuntime(t)
	now := time.Unix(1_800_000_000, 0)

	t.Run("unregistered_ingress", func(t *testing.T) {
		a, b := fixturePair("unregistered-ingress")
		encA, _, err := runtime.EncryptPledge(a)
		if err != nil {
			t.Fatal(err)
		}
		encB, _, err := runtime.EncryptPledge(b)
		if err != nil {
			t.Fatal(err)
		}
		request := fixtureRequest(runtime, "unregistered-ingress", encA, encB, now)
		if _, _, err := runtime.Evaluate(request, now); !errors.Is(err, ErrUnauthorizedIngress) {
			t.Fatalf("expected unregistered ingress rejection, got %v", err)
		}
	})

	t.Run("expired_ingress_grant", func(t *testing.T) {
		a, b := fixturePair("expired-ingress")
		encA, _, err := runtime.EncryptPledge(a)
		if err != nil {
			t.Fatal(err)
		}
		encB, _, err := runtime.EncryptPledge(b)
		if err != nil {
			t.Fatal(err)
		}
		expired := now.Add(-time.Nanosecond)
		if err := runtime.GrantIngress(a.AuthorizationCommitment, PolicyVersion, expired); err != nil {
			t.Fatal(err)
		}
		if err := runtime.GrantIngress(b.AuthorizationCommitment, PolicyVersion, expired); err != nil {
			t.Fatal(err)
		}
		request := fixtureRequest(runtime, "expired-ingress", encA, encB, now)
		if _, _, err := runtime.Evaluate(request, now); !errors.Is(err, ErrUnauthorizedIngress) {
			t.Fatalf("expected expired ingress rejection, got %v", err)
		}
	})

	t.Run("revoked_ingress_grant", func(t *testing.T) {
		a, b := fixturePair("revoked-ingress")
		authorizePair(t, runtime, a, b)
		runtime.RevokeIngress(b.AuthorizationCommitment)
		encA, _, err := runtime.EncryptPledge(a)
		if err != nil {
			t.Fatal(err)
		}
		encB, _, err := runtime.EncryptPledge(b)
		if err != nil {
			t.Fatal(err)
		}
		request := fixtureRequest(runtime, "revoked-ingress", encA, encB, now)
		if _, _, err := runtime.Evaluate(request, now); !errors.Is(err, ErrUnauthorizedIngress) {
			t.Fatalf("expected revoked ingress rejection, got %v", err)
		}
	})

	t.Run("public_mode_requires_commitment", func(t *testing.T) {
		a, _ := fixturePair("public-needs-commitment")
		a.ReceivableCommitment = [32]byte{}
		if _, _, err := runtime.EncryptPledgeForMode(a, IdentityPublicCommitment); !errors.Is(err, ErrInvalidPlaintext) {
			t.Fatalf("expected missing public commitment rejection, got %v", err)
		}
	})

	t.Run("full_fhe_forbids_public_commitment", func(t *testing.T) {
		a, _ := fixturePair("full-fhe-no-public-link")
		if _, _, err := runtime.EncryptPledgeForMode(a, IdentityFullFHE256); !errors.Is(err, ErrInvalidPlaintext) {
			t.Fatalf("expected public-link leakage rejection, got %v", err)
		}
	})
}

func TestSerializationAndUint256Boundary(t *testing.T) {
	runtime := sharedTestRuntime(t)
	a, _ := fixturePair("serialization")
	a.Amount = Uint256{math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64}
	pledge, metrics, err := runtime.EncryptPledge(a)
	if err != nil {
		t.Fatalf("uint256 max encryption failed: %v", err)
	}
	if metrics.CiphertextBytes <= 0 || metrics.Digest == "" {
		t.Fatalf("missing serialization metrics: %+v", metrics)
	}
	clone, err := cloneCipherPledge(pledge)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := CipherPledgeDigest(clone)
	if err != nil {
		t.Fatal(err)
	}
	if digest != metrics.Digest {
		t.Fatalf("serialized pledge digest changed across round-trip")
	}

	serialized, err := pledge.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalCipherPledge(serialized[:len(serialized)/2]); !errors.Is(err, ErrMalformedPledge) {
		t.Fatalf("expected truncated ciphertext rejection, got %v", err)
	}

	a.ActiveUntil = a.ActiveFrom
	if _, _, err := runtime.EncryptPledge(a); !errors.Is(err, ErrInvalidPlaintext) {
		t.Fatalf("expected invalid interval rejection, got %v", err)
	}
}

func evaluateFixture(t *testing.T, runtime *Runtime, label string, a, b PlainPledge, mode IdentityMode) *EncryptedDecision {
	t.Helper()
	a, b = normalizeForMode(a, b, mode)
	authorizePair(t, runtime, a, b)
	encA, _, err := runtime.EncryptPledgeForMode(a, mode)
	if err != nil {
		t.Fatalf("encrypt A failed: %v", err)
	}
	encB, _, err := runtime.EncryptPledgeForMode(b, mode)
	if err != nil {
		t.Fatalf("encrypt B failed: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	request := fixtureRequest(runtime, label, encA, encB, now)
	request.IdentityMode = mode
	if label == "policy-overlap_true" {
		request.ValidUntil = now // the exact boundary remains valid
	}
	decision, _, err := runtime.Evaluate(request, now)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	return decision
}

func normalizeForMode(a, b PlainPledge, mode IdentityMode) (PlainPledge, PlainPledge) {
	if mode == IdentityFullFHE256 {
		a.ReceivableCommitment = [32]byte{}
		b.ReceivableCommitment = [32]byte{}
	}
	return a, b
}

func cloneCipherPledge(pledge *CipherPledge) (*CipherPledge, error) {
	serialized, err := pledge.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return UnmarshalCipherPledge(serialized)
}

func fixturePair(label string) (PlainPledge, PlainPledge) {
	commitment := sha256.Sum256([]byte("public-salted-receivable-commitment"))
	a := PlainPledge{
		ActiveFrom:                100,
		ActiveUntil:               400,
		Amount:                    Uint256{0, 0, 0, 1_000_000},
		Currency:                  sha256.Sum256([]byte("currency-usd")),
		ObligationID:              sha256.Sum256([]byte("obligation-a-" + label)),
		ReceivableID:              sha256.Sum256([]byte("private-receivable-id")),
		Exclusive:                 true,
		ReceivableCommitment:      commitment,
		AuthorizationCommitment:   sha256.Sum256([]byte("authorized-source-a-" + label)),
		PrivateMetadataCommitment: sha256.Sum256([]byte("salted-private-metadata-a-" + label)),
	}
	b := PlainPledge{
		ActiveFrom:                200,
		ActiveUntil:               500,
		Amount:                    Uint256{0, 0, 0, 900_000},
		Currency:                  sha256.Sum256([]byte("currency-usd")),
		ObligationID:              sha256.Sum256([]byte("obligation-b-" + label)),
		ReceivableID:              sha256.Sum256([]byte("private-receivable-id")),
		Exclusive:                 true,
		ReceivableCommitment:      commitment,
		AuthorizationCommitment:   sha256.Sum256([]byte("authorized-source-b-" + label)),
		PrivateMetadataCommitment: sha256.Sum256([]byte("salted-private-metadata-b-" + label)),
	}
	return a, b
}

func fixtureRequest(runtime *Runtime, label string, a, b *CipherPledge, now time.Time) EvaluationRequest {
	return EvaluationRequest{
		KeyID:         runtime.KeyID(),
		PolicyVersion: PolicyVersion,
		Nonce:         sha256.Sum256([]byte("nonce-" + label)),
		ValidUntil:    now.Add(time.Minute),
		IdentityMode:  IdentityPublicCommitment,
		A:             a,
		B:             b,
	}
}

func authorizePair(t *testing.T, runtime *Runtime, a, b PlainPledge) {
	t.Helper()
	grantExpiry := time.Unix(2_100_000_000, 0)
	if err := runtime.GrantIngress(a.AuthorizationCommitment, PolicyVersion, grantExpiry); err != nil {
		t.Fatal(err)
	}
	if err := runtime.GrantIngress(b.AuthorizationCommitment, PolicyVersion, grantExpiry); err != nil {
		t.Fatal(err)
	}
}
