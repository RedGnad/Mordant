package lattigospike

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// The fingerprint is only worth binding if it actually changes when the thing
// it describes changes. These tests assert exactly that, constituent by
// constituent, and that the declared gate sequence cannot drift away from the
// circuit it claims to describe.

// fingerprintMaterial returns the shared ceremony's collective public key
// material, which is what a real operator loads from disk.
func fingerprintMaterial(t *testing.T) (bgv.Parameters, *rlwe.PublicKey, *rlwe.RelinearizationKey, []*rlwe.GaloisKey) {
	t.Helper()
	fixture := sharedV5Ceremony(t)
	publicKey, relinKey, galoisKeys, err := fixture.aggregator.CollectiveKeys()
	if err != nil {
		t.Fatalf("collective keys: %v", err)
	}
	return fixture.params, publicKey, relinKey, galoisKeys
}

func TestTheLocalRuntimeIdentityIsDerivedNotAsserted(t *testing.T) {
	params, publicKey, relinKey, galoisKeys := fingerprintMaterial(t)
	identity, err := LocalRuntimeIdentity(params, publicKey, relinKey, galoisKeys, 1)
	if err != nil {
		t.Fatalf("local runtime identity: %v", err)
	}
	described := identity.Describe()
	if described.LattigoVersion == "" || described.LattigoVersion == "(devel)" {
		t.Fatalf("lattigo version not pinned: %q", described.LattigoVersion)
	}
	if !strings.HasPrefix(described.GoVersion, "go1.") {
		t.Fatalf("unexpected go version %q", described.GoVersion)
	}
	if described.GOOS == "" || described.GOARCH == "" {
		t.Fatal("target os/arch missing")
	}
	if described.CircuitVersion != CircuitV5Version {
		t.Fatalf("circuit version %d", described.CircuitVersion)
	}
	if described.SerializationVersion != SerializationVersion {
		t.Fatalf("serialization version %d", described.SerializationVersion)
	}
	if described.ReleaseLayoutVersion != ReleaseLayoutVersion {
		t.Fatalf("release layout version %d", described.ReleaseLayoutVersion)
	}
	if len(described.Fingerprint) != 64 {
		t.Fatalf("fingerprint is not 32 bytes: %q", described.Fingerprint)
	}
}

func TestTheSameBuildAndKeysProduceTheSameFingerprint(t *testing.T) {
	params, publicKey, relinKey, galoisKeys := fingerprintMaterial(t)
	first, err := LocalRuntimeIdentity(params, publicKey, relinKey, galoisKeys, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LocalRuntimeIdentity(params, publicKey, relinKey, galoisKeys, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatal("two derivations of the same build disagree")
	}
	if err := first.RequireSameRuntime(second); err != nil {
		t.Fatalf("same build refused: %v", err)
	}
}

// Loading order must not change the fingerprint, or an operator would be
// refused for the order it happened to read its keys in.
func TestTheFingerprintIsIndependentOfGaloisKeyOrder(t *testing.T) {
	params, publicKey, relinKey, galoisKeys := fingerprintMaterial(t)
	forward, err := LocalRuntimeIdentity(params, publicKey, relinKey, galoisKeys, 1)
	if err != nil {
		t.Fatal(err)
	}
	reversed := append([]*rlwe.GaloisKey(nil), galoisKeys...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	backward, err := LocalRuntimeIdentity(params, publicKey, relinKey, reversed, 1)
	if err != nil {
		t.Fatal(err)
	}
	if forward.Fingerprint() != backward.Fingerprint() {
		t.Fatal("galois key loading order changed the fingerprint")
	}
}

func TestADifferentKeyEpochIsADifferentRuntime(t *testing.T) {
	params, publicKey, relinKey, galoisKeys := fingerprintMaterial(t)
	first, err := LocalRuntimeIdentity(params, publicKey, relinKey, galoisKeys, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LocalRuntimeIdentity(params, publicKey, relinKey, galoisKeys, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint() == second.Fingerprint() {
		t.Fatal("a key epoch rotation did not change the fingerprint")
	}
	err = first.RequireSameRuntime(second)
	if !errors.Is(err, ErrRuntimeMismatch) || !strings.Contains(err.Error(), "key epoch 1 vs 2") {
		t.Fatalf("expected a named key epoch mismatch, got %v", err)
	}
}

func TestADifferentKeySetIsADifferentRuntime(t *testing.T) {
	params, publicKey, relinKey, galoisKeys := fingerprintMaterial(t)
	first, err := LocalRuntimeIdentity(params, publicKey, relinKey, galoisKeys, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Drop one Galois key: the operator can no longer evaluate the same circuit.
	truncated := galoisKeys[:len(galoisKeys)-1]
	second, err := LocalRuntimeIdentity(params, publicKey, relinKey, truncated, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = first.RequireSameRuntime(second)
	if !errors.Is(err, ErrRuntimeMismatch) || !strings.Contains(err.Error(), "evaluation keys") {
		t.Fatalf("expected a named evaluation key mismatch, got %v", err)
	}
}

func TestAnUnapprovedRuntimeIsRefused(t *testing.T) {
	params, publicKey, relinKey, galoisKeys := fingerprintMaterial(t)
	identity, err := LocalRuntimeIdentity(params, publicKey, relinKey, galoisKeys, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.RequireApproved(identity.Fingerprint()); err != nil {
		t.Fatalf("approved runtime refused: %v", err)
	}
	if err := identity.RequireApproved(label32("some-other-approved-build")); !errors.Is(err, ErrRuntimeMismatch) {
		t.Fatalf("expected ErrRuntimeMismatch, got %v", err)
	}
}

// The circuit hash is only meaningful if the declared gate sequence describes
// the circuit that actually runs. This reads the implementation and compares
// the ordered primitives, so the two cannot drift apart silently.
func TestTheCircuitHashTracksTheGateSequence(t *testing.T) {
	source, err := os.ReadFile("circuit_v5.go")
	if err != nil {
		t.Fatal(err)
	}
	body := functionBody(t, string(source), "func (r *Runtime) RecomputeCircuitV5")

	primitive := regexp.MustCompile(`comparisonLayout|compareTwoBlocks|keepSlots|RotateColumnsNew|mulBoolean|equal256`)
	implemented := primitive.FindAllString(body, -1)

	declared := make([]string, 0, len(circuitV5GateSequence))
	for _, gate := range circuitV5GateSequence {
		name := gate[:strings.Index(gate, "(")]
		switch name {
		case "rotateColumns":
			name = "RotateColumnsNew"
		case "release":
			continue
		}
		declared = append(declared, name)
	}

	if len(implemented) != len(declared) {
		t.Fatalf("circuit uses %d primitives, gate sequence declares %d:\n implemented %v\n declared    %v",
			len(implemented), len(declared), implemented, declared)
	}
	for index := range declared {
		if implemented[index] != declared[index] {
			t.Fatalf("gate %d: circuit runs %q, sequence declares %q", index, implemented[index], declared[index])
		}
	}
}

// The compile-time pin is the fallback for test binaries and the cross-check
// for real ones, so it must equal what go.mod actually requires.
func TestThePinnedLattigoVersionMatchesGoMod(t *testing.T) {
	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	needle := LattigoModulePath + " " + lattigoPinnedVersion
	if !strings.Contains(string(goMod), needle) {
		t.Fatalf("go.mod does not require %q; the compile-time pin has drifted", needle)
	}
}

func TestTheCircuitHashIsStableAndNonZero(t *testing.T) {
	first := CircuitHashV5()
	if first == ([32]byte{}) {
		t.Fatal("circuit hash is zero")
	}
	if first != CircuitHashV5() {
		t.Fatal("circuit hash is not stable")
	}
}

// functionBody extracts one function's body by brace matching, so the test does
// not depend on the file's formatting.
func functionBody(t *testing.T, source, signature string) string {
	t.Helper()
	start := strings.Index(source, signature)
	if start < 0 {
		t.Fatalf("function %q not found", signature)
	}
	open := strings.Index(source[start:], "{")
	if open < 0 {
		t.Fatalf("no body for %q", signature)
	}
	depth := 0
	for index := start + open; index < len(source); index++ {
		switch source[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[start+open : index]
			}
		}
	}
	t.Fatalf("unbalanced braces in %q", signature)
	return ""
}
