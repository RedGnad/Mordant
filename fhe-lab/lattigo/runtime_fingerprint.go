package lattigospike

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"golang.org/x/crypto/sha3"
)

// The canonical runtime fingerprint.
//
// Operator-side recomputation only means something if every operator is running
// the same thing. Two operators on different Lattigo versions, different Go
// versions or different serialization can disagree byte for byte while both
// being honest, and a disagreement that is really a version skew is
// indistinguishable from a disagreement that is really an attack.
//
// The fingerprint below is bound into the release descriptor, into every
// operator attestation and into the on-chain V5 result core. A dependency
// upgrade changes it, which is what makes silently mixing builds impossible
// rather than merely discouraged: an upgraded operator produces a different
// fingerprint and is refused until a new runtime version or key epoch is
// approved.
//
// Each operator computes this LOCALLY from its own installed build. A
// coordinator may not supply executable code, a circuit binary, parameters or a
// claimed fingerprint as an authority.

const (
	// SerializationVersion identifies the ciphertext and share wire encodings.
	// Bump it whenever a marshalled form changes, even compatibly: the point is
	// that a byte comparison across versions is refused, not reconciled.
	SerializationVersion uint32 = 1

	// LattigoModulePath is the dependency whose version is load-bearing.
	LattigoModulePath = "github.com/tuneinsight/lattigo/v6"

	// lattigoPinnedVersion mirrors go.mod. In a normal build the embedded build
	// info is authoritative and this constant is a cross-check that must agree.
	// `go test` binaries carry no dependency list at all, so it is also the
	// fallback there. TestThePinnedLattigoVersionMatchesGoMod asserts it against
	// go.mod, so it cannot drift.
	lattigoPinnedVersion = "v6.2.0"

	runtimeFingerprintDomain = "MordantRuntimeFingerprint/v5"
)

var (
	// ErrRuntimeUnpinned reports a build whose dependency versions cannot be
	// read. A runtime that cannot state what it is must not serve a release.
	ErrRuntimeUnpinned = errors.New("runtime dependency versions are not pinned")
	// ErrRuntimeMismatch reports two runtimes that are not the same approved
	// version.
	ErrRuntimeMismatch = errors.New("runtime fingerprint mismatch")
)

// RuntimeDescriptor is the human-readable form of what the fingerprint covers.
// It is emitted into evidence so a reviewer can see which build produced a
// result without having to reverse a hash.
type RuntimeDescriptor struct {
	LattigoVersion       string `json:"lattigo_version"`
	GoVersion            string `json:"go_version"`
	GOOS                 string `json:"goos"`
	GOARCH               string `json:"goarch"`
	CircuitVersion       uint32 `json:"circuit_version"`
	CircuitHash          string `json:"circuit_hash"`
	ParameterFingerprint string `json:"parameter_fingerprint"`
	EvaluationKeyDigest  string `json:"evaluation_key_digest"`
	EvaluationKeyEpoch   uint32 `json:"evaluation_key_epoch"`
	SerializationVersion uint32 `json:"serialization_version"`
	ReleaseLayoutVersion uint16 `json:"release_layout_version"`
	Fingerprint          string `json:"fingerprint"`
}

// RuntimeIdentity is the locally pinned build identity of one process.
type RuntimeIdentity struct {
	lattigoVersion       string
	goVersion            string
	goos                 string
	goarch               string
	circuitHash          [32]byte
	parameterFingerprint [32]byte
	evaluationKeyDigest  [32]byte
	evaluationKeyEpoch   uint32
	fingerprint          [32]byte
}

// LocalRuntimeIdentity derives this process's runtime identity from its own
// build metadata and its own key material.
//
// Nothing here is a parameter a caller may assert. The Lattigo version comes
// from the embedded build info, the Go version and target from the runtime
// package, the circuit hash from the compiled circuit description, and the key
// material from the keys the operator actually loaded.
func LocalRuntimeIdentity(
	params interface{ MarshalBinary() ([]byte, error) },
	publicKey *rlwe.PublicKey,
	relinearizationKey *rlwe.RelinearizationKey,
	galoisKeys []*rlwe.GaloisKey,
	evaluationKeyEpoch uint32,
) (RuntimeIdentity, error) {
	var identity RuntimeIdentity
	if params == nil || publicKey == nil || relinearizationKey == nil || evaluationKeyEpoch == 0 {
		return identity, ErrCeremonyMaterial
	}
	lattigoVersion, err := pinnedModuleVersion(LattigoModulePath)
	if err != nil {
		return identity, err
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return identity, fmt.Errorf("marshal parameters: %w", err)
	}
	keyDigest, err := EvaluationKeyDigest(publicKey, relinearizationKey, galoisKeys)
	if err != nil {
		return identity, err
	}

	identity = RuntimeIdentity{
		lattigoVersion:       lattigoVersion,
		goVersion:            runtime.Version(),
		goos:                 runtime.GOOS,
		goarch:               runtime.GOARCH,
		circuitHash:          CircuitHashV5(),
		parameterFingerprint: legacyKeccak(parameterBytes),
		evaluationKeyDigest:  keyDigest,
		evaluationKeyEpoch:   evaluationKeyEpoch,
	}
	identity.fingerprint = identity.compute()
	return identity, nil
}

func (identity RuntimeIdentity) compute() [32]byte {
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte(runtimeFingerprintDomain))
	// Length-prefixed so two different field splits cannot collide.
	for _, text := range []string{
		identity.lattigoVersion, identity.goVersion, identity.goos, identity.goarch,
	} {
		_ = writeLengthPrefixed(hash, []byte(text))
	}
	_, _ = hash.Write(identity.circuitHash[:])
	_, _ = hash.Write(uint32Word(CircuitV5Version))
	_, _ = hash.Write(identity.parameterFingerprint[:])
	_, _ = hash.Write(identity.evaluationKeyDigest[:])
	_, _ = hash.Write(uint32Word(identity.evaluationKeyEpoch))
	_, _ = hash.Write(uint32Word(SerializationVersion))
	_, _ = hash.Write(uint16Word(ReleaseLayoutVersion))
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

// Fingerprint is the 32-byte value bound on chain and in every attestation.
func (identity RuntimeIdentity) Fingerprint() [32]byte { return identity.fingerprint }

// CircuitHash is the compiled circuit's identity.
func (identity RuntimeIdentity) CircuitHash() [32]byte { return identity.circuitHash }

// ParameterFingerprint is the FHE parameter set's identity.
func (identity RuntimeIdentity) ParameterFingerprint() [32]byte { return identity.parameterFingerprint }

// EvaluationKeyDigest is the digest of the public evaluation key material.
func (identity RuntimeIdentity) EvaluationKeyDigest() [32]byte { return identity.evaluationKeyDigest }

// EvaluationKeyEpoch is the approved key epoch this runtime serves.
func (identity RuntimeIdentity) EvaluationKeyEpoch() uint32 { return identity.evaluationKeyEpoch }

// Describe returns the auditable expansion of the fingerprint.
func (identity RuntimeIdentity) Describe() RuntimeDescriptor {
	return RuntimeDescriptor{
		LattigoVersion:       identity.lattigoVersion,
		GoVersion:            identity.goVersion,
		GOOS:                 identity.goos,
		GOARCH:               identity.goarch,
		CircuitVersion:       CircuitV5Version,
		CircuitHash:          hexOf(identity.circuitHash),
		ParameterFingerprint: hexOf(identity.parameterFingerprint),
		EvaluationKeyDigest:  hexOf(identity.evaluationKeyDigest),
		EvaluationKeyEpoch:   identity.evaluationKeyEpoch,
		SerializationVersion: SerializationVersion,
		ReleaseLayoutVersion: ReleaseLayoutVersion,
		Fingerprint:          hexOf(identity.fingerprint),
	}
}

// RequireSameRuntime refuses a peer whose build is not this build.
//
// The comparison is on the fingerprint, so it covers every constituent at once.
// The error names the first differing constituent, because "runtime mismatch"
// alone is not actionable at three in the morning.
func (identity RuntimeIdentity) RequireSameRuntime(other RuntimeIdentity) error {
	if identity.fingerprint == other.fingerprint {
		return nil
	}
	differences := make([]string, 0, 4)
	if identity.lattigoVersion != other.lattigoVersion {
		differences = append(differences, fmt.Sprintf("lattigo %s vs %s", identity.lattigoVersion, other.lattigoVersion))
	}
	if identity.goVersion != other.goVersion {
		differences = append(differences, fmt.Sprintf("go %s vs %s", identity.goVersion, other.goVersion))
	}
	if identity.goos != other.goos || identity.goarch != other.goarch {
		differences = append(differences, fmt.Sprintf("target %s/%s vs %s/%s",
			identity.goos, identity.goarch, other.goos, other.goarch))
	}
	if identity.circuitHash != other.circuitHash {
		differences = append(differences, "circuit build")
	}
	if identity.parameterFingerprint != other.parameterFingerprint {
		differences = append(differences, "fhe parameters")
	}
	if identity.evaluationKeyDigest != other.evaluationKeyDigest {
		differences = append(differences, "evaluation keys")
	}
	if identity.evaluationKeyEpoch != other.evaluationKeyEpoch {
		differences = append(differences, fmt.Sprintf("key epoch %d vs %d", identity.evaluationKeyEpoch, other.evaluationKeyEpoch))
	}
	if len(differences) == 0 {
		differences = append(differences, "serialization or release layout")
	}
	return fmt.Errorf("%w: %s", ErrRuntimeMismatch, strings.Join(differences, ", "))
}

// RequireApproved refuses a runtime that is not the one the deployment approved.
// A coordinator's claim about which runtime is in use is never consulted; this
// compares the operator's own locally derived fingerprint against a value the
// deployment pinned out of band.
func (identity RuntimeIdentity) RequireApproved(approved [32]byte) error {
	if identity.fingerprint != approved {
		return fmt.Errorf("%w: local %x is not the approved %x", ErrRuntimeMismatch, identity.fingerprint, approved)
	}
	return nil
}

// EvaluationKeyDigest commits to the public evaluation key material, ordered by
// Galois element so the digest is independent of loading order. Gate 1 measured
// that loading order does not change the recomputed output; this makes it not
// change the fingerprint either.
func EvaluationKeyDigest(
	publicKey *rlwe.PublicKey,
	relinearizationKey *rlwe.RelinearizationKey,
	galoisKeys []*rlwe.GaloisKey,
) ([32]byte, error) {
	var digest [32]byte
	if publicKey == nil || relinearizationKey == nil {
		return digest, ErrCeremonyMaterial
	}
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte("mordant.evaluation-key-digest/1"))
	for _, item := range []interface{ MarshalBinary() ([]byte, error) }{publicKey, relinearizationKey} {
		encoded, err := item.MarshalBinary()
		if err != nil {
			return digest, err
		}
		if err := writeLengthPrefixed(hash, encoded); err != nil {
			return digest, err
		}
	}
	sorted := append([]*rlwe.GaloisKey(nil), galoisKeys...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].GaloisElement < sorted[j].GaloisElement })
	for _, key := range sorted {
		encoded, err := key.MarshalBinary()
		if err != nil {
			return digest, err
		}
		if err := writeLengthPrefixed(hash, encoded); err != nil {
			return digest, err
		}
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

// CircuitHashV5 identifies the compiled circuit.
//
// It commits to the circuit's structural description rather than to its source
// text, so a comment change does not invalidate every operator, while any
// change to the gate sequence, the slot layout or the released outputs does.
func CircuitHashV5() [32]byte {
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte("mordant.circuit-v5-structure/1"))
	_, _ = hash.Write(uint32Word(CircuitV5Version))
	// The layout constants the circuit reads.
	for _, value := range []uint32{fromStart, untilStart, exclusiveSlot, uint64Bits, obligationBits, policyDepth} {
		_, _ = hash.Write(uint32Word(value))
	}
	// The ordered gate sequence, as the circuit executes it. Any reordering,
	// insertion or removal changes this value.
	for _, gate := range circuitV5GateSequence {
		_ = writeLengthPrefixed(hash, []byte(gate))
	}
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

// circuitV5GateSequence mirrors RecomputeCircuitV5 exactly. It is asserted
// against the implementation by TestCircuitHashTracksTheGateSequence, so it
// cannot drift silently.
var circuitV5GateSequence = []string{
	"comparisonLayout(policyA,policyB)",
	"compareTwoBlocks(left,right)",
	"keepSlots(less,{0})",
	"rotateColumns(less,64)",
	"keepSlots(rotated,{0})",
	"mulBoolean(aFromBeforeBUntil,bFromBeforeAUntil)",
	"mulBoolean(policyA,policyB)",
	"keepSlots(flagsProduct,{exclusiveSlot})",
	"rotateColumns(flagsProduct,exclusiveSlot)",
	"keepSlots(allFlags,{0})",
	"equal256(currencyA,currencyB)",
	"equal256(receivableA,receivableB)",
	"mulBoolean(overlap,allFlags)",
	"mulBoolean(currencyEqual,identityEqual)",
	"mulBoolean(overlapAndFlags,currencyAndIdentity)",
	"release(sameEconomicAsset=identityEqual,policyConflict=conflict)",
}

// ReleaseLayoutVersion is the layout of the released plaintext vector: slot 0
// carries the Boolean and every other slot is zero. It matches
// MordantResultCoreV5.RELEASE_LAYOUT_VERSION.
const ReleaseLayoutVersion uint16 = 1

// pinnedModuleVersion reads a dependency's version from the embedded build
// info, which is what a deployed operator binary carries.
//
// A binary built without module information cannot state what it is, so it is
// refused rather than defaulted. The one exception is a `go test` binary, which
// the toolchain builds with an empty dependency list; there the compile-time pin
// is used, and it is asserted against go.mod by a test.
func pinnedModuleVersion(path string) (string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", fmt.Errorf("%w: no embedded build info", ErrRuntimeUnpinned)
	}
	for _, dependency := range info.Deps {
		if dependency.Path != path {
			continue
		}
		// A replaced module is a different module.
		if dependency.Replace != nil {
			return "", fmt.Errorf("%w: %s is replaced by %s", ErrRuntimeUnpinned, path, dependency.Replace.Path)
		}
		if dependency.Version == "" || dependency.Version == "(devel)" {
			return "", fmt.Errorf("%w: %s has no pinned version", ErrRuntimeUnpinned, path)
		}
		// Build info is authoritative, and it must agree with the version this
		// build was compiled to expect. Disagreement means the binary was linked
		// against something other than what its source pins.
		if path == LattigoModulePath && dependency.Version != lattigoPinnedVersion {
			return "", fmt.Errorf("%w: linked against %s but source pins %s",
				ErrRuntimeMismatch, dependency.Version, lattigoPinnedVersion)
		}
		return dependency.Version, nil
	}
	if len(info.Deps) == 0 && path == LattigoModulePath {
		return lattigoPinnedVersion, nil
	}
	return "", fmt.Errorf("%w: %s is not in the build info", ErrRuntimeUnpinned, path)
}

func hexOf(value [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for index, b := range value {
		out[index*2] = digits[b>>4]
		out[index*2+1] = digits[b&0x0f]
	}
	return string(out)
}
