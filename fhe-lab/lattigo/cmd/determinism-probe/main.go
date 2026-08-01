// Command determinism-probe answers exactly one question, empirically:
//
//	does RecomputeCircuitV5 produce a byte-identical ciphertext when the same
//	inputs and the same evaluation keys are loaded by a different process?
//
// The owner's Gate 1 for external audit finding H-03 forbids assuming that
// Lattigo evaluation is byte-deterministic, and forbids recovering agreement
// with a tolerant ciphertext comparison. Operator-side recomputation is only a
// real check if operators can compare exact bytes, so this must be measured
// before any of the release protocol is designed around it.
//
//	setup    runs one ceremony and freezes parameters, evaluation keys and six
//	         input ciphertexts to a directory.
//	evaluate loads that directory in a fresh process and prints the digests of
//	         the recomputed outputs.
//
// The driver runs `evaluate` many times, across process restarts, key loading
// orders, thread counts and architectures, and compares the digests exactly.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"

	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/internal/synthetic"
)

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: determinism-probe <setup|evaluate> [flags]"))
	}
	var err error
	switch os.Args[1] {
	case "setup":
		err = runSetup(os.Args[2:])
	case "evaluate":
		err = runEvaluate(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "determinism-probe: %v\n", err)
	os.Exit(1)
}

func probeParameters() (bgv.Parameters, error) {
	// The production V4/V5 parameter set. Determinism must be established for
	// the parameters the product actually uses, not a convenient small one.
	return bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP:             []int{60, 60, 60},
		PlaintextModulus: 65537,
	})
}

/* ------------------------------------------------------------------ setup */

func runSetup(args []string) error {
	flags := flag.NewFlagSet("setup", flag.ExitOnError)
	dir := flags.String("dir", "", "directory to write frozen probe material into")
	conflicting := flags.Bool("conflicting", true, "generate a pair that collides on identity and policy")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("-dir is required")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}

	params, err := probeParameters()
	if err != nil {
		return fmt.Errorf("parameters: %w", err)
	}
	publicKey, relinKey, galoisKeys, err := runCeremony(params)
	if err != nil {
		return fmt.Errorf("ceremony: %w", err)
	}
	runtimeInstance, err := fhe.NewEvaluationRuntime(params, publicKey, relinKey, galoisKeys)
	if err != nil {
		return fmt.Errorf("evaluation runtime: %w", err)
	}

	label := "determinism-probe"
	if !*conflicting {
		label = "determinism-probe-distinct"
	}
	pledgeA, pledgeB, err := synthetic.Pair(runtimeInstance, label, fhe.IdentityFullFHE256)
	if err != nil {
		return fmt.Errorf("synthetic pair: %w", err)
	}
	if !*conflicting {
		// Force a different receivable so the probe can also be run on the
		// negative branch of the circuit.
		pledgeB.ReceivableID = sha256.Sum256([]byte("determinism-probe-distinct-receivable"))
	}
	cipherA, _, err := runtimeInstance.EncryptPledgeForMode(pledgeA, fhe.IdentityFullFHE256)
	if err != nil {
		return fmt.Errorf("encrypt A: %w", err)
	}
	cipherB, _, err := runtimeInstance.EncryptPledgeForMode(pledgeB, fhe.IdentityFullFHE256)
	if err != nil {
		return fmt.Errorf("encrypt B: %w", err)
	}

	if err := writeBinary(filepath.Join(*dir, "params.bin"), params); err != nil {
		return err
	}
	if err := writeBinary(filepath.Join(*dir, "public-key.bin"), publicKey); err != nil {
		return err
	}
	if err := writeBinary(filepath.Join(*dir, "relin-key.bin"), relinKey); err != nil {
		return err
	}
	for index, key := range galoisKeys {
		name := fmt.Sprintf("galois-%02d-%d.bin", index, key.GaloisElement)
		if err := writeBinary(filepath.Join(*dir, name), key); err != nil {
			return err
		}
	}
	inputs := map[string]*rlwe.Ciphertext{
		"input-a-policy.bin":     cipherA.PolicyBits,
		"input-b-policy.bin":     cipherB.PolicyBits,
		"input-a-currency.bin":   cipherA.CurrencyBits,
		"input-b-currency.bin":   cipherB.CurrencyBits,
		"input-a-receivable.bin": cipherA.ReceivableIDBits,
		"input-b-receivable.bin": cipherB.ReceivableIDBits,
	}
	for name, ciphertext := range inputs {
		if err := writeBinary(filepath.Join(*dir, name), ciphertext); err != nil {
			return err
		}
	}

	// The plaintext pledges never leave this process. Only ciphertexts and
	// public keys are written.
	fmt.Printf("frozen probe material written to %s\n", *dir)
	return nil
}

func runCeremony(params bgv.Parameters) (*rlwe.PublicKey, *rlwe.RelinearizationKey, []*rlwe.GaloisKey, error) {
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, nil, nil, err
	}
	var ceremonyID [32]byte
	if _, err := rand.Read(ceremonyID[:]); err != nil {
		return nil, nil, nil, err
	}

	const operatorCount = 3
	signingKeys := make([]ed25519.PrivateKey, operatorCount)
	identities := make([]fhe.CeremonyOperatorIdentity, operatorCount)
	for index := range signingKeys {
		_, secret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		signingKeys[index] = secret
		identities[index] = fhe.CeremonyOperatorIdentity{Point: uint64(index + 1)}
		copy(identities[index].SigningPublicKey[:], secret.Public().(ed25519.PublicKey))
	}
	roster := fhe.CeremonyRoster{
		ParameterFingerprint: sha256.Sum256(parameterBytes),
		Threshold:            2,
		CeremonyID:           ceremonyID,
		KeyEpoch:             1,
		Operators:            identities,
	}

	operators := make([]*fhe.CeremonyOperatorState, operatorCount)
	for index := range operators {
		state, err := fhe.NewCeremonyOperatorState(params, roster, uint64(index+1), signingKeys[index])
		if err != nil {
			return nil, nil, nil, err
		}
		operators[index] = state
	}
	aggregator, err := fhe.NewCeremonyAggregator(params, roster)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, source := range operators {
		for _, target := range operators {
			if err := target.AcceptCRSContribution(source.Point(), source.CRSContribution()); err != nil {
				return nil, nil, nil, err
			}
		}
		if err := aggregator.AcceptCRSContribution(source.Point(), source.CRSContribution()); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, operator := range operators {
		if err := operator.SealCRS(); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := aggregator.SealCRS(); err != nil {
		return nil, nil, nil, err
	}
	for _, source := range operators {
		for _, target := range operators {
			share, err := source.PrivateShareFor(target.Point())
			if err != nil {
				return nil, nil, nil, err
			}
			if err := target.AcceptPrivateShare(share); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	for _, operator := range operators {
		if err := operator.SealThresholdShare(); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, operator := range operators {
		wire, err := operator.PublicKeyShare()
		if err != nil {
			return nil, nil, nil, err
		}
		if err := aggregator.AcceptPublicKeyShare(operator.Point(), wire); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, operator := range operators {
		wire, err := operator.RelinearizationShareRoundOne()
		if err != nil {
			return nil, nil, nil, err
		}
		if err := aggregator.AcceptRelinearizationShareRoundOne(operator.Point(), wire); err != nil {
			return nil, nil, nil, err
		}
	}
	combined, err := aggregator.AggregatedRelinearizationRoundOne()
	if err != nil {
		return nil, nil, nil, err
	}
	for _, operator := range operators {
		wire, err := operator.RelinearizationShareRoundTwo(combined)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := aggregator.AcceptRelinearizationShareRoundTwo(operator.Point(), wire); err != nil {
			return nil, nil, nil, err
		}
	}
	for {
		element, pending := aggregator.CurrentGaloisElement()
		if !pending {
			break
		}
		for _, operator := range operators {
			wire, err := operator.GaloisShare(element)
			if err != nil {
				return nil, nil, nil, err
			}
			if err := aggregator.AcceptGaloisShare(operator.Point(), wire); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	if !aggregator.Complete() {
		return nil, nil, nil, fmt.Errorf("ceremony did not complete")
	}
	return aggregator.CollectiveKeys()
}

/* --------------------------------------------------------------- evaluate */

type probeReport struct {
	Mode                string `json:"mode"`
	GOOS                string `json:"goos"`
	GOARCH              string `json:"goarch"`
	GoVersion           string `json:"go_version"`
	GOMAXPROCS          int    `json:"gomaxprocs"`
	GaloisOrder         string `json:"galois_order"`
	PID                 int    `json:"pid"`
	InputDigest         string `json:"input_digest"`
	OutputDigest        string `json:"output_digest"`
	SameAssetDigest     string `json:"same_economic_asset_digest"`
	ConflictDigest      string `json:"policy_conflict_digest"`
	KeyDigest           string `json:"evaluation_key_digest"`
	RecomputeMillis     int64  `json:"recompute_ms"`
	KeyLoadMillis       int64  `json:"key_load_ms"`
	TotalAllocMegabytes uint64 `json:"total_alloc_mb"`
	SysMegabytes        uint64 `json:"sys_mb"`
}

func runEvaluate(args []string) error {
	flags := flag.NewFlagSet("evaluate", flag.ExitOnError)
	dir := flags.String("dir", "", "directory holding frozen probe material")
	order := flags.String("galois-order", "natural", "natural | reverse | element-sorted")
	repeat := flags.Int("repeat", 1, "recompute this many times in-process and compare")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("-dir is required")
	}

	keyLoadStart := time.Now()
	params, err := probeParameters()
	if err != nil {
		return err
	}
	publicKey := rlwe.NewPublicKey(params)
	if err := readBinary(filepath.Join(*dir, "public-key.bin"), publicKey); err != nil {
		return err
	}
	relinKey := rlwe.NewRelinearizationKey(params)
	if err := readBinary(filepath.Join(*dir, "relin-key.bin"), relinKey); err != nil {
		return err
	}
	galoisKeys, err := loadGaloisKeys(*dir, params, *order)
	if err != nil {
		return err
	}
	keyLoad := time.Since(keyLoadStart)

	runtimeInstance, err := fhe.NewEvaluationRuntime(params, publicKey, relinKey, galoisKeys)
	if err != nil {
		return fmt.Errorf("evaluation runtime: %w", err)
	}

	inputs := fhe.CircuitInputsV5{}
	targets := []struct {
		name string
		dst  **rlwe.Ciphertext
	}{
		{"input-a-policy.bin", &inputs.PolicyBitsA},
		{"input-b-policy.bin", &inputs.PolicyBitsB},
		{"input-a-currency.bin", &inputs.CurrencyBitsA},
		{"input-b-currency.bin", &inputs.CurrencyBitsB},
		{"input-a-receivable.bin", &inputs.ReceivableIDsA},
		{"input-b-receivable.bin", &inputs.ReceivableIDsB},
	}
	for _, target := range targets {
		ciphertext := rlwe.NewCiphertext(params, 1, params.MaxLevel())
		if err := readBinary(filepath.Join(*dir, target.name), ciphertext); err != nil {
			return err
		}
		*target.dst = ciphertext
	}

	inputDigest, err := inputs.Digest()
	if err != nil {
		return err
	}

	var first [32]byte
	var outputs *fhe.CircuitOutputsV5
	recomputeStart := time.Now()
	for attempt := 0; attempt < *repeat; attempt++ {
		outputs, err = runtimeInstance.RecomputeCircuitV5(inputs)
		if err != nil {
			return fmt.Errorf("recompute: %w", err)
		}
		digest, err := outputs.Digest()
		if err != nil {
			return err
		}
		if attempt == 0 {
			first = digest
			continue
		}
		// In-process repetition. Exact bytes, never a distance.
		if digest != first {
			return fmt.Errorf(
				"NON-DETERMINISTIC in-process: attempt %d digest %x differs from attempt 0 digest %x",
				attempt, digest, first)
		}
	}
	recompute := time.Since(recomputeStart) / time.Duration(*repeat)

	sameDigest, err := marshalDigest(outputs.SameEconomicAsset)
	if err != nil {
		return err
	}
	conflictDigest, err := marshalDigest(outputs.PolicyConflict)
	if err != nil {
		return err
	}
	keyDigest, err := evaluationKeyDigest(publicKey, relinKey, galoisKeys)
	if err != nil {
		return err
	}

	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	report := probeReport{
		Mode:                "evaluate",
		GOOS:                runtime.GOOS,
		GOARCH:              runtime.GOARCH,
		GoVersion:           runtime.Version(),
		GOMAXPROCS:          runtime.GOMAXPROCS(0),
		GaloisOrder:         *order,
		PID:                 os.Getpid(),
		InputDigest:         hex.EncodeToString(inputDigest[:]),
		OutputDigest:        hex.EncodeToString(first[:]),
		SameAssetDigest:     hex.EncodeToString(sameDigest[:]),
		ConflictDigest:      hex.EncodeToString(conflictDigest[:]),
		KeyDigest:           hex.EncodeToString(keyDigest[:]),
		RecomputeMillis:     recompute.Milliseconds(),
		KeyLoadMillis:       keyLoad.Milliseconds(),
		TotalAllocMegabytes: stats.TotalAlloc / (1024 * 1024),
		SysMegabytes:        stats.Sys / (1024 * 1024),
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	debug.FreeOSMemory()
	return nil
}

// loadGaloisKeys deliberately supports several loading orders. The evaluation
// key set is a map keyed by Galois element, so order *should* be irrelevant.
// Gate 1 requires that to be measured rather than assumed.
func loadGaloisKeys(dir string, params bgv.Parameters, order string) ([]*rlwe.GaloisKey, error) {
	entries, err := filepath.Glob(filepath.Join(dir, "galois-*.bin"))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no galois keys in %s", dir)
	}
	sort.Strings(entries)
	switch order {
	case "natural":
	case "reverse":
		for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
			entries[i], entries[j] = entries[j], entries[i]
		}
	case "element-sorted":
		sort.Slice(entries, func(i, j int) bool {
			return galoisElementOf(entries[i]) < galoisElementOf(entries[j])
		})
	default:
		return nil, fmt.Errorf("unknown galois order %q", order)
	}
	keys := make([]*rlwe.GaloisKey, 0, len(entries))
	for _, entry := range entries {
		key := rlwe.NewGaloisKey(params)
		if err := readBinary(entry, key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func galoisElementOf(path string) uint64 {
	var index int
	var element uint64
	if _, err := fmt.Sscanf(filepath.Base(path), "galois-%02d-%d.bin", &index, &element); err != nil {
		return 0
	}
	return element
}

func evaluationKeyDigest(publicKey *rlwe.PublicKey, relinKey *rlwe.RelinearizationKey, galoisKeys []*rlwe.GaloisKey) ([32]byte, error) {
	var digest [32]byte
	hash := sha256.New()
	for _, item := range append([]encoding.BinaryMarshaler{publicKey, relinKey}, galoisMarshalers(galoisKeys)...) {
		encoded, err := item.MarshalBinary()
		if err != nil {
			return digest, err
		}
		_, _ = hash.Write(encoded)
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func galoisMarshalers(keys []*rlwe.GaloisKey) []encoding.BinaryMarshaler {
	// Sorted by Galois element so the digest is independent of loading order,
	// which is exactly the variable the probe is testing.
	sorted := append([]*rlwe.GaloisKey(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].GaloisElement < sorted[j].GaloisElement })
	out := make([]encoding.BinaryMarshaler, 0, len(sorted))
	for _, key := range sorted {
		out = append(out, key)
	}
	return out
}

func marshalDigest(ciphertext *rlwe.Ciphertext) ([32]byte, error) {
	var digest [32]byte
	encoded, err := ciphertext.MarshalBinary()
	if err != nil {
		return digest, err
	}
	return sha256.Sum256(encoded), nil
}

/* ------------------------------------------------------------------- io */

func writeBinary(path string, value encoding.BinaryMarshaler) error {
	encoded, err := value.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal %s: %w", filepath.Base(path), err)
	}
	return os.WriteFile(path, encoded, 0o600)
}

func readBinary(path string, value encoding.BinaryUnmarshaler) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := value.UnmarshalBinary(encoded); err != nil {
		return fmt.Errorf("unmarshal %s: %w", filepath.Base(path), err)
	}
	return nil
}
