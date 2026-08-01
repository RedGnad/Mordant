package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/internal/synthetic"
)

const benchmarkRuns = 5

type report struct {
	SchemaVersion  string       `json:"schemaVersion"`
	Provider       string       `json:"provider"`
	Scheme         string       `json:"scheme"`
	GoVersion      string       `json:"goVersion"`
	GOOS           string       `json:"goos"`
	GOARCH         string       `json:"goarch"`
	LogicalCPU     int          `json:"logicalCpu"`
	GPUPath        string       `json:"gpuPath"`
	ClientBoundary string       `json:"clientBoundary"`
	Setup          setupReport  `json:"setup"`
	Modes          []modeReport `json:"modes"`
}

type setupReport struct {
	ThresholdSetupMilliseconds       float64 `json:"thresholdSetupMilliseconds"`
	CollectivePublicKeyMilliseconds  float64 `json:"collectivePublicKeyMilliseconds"`
	RelinearizationKeyMilliseconds   float64 `json:"relinearizationKeyMilliseconds"`
	GaloisKeysMilliseconds           float64 `json:"galoisKeysMilliseconds"`
	TotalMilliseconds                float64 `json:"totalMilliseconds"`
	PublicKeyBytes                   int     `json:"publicKeyBytes"`
	EvaluationKeyBytes               int     `json:"evaluationKeyBytes"`
	ThresholdShareBytesPerParty      int     `json:"thresholdShareBytesPerParty"`
	ThresholdShareBytesAllParties    int     `json:"thresholdShareBytesAllParties"`
	FullFHEIdentityKeyDeltaBytes     int     `json:"fullFheIdentityKeyDeltaBytes"`
	PublicKeyMarshalMilliseconds     float64 `json:"publicKeyMarshalMilliseconds"`
	EvaluationKeyMarshalMilliseconds float64 `json:"evaluationKeyMarshalMilliseconds"`
}

type modeReport struct {
	IdentityMode            fhe.IdentityMode `json:"identityMode"`
	WarmupRuns              int              `json:"warmupRuns"`
	Runs                    int              `json:"runs"`
	AllDecisionsConfirmed   bool             `json:"allDecisionsConfirmed"`
	PledgeABytes            sizeStats        `json:"pledgeABytes"`
	PledgeBBytes            sizeStats        `json:"pledgeBBytes"`
	IdentityCiphertextBytes sizeStats        `json:"identityCiphertextBytes"`
	DecisionCiphertextBytes sizeStats        `json:"decisionCiphertextBytes"`
	FHEEnvelopeBytes        sizeStats        `json:"fheEnvelopeBytes"`
	LatencyMilliseconds     map[string]stats `json:"latencyMilliseconds"`
	Memory                  memoryReport     `json:"memory"`
}

type stats struct {
	Mean   float64 `json:"mean"`
	Median float64 `json:"median"`
	P95    float64 `json:"p95"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
}

type sizeStats struct {
	Min  int     `json:"min"`
	Max  int     `json:"max"`
	Mean float64 `json:"mean"`
}

type memoryReport struct {
	HeapAllocBeforeBytes uint64 `json:"heapAllocBeforeBytes"`
	HeapAllocAfterBytes  uint64 `json:"heapAllocAfterBytes"`
	PeakHeapAllocBytes   uint64 `json:"peakHeapAllocBytes"`
	TotalAllocDeltaBytes uint64 `json:"totalAllocDeltaBytes"`
	SystemBytesAfter     uint64 `json:"systemBytesAfter"`
}

type runSample struct {
	latency          map[string]float64
	pledgeABytes     int
	pledgeBBytes     int
	identityBytes    int
	decisionBytes    int
	fheEnvelopeBytes int
	confirmed        bool
}

func main() {
	if err := run(); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(map[string]any{
			"schemaVersion": "mordant.lattigo-benchmark-error/1",
			"success":       false,
			"errorCode":     "BENCHMARK_FAILED",
		})
		os.Exit(1)
	}
}

func run() error {
	runtime.GC()
	fheRuntime, setup, err := fhe.NewRuntime()
	if err != nil {
		return err
	}
	modes := make([]modeReport, 0, 2)
	for _, mode := range []fhe.IdentityMode{fhe.IdentityPublicCommitment, fhe.IdentityFullFHE256} {
		measured, err := measureMode(fheRuntime, mode)
		if err != nil {
			return err
		}
		modes = append(modes, measured)
	}
	out := report{
		SchemaVersion:  "mordant.lattigo-benchmark/1",
		Provider:       "github.com/tuneinsight/lattigo/v6@v6.2.0",
		Scheme:         "scale-invariant BGV/BFV exact integer",
		GoVersion:      runtime.Version(),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		LogicalCPU:     runtime.NumCPU(),
		GPUPath:        "not-used",
		ClientBoundary: "co-located-authenticated-gateway-simulation",
		Setup: setupReport{
			ThresholdSetupMilliseconds:       ms(setup.ThresholdSetup),
			CollectivePublicKeyMilliseconds:  ms(setup.CollectivePublicKey),
			RelinearizationKeyMilliseconds:   ms(setup.RelinearizationKey),
			GaloisKeysMilliseconds:           ms(setup.GaloisKeys),
			TotalMilliseconds:                ms(setup.Total),
			PublicKeyBytes:                   setup.PublicKeyBytes,
			EvaluationKeyBytes:               setup.EvaluationKeyBytes,
			ThresholdShareBytesPerParty:      setup.ThresholdShareBytes,
			ThresholdShareBytesAllParties:    setup.ThresholdShareBytes * 3,
			FullFHEIdentityKeyDeltaBytes:     setup.FullFHEIdentityKeyDeltaBytes,
			PublicKeyMarshalMilliseconds:     ms(setup.PublicKeyMarshal),
			EvaluationKeyMarshalMilliseconds: ms(setup.EvaluationKeyMarshal),
		},
		Modes: modes,
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func measureMode(fheRuntime *fhe.Runtime, mode fhe.IdentityMode) (modeReport, error) {
	// One full unmeasured run primes Go code/data paths before the five samples.
	if _, err := measureRun(fheRuntime, mode, 10_000); err != nil {
		return modeReport{}, err
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	stop, done, peak := startMemorySampler(before.HeapAlloc)
	samples := make([]runSample, 0, benchmarkRuns)
	for i := 0; i < benchmarkRuns; i++ {
		sample, err := measureRun(fheRuntime, mode, i)
		if err != nil {
			close(stop)
			<-done
			return modeReport{}, err
		}
		samples = append(samples, sample)
	}
	close(stop)
	<-done
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	peakValue := <-peak
	if after.HeapAlloc > peakValue {
		peakValue = after.HeapAlloc
	}

	latencies := make(map[string][]float64)
	var pledgeA, pledgeB, identity, decision, envelopes []int
	allConfirmed := true
	for _, sample := range samples {
		for name, value := range sample.latency {
			latencies[name] = append(latencies[name], value)
		}
		pledgeA = append(pledgeA, sample.pledgeABytes)
		pledgeB = append(pledgeB, sample.pledgeBBytes)
		identity = append(identity, sample.identityBytes)
		decision = append(decision, sample.decisionBytes)
		envelopes = append(envelopes, sample.fheEnvelopeBytes)
		allConfirmed = allConfirmed && sample.confirmed
	}
	aggregated := make(map[string]stats, len(latencies))
	for name, values := range latencies {
		aggregated[name] = summarize(values)
	}
	return modeReport{
		IdentityMode:            mode,
		WarmupRuns:              1,
		Runs:                    len(samples),
		AllDecisionsConfirmed:   allConfirmed,
		PledgeABytes:            summarizeSizes(pledgeA),
		PledgeBBytes:            summarizeSizes(pledgeB),
		IdentityCiphertextBytes: summarizeSizes(identity),
		DecisionCiphertextBytes: summarizeSizes(decision),
		FHEEnvelopeBytes:        summarizeSizes(envelopes),
		LatencyMilliseconds:     aggregated,
		Memory: memoryReport{
			HeapAllocBeforeBytes: before.HeapAlloc,
			HeapAllocAfterBytes:  after.HeapAlloc,
			PeakHeapAllocBytes:   peakValue,
			TotalAllocDeltaBytes: after.TotalAlloc - before.TotalAlloc,
			SystemBytesAfter:     after.Sys,
		},
	}, nil
}

func measureRun(fheRuntime *fhe.Runtime, mode fhe.IdentityMode, index int) (runSample, error) {
	label := fmt.Sprintf("benchmark-%s-%d", mode, index)
	a, b, err := synthetic.Pair(fheRuntime, label, mode)
	if err != nil {
		return runSample{}, err
	}
	if err := synthetic.GrantPair(fheRuntime, a, b); err != nil {
		return runSample{}, err
	}

	latency := make(map[string]float64)
	phase := time.Now()
	encA, encryptedA, err := fheRuntime.EncryptPledgeForMode(a, mode)
	if err != nil {
		return runSample{}, err
	}
	latency["encryptPledgeAEndToEnd"] = ms(time.Since(phase))
	phase = time.Now()
	encB, encryptedB, err := fheRuntime.EncryptPledgeForMode(b, mode)
	if err != nil {
		return runSample{}, err
	}
	latency["encryptPledgeBEndToEnd"] = ms(time.Since(phase))
	latency["encryptPolicyBitsA"] = ms(encryptedA.PolicyBits)
	latency["encryptCurrencyBitsA"] = ms(encryptedA.CurrencyBits)
	latency["encryptAmountBitsA"] = ms(encryptedA.AmountBits)
	latency["encryptObligationBitsA"] = ms(encryptedA.ObligationBits)
	latency["encryptIdentityBitsA"] = ms(encryptedA.ReceivableIdentityBits)
	latency["serializePledgeA"] = ms(encryptedA.Marshal)
	latency["deserializePledgeA"] = ms(encryptedA.Unmarshal)

	phase = time.Now()
	if _, err := fheRuntime.CanonicalInputCommitment(encA, synthetic.InputContext(0, uint64(index*2+101))); err != nil {
		return runSample{}, err
	}
	if _, err := fheRuntime.CanonicalInputCommitment(encB, synthetic.InputContext(1, uint64(index*2+102))); err != nil {
		return runSample{}, err
	}
	latency["canonicalInputCommitmentPair"] = ms(time.Since(phase))

	now := time.Unix(2_000_000_000, 0)
	nonce := sha256.Sum256([]byte(label))
	phase = time.Now()
	decision, evaluated, err := fheRuntime.Evaluate(fhe.EvaluationRequest{
		KeyID:         fheRuntime.KeyID(),
		PolicyVersion: fhe.PolicyVersion,
		Nonce:         nonce,
		ValidUntil:    now.Add(5 * time.Minute),
		IdentityMode:  mode,
		A:             encA,
		B:             encB,
	}, now)
	if err != nil {
		return runSample{}, err
	}
	latency["evaluateEndToEnd"] = ms(time.Since(phase))
	latency["comparisonBatchTwo"] = ms(evaluated.ComparisonBatch)
	latency["comparisonAmortizedOne"] = ms(evaluated.ComparisonAAmortized)
	latency["currencyEquality"] = ms(evaluated.CurrencyEquality)
	latency["identityEquality"] = ms(evaluated.IdentityEquality)
	latency["conditions"] = ms(evaluated.Conditions)
	latency["finalAnd"] = ms(evaluated.FinalAND)

	coalitions := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	coalition := coalitions[index%len(coalitions)]
	phase = time.Now()
	confirmed, decrypted, err := fheRuntime.DecryptThresholdWithCoalition(decision, coalition[0], coalition[1])
	if err != nil {
		return runSample{}, err
	}
	latency["thresholdDecryptEndToEnd"] = ms(time.Since(phase))
	latency["thresholdKeySwitch"] = ms(decrypted.ThresholdKeySwitch)
	latency["receiverDecrypt"] = ms(decrypted.ReceiverDecrypt)
	decisionBytes := decision.Conflict.BinarySize()
	return runSample{
		latency:          latency,
		pledgeABytes:     encryptedA.CiphertextBytes,
		pledgeBBytes:     encryptedB.CiphertextBytes,
		identityBytes:    encryptedA.IdentityCiphertextBytes,
		decisionBytes:    decisionBytes,
		fheEnvelopeBytes: encryptedA.CiphertextBytes + encryptedB.CiphertextBytes + decisionBytes,
		confirmed:        confirmed,
	}, nil
}

func startMemorySampler(initial uint64) (stop chan struct{}, done chan struct{}, peak chan uint64) {
	stop = make(chan struct{})
	done = make(chan struct{})
	peak = make(chan uint64, 1)
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		maximum := initial
		for {
			select {
			case <-ticker.C:
				var sample runtime.MemStats
				runtime.ReadMemStats(&sample)
				if sample.HeapAlloc > maximum {
					maximum = sample.HeapAlloc
				}
			case <-stop:
				peak <- maximum
				return
			}
		}
	}()
	return
}

func summarize(values []float64) stats {
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	var total float64
	for _, value := range ordered {
		total += value
	}
	median := ordered[len(ordered)/2]
	if len(ordered)%2 == 0 {
		median = (ordered[len(ordered)/2-1] + ordered[len(ordered)/2]) / 2
	}
	p95Index := int(math.Ceil(0.95*float64(len(ordered)))) - 1
	return stats{Mean: total / float64(len(ordered)), Median: median, P95: ordered[p95Index], Min: ordered[0], Max: ordered[len(ordered)-1]}
}

func summarizeSizes(values []int) sizeStats {
	minimum, maximum, total := values[0], values[0], 0
	for _, value := range values {
		if value < minimum {
			minimum = value
		}
		if value > maximum {
			maximum = value
		}
		total += value
	}
	return sizeStats{Min: minimum, Max: maximum, Mean: float64(total) / float64(len(values))}
}

func ms(value time.Duration) float64 { return float64(value.Microseconds()) / 1000 }
