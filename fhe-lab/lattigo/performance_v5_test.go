package lattigospike

import (
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// V5 concurrent-operator performance.
//
// The two selected operators recompute the circuit CONCURRENTLY, because that
// is how a release actually runs and it is the configuration where the cost
// lands: two full evaluations of the same circuit on overlapping hardware. A
// sequential measurement would understate peak memory and hide CPU contention
// entirely.
//
// Nothing here weakens verification to improve a number. Where a figure is
// worse than RC1 it is reported as worse.

type operatorMeasurement struct {
	Point            uint64 `json:"point"`
	RecomputeMillis  int64  `json:"recompute_ms"`
	VerifyMillis     int64  `json:"verify_ms"`
	ShareMillis      int64  `json:"share_ms"`
	ChecksRun        int    `json:"checks_run"`
	Accepted         bool   `json:"accepted"`
	OutputDigestHex  string `json:"output_digest"`
	RuntimeMatchedOK bool   `json:"runtime_matched"`
}

type v5Performance struct {
	SchemaVersion string            `json:"schema_version"`
	Runtime       RuntimeDescriptor `json:"runtime"`
	Concurrency   struct {
		OperatorsRunConcurrently int `json:"operators_run_concurrently"`
		GOMAXPROCS               int `json:"gomaxprocs"`
	} `json:"concurrency"`

	EvaluatorMillis      int64  `json:"evaluator_ms"`
	KeyLoadMillis        int64  `json:"key_load_ms"`
	CiphertextTransport  int    `json:"ciphertext_transport_bytes"`
	ThresholdReleaseMs   int64  `json:"threshold_release_ms"`
	EndToEndMillis       int64  `json:"end_to_end_ms"`
	WallClockConcurrentM int64  `json:"concurrent_operator_wall_ms"`
	SumOperatorMillis    int64  `json:"sum_operator_ms"`
	ParallelSpeedup      string `json:"parallel_speedup"`

	HeapAllocPeakMB   uint64                `json:"heap_alloc_peak_mb"`
	SysPeakMB         uint64                `json:"sys_peak_mb"`
	TotalAllocMB      uint64                `json:"total_alloc_mb"`
	Operators         []operatorMeasurement `json:"operators"`
	RefusalMillis     int64                 `json:"refusal_ms"`
	RefusalIsTerminal bool                  `json:"refusal_is_terminal"`
	Notes             []string              `json:"notes"`
}

func TestV5ConcurrentOperatorPerformance(t *testing.T) {
	harness := newV5ReleaseHarness(t, true)
	var report v5Performance
	report.SchemaVersion = "mordant.v5-performance/1"
	report.Concurrency.OperatorsRunConcurrently = 2
	report.Concurrency.GOMAXPROCS = runtime.GOMAXPROCS(0)
	report.Runtime = harness.operators[0].RuntimeIdentity().Describe()

	// Transport: what the coordinator actually ships to each operator.
	transport := 0
	for _, ciphertext := range harness.request.Inputs.ordered() {
		encoded, err := ciphertext.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		transport += len(encoded)
	}
	report.CiphertextTransport = transport

	// Evaluator: one evaluation, the coordinator's proposal.
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	endToEnd := time.Now()
	evaluatorStart := time.Now()
	if _, err := harness.fixture.runtime.RecomputeCircuitV5(harness.inputs); err != nil {
		t.Fatal(err)
	}
	report.EvaluatorMillis = time.Since(evaluatorStart).Milliseconds()

	// Key load, measured as a fresh evaluation-key set construction.
	keyLoad := time.Now()
	publicKey, relinKey, galoisKeys, err := harness.fixture.aggregator.CollectiveKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEvaluationRuntime(harness.fixture.params, publicKey, relinKey, galoisKeys); err != nil {
		t.Fatal(err)
	}
	report.KeyLoadMillis = time.Since(keyLoad).Milliseconds()

	// The two operators, concurrently.
	measurements := make([]operatorMeasurement, 2)
	verdicts := make([]OperatorVerdictV5, 2)
	errs := make([]error, 2)
	concurrentStart := time.Now()
	var group sync.WaitGroup
	for index := 0; index < 2; index++ {
		group.Add(1)
		go func(slot int) {
			defer group.Done()
			operator := harness.operators[slot]
			started := time.Now()
			verdict, err := operator.VerifyAndRecompute(harness.request, harness.now)
			elapsed := time.Since(started)
			verdicts[slot] = verdict
			errs[slot] = err
			measurements[slot] = operatorMeasurement{
				Point:            uint64(slot + 1),
				RecomputeMillis:  verdict.RecomputeDuration.Milliseconds(),
				VerifyMillis:     elapsed.Milliseconds(),
				ChecksRun:        len(verdict.Checks),
				Accepted:         verdict.Accepted,
				OutputDigestHex:  hexOf(verdict.RecomputedOutputsDigest),
				RuntimeMatchedOK: err == nil,
			}
		}(index)
	}
	group.Wait()
	report.WallClockConcurrentM = time.Since(concurrentStart).Milliseconds()

	for slot, err := range errs {
		if err != nil {
			t.Fatalf("operator %d: %v", slot, err)
		}
	}
	// Both operators must have recomputed the same bytes. This is Gate 1
	// enforced inside the protocol rather than only measured by the probe.
	if verdicts[0].RecomputedOutputsDigest != verdicts[1].RecomputedOutputsDigest {
		t.Fatal("concurrent operators recomputed different outputs")
	}

	// Shares, then the threshold release for both bits.
	shareStart := time.Now()
	sameShares := make([]ThresholdReleaseResponse, 0, 2)
	conflictShares := make([]ThresholdReleaseResponse, 0, 2)
	for slot, operator := range harness.operators[:2] {
		same, conflict, err := operator.ReleaseShares(harness.request, verdicts[slot], harness.now)
		if err != nil {
			t.Fatal(err)
		}
		sameShares = append(sameShares, same)
		conflictShares = append(conflictShares, conflict)
		measurements[slot].ShareMillis = time.Since(shareStart).Milliseconds()
	}
	releaseStart := time.Now()
	sameAsset := harness.combine(t, verdicts[0].outputs.SameEconomicAsset, sameShares, 0)
	conflict := harness.combine(t, verdicts[0].outputs.PolicyConflict, conflictShares, 1)
	report.ThresholdReleaseMs = time.Since(releaseStart).Milliseconds()
	report.EndToEndMillis = time.Since(endToEnd).Milliseconds()

	if !sameAsset || !conflict {
		t.Fatalf("expected (true, true), got (%t, %t)", sameAsset, conflict)
	}

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	report.HeapAllocPeakMB = after.HeapAlloc / (1024 * 1024)
	report.SysPeakMB = after.Sys / (1024 * 1024)
	report.TotalAllocMB = (after.TotalAlloc - before.TotalAlloc) / (1024 * 1024)
	report.Operators = measurements
	for _, measurement := range measurements {
		report.SumOperatorMillis += measurement.VerifyMillis
	}
	// Summed operator time over wall-clock time, with two operators. 2.00x is
	// perfect parallelism and 1.00x is full serialization, so a figure near 2
	// means the second operator cost almost no extra wall time and a figure near
	// 1 means the two contended for the same cores.
	if report.WallClockConcurrentM > 0 {
		ratio := float64(report.SumOperatorMillis) / float64(report.WallClockConcurrentM)
		report.ParallelSpeedup = formatRatio(ratio)
	}

	// Refusal and cancellation: a mismatched output must be refused, quickly and
	// terminally, without producing a share.
	refusalStart := time.Now()
	forged := harness.request
	forgedOutputs := CircuitOutputsV5{
		SameEconomicAsset: harness.inputs.ReceivableIDsA,
		PolicyConflict:    harness.inputs.ReceivableIDsA,
	}
	forgedDigest, err := forgedOutputs.Digest()
	if err != nil {
		t.Fatal(err)
	}
	forged.Descriptor.OutputsDigest = forgedDigest
	refusedVerdict, refusalErr := harness.operators[0].VerifyAndRecompute(forged, harness.now)
	report.RefusalMillis = time.Since(refusalStart).Milliseconds()
	if !errors.Is(refusalErr, ErrOperatorRecomputationMismatch) {
		t.Fatalf("expected ErrOperatorRecomputationMismatch, got %v", refusalErr)
	}
	// Terminal means no share can be produced from a refused verdict.
	_, _, shareErr := harness.operators[0].ReleaseShares(forged, refusedVerdict, harness.now)
	report.RefusalIsTerminal = errors.Is(shareErr, ErrOperatorCheckFailed)
	if !report.RefusalIsTerminal {
		t.Fatalf("a refused verdict still produced shares: %v", shareErr)
	}

	report.Notes = []string{
		"The two operator recomputations run concurrently, which is how a release runs and where the cost lands.",
		"Refusal costs a full recomputation by construction: the operator cannot know the output differs until it has computed it.",
		"Peak memory is process-wide and covers the evaluator plus both operators in one address space; three separate hosts would each carry roughly the single-operator figure.",
		"parallel_speedup is summed operator time over wall-clock time with two operators: 2.00x is perfect parallelism, 1.00x is full serialization.",
		"No verification was weakened to improve any figure here.",
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("../../docs/evidence/private-matching-v5", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../../docs/evidence/private-matching-v5/performance.json", append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("evaluator %dms | concurrent operators %dms (sum %dms, speedup %s of 2.00x) | release %dms | end-to-end %dms",
		report.EvaluatorMillis, report.WallClockConcurrentM, report.SumOperatorMillis,
		report.ParallelSpeedup, report.ThresholdReleaseMs, report.EndToEndMillis)
	t.Logf("transport %d bytes | sys peak %d MB | refusal %dms terminal=%t",
		report.CiphertextTransport, report.SysPeakMB, report.RefusalMillis, report.RefusalIsTerminal)
}

func formatRatio(value float64) string {
	whole := int(value)
	hundredths := int((value - float64(whole)) * 100)
	if hundredths < 0 {
		hundredths = -hundredths
	}
	return itoa(whole) + "." + pad2(hundredths) + "x"
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}

func pad2(value int) string {
	if value < 10 {
		return "0" + itoa(value)
	}
	return itoa(value)
}
