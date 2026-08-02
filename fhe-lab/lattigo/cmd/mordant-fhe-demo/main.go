// Command mordant-fhe-demo runs the deterministic local vertical slice. The
// evaluator and decryptor are mandatory separate subprocesses; plaintext test
// fixtures remain only in this orchestrator's memory.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

type processEvaluation struct {
	ArtifactDigest governedfhe.Digest `json:"artifactDigest"`
	DurationNanos  int64              `json:"durationNanos"`
	ResultBytes    int64              `json:"resultBytes"`
	ArtifactBytes  int64              `json:"artifactBytes"`
}

type processRelease struct {
	ResultDigest  governedfhe.Digest              `json:"resultDigest"`
	Conflict      bool                            `json:"conflict"`
	ReleaseMode   string                          `json:"releaseMode"`
	DurationNanos int64                           `json:"durationNanos"`
	ResultBytes   int64                           `json:"resultBytes"`
	ExactRetry    bool                            `json:"exactRetry"`
	TrustedPins   governedfhe.TrustedRecoursePins `json:"trustedRecoursePins"`
}

type scenarioSummary struct {
	Name              string                     `json:"name"`
	Conflict          bool                       `json:"conflict"`
	RecourseActivated bool                       `json:"recourseActivated"`
	Evidence          governedfhe.PublicEvidence `json:"evidence"`
}

func main() {
	workRoot := flag.String("work-root", "", "new absolute smoke output root")
	evaluatorPath := flag.String("evaluator", "", "mordant-fhe-evaluator executable")
	decryptorPath := flag.String("decryptor", "", "mordant-fhe-decryptor executable")
	flag.Parse()
	if !filepath.IsAbs(*workRoot) || !filepath.IsAbs(*evaluatorPath) || !filepath.IsAbs(*decryptorPath) {
		fail(fmt.Errorf("all paths must be absolute"))
	}
	if err := os.Mkdir(*workRoot, 0o700); err != nil {
		fail(fmt.Errorf("work root must be new: %w", err))
	}
	conflict, err := runScenario(*workRoot, "conflict", true, *evaluatorPath, *decryptorPath)
	if err != nil {
		fail(err)
	}
	noConflict, err := runScenario(*workRoot, "no-conflict", false, *evaluatorPath, *decryptorPath)
	if err != nil {
		fail(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		SchemaVersion string          `json:"schemaVersion"`
		Conflict      scenarioSummary `json:"conflict"`
		NoConflict    scenarioSummary `json:"noConflict"`
		ProductClaim  string          `json:"productClaim"`
	}{"mordant.governed-fhe-smoke/1", conflict, noConflict, governedfhe.ProductClaim}); err != nil {
		fail(err)
	}
}

func runScenario(workRoot, name string, conflicting bool, evaluatorPath, decryptorPath string) (scenarioSummary, error) {
	started := time.Now()
	root := filepath.Join(workRoot, name)
	publicRoot := filepath.Join(root, "public")
	privateRoot := filepath.Join(root, "decryptor-private")
	participantRoot := filepath.Join(root, "participant-private")
	if err := os.MkdirAll(participantRoot, 0o700); err != nil {
		return scenarioSummary{}, err
	}
	publicA, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return scenarioSummary{}, err
	}
	publicB, privateB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return scenarioSummary{}, err
	}
	if err := writePrivate(filepath.Join(participantRoot, "participant-a.ed25519"), privateA); err != nil {
		return scenarioSummary{}, err
	}
	if err := writePrivate(filepath.Join(participantRoot, "participant-b.ed25519"), privateB); err != nil {
		return scenarioSummary{}, err
	}
	now := time.Now().UTC()
	identityA := governedfhe.ParticipantIdentity{ID: digestLabel(name + "/participant-a"), Role: governedfhe.RoleA, SigningPublicKey: publicA}
	identityB := governedfhe.ParticipantIdentity{ID: digestLabel(name + "/participant-b"), Role: governedfhe.RoleB, SigningPublicKey: publicB}
	provenance, err := governedfhe.ExecutableDigest()
	if err != nil {
		return scenarioSummary{}, err
	}
	spec := governedfhe.CaseSpec{
		CaseID: digestLabel(name + "/case"), AssetIdentity: digestLabel(name + "/asset"), PolicyID: digestLabel("conflicting-pledge-policy/v1"),
		ParticipantA: identityA, ParticipantB: identityB, CaseNonce: digestLabel(name + "/case-nonce"),
		CreatedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(2 * time.Hour).Unix(),
	}
	_, keyReport, err := governedfhe.CreateCase(governedfhe.CreateCaseOptions{
		PublicRoot: publicRoot, PrivateRoot: privateRoot, Spec: spec, SourceProvenance: provenance,
	})
	if err != nil {
		return scenarioSummary{}, fmt.Errorf("%s keygen: %w", name, err)
	}
	pledgeA, pledgeB := fixturePair(name, conflicting)
	artifactA, reportA, err := governedfhe.SubmitParticipant(governedfhe.ParticipantSubmissionOptions{
		PublicRoot: publicRoot, Role: governedfhe.RoleA, SigningKey: privateA, Pledge: pledgeA,
		SubmissionNonce: digestLabel(name + "/submission-a"), ExpiresAtUnix: now.Add(time.Hour).Unix(), Now: now,
	})
	if err != nil {
		return scenarioSummary{}, fmt.Errorf("%s participant A: %w", name, err)
	}
	artifactB, reportB, err := governedfhe.SubmitParticipant(governedfhe.ParticipantSubmissionOptions{
		PublicRoot: publicRoot, Role: governedfhe.RoleB, SigningKey: privateB, Pledge: pledgeB,
		SubmissionNonce: digestLabel(name + "/submission-b"), ExpiresAtUnix: now.Add(time.Hour).Unix(), Now: now,
	})
	if err != nil {
		return scenarioSummary{}, fmt.Errorf("%s participant B: %w", name, err)
	}
	manifest, err := governedfhe.FinalizeCase(publicRoot)
	if err != nil {
		return scenarioSummary{}, fmt.Errorf("%s finalize: %w", name, err)
	}
	_ = artifactA
	_ = artifactB

	evaluationOutput, evaluatorRSS, err := runProcess(evaluatorPath, "-public-root", publicRoot)
	if err != nil {
		return scenarioSummary{}, fmt.Errorf("%s evaluator: %w", name, err)
	}
	var evaluation processEvaluation
	if json.Unmarshal(evaluationOutput, &evaluation) != nil || !nonzeroDigest(evaluation.ArtifactDigest) {
		return scenarioSummary{}, fmt.Errorf("%s evaluator output", name)
	}
	firstReleaseOutput, decryptorRSS, err := runProcess(decryptorPath, "-public-root", publicRoot, "-private-root", privateRoot)
	if err != nil {
		return scenarioSummary{}, fmt.Errorf("%s decryptor: %w", name, err)
	}
	var firstRelease processRelease
	if json.Unmarshal(firstReleaseOutput, &firstRelease) != nil || firstRelease.Conflict != conflicting || firstRelease.ExactRetry || firstRelease.ReleaseMode != governedfhe.ReleaseModeGovernedDecryptor {
		return scenarioSummary{}, fmt.Errorf("%s release output", name)
	}
	retainedBefore, err := os.ReadFile(filepath.Join(privateRoot, "retained-governed-result.json"))
	if err != nil {
		return scenarioSummary{}, err
	}
	retryOutput, _, err := runProcess(decryptorPath, "-public-root", publicRoot, "-private-root", privateRoot)
	if err != nil {
		return scenarioSummary{}, fmt.Errorf("%s retry: %w", name, err)
	}
	var retry processRelease
	retainedAfter, _ := os.ReadFile(filepath.Join(privateRoot, "retained-governed-result.json"))
	if json.Unmarshal(retryOutput, &retry) != nil || !retry.ExactRetry || retry.ResultDigest != firstRelease.ResultDigest || !bytes.Equal(retainedBefore, retainedAfter) {
		return scenarioSummary{}, fmt.Errorf("%s non-identical retry", name)
	}
	governedResult, signedResult, err := governedfhe.LoadGovernedConflictResult(publicRoot)
	if err != nil || governedResult.Conflict != conflicting {
		return scenarioSummary{}, fmt.Errorf("%s signed result readback: %w", name, err)
	}

	recourseActivated := false
	recourseConfig := governedfhe.RecourseAdapterConfig{
		RecordRoot: publicRoot, CaseManifest: manifest, ExpectedPins: firstRelease.TrustedPins,
		RecordDateUnix: spec.CreatedAtUnix - 3600, CurePeriod: 24 * time.Hour,
		ReserveBasisPoints: governedfhe.MVPReserveBasisPoints, HolderAllocationDigest: digestLabel(name + "/holder-allocation"), Now: time.Now().UTC(),
	}
	if conflicting {
		record, err := governedfhe.AdaptSignedResultToRecourse(recourseConfig, signedResult)
		if err != nil || !record.Open || !record.OriginalReceivableIntact {
			return scenarioSummary{}, fmt.Errorf("%s recourse: %w", name, err)
		}
		recourseActivated = true
	} else if _, err := governedfhe.AdaptSignedResultToRecourse(recourseConfig, signedResult); !errors.Is(err, governedfhe.ErrRecourse) {
		return scenarioSummary{}, fmt.Errorf("%s false result activated recourse", name)
	}

	peakRSS := maximum(evaluatorRSS, decryptorRSS, currentProcessMaxRSS())
	measurements := governedfhe.SmokeMeasurements{
		KeyGeneration: keyReport, Submissions: []governedfhe.SubmissionReport{reportA, reportB},
		Evaluation: governedfhe.EvaluationReport{
			Duration: time.Duration(evaluation.DurationNanos), ResultCiphertextBytes: evaluation.ResultBytes, ArtifactBytes: evaluation.ArtifactBytes,
		},
		Release: governedfhe.ReleaseReport{
			Duration: time.Duration(firstRelease.DurationNanos), ResultBytes: firstRelease.ResultBytes, Pins: firstRelease.TrustedPins,
		},
		CompleteDuration: time.Since(started), PeakRSSBytes: peakRSS,
	}
	evidence, err := governedfhe.ExportPublicEvidence(publicRoot, measurements, time.Now().UTC())
	if err != nil {
		return scenarioSummary{}, fmt.Errorf("%s evidence: %w", name, err)
	}
	return scenarioSummary{Name: name, Conflict: conflicting, RecourseActivated: recourseActivated, Evidence: evidence}, nil
}

func fixturePair(label string, conflicting bool) (fhe.PlainPledge, fhe.PlainPledge) {
	receivableA := sha256.Sum256([]byte("synthetic-private-receivable/" + label))
	receivableB := receivableA
	if !conflicting {
		receivableB = sha256.Sum256([]byte("synthetic-private-receivable/" + label + "/different"))
	}
	base := func(side string, receivable [32]byte, from, until uint64) fhe.PlainPledge {
		return fhe.PlainPledge{
			ActiveFrom: from, ActiveUntil: until, Amount: fhe.Uint256{0, 0, 0, 1_000_000},
			Currency: sha256.Sum256([]byte("currency/usd")), ObligationID: sha256.Sum256([]byte("obligation/" + label + "/" + side)),
			ReceivableID: receivable, Exclusive: true,
			AuthorizationCommitment:   sha256.Sum256([]byte("authorization/" + label + "/" + side)),
			PrivateMetadataCommitment: sha256.Sum256([]byte("private-metadata/" + label + "/" + side)),
		}
	}
	return base("a", receivableA, 100, 400), base("b", receivableB, 200, 500)
}

func digestLabel(label string) governedfhe.Digest {
	return governedfhe.DigestBytes([]byte("MordantDemo/v1\x00" + label))
}
func nonzeroDigest(value governedfhe.Digest) bool { return value != (governedfhe.Digest{}) }

func writePrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func runProcess(path string, args ...string) ([]byte, uint64, error) {
	command := exec.Command(path, args...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	peakRSS := processMaxRSS(command.ProcessState)
	if err != nil {
		return nil, peakRSS, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return output, peakRSS, nil
}

func processMaxRSS(state *os.ProcessState) uint64 {
	if state == nil {
		return 0
	}
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage.Maxrss <= 0 {
		return 0
	}
	return normalizedMaxRSS(uint64(usage.Maxrss))
}

func currentProcessMaxRSS() uint64 {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil || usage.Maxrss <= 0 {
		return 0
	}
	return normalizedMaxRSS(uint64(usage.Maxrss))
}

func normalizedMaxRSS(value uint64) uint64 {
	// Darwin reports ru_maxrss in bytes; Linux reports KiB.
	if runtime.GOOS == "linux" {
		return value * 1024
	}
	return value
}

func maximum(values ...uint64) uint64 {
	var result uint64
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-demo: %v\n", err)
	os.Exit(1)
}
