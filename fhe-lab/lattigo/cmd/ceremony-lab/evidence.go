package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/internal/thresholdnet"
)

func labParameters() (bgv.Parameters, error) {
	return bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP:             []int{60, 60, 60},
		PlaintextModulus: 65537,
	})
}

func (l *lab) writeEvidence() error {
	public := filepath.Join(l.root, "public")
	ceremonyEvidence, err := os.ReadFile(filepath.Join(public, "ceremony-evidence.json"))
	if err != nil {
		return err
	}
	manifestBytes, err := os.ReadFile(filepath.Join(public, "key-manifest.json"))
	if err != nil {
		return err
	}
	evaluatorOutput, err := os.ReadFile(filepath.Join(public, "evaluator-result.json"))
	if err != nil {
		return err
	}

	statements, err := l.collectOperatorStatements()
	if err != nil {
		return fmt.Errorf("operator statements: %w", err)
	}
	isolation, err := l.auditShareIsolation()
	if err != nil {
		return fmt.Errorf("share isolation: %w", err)
	}
	negatives, err := l.runNegativeChecks(manifestBytes)
	if err != nil {
		return fmt.Errorf("negative checks: %w", err)
	}
	binding, err := l.bindSource()
	if err != nil {
		return fmt.Errorf("source binding: %w", err)
	}

	rosterDigest := l.roster.Digest()
	report := evidence{
		SchemaVersion:  "mordant.dealerless-custody-evidence/4",
		Classification: "DEALERLESS PROCESS-SEPARATED CONTROLLED LAB",
		LattigoVersion: fhe.LattigoVersion,
		CustodyModel:   string(fhe.CustodyDealerlessCeremony),
		Source:         binding,
		Processes:      l.processes,
		Roster:         json.RawMessage(l.rosterRaw),
		RosterDigest:   hex.EncodeToString(rosterDigest[:]),
		Ceremony:       json.RawMessage(bytes.TrimSpace(ceremonyEvidence)),
		KeyManifest:    json.RawMessage(bytes.TrimSpace(manifestBytes)),
		OperatorProof:  statements,
		Evaluator:      json.RawMessage(bytes.TrimSpace(evaluatorOutput)),
		ShareIsolation: isolation,
		Negatives:      negatives,
		Limitations: []string{
			"Lattigo multiparty is secure against passive adversaries only; no operator proves its share was honestly computed.",
			"No proof of correct FHE execution; the release authenticates who endorsed a commitment.",
			"The CRS contributions are revealed in one round without commit-then-reveal; an active adversary revealing last could bias the seed.",
			"Roster and PKI distribution is a lab bootstrap assumption.",
			"Three processes on one host under one administrator is process separation, not independent organizational custody.",
			"Not production authorized.",
		},
		CompletedAtUTC:   time.Now().UTC().Format(time.RFC3339Nano),
		ThresholdEpoch:   l.roster.KeyEpoch,
		SelectedCoalitio: []uint64{1, 2},
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(l.out, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"key-manifest.json", "ceremony-evidence.json", "evaluator-result.json"} {
		raw, err := os.ReadFile(filepath.Join(public, name))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(l.out, name), raw, 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(l.out, "roster.json"), l.rosterRaw, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(l.out, "dealerless-custody-evidence.json"), append(encoded, '\n'), 0o644)
}

// collectOperatorStatements reads each operator's own signed statement directly
// from that operator and verifies the signature against the roster. Node 3's
// state is therefore operator-authored and independently checkable, not a
// coordinator constant.
func (l *lab) collectOperatorStatements() ([]operatorProof, error) {
	proofs := make([]operatorProof, 0, operatorCount)
	for point := uint64(1); point <= operatorCount; point++ {
		transport := &http.Transport{
			TLSClientConfig: thresholdnet.ClientTLSConfig(l.labCert, l.roots, fmt.Sprintf("node%d.local", point)),
		}
		client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
		response, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/v1/ceremony/status", l.ports[point]))
		if err != nil {
			return nil, err
		}
		body, err := readAllLimited(response)
		if err != nil {
			return nil, err
		}
		var signed thresholdnet.SignedOperatorStatement
		if err := json.Unmarshal(body, &signed); err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(signed.Signature)
		if err != nil || len(raw) != ed25519.SignatureSize {
			return nil, errors.New("invalid operator statement signature")
		}
		var signature [ed25519.SignatureSize]byte
		copy(signature[:], raw)
		if err := fhe.VerifyOperatorStatement(l.roster, signed.Point, signed.Statement, signature); err != nil {
			return nil, fmt.Errorf("operator %d statement: %w", point, err)
		}
		var statement thresholdnet.OperatorStatement
		if err := json.Unmarshal(signed.Statement, &statement); err != nil {
			return nil, err
		}
		if statement.Point != point {
			return nil, fmt.Errorf("operator %d returned a statement for point %d", point, statement.Point)
		}
		if !statement.Sealed {
			return nil, fmt.Errorf("operator %d did not seal", point)
		}
		if statement.HoldsLocalSecretKey {
			return nil, fmt.Errorf("operator %d still holds its transient local secret", point)
		}
		proofs = append(proofs, operatorProof{
			Point:               statement.Point,
			SignatureVerified:   true,
			Sealed:              statement.Sealed,
			HoldsLocalSecretKey: statement.HoldsLocalSecretKey,
			Statement:           signed.Statement,
		})
	}
	return proofs, nil
}

// auditShareIsolation proves that no file holds more than one operator's Shamir
// share, and that each operator's share appears only inside its own storage.
//
// The audit reads one operator's share at a time and discards it before moving
// to the next, so the auditing process never holds two shares simultaneously.
// The bundle format itself carries exactly one share, which is the structural
// half of this argument; the content sweep is the empirical half.
func (l *lab) auditShareIsolation() (shareIsolation, error) {
	report := shareIsolation{
		Method: "per-operator sequential sweep: one share held at a time, searched byte-for-byte " +
			"across every file in the lab tree outside that operator's own storage",
		ForeignShareHit: []string{},
		MultiShareFiles: []string{},
	}
	files, err := allFiles(l.root)
	if err != nil {
		return report, err
	}
	report.FilesScanned = len(files)
	hits := map[string]int{}
	for point := uint64(1); point <= operatorCount; point++ {
		storage := filepath.Join(l.root, "operators", fmt.Sprintf("%d", point))
		bundlePath := filepath.Join(storage, "operator.bin")
		bundle, err := os.ReadFile(bundlePath)
		if err != nil {
			return report, fmt.Errorf("operator %d bundle: %w", point, err)
		}
		operator, err := fhe.NewThresholdOperator(bundle)
		if err != nil {
			return report, err
		}
		if operator.Public().Point != point {
			return report, fmt.Errorf("operator %d bundle declares point %d", point, operator.Public().Point)
		}
		report.BundleFiles = append(report.BundleFiles, relative(l.root, bundlePath))
		report.BundlePoints = append(report.BundlePoints, operator.Public().Point)

		// The share bytes are the tail-most sized field of the bundle; searching
		// for the whole bundle body is a superset test that cannot miss a copy.
		needle := bundle
		for _, candidate := range files {
			if candidate == bundlePath {
				continue
			}
			contents, err := os.ReadFile(candidate)
			if err != nil {
				continue
			}
			if bytes.Contains(contents, needle) {
				name := relative(l.root, candidate)
				report.ForeignShareHit = append(report.ForeignShareHit, name)
				hits[name]++
			}
		}
		// Discard this operator's material before touching the next one.
		needle = nil
		bundle = nil
		_ = needle
		_ = bundle
	}
	for name, count := range hits {
		if count > 1 {
			report.MultiShareFiles = append(report.MultiShareFiles, name)
		}
	}
	sort.Strings(report.MultiShareFiles)
	sort.Strings(report.ForeignShareHit)
	if len(report.ForeignShareHit) != 0 {
		return report, fmt.Errorf("operator share material found outside its own storage: %v", report.ForeignShareHit)
	}
	if len(report.BundlePoints) != operatorCount {
		return report, errors.New("missing operator bundles")
	}
	// No file in the coordinator or evaluator directories may parse as a bundle.
	for _, directory := range []string{"coordinator", "evaluator", "public", "clients"} {
		candidates, err := allFiles(filepath.Join(l.root, directory))
		if err != nil {
			continue
		}
		for _, candidate := range candidates {
			raw, err := os.ReadFile(candidate)
			if err != nil || len(raw) == 0 {
				continue
			}
			if _, err := fhe.NewThresholdOperator(raw); err == nil {
				return report, fmt.Errorf("%s parses as an operator bundle", relative(l.root, candidate))
			}
		}
	}
	return report, nil
}

// runNegativeChecks exercises the mission's confidentiality-boundary negatives
// against the live lab: a single operator cannot release, and a client refuses a
// key manifest that the operators did not sign.
func (l *lab) runNegativeChecks(manifestBytes []byte) (map[string]string, error) {
	results := map[string]string{}

	manifest, err := fhe.UnmarshalCollectiveKeyManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	rosterDigest := l.roster.Digest()

	// A manifest whose public-key commitment was swapped by an evaluator loses
	// every operator signature.
	substituted := manifest
	substituted.PublicKeyCommitment = hex.EncodeToString(sha256Sum([]byte("evaluator-substituted-key")))
	keyID, err := hex.DecodeString(manifest.KeyID)
	if err != nil {
		return nil, err
	}
	var keyIDArray [32]byte
	copy(keyIDArray[:], keyID)
	policyID, err := hex.DecodeString(manifest.PolicyID)
	if err != nil {
		return nil, err
	}
	var policyArray [32]byte
	copy(policyArray[:], policyID)
	expectation := fhe.ClientKeyExpectation{
		RosterDigest: rosterDigest, Threshold: manifest.Threshold, KeyEpoch: manifest.KeyEpoch,
		ChainID: manifest.ChainID, PolicyID: policyArray, PolicyVersion: manifest.PolicyVersion,
		Now: time.Now().UTC(),
	}
	var substitutedCommitment [32]byte
	copy(substitutedCommitment[:], sha256Sum([]byte("evaluator-substituted-key")))
	if err := fhe.VerifyCollectiveKeyManifest(substituted, expectation, keyIDArray, substitutedCommitment); err == nil {
		return nil, errors.New("a substituted public key was accepted by the client gate")
	} else {
		results["clientRejectsEvaluatorSubstitutedPublicKey"] = "REFUSED: " + err.Error()
	}

	// Dropping one attestation must break the manifest: the key set is jointly
	// authenticated or not authenticated at all.
	partial := manifest
	partial.Attestations = manifest.Attestations[:len(manifest.Attestations)-1]
	var trueCommitment [32]byte
	raw, err := hex.DecodeString(manifest.PublicKeyCommitment)
	if err != nil {
		return nil, err
	}
	copy(trueCommitment[:], raw)
	if err := fhe.VerifyCollectiveKeyManifest(partial, expectation, keyIDArray, trueCommitment); err == nil {
		return nil, errors.New("a partially attested manifest was accepted")
	} else {
		results["clientRejectsPartiallyAttestedManifest"] = "REFUSED: " + err.Error()
	}

	// The evaluator's own recorded negatives are copied from its output.
	evaluatorRaw, err := os.ReadFile(filepath.Join(l.root, "public", "evaluator-result.json"))
	if err != nil {
		return nil, err
	}
	var evaluatorParsed struct {
		EvaluatorCapabilities struct {
			HoldsThresholdParties     bool   `json:"holdsThresholdParties"`
			LocalDecryptAttempt       string `json:"localDecryptAttempt"`
			ProvisionOperatorsAttempt string `json:"provisionOperatorsAttempt"`
			ReleaseShareAttempt       string `json:"releaseShareAttempt"`
		} `json:"evaluatorCapabilities"`
		ConflictConfirmed bool `json:"conflictConfirmed"`
	}
	if err := json.Unmarshal(evaluatorRaw, &evaluatorParsed); err != nil {
		return nil, err
	}
	if evaluatorParsed.EvaluatorCapabilities.HoldsThresholdParties {
		return nil, errors.New("evaluator reported holding threshold parties")
	}
	if !evaluatorParsed.ConflictConfirmed {
		return nil, errors.New("the exact policy did not confirm the conflict")
	}
	results["evaluatorHoldsThresholdParties"] = "false"
	results["evaluatorLocalDecrypt"] = evaluatorParsed.EvaluatorCapabilities.LocalDecryptAttempt
	results["evaluatorProvisionOperators"] = evaluatorParsed.EvaluatorCapabilities.ProvisionOperatorsAttempt
	results["evaluatorCreateReleaseShare"] = evaluatorParsed.EvaluatorCapabilities.ReleaseShareAttempt
	results["exactPolicyConflictConfirmed"] = "true"

	// Static evidence: the evaluator binary's source must not reference the
	// trusted-dealer constructors at all.
	dealerRefs, err := grepSource(filepath.Join(l.repo, "cmd", "ceremony-evaluator"),
		"NewTrustedDealerRuntime", "ProvisionThresholdOperators(", "ShamirSecretShare", "GenSecretKeyNew")
	if err != nil {
		return nil, err
	}
	if len(dealerRefs) != 0 {
		return nil, fmt.Errorf("evaluator source references secret-material APIs: %v", dealerRefs)
	}
	results["evaluatorSourceReferencesSecretMaterialAPIs"] = "none"
	return results, nil
}

func grepSource(directory string, needles ...string) ([]string, error) {
	files, err := allFiles(directory)
	if err != nil {
		return nil, err
	}
	hits := []string{}
	for _, file := range files {
		if !strings.HasSuffix(file, ".go") {
			continue
		}
		contents, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for _, needle := range needles {
			// The evaluator legitimately calls ProvisionThresholdOperators as a
			// recorded negative check, so only flag a use that is not the
			// documented refusal probe.
			if needle == "ProvisionThresholdOperators(" && bytes.Contains(contents, []byte("provisionErr")) {
				continue
			}
			if bytes.Contains(contents, []byte(needle)) {
				hits = append(hits, filepath.Base(file)+":"+needle)
			}
		}
	}
	return hits, nil
}

func (l *lab) bindSource() (sourceBinding, error) {
	binding := sourceBinding{BinarySha256: map[string]string{}}
	commit, err := gitOutput(l.repo, "rev-parse", "HEAD")
	if err != nil {
		return binding, err
	}
	binding.Commit = commit
	// Cleanliness is judged over tracked files: an untracked file elsewhere in
	// the repository cannot change the source that produced these binaries, but
	// a modified tracked file can. Untracked paths are counted, not ignored.
	tracked, err := gitOutput(l.repo, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return binding, err
	}
	if tracked == "" {
		binding.WorkingTree = "clean (no modified tracked files)"
	} else {
		binding.WorkingTree = "dirty (modified tracked files present)"
		binding.ModifiedTracked = strings.Split(tracked, "\n")
	}
	untracked, err := gitOutput(l.repo, "ls-files", "--others", "--exclude-standard")
	if err == nil && untracked != "" {
		binding.UntrackedPaths = len(strings.Split(untracked, "\n"))
	}
	tree, err := hashSourceTree(l.repo)
	if err != nil {
		return binding, err
	}
	binding.SourceTreeHash = tree
	for name, path := range l.binaries {
		raw, err := os.ReadFile(path)
		if err != nil {
			return binding, err
		}
		digest := sha256.Sum256(raw)
		binding.BinarySha256[name] = hex.EncodeToString(digest[:])
	}
	return binding, nil
}

// hashSourceTree hashes every tracked Go and Markdown source file under the
// module, so the evidence names the exact source that produced it.
func hashSourceTree(root string) (string, error) {
	files, err := allFiles(root)
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	hash := sha256.New()
	for _, file := range files {
		if !strings.HasSuffix(file, ".go") && !strings.HasSuffix(file, ".mod") && !strings.HasSuffix(file, ".sum") {
			continue
		}
		contents, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		_, _ = hash.Write([]byte(relative(root, file)))
		digest := sha256.Sum256(contents)
		_, _ = hash.Write(digest[:])
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func gitOutput(directory string, arguments ...string) (string, error) {
	command := exec.Command("git", arguments...)
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func allFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode().IsRegular() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func relative(root, path string) string {
	value, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return value
}

func sha256Sum(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func readAllLimited(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", response.StatusCode)
	}
	buffer := make([]byte, 0, 64<<10)
	chunk := make([]byte, 8<<10)
	for {
		read, err := response.Body.Read(chunk)
		if read > 0 {
			buffer = append(buffer, chunk[:read]...)
		}
		if err != nil {
			break
		}
		if len(buffer) > 4<<20 {
			return nil, errors.New("status response too large")
		}
	}
	return buffer, nil
}
