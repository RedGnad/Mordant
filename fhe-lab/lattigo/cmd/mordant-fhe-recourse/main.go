// Command mordant-fhe-recourse is the narrow product adapter from the accepted
// signed governed Boolean to the existing local recourse protocol double and
// public evidence exporter. It exposes no decrypt or ciphertext API.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

type recourseRequest struct {
	AssetIdentity          governedfhe.Digest              `json:"assetIdentity"`
	CaseID                 governedfhe.Digest              `json:"caseId"`
	ExpectedPins           governedfhe.TrustedRecoursePins `json:"expectedPins"`
	RecordDateUnix         int64                           `json:"recordDateUnix"`
	HolderAllocationDigest governedfhe.Digest              `json:"holderAllocationDigest"`
	NowUnix                int64                           `json:"nowUnix"`
}

func main() {
	mode := flag.String("mode", "recourse", "recourse, attest, or evidence")
	publicRoot := flag.String("public-root", "", "absolute immutable public case root")
	privateRoot := flag.String("private-root", "", "absolute private decryptor root; attest only")
	requestPath := flag.String("request", "", "absolute strict request JSON")
	flag.Parse()
	if !filepath.IsAbs(*publicRoot) || !filepath.IsAbs(*requestPath) {
		fail(fmt.Errorf("-public-root and -request must be absolute"))
	}
	switch *mode {
	case "recourse":
		runRecourse(*publicRoot, *requestPath)
	case "attest":
		if !filepath.IsAbs(*privateRoot) {
			fail(fmt.Errorf("attest requires -private-root"))
		}
		runAttest(*publicRoot, *privateRoot, *requestPath)
	case "evidence":
		runEvidence(*publicRoot, *requestPath)
	default:
		fail(fmt.Errorf("unsupported mode"))
	}
}

func strictRead(path string, target any) {
	data, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		fail(fmt.Errorf("invalid request JSON"))
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		fail(fmt.Errorf("invalid request JSON"))
	}
}

func loadManifest(publicRoot string) governedfhe.FHECaseManifest {
	var manifest governedfhe.FHECaseManifest
	strictRead(filepath.Join(publicRoot, "case-manifest.json"), &manifest)
	return manifest
}

func runRecourse(publicRoot, requestPath string) {
	var request recourseRequest
	strictRead(requestPath, &request)
	authorization, err := governedfhe.VerifyProtectionAuthorization(publicRoot)
	if err != nil || authorization.Binding.FHECaseID != request.CaseID ||
		authorization.Binding.CleanverseAssetRecordDigest != request.AssetIdentity ||
		authorization.Binding.HolderAllocationDigest != request.HolderAllocationDigest {
		fail(governedfhe.ErrRecourse)
	}
	result, signedResult, err := governedfhe.LoadGovernedConflictResult(publicRoot)
	if err != nil || result.CaseID != request.CaseID || result.AssetIdentity != request.AssetIdentity {
		fail(governedfhe.ErrRecourse)
	}
	config := governedfhe.RecourseAdapterConfig{
		RecordRoot: publicRoot, CaseManifest: loadManifest(publicRoot), ExpectedPins: request.ExpectedPins,
		RecordDateUnix: request.RecordDateUnix, CurePeriod: 24 * time.Hour,
		ReserveBasisPoints:     governedfhe.MVPReserveBasisPoints,
		HolderAllocationDigest: request.HolderAllocationDigest, Now: time.Unix(request.NowUnix, 0).UTC(),
	}
	record, err := governedfhe.AdaptSignedResultToRecourse(config, signedResult)
	if errors.Is(err, governedfhe.ErrRecourse) && !result.Conflict {
		writeJSON(struct {
			Opened bool   `json:"opened"`
			Reason string `json:"reason"`
		}{false, "SIGNED_RESULT_FALSE"})
		return
	}
	if err != nil {
		fail(err)
	}
	writeJSON(struct {
		Opened bool                       `json:"opened"`
		Record governedfhe.RecourseRecord `json:"record"`
	}{true, record})
}

func runAttest(publicRoot, privateRoot, requestPath string) {
	var chronology governedfhe.ProductChronology
	strictRead(requestPath, &chronology)
	attestation, err := governedfhe.CreateRecourseAttestation(publicRoot, privateRoot, chronology)
	if err != nil {
		fail(err)
	}
	digest, err := attestation.Digest()
	if err != nil {
		fail(err)
	}
	writeJSON(struct {
		Digest      governedfhe.Digest                     `json:"digest"`
		Attestation governedfhe.MordantRecourseAttestation `json:"attestation"`
	}{digest, attestation})
}

func runEvidence(publicRoot, requestPath string) {
	var measurements governedfhe.SmokeMeasurements
	strictRead(requestPath, &measurements)
	if _, err := governedfhe.LoadProductRecourseAttestation(publicRoot); err != nil {
		fail(err)
	}
	evidence, err := governedfhe.ExportPublicEvidence(publicRoot, measurements, time.Now().UTC())
	if err != nil {
		fail(err)
	}
	writeJSON(evidence)
}

func writeJSON(value any) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-recourse: %v\n", err)
	os.Exit(1)
}
