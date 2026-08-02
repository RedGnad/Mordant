package oneshotruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

const FrozenLibraryTag = "private-matching-v5-oneshot-code-rc1"

type PublicOperatorEvidence struct {
	Point                 uint64         `json:"point" required:"true"`
	Identity              PublicIdentity `json:"identity" required:"true"`
	BinarySHA256          string         `json:"binarySha256" required:"true"`
	ConfigurationSHA256   string         `json:"configurationSha256" required:"true"`
	Disposition           string         `json:"disposition" required:"true"`
	WitnessRecordCount    int            `json:"witnessRecordCount" required:"true"`
	WitnessHead           string         `json:"witnessHead,omitempty"`
	TerminalTombstoneHash string         `json:"terminalTombstoneSha256,omitempty"`
}

type PublicEvidenceManifest struct {
	SchemaVersion        string                   `json:"schemaVersion" required:"true"`
	Classification       string                   `json:"classification" required:"true"`
	Scenario             string                   `json:"scenario" required:"true"`
	FrozenLibraryTag     string                   `json:"frozenLibraryTag" required:"true"`
	RuntimeCommit        string                   `json:"runtimeCommit" required:"true"`
	CeremonyID           string                   `json:"ceremonyId" required:"true"`
	SessionBindingDigest string                   `json:"sessionBindingDigest" required:"true"`
	ContextDigest        string                   `json:"contextDigest" required:"true"`
	KeyID                string                   `json:"keyId,omitempty"`
	BundleDigest         string                   `json:"bundleDigest,omitempty"`
	PublicationReceipt   string                   `json:"publicationReceiptDigest,omitempty"`
	StartedAt            string                   `json:"startedAt" required:"true"`
	EndedAt              string                   `json:"endedAt" required:"true"`
	ElapsedMilliseconds  int64                    `json:"elapsedMilliseconds" required:"true" allowzero:"true"`
	OperationCount       int                      `json:"operationCount" required:"true"`
	Operators            []PublicOperatorEvidence `json:"operators" required:"true"`
}

func ExportRunEvidence(root string, result RunResult) (string, error) {
	if !filepath.IsAbs(root) || result.Context.Validate() != nil || len(result.Operators) != ceremony.PartyCount || result.Scenario == "" {
		return "", ErrEvidence
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return "", err
	}
	ceremonyID := result.Context.CeremonyID()
	directory := filepath.Join(root, strings.ToLower(result.Scenario)+"-"+hex.EncodeToString(ceremonyID[:8]))
	if err := os.Mkdir(directory, 0o700); err != nil {
		return "", ErrEvidence
	}
	contextBytes, err := result.Context.MarshalBinary()
	if err != nil {
		return "", err
	}
	sessionBindingDigest := result.Context.SessionBindingDigest()
	contextDigest := result.Context.ContextDigest()
	if err := writeNoReplace(filepath.Join(directory, "context.bin"), contextBytes, 0o600); err != nil {
		return "", err
	}
	manifest := PublicEvidenceManifest{
		SchemaVersion:        EvidenceSchema,
		Classification:       "MVP_FUNCTIONAL_ONE_ADMIN_TOPOLOGY",
		Scenario:             result.Scenario,
		FrozenLibraryTag:     FrozenLibraryTag,
		RuntimeCommit:        result.Context.SourceCommit,
		CeremonyID:           encodeHex(ceremonyID[:]),
		SessionBindingDigest: encodeHex(sessionBindingDigest[:]),
		ContextDigest:        encodeHex(contextDigest[:]),
		StartedAt:            result.StartedAt.Format(timeFormat),
		EndedAt:              result.EndedAt.Format(timeFormat),
		ElapsedMilliseconds:  result.EndedAt.Sub(result.StartedAt).Milliseconds(),
		OperationCount:       result.OperationCount,
		Operators:            make([]PublicOperatorEvidence, len(result.Operators)),
	}
	if result.Bundle.SchemaVersion != "" {
		bundleBytes, err := result.Bundle.MarshalBinary()
		if err != nil {
			return "", err
		}
		if err := writeNoReplace(filepath.Join(directory, "public.bundle"), bundleBytes, 0o600); err != nil {
			return "", err
		}
		manifest.KeyID = encodeHex(result.Bundle.Unsigned.KeyID[:])
		bundleDigest := result.Bundle.Digest()
		manifest.BundleDigest = encodeHex(bundleDigest[:])
		receiptDigest := result.Receipt.Digest()
		manifest.PublicationReceipt = encodeHex(receiptDigest[:])
		receiptBytes, err := result.Receipt.MarshalBinary()
		if err != nil {
			return "", err
		}
		if err := writeNoReplace(filepath.Join(directory, "publication-receipt.bin"), receiptBytes, 0o600); err != nil {
			return "", err
		}
	}
	for index, reservation := range result.Reservations {
		encoded, err := reservation.MarshalBinary()
		if err != nil {
			return "", err
		}
		if err := writeNoReplace(filepath.Join(directory, fmt.Sprintf("reservation-%d.bin", index+1)), encoded, 0o600); err != nil {
			return "", err
		}
	}
	for index, operator := range result.Operators {
		operatorDirectory := filepath.Join(directory, fmt.Sprintf("operator-%d", index+1))
		if err := os.Mkdir(operatorDirectory, 0o700); err != nil {
			return "", ErrEvidence
		}
		if err := writeJSONNoReplace(filepath.Join(operatorDirectory, "public-identity.json"), operator.Identity, 0o600); err != nil {
			return "", err
		}
		for recordIndex, record := range operator.Records {
			if err := writeNoReplace(filepath.Join(operatorDirectory, fmt.Sprintf("witness-%04d.bin", recordIndex+1)), record, 0o600); err != nil {
				return "", err
			}
		}
		public := PublicOperatorEvidence{
			Point:               operator.Identity.Point,
			Identity:            operator.Identity,
			BinarySHA256:        operator.Identity.RuntimeBinaryDigest,
			ConfigurationSHA256: encodeHex(operator.ConfigurationHash[:]),
			Disposition:         operator.Disposition,
			WitnessRecordCount:  len(operator.Records),
		}
		if len(operator.Records) > 0 {
			last, parseErr := ceremony.ParseWitnessRecord(operator.Records[len(operator.Records)-1])
			if parseErr != nil {
				return "", parseErr
			}
			head := last.EventDigest()
			public.WitnessHead = encodeHex(head[:])
		}
		if len(operator.TerminalTombstone) > 0 {
			if _, parseErr := ceremony.ParseTerminalTombstone(operator.TerminalTombstone); parseErr != nil {
				return "", parseErr
			}
			if err := writeNoReplace(filepath.Join(operatorDirectory, "terminal-tombstone.bin"), operator.TerminalTombstone, 0o600); err != nil {
				return "", err
			}
			digest := sha256.Sum256(operator.TerminalTombstone)
			public.TerminalTombstoneHash = encodeHex(digest[:])
		}
		manifest.Operators[index] = public
	}
	if err := writeJSONNoReplace(filepath.Join(directory, "manifest.json"), manifest, 0o600); err != nil {
		return "", err
	}
	paths, err := verifyEvidenceTree(directory, nil, false)
	if err != nil {
		return "", err
	}
	if err := scanKnownSecretFiles(paths, nil); err != nil {
		return "", err
	}
	return directory, nil
}

func ExportCompletedEvidence(config RunnerConfig, runDirectory string) (string, error) {
	if config.validate() != nil || runDirectory == "" || filepath.Base(runDirectory) != runDirectory || strings.ContainsAny(runDirectory, `/\\`) {
		return "", ErrEvidence
	}
	source := filepath.Join(config.EvidenceRoot, runDirectory)
	if relative, err := filepath.Rel(config.EvidenceRoot, source); err != nil || relative != runDirectory {
		return "", ErrEvidence
	}
	paths, err := verifyEvidenceTree(source, &config, true)
	if err != nil || scanKnownSecretFiles(paths, nil) != nil {
		return "", ErrEvidence
	}
	if err := ensurePrivateDirectory(config.ExportRoot); err != nil {
		return "", err
	}
	destination := filepath.Join(config.ExportRoot, runDirectory)
	if err := os.Mkdir(destination, 0o700); err != nil {
		return "", ErrEvidence
	}
	for _, sourcePath := range paths {
		relative, err := filepath.Rel(source, sourcePath)
		if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
			return "", ErrEvidence
		}
		destinationPath := filepath.Join(destination, relative)
		if err := os.MkdirAll(filepath.Dir(destinationPath), 0o700); err != nil {
			return "", ErrEvidence
		}
		data, err := readRestrictedExact(sourcePath, maxWireBytes, 0o600)
		if err != nil || writeNoReplace(destinationPath, data, 0o600) != nil {
			return "", ErrEvidence
		}
	}
	exported, err := verifyEvidenceTree(destination, &config, true)
	if err != nil || scanKnownSecretFiles(exported, nil) != nil {
		return "", ErrEvidence
	}
	return destination, nil
}

func verifyEvidenceTree(root string, config *RunnerConfig, requireCompleted bool) ([]string, error) {
	if !filepath.IsAbs(root) {
		return nil, ErrEvidence
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm() != 0o700 {
		return nil, ErrEvidence
	}
	var manifest PublicEvidenceManifest
	if readStrictJSONExact(filepath.Join(root, "manifest.json"), &manifest, maxConfigBytes, 0o600) != nil ||
		manifest.SchemaVersion != EvidenceSchema || manifest.Classification != "MVP_FUNCTIONAL_ONE_ADMIN_TOPOLOGY" ||
		manifest.FrozenLibraryTag != FrozenLibraryTag || len(manifest.Operators) != ceremony.PartyCount || manifest.OperationCount <= 0 {
		return nil, ErrEvidence
	}
	if requireCompleted && manifest.Scenario != "SUCCESS" {
		return nil, ErrEvidence
	}
	contextBytes, err := readRestrictedExact(filepath.Join(root, "context.bin"), maxWireBytes, 0o600)
	if err != nil {
		return nil, ErrEvidence
	}
	contextValue, err := ceremony.ParseContext(contextBytes)
	ceremonyID, sessionBinding, contextDigest := contextValue.CeremonyID(), contextValue.SessionBindingDigest(), contextValue.ContextDigest()
	if err != nil || manifest.RuntimeCommit != contextValue.SourceCommit || manifest.CeremonyID != encodeHex(ceremonyID[:]) ||
		manifest.SessionBindingDigest != encodeHex(sessionBinding[:]) || manifest.ContextDigest != encodeHex(contextDigest[:]) {
		return nil, ErrEvidence
	}
	startedAt, err := time.Parse(timeFormat, manifest.StartedAt)
	if err != nil {
		return nil, ErrEvidence
	}
	endedAt, err := time.Parse(timeFormat, manifest.EndedAt)
	if err != nil || endedAt.Before(startedAt) || endedAt.Sub(startedAt).Milliseconds() != manifest.ElapsedMilliseconds {
		return nil, ErrEvidence
	}
	switch manifest.Scenario {
	case "SUCCESS", "STALE_REPLICA", "ABORT":
	default:
		return nil, ErrEvidence
	}
	expectedDirectories := map[string]struct{}{".": {}}
	expectedFiles := map[string]struct{}{
		"manifest.json": {}, "context.bin": {}, "reservation-1.bin": {}, "reservation-2.bin": {}, "reservation-3.bin": {},
	}
	if manifest.Scenario == "SUCCESS" {
		expectedFiles["public.bundle"] = struct{}{}
		expectedFiles["publication-receipt.bin"] = struct{}{}
	}
	for index, operator := range manifest.Operators {
		var configurationDigest [32]byte
		if operator.Point != uint64(index+1) || operator.Identity.Point != operator.Point || decodeFixed(operator.ConfigurationSHA256, configurationDigest[:]) != nil ||
			operator.BinarySHA256 != operator.Identity.RuntimeBinaryDigest || operator.WitnessRecordCount < 1 || operator.WitnessRecordCount > 64 {
			return nil, ErrEvidence
		}
		directory := fmt.Sprintf("operator-%d", index+1)
		expectedDirectories[directory] = struct{}{}
		expectedFiles[filepath.Join(directory, "public-identity.json")] = struct{}{}
		for record := 1; record <= operator.WitnessRecordCount; record++ {
			expectedFiles[filepath.Join(directory, fmt.Sprintf("witness-%04d.bin", record))] = struct{}{}
		}
		if operator.TerminalTombstoneHash != "" {
			expectedFiles[filepath.Join(directory, "terminal-tombstone.bin")] = struct{}{}
		}
	}
	seenFiles := make(map[string]struct{})
	seenDirectories := make(map[string]struct{})
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return ErrEvidence
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(relative, "..") {
			return ErrEvidence
		}
		if entry.IsDir() {
			if _, allowed := expectedDirectories[relative]; !allowed {
				return ErrEvidence
			}
			info, err := entry.Info()
			if err != nil || info.Mode().Perm() != 0o700 {
				return ErrEvidence
			}
			seenDirectories[relative] = struct{}{}
			return nil
		}
		if _, allowed := expectedFiles[relative]; !allowed {
			return ErrEvidence
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxWireBytes {
			return ErrEvidence
		}
		seenFiles[relative] = struct{}{}
		return nil
	})
	if err != nil || len(seenFiles) != len(expectedFiles) || len(seenDirectories) != len(expectedDirectories) {
		return nil, ErrEvidence
	}
	paths := make([]string, 0, len(expectedFiles))
	for relative := range expectedFiles {
		if _, found := seenFiles[relative]; !found {
			return nil, ErrEvidence
		}
		paths = append(paths, filepath.Join(root, relative))
	}
	sort.Strings(paths)
	reservations := make([]ceremony.AttemptReservation, ceremony.PartyCount)
	for index := range reservations {
		data, err := readRestrictedExact(filepath.Join(root, fmt.Sprintf("reservation-%d.bin", index+1)), maxWireBytes, 0o600)
		if err != nil {
			return nil, ErrEvidence
		}
		reservations[index], err = ceremony.ParseAttemptReservation(data)
		if err != nil || ceremony.VerifyAttemptReservation(contextValue, reservations[index]) != nil || reservations[index].OperatorPoint != uint64(index+1) {
			return nil, ErrEvidence
		}
	}
	replicas := make([][]ceremony.WitnessRecord, ceremony.PartyCount)
	for index, operator := range manifest.Operators {
		directory := filepath.Join(root, fmt.Sprintf("operator-%d", index+1))
		var identity PublicIdentity
		if readStrictJSONExact(filepath.Join(directory, "public-identity.json"), &identity, maxConfigBytes, 0o600) != nil || identity != operator.Identity {
			return nil, ErrEvidence
		}
		contextIdentity, err := identity.operatorIdentity()
		if err != nil || contextIdentity != contextValue.Operators[index] {
			return nil, ErrEvidence
		}
		if config != nil && config.Operators[index].Identity != identity {
			return nil, ErrEvidence
		}
		replicas[index] = make([]ceremony.WitnessRecord, operator.WitnessRecordCount)
		for recordIndex := range replicas[index] {
			data, err := readRestrictedExact(filepath.Join(directory, fmt.Sprintf("witness-%04d.bin", recordIndex+1)), maxWireBytes, 0o600)
			if err != nil {
				return nil, ErrEvidence
			}
			replicas[index][recordIndex], err = ceremony.ParseWitnessRecord(data)
			if err != nil {
				return nil, ErrEvidence
			}
		}
		head := replicas[index][len(replicas[index])-1].EventDigest()
		if operator.WitnessHead != encodeHex(head[:]) {
			return nil, ErrEvidence
		}
		if operator.TerminalTombstoneHash != "" {
			data, err := readRestrictedExact(filepath.Join(directory, "terminal-tombstone.bin"), maxWireBytes, 0o600)
			tombstoneDigest := sha256.Sum256(data)
			if err != nil || operator.TerminalTombstoneHash != encodeHex(tombstoneDigest[:]) {
				return nil, ErrEvidence
			}
			tombstone, err := ceremony.ParseTerminalTombstone(data)
			if err != nil || tombstone.CeremonyID != contextValue.CeremonyID() || tombstone.SessionBindingDigest != contextValue.SessionBindingDigest() ||
				dispositionName(tombstone.Disposition) != operator.Disposition {
				return nil, ErrEvidence
			}
		} else if operator.Disposition != "ACTIVE" {
			return nil, ErrEvidence
		}
	}
	if manifest.Scenario == "SUCCESS" {
		bundleBytes, err := readRestrictedExact(filepath.Join(root, "public.bundle"), maxWireBytes, 0o600)
		if err != nil {
			return nil, ErrEvidence
		}
		bundle, err := ceremony.ParsePublicBundle(bundleBytes)
		if err != nil {
			return nil, ErrEvidence
		}
		receiptBytes, err := readRestrictedExact(filepath.Join(root, "publication-receipt.bin"), maxWireBytes, 0o600)
		if err != nil {
			return nil, ErrEvidence
		}
		receipt, err := parsePublicationReceipt(receiptBytes)
		bundleDigest, receiptDigest := bundle.Digest(), receipt.Digest()
		if err != nil || ceremony.VerifyPublishedCeremony(contextValue, bundle, receipt, replicas...) != nil ||
			manifest.KeyID != encodeHex(bundle.Unsigned.KeyID[:]) || manifest.BundleDigest != encodeHex(bundleDigest[:]) ||
			manifest.PublicationReceipt != encodeHex(receiptDigest[:]) {
			return nil, ErrEvidence
		}
		if config != nil {
			if receipt.ObjectPath != filepath.Join(config.PublicationRoot, "public.bundle") {
				return nil, ErrEvidence
			}
			published, err := readRestrictedExact(receipt.ObjectPath, maxWireBytes, 0o600)
			if err != nil || !bytes.Equal(published, bundleBytes) {
				return nil, ErrEvidence
			}
		}
		for _, operator := range manifest.Operators {
			if operator.Disposition != "COMPLETED" || operator.TerminalTombstoneHash == "" {
				return nil, ErrEvidence
			}
		}
	}
	if manifest.Scenario == "ABORT" {
		for _, operator := range manifest.Operators {
			if operator.Disposition != "ABORTED" || operator.TerminalTombstoneHash == "" {
				return nil, ErrEvidence
			}
		}
	}
	if manifest.Scenario == "STALE_REPLICA" {
		for index, operator := range manifest.Operators {
			if index < ceremony.Threshold && (operator.Disposition != "POISONED" || operator.TerminalTombstoneHash == "") ||
				index >= ceremony.Threshold && (operator.Disposition != "ACTIVE" || operator.TerminalTombstoneHash != "") {
				return nil, ErrEvidence
			}
		}
	}
	return paths, nil
}

func scanKnownSecretFiles(paths []string, knownSecrets [][]byte) error {
	for _, path := range paths {
		if !filepath.IsAbs(path) || rejectPrivateFieldName(filepath.Base(path)) {
			return ErrEvidence
		}
		data, err := readRestrictedExact(path, maxWireBytes, 0o600)
		if err != nil {
			return ErrEvidence
		}
		lower := strings.ToLower(string(data))
		for _, field := range []string{"\"signingprivatekey\"", "\"encryptionprivatekey\"", "\"transportprivatekey\"", "\"sealingkey\"", "\"thresholdshare\"", "\"privatebundle\""} {
			if strings.Contains(lower, field) {
				return ErrEvidence
			}
		}
		for _, secret := range knownSecrets {
			if len(secret) < 16 || bytes.Contains(data, secret) || bytes.Contains(data, []byte(hex.EncodeToString(secret))) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(secret))) {
				return ErrEvidence
			}
		}
	}
	return nil
}

func dispositionName(disposition ceremony.TerminalDisposition) string {
	switch disposition {
	case ceremony.DispositionPoisoned:
		return "POISONED"
	case ceremony.DispositionAborted:
		return "ABORTED"
	case ceremony.DispositionCompleted:
		return "COMPLETED"
	default:
		return ""
	}
}

func ensurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return ErrEvidence
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return ErrEvidence
		}
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return ErrEvidence
	}
	return nil
}

const timeFormat = "2006-01-02T15:04:05.000000000Z"

func jsonDigest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, ErrEvidence
	}
	return sha256.Sum256(encoded), nil
}
