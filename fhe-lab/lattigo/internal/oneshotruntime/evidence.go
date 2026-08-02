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

	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

const FrozenLibraryTag = "private-matching-v5-oneshot-code-rc1"

type PublicOperatorEvidence struct {
	Point                 uint64         `json:"point"`
	Identity              PublicIdentity `json:"identity"`
	BinarySHA256          string         `json:"binarySha256"`
	ConfigurationSHA256   string         `json:"configurationSha256"`
	RuntimeState          string         `json:"runtimeState"`
	WitnessRecordCount    int            `json:"witnessRecordCount"`
	WitnessHead           string         `json:"witnessHead,omitempty"`
	TerminalTombstoneHash string         `json:"terminalTombstoneSha256,omitempty"`
}

type PublicEvidenceManifest struct {
	SchemaVersion        string                   `json:"schemaVersion"`
	Classification       string                   `json:"classification"`
	Scenario             string                   `json:"scenario"`
	FrozenLibraryTag     string                   `json:"frozenLibraryTag"`
	RuntimeCommit        string                   `json:"runtimeCommit"`
	CeremonyID           string                   `json:"ceremonyId"`
	SessionBindingDigest string                   `json:"sessionBindingDigest"`
	ContextDigest        string                   `json:"contextDigest"`
	KeyID                string                   `json:"keyId,omitempty"`
	BundleDigest         string                   `json:"bundleDigest,omitempty"`
	PublicationReceipt   string                   `json:"publicationReceiptDigest,omitempty"`
	StartedAt            string                   `json:"startedAt"`
	EndedAt              string                   `json:"endedAt"`
	ElapsedMilliseconds  int64                    `json:"elapsedMilliseconds"`
	OperationCount       int                      `json:"operationCount"`
	Operators            []PublicOperatorEvidence `json:"operators"`
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
		if err := writeJSONNoReplace(filepath.Join(directory, "publication-receipt.json"), result.Receipt, 0o600); err != nil {
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
			RuntimeState:        operator.RuntimeState,
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
	if err := ScanPublicEvidence(directory, nil); err != nil {
		return "", err
	}
	return directory, nil
}

func ExportEvidence(source, destination string) error {
	if !filepath.IsAbs(source) || !filepath.IsAbs(destination) || source == destination || ScanPublicEvidence(source, nil) != nil {
		return ErrEvidence
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return ErrEvidence
	}
	entries := make([]string, 0)
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return ErrEvidence
		}
		if path == source {
			return nil
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || strings.HasPrefix(relative, "..") {
			return ErrEvidence
		}
		entries = append(entries, relative)
		return nil
	})
	if err != nil {
		return ErrEvidence
	}
	sort.Strings(entries)
	for _, relative := range entries {
		sourcePath := filepath.Join(source, relative)
		destinationPath := filepath.Join(destination, relative)
		info, err := os.Lstat(sourcePath)
		if err != nil {
			return ErrEvidence
		}
		if info.IsDir() {
			if err := os.Mkdir(destinationPath, 0o700); err != nil {
				return ErrEvidence
			}
			continue
		}
		data, err := readRegular(sourcePath, maxWireBytes)
		if err != nil || writeNoReplace(destinationPath, data, 0o600) != nil {
			return ErrEvidence
		}
	}
	return ScanPublicEvidence(destination, nil)
}

func ScanPublicEvidence(root string, knownSecrets [][]byte) error {
	if !filepath.IsAbs(root) {
		return ErrEvidence
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return ErrEvidence
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxWireBytes {
			return ErrEvidence
		}
		if rejectPrivateFieldName(entry.Name()) {
			return ErrEvidence
		}
		data, err := os.ReadFile(path)
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
			if len(secret) < 16 {
				return ErrEvidence
			}
			if bytes.Contains(data, secret) || bytes.Contains(data, []byte(hex.EncodeToString(secret))) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(secret))) {
				return ErrEvidence
			}
		}
		return nil
	})
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
