package oneshotruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	requestJournalSchema     = "mordant.oneshot-request-journal/1"
	requestJournalMaxEntries = 4096
	requestJournalMaxBytes   = int64(1 << 30)
)

var ErrJournal = errors.New("one-shot runtime request journal rejected")

type requestJournalRecord struct {
	SchemaVersion    string `json:"schemaVersion" required:"true"`
	AuthorizationID  string `json:"authorizationId" required:"true"`
	CeremonyID       string `json:"ceremonyId" required:"true"`
	Operation        string `json:"operation" required:"true"`
	RequestID        string `json:"requestId" required:"true"`
	PayloadDigest    string `json:"payloadDigest" required:"true"`
	Sequence         uint64 `json:"sequence" required:"true"`
	RequestExpiresAt int64  `json:"requestExpiresAt" required:"true"`
	CompletedAt      string `json:"completedAt" required:"true"`
	Status           string `json:"status" required:"true"`
	ResponseArtifact string `json:"responseArtifact" required:"true"`
	ResponseDigest   string `json:"responseDigest" required:"true"`
	ResponseSize     int64  `json:"responseSize" required:"true"`
}

type requestJournal struct {
	root         string
	records      map[[32]byte]requestJournalRecord
	requestIDs   map[[32]byte][32]byte
	maxSequences map[[32]byte]uint64
	totalBytes   int64
}

func openRequestJournal(stateRoot string) (*requestJournal, error) {
	if !filepath.IsAbs(stateRoot) {
		return nil, ErrJournal
	}
	root := filepath.Join(filepath.Clean(stateRoot), "runtime-request-journal")
	if err := ensureRuntimeDirectory(root); err != nil {
		return nil, err
	}
	journal := &requestJournal{
		root: root, records: make(map[[32]byte]requestJournalRecord), requestIDs: make(map[[32]byte][32]byte),
		maxSequences: make(map[[32]byte]uint64),
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > requestJournalMaxEntries*2 {
		return nil, ErrJournal
	}
	responseFiles := make(map[string]os.FileInfo)
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, ErrJournal
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return nil, ErrJournal
		}
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, ".response"):
			responseFiles[name] = info
		case strings.HasSuffix(name, ".meta.json"):
			var record requestJournalRecord
			if readStrictJSONExact(filepath.Join(root, name), &record, maxConfigBytes, 0o600) != nil || validateJournalRecord(record) != nil {
				return nil, ErrJournal
			}
			key, err := record.key()
			base := strings.TrimSuffix(name, ".meta.json")
			if err != nil || base != hex.EncodeToString(key[:]) || record.ResponseArtifact != base+".response" {
				return nil, ErrJournal
			}
			if _, duplicate := journal.records[key]; duplicate {
				return nil, ErrJournal
			}
			requestIDKey, err := record.requestIDKey()
			if err != nil {
				return nil, ErrJournal
			}
			if _, duplicate := journal.requestIDs[requestIDKey]; duplicate {
				return nil, ErrJournal
			}
			journal.records[key] = record
			journal.requestIDs[requestIDKey] = key
			sequenceKey, err := record.sequenceKey()
			if err != nil {
				return nil, ErrJournal
			}
			if record.Sequence > journal.maxSequences[sequenceKey] {
				journal.maxSequences[sequenceKey] = record.Sequence
			}
		default:
			return nil, ErrJournal
		}
	}
	if len(journal.records) != len(responseFiles) {
		return nil, ErrJournal
	}
	for _, record := range journal.records {
		info, ok := responseFiles[record.ResponseArtifact]
		if !ok || info.Size() != record.ResponseSize || info.Size() <= 0 || info.Size() > maxResponseBytes {
			return nil, ErrJournal
		}
		response, err := readRestrictedExact(filepath.Join(root, record.ResponseArtifact), maxResponseBytes, 0o600)
		if err != nil || sha256.Sum256(response) != mustDecode32(record.ResponseDigest) {
			return nil, ErrJournal
		}
		journal.totalBytes += info.Size()
	}
	if journal.totalBytes > requestJournalMaxBytes {
		return nil, ErrJournal
	}
	return journal, nil
}

func (j *requestJournal) lookup(request AuthorizedRequest) ([]byte, bool, error) {
	if j == nil {
		return nil, false, ErrJournal
	}
	key := journalRequestKey(request.AuthorizationID, request.CeremonyID, request.Operation, request.RequestID)
	record, exists := j.records[key]
	if !exists {
		requestIDKey := journalRequestIDKey(request.AuthorizationID, request.CeremonyID, request.RequestID)
		if _, collision := j.requestIDs[requestIDKey]; collision {
			return nil, false, ErrRequestReplay
		}
		sequenceKey := journalSequenceKey(request.AuthorizationID, request.CeremonyID)
		if request.Sequence <= j.maxSequences[sequenceKey] {
			return nil, false, ErrAuthorization
		}
		return nil, false, nil
	}
	if record.Operation != request.Operation || record.PayloadDigest != hex.EncodeToString(request.PayloadDigest[:]) ||
		record.Sequence != request.Sequence || record.RequestExpiresAt != request.ExpiresAtUnix {
		return nil, false, ErrRequestReplay
	}
	response, err := readRestrictedExact(filepath.Join(j.root, record.ResponseArtifact), maxResponseBytes, 0o600)
	if err != nil || int64(len(response)) != record.ResponseSize || sha256.Sum256(response) != mustDecode32(record.ResponseDigest) {
		return nil, false, ErrJournal
	}
	return response, true, nil
}

func (j *requestJournal) complete(request AuthorizedRequest, response []byte, now time.Time) error {
	if j == nil || len(response) == 0 || int64(len(response)) > maxResponseBytes || len(j.records) >= requestJournalMaxEntries ||
		j.totalBytes+int64(len(response)) > requestJournalMaxBytes {
		return ErrJournal
	}
	key := journalRequestKey(request.AuthorizationID, request.CeremonyID, request.Operation, request.RequestID)
	if _, exists := j.records[key]; exists {
		return ErrJournal
	}
	requestIDKey := journalRequestIDKey(request.AuthorizationID, request.CeremonyID, request.RequestID)
	if _, collision := j.requestIDs[requestIDKey]; collision {
		return ErrRequestReplay
	}
	base := hex.EncodeToString(key[:])
	responseName := base + ".response"
	responsePath := filepath.Join(j.root, responseName)
	if err := writeNoReplace(responsePath, response, 0o600); err != nil {
		return ErrJournal
	}
	responseDigest := sha256.Sum256(response)
	record := requestJournalRecord{
		SchemaVersion: requestJournalSchema, AuthorizationID: hex.EncodeToString(request.AuthorizationID[:]),
		CeremonyID: hex.EncodeToString(request.CeremonyID[:]), Operation: request.Operation,
		RequestID: hex.EncodeToString(request.RequestID[:]), PayloadDigest: hex.EncodeToString(request.PayloadDigest[:]),
		Sequence: request.Sequence, RequestExpiresAt: request.ExpiresAtUnix, CompletedAt: now.UTC().Format(timeFormat),
		Status: "COMPLETED", ResponseArtifact: responseName, ResponseDigest: hex.EncodeToString(responseDigest[:]), ResponseSize: int64(len(response)),
	}
	metadataPath := filepath.Join(j.root, base+".meta.json")
	if err := writeJSONNoReplace(metadataPath, record, 0o600); err != nil {
		_ = os.Remove(responsePath)
		return ErrJournal
	}
	j.records[key] = record
	j.requestIDs[requestIDKey] = key
	sequenceKey := journalSequenceKey(request.AuthorizationID, request.CeremonyID)
	if request.Sequence > j.maxSequences[sequenceKey] {
		j.maxSequences[sequenceKey] = request.Sequence
	}
	j.totalBytes += int64(len(response))
	return nil
}

func validateJournalRecord(record requestJournalRecord) error {
	if record.SchemaVersion != requestJournalSchema || !protectedOperation(record.Operation) || record.Sequence == 0 ||
		record.RequestExpiresAt <= 0 || record.Status != "COMPLETED" || record.ResponseSize <= 0 || record.ResponseSize > maxResponseBytes ||
		len(record.CompletedAt) != len(timeFormat) || !strings.HasSuffix(record.ResponseArtifact, ".response") {
		return ErrJournal
	}
	for _, value := range []string{record.AuthorizationID, record.CeremonyID, record.RequestID, record.PayloadDigest, record.ResponseDigest} {
		var decoded [32]byte
		if decodeFixed(value, decoded[:]) != nil {
			return ErrJournal
		}
	}
	if _, err := time.Parse(timeFormat, record.CompletedAt); err != nil {
		return ErrJournal
	}
	return nil
}

func (r requestJournalRecord) key() ([32]byte, error) {
	var authorizationID, ceremonyID, requestID [32]byte
	if decodeFixed(r.AuthorizationID, authorizationID[:]) != nil || decodeFixed(r.CeremonyID, ceremonyID[:]) != nil || decodeFixed(r.RequestID, requestID[:]) != nil {
		return [32]byte{}, ErrJournal
	}
	return journalRequestKey(authorizationID, ceremonyID, r.Operation, requestID), nil
}

func (r requestJournalRecord) requestIDKey() ([32]byte, error) {
	var authorizationID, ceremonyID, requestID [32]byte
	if decodeFixed(r.AuthorizationID, authorizationID[:]) != nil || decodeFixed(r.CeremonyID, ceremonyID[:]) != nil || decodeFixed(r.RequestID, requestID[:]) != nil {
		return [32]byte{}, ErrJournal
	}
	return journalRequestIDKey(authorizationID, ceremonyID, requestID), nil
}

func (r requestJournalRecord) sequenceKey() ([32]byte, error) {
	var authorizationID, ceremonyID [32]byte
	if decodeFixed(r.AuthorizationID, authorizationID[:]) != nil || decodeFixed(r.CeremonyID, ceremonyID[:]) != nil {
		return [32]byte{}, ErrJournal
	}
	return journalSequenceKey(authorizationID, ceremonyID), nil
}

func journalRequestKey(authorizationID, ceremonyID [32]byte, operation string, requestID [32]byte) [32]byte {
	data := append([]byte("MordantOneShotRequestJournalKey/v1\x00"), authorizationID[:]...)
	data = append(data, ceremonyID[:]...)
	data = append(data, []byte(operation)...)
	data = append(data, 0)
	data = append(data, requestID[:]...)
	return sha256.Sum256(data)
}

func journalRequestIDKey(authorizationID, ceremonyID, requestID [32]byte) [32]byte {
	data := append([]byte("MordantOneShotRequestJournalRequestID/v1\x00"), authorizationID[:]...)
	data = append(data, ceremonyID[:]...)
	data = append(data, requestID[:]...)
	return sha256.Sum256(data)
}

func journalSequenceKey(authorizationID, ceremonyID [32]byte) [32]byte {
	data := append([]byte("MordantOneShotRequestJournalSequence/v1\x00"), authorizationID[:]...)
	data = append(data, ceremonyID[:]...)
	return sha256.Sum256(data)
}

func ensureRuntimeDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return ErrJournal
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return ErrJournal
		}
		parent, openErr := os.Open(filepath.Dir(path))
		if openErr != nil {
			return ErrJournal
		}
		syncErr := parent.Sync()
		_ = parent.Close()
		if syncErr != nil {
			return ErrJournal
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrJournal
	}
	return nil
}

var ErrRequestReplay = errors.New("one-shot runtime request ID replay rejected")
