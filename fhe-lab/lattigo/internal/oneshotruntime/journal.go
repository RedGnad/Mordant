package oneshotruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	requestJournalSchema       = "mordant.oneshot-request-journal/2"
	sessionTerminalSchema      = "mordant.oneshot-journal-session-terminal/1"
	journalStatusPending       = "PENDING"
	journalStatusCompleted     = "COMPLETED"
	journalStatusIndeterminate = "INDETERMINATE_TERMINAL"
	requestJournalMaxEntries   = 4096
	requestJournalMaxBytes     = int64(1 << 30)
	journalMetadataReserve     = int64(64 << 10)
	indeterminateCode          = "INDETERMINATE_TERMINAL_ABORT"
)

var (
	ErrJournal              = errors.New("one-shot runtime request journal rejected")
	ErrJournalExhausted     = errors.New("one-shot runtime request journal exhausted")
	ErrRequestReplay        = errors.New("one-shot runtime request ID replay rejected")
	ErrRequestPending       = errors.New("one-shot runtime request pending")
	ErrSessionIndeterminate = errors.New("one-shot runtime session indeterminate terminal")
)

type journalRequestBinding struct {
	OperatorPoint        uint64
	AuthorizationID      [32]byte
	AuthorizationDigest  [32]byte
	CeremonyID           [32]byte
	ContextDigest        [32]byte
	SessionBindingDigest [32]byte
	Operation            string
	RequestID            [32]byte
	Sequence             uint64
	PayloadDigest        [32]byte
	RequestExpiresAt     int64
}

type requestJournalRecord struct {
	SchemaVersion        string `json:"schemaVersion" required:"true"`
	Status               string `json:"status" required:"true"`
	OperatorPoint        uint64 `json:"operatorPoint" required:"true"`
	AuthorizationID      string `json:"authorizationId" required:"true"`
	AuthorizationDigest  string `json:"authorizationDigest" required:"true"`
	CeremonyID           string `json:"ceremonyId" required:"true"`
	ContextDigest        string `json:"contextDigest" required:"true"`
	SessionBindingDigest string `json:"sessionBindingDigest" required:"true"`
	Operation            string `json:"operation" required:"true"`
	RequestID            string `json:"requestId" required:"true"`
	Sequence             uint64 `json:"sequence" required:"true"`
	PayloadDigest        string `json:"payloadDigest" required:"true"`
	RequestExpiresAt     int64  `json:"requestExpiresAt" required:"true"`
	ResponseLimit        int64  `json:"responseLimit" required:"true"`
	AdmittedAt           string `json:"admittedAt" required:"true"`
	FinishedAt           string `json:"finishedAt,omitempty"`
	HTTPStatus           int    `json:"httpStatus,omitempty"`
	ResponseArtifact     string `json:"responseArtifact,omitempty"`
	ResponseDigest       string `json:"responseDigest,omitempty"`
	ResponseSize         int64  `json:"responseSize,omitempty"`
	TerminalReason       string `json:"terminalReason,omitempty"`
}

type sessionTerminalRecord struct {
	SchemaVersion        string `json:"schemaVersion" required:"true"`
	SessionBindingDigest string `json:"sessionBindingDigest" required:"true"`
	CauseRequestKey      string `json:"causeRequestKey" required:"true"`
	Reason               string `json:"reason" required:"true"`
	CreatedAt            string `json:"createdAt" required:"true"`
}

type journalEntry struct {
	key       [32]byte
	admission requestJournalRecord
	final     requestJournalRecord
	status    string
}

type journalLookupResult struct {
	Status     string
	HTTPStatus int
	Response   []byte
	Found      bool
	RequestKey [32]byte
}

type requestJournal struct {
	root               string
	operatorPoint      uint64
	records            map[[32]byte]*journalEntry
	requestIDs         map[[32]byte][32]byte
	maxSequences       map[[32]byte]uint64
	terminatedSessions map[[32]byte]sessionTerminalRecord
	totalBytes         int64
	reservedBytes      int64
	maxEntries         int
	maxBytes           int64
}

type journalDiskGroup struct {
	base                 string
	pendingPath          string
	completedPath        string
	indeterminatePath    string
	responsePath         string
	terminalResponsePath string
}

func openRequestJournal(stateRoot string, operatorPoint uint64) (*requestJournal, error) {
	if !filepath.IsAbs(stateRoot) || operatorPoint == 0 {
		return nil, ErrJournal
	}
	root := filepath.Join(filepath.Clean(stateRoot), "runtime-request-journal")
	if err := ensureRuntimeDirectory(root); err != nil {
		return nil, err
	}
	maxEntries, maxBytes := runtimeJournalLimits()
	if maxEntries <= 0 || maxEntries > requestJournalMaxEntries || maxBytes <= 0 || maxBytes > requestJournalMaxBytes {
		return nil, ErrJournal
	}
	journal := &requestJournal{
		root: root, operatorPoint: operatorPoint, records: make(map[[32]byte]*journalEntry),
		requestIDs: make(map[[32]byte][32]byte), maxSequences: make(map[[32]byte]uint64),
		terminatedSessions: make(map[[32]byte]sessionTerminalRecord), maxEntries: maxEntries, maxBytes: maxBytes,
	}
	groups, terminals, err := journal.scanDisk()
	if err != nil {
		return nil, err
	}
	for _, path := range terminals {
		var terminal sessionTerminalRecord
		if readStrictJSONExact(path, &terminal, maxConfigBytes, 0o600) != nil || validateSessionTerminal(terminal) != nil {
			return nil, ErrJournal
		}
		var sessionBinding [32]byte
		if decodeFixed(terminal.SessionBindingDigest, sessionBinding[:]) != nil ||
			filepath.Base(path) != sessionTerminalName(sessionBinding) {
			return nil, ErrJournal
		}
		if _, duplicate := journal.terminatedSessions[sessionBinding]; duplicate {
			return nil, ErrJournal
		}
		journal.terminatedSessions[sessionBinding] = terminal
	}
	if len(groups) > journal.maxEntries {
		return nil, ErrJournal
	}
	for _, group := range groups {
		if err := journal.loadGroup(group); err != nil {
			return nil, err
		}
	}
	if journal.totalBytes > journal.maxBytes || len(journal.records) > journal.maxEntries {
		return nil, ErrJournal
	}
	return journal, nil
}

func (j *requestJournal) scanDisk() (map[string]*journalDiskGroup, []string, error) {
	entries, err := os.ReadDir(j.root)
	if err != nil || len(entries) > j.maxEntries*7 {
		return nil, nil, ErrJournal
	}
	groups := make(map[string]*journalDiskGroup)
	terminals := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, nil, ErrJournal
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxResponseBytes {
			return nil, nil, ErrJournal
		}
		j.totalBytes += info.Size()
		name := entry.Name()
		path := filepath.Join(j.root, name)
		if strings.HasPrefix(name, "session-") && strings.HasSuffix(name, ".terminal.json") {
			terminals = append(terminals, path)
			continue
		}
		base, kind, ok := classifyJournalFile(name)
		if !ok || !validJournalBase(base) {
			return nil, nil, ErrJournal
		}
		group := groups[base]
		if group == nil {
			group = &journalDiskGroup{base: base}
			groups[base] = group
		}
		target := ""
		switch kind {
		case "pending":
			target, group.pendingPath = group.pendingPath, path
		case "completed":
			target, group.completedPath = group.completedPath, path
		case "indeterminate":
			target, group.indeterminatePath = group.indeterminatePath, path
		case "response":
			target, group.responsePath = group.responsePath, path
		case "terminal-response":
			target, group.terminalResponsePath = group.terminalResponsePath, path
		}
		if target != "" {
			return nil, nil, ErrJournal
		}
	}
	return groups, terminals, nil
}

func (j *requestJournal) loadGroup(group *journalDiskGroup) error {
	if group == nil || group.pendingPath == "" || group.completedPath != "" && group.indeterminatePath != "" {
		return ErrJournal
	}
	var admission requestJournalRecord
	if readStrictJSONExact(group.pendingPath, &admission, maxConfigBytes, 0o600) != nil ||
		validateJournalRecord(admission, journalStatusPending) != nil {
		return ErrJournal
	}
	binding, err := admission.binding()
	key := journalRequestKey(binding)
	if err != nil || binding.OperatorPoint != j.operatorPoint || group.base != hex.EncodeToString(key[:]) ||
		filepath.Base(group.pendingPath) != group.base+".pending.json" {
		return ErrJournal
	}
	if _, duplicate := j.records[key]; duplicate {
		return ErrJournal
	}
	requestIDKey := journalRequestIDKey(binding.RequestID)
	if _, duplicate := j.requestIDs[requestIDKey]; duplicate {
		return ErrJournal
	}
	entry := &journalEntry{key: key, admission: admission, status: journalStatusPending}
	j.records[key] = entry
	j.requestIDs[requestIDKey] = key
	sequenceKey := journalSequenceKey(binding)
	if binding.Sequence > j.maxSequences[sequenceKey] {
		j.maxSequences[sequenceKey] = binding.Sequence
	}

	switch {
	case group.completedPath != "":
		if group.responsePath == "" || group.terminalResponsePath != "" {
			return ErrJournal
		}
		var completed requestJournalRecord
		if readStrictJSONExact(group.completedPath, &completed, maxConfigBytes, 0o600) != nil ||
			validateJournalRecord(completed, journalStatusCompleted) != nil || !sameJournalBinding(admission, completed) ||
			completed.ResponseArtifact != group.base+".response" {
			return ErrJournal
		}
		response, err := readRestrictedExact(group.responsePath, admission.ResponseLimit, 0o600)
		if err != nil || int64(len(response)) != completed.ResponseSize || sha256.Sum256(response) != mustDecode32(completed.ResponseDigest) {
			return ErrJournal
		}
		entry.final, entry.status = completed, journalStatusCompleted
	case group.indeterminatePath != "":
		if group.terminalResponsePath == "" {
			return ErrJournal
		}
		var terminal requestJournalRecord
		if readStrictJSONExact(group.indeterminatePath, &terminal, maxConfigBytes, 0o600) != nil ||
			validateJournalRecord(terminal, journalStatusIndeterminate) != nil || !sameJournalBinding(admission, terminal) ||
			terminal.ResponseArtifact != group.base+".terminal.response" || terminal.TerminalReason == "" {
			return ErrJournal
		}
		response, err := readRestrictedExact(group.terminalResponsePath, admission.ResponseLimit, 0o600)
		if err != nil || int64(len(response)) != terminal.ResponseSize || sha256.Sum256(response) != mustDecode32(terminal.ResponseDigest) ||
			!bytes.Equal(response, indeterminateResponseBytes()) {
			return ErrJournal
		}
		entry.final, entry.status = terminal, journalStatusIndeterminate
		if err := j.ensureSessionTerminal(binding.SessionBindingDigest, key, terminal.TerminalReason, time.Now().UTC()); err != nil {
			return err
		}
	default:
		if group.responsePath != "" {
			info, err := os.Lstat(group.responsePath)
			if err != nil || info.Size() > admission.ResponseLimit {
				return ErrJournal
			}
		}
		if err := j.recoverPending(entry, group, time.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}

func (j *requestJournal) lookup(binding journalRequestBinding, now time.Time) (journalLookupResult, error) {
	if j == nil || validateJournalBinding(binding) != nil || binding.OperatorPoint != j.operatorPoint {
		return journalLookupResult{}, ErrJournal
	}
	prior, err := j.lookupExact(binding)
	if err != nil || prior.Found {
		return prior, err
	}
	if _, collision := j.requestIDs[journalRequestIDKey(binding.RequestID)]; collision {
		return journalLookupResult{}, ErrRequestReplay
	}
	if _, terminated := j.terminatedSessions[binding.SessionBindingDigest]; terminated {
		return journalLookupResult{}, ErrSessionIndeterminate
	}
	sequenceKey := journalSequenceKey(binding)
	if binding.Sequence <= j.maxSequences[sequenceKey] {
		if err := j.ensureSessionTerminal(binding.SessionBindingDigest, journalRequestKey(binding), "RUNNER_SEQUENCE_REGRESSION", now); err != nil {
			return journalLookupResult{}, err
		}
		return journalLookupResult{}, ErrSessionIndeterminate
	}
	return journalLookupResult{RequestKey: journalRequestKey(binding)}, nil
}

// lookupExact has no side effects. It permits a cryptographically verified
// exact retry to recover its retained bytes before any participant is restored.
func (j *requestJournal) lookupExact(binding journalRequestBinding) (journalLookupResult, error) {
	if j == nil || validateJournalBinding(binding) != nil || binding.OperatorPoint != j.operatorPoint {
		return journalLookupResult{}, ErrJournal
	}
	key := journalRequestKey(binding)
	if entry, exists := j.records[key]; exists {
		if !recordMatchesBinding(entry.admission, binding) {
			return journalLookupResult{}, ErrRequestReplay
		}
		switch entry.status {
		case journalStatusCompleted, journalStatusIndeterminate:
			response, err := readRestrictedExact(filepath.Join(j.root, entry.final.ResponseArtifact), entry.admission.ResponseLimit, 0o600)
			if err != nil || int64(len(response)) != entry.final.ResponseSize || sha256.Sum256(response) != mustDecode32(entry.final.ResponseDigest) {
				return journalLookupResult{}, ErrJournal
			}
			return journalLookupResult{Status: entry.status, HTTPStatus: entry.final.HTTPStatus, Response: response, Found: true, RequestKey: key}, nil
		case journalStatusPending:
			return journalLookupResult{Status: journalStatusPending, Found: true, RequestKey: key}, ErrRequestPending
		default:
			return journalLookupResult{}, ErrJournal
		}
	}
	return journalLookupResult{RequestKey: key}, nil
}

func (j *requestJournal) admit(binding journalRequestBinding, responseLimit int64, now time.Time) error {
	if j == nil || validateJournalBinding(binding) != nil || binding.OperatorPoint != j.operatorPoint || responseLimit <= 0 || responseLimit > maxResponseBytes {
		return ErrJournal
	}
	if _, exists := j.records[journalRequestKey(binding)]; exists || len(j.records) >= j.maxEntries {
		return ErrJournalExhausted
	}
	if _, collision := j.requestIDs[journalRequestIDKey(binding.RequestID)]; collision {
		return ErrRequestReplay
	}
	if _, terminal := j.terminatedSessions[binding.SessionBindingDigest]; terminal {
		return ErrSessionIndeterminate
	}
	sequenceKey := journalSequenceKey(binding)
	if binding.Sequence <= j.maxSequences[sequenceKey] {
		if err := j.ensureSessionTerminal(binding.SessionBindingDigest, journalRequestKey(binding), "RUNNER_SEQUENCE_REGRESSION", now); err != nil {
			return err
		}
		return ErrSessionIndeterminate
	}
	record := newJournalRecord(binding, journalStatusPending, responseLimit, now)
	encoded, err := journalJSONBytes(record)
	if err != nil || int64(len(encoded)) > maxConfigBytes ||
		j.totalBytes+j.reservedBytes+int64(len(encoded))+responseLimit+journalMetadataReserve > j.maxBytes {
		return ErrJournalExhausted
	}
	key := journalRequestKey(binding)
	path := filepath.Join(j.root, hex.EncodeToString(key[:])+".pending.json")
	if err := writeJournalMarker(path, encoded); err != nil {
		return ErrJournal
	}
	j.totalBytes += int64(len(encoded))
	j.reservedBytes += responseLimit + journalMetadataReserve
	j.records[key] = &journalEntry{key: key, admission: record, status: journalStatusPending}
	j.requestIDs[journalRequestIDKey(binding.RequestID)] = key
	j.maxSequences[sequenceKey] = binding.Sequence
	return nil
}

func (j *requestJournal) persistResponse(binding journalRequestBinding, response []byte) error {
	entry, err := j.pendingEntry(binding)
	if err != nil || len(response) == 0 || int64(len(response)) > entry.admission.ResponseLimit {
		return ErrJournal
	}
	path := filepath.Join(j.root, hex.EncodeToString(entry.key[:])+".response")
	if err := writeNoReplace(path, response, 0o600); err != nil {
		return ErrJournal
	}
	j.totalBytes += int64(len(response))
	j.reservedBytes -= entry.admission.ResponseLimit
	return nil
}

func (j *requestJournal) complete(binding journalRequestBinding, response []byte, httpStatus int, now time.Time) error {
	entry, err := j.pendingEntry(binding)
	if err != nil || httpStatus < 200 || httpStatus > 599 {
		return ErrJournal
	}
	responseName := hex.EncodeToString(entry.key[:]) + ".response"
	persisted, err := readRestrictedExact(filepath.Join(j.root, responseName), entry.admission.ResponseLimit, 0o600)
	if err != nil || !bytes.Equal(persisted, response) {
		return ErrJournal
	}
	final := entry.admission
	final.Status = journalStatusCompleted
	final.FinishedAt = now.UTC().Format(timeFormat)
	final.HTTPStatus = httpStatus
	final.ResponseArtifact = responseName
	digest := sha256.Sum256(response)
	final.ResponseDigest = hex.EncodeToString(digest[:])
	final.ResponseSize = int64(len(response))
	encoded, err := journalJSONBytes(final)
	if err != nil || int64(len(encoded)) > journalMetadataReserve || j.totalBytes+j.reservedBytes+int64(len(encoded)) > j.maxBytes {
		return ErrJournal
	}
	path := filepath.Join(j.root, hex.EncodeToString(entry.key[:])+".completed.json")
	if err := writeJournalMarker(path, encoded); err != nil {
		return ErrJournal
	}
	j.totalBytes += int64(len(encoded))
	j.reservedBytes -= journalMetadataReserve
	entry.final, entry.status = final, journalStatusCompleted
	return nil
}

func (j *requestJournal) recoverPending(entry *journalEntry, group *journalDiskGroup, now time.Time) error {
	binding, err := entry.admission.binding()
	if err != nil {
		return ErrJournal
	}
	response := indeterminateResponseBytes()
	responseName := group.base + ".terminal.response"
	responsePath := filepath.Join(j.root, responseName)
	if group.terminalResponsePath == "" {
		if err := writeNoReplace(responsePath, response, 0o600); err != nil {
			return ErrJournal
		}
		j.totalBytes += int64(len(response))
	} else {
		existing, err := readRestrictedExact(responsePath, entry.admission.ResponseLimit, 0o600)
		if err != nil || !bytes.Equal(existing, response) {
			return ErrJournal
		}
	}
	terminal := entry.admission
	terminal.Status = journalStatusIndeterminate
	terminal.FinishedAt = now.UTC().Format(timeFormat)
	terminal.HTTPStatus = 409
	terminal.ResponseArtifact = responseName
	digest := sha256.Sum256(response)
	terminal.ResponseDigest = hex.EncodeToString(digest[:])
	terminal.ResponseSize = int64(len(response))
	terminal.TerminalReason = "UNRESOLVED_PENDING_AFTER_RESTART"
	encoded, err := journalJSONBytes(terminal)
	if err != nil || int64(len(encoded)) > journalMetadataReserve {
		return ErrJournal
	}
	terminalPath := filepath.Join(j.root, group.base+".indeterminate.json")
	if err := writeNoReplace(terminalPath, encoded, 0o600); err != nil {
		return ErrJournal
	}
	j.totalBytes += int64(len(encoded))
	entry.final, entry.status = terminal, journalStatusIndeterminate
	if err := j.ensureSessionTerminal(binding.SessionBindingDigest, entry.key, terminal.TerminalReason, now); err != nil {
		return err
	}
	if j.totalBytes > j.maxBytes {
		return ErrJournal
	}
	return nil
}

func (j *requestJournal) ensureSessionTerminal(sessionBinding, cause [32]byte, reason string, now time.Time) error {
	if j == nil || zero32(sessionBinding) || zero32(cause) || reason == "" {
		return ErrJournal
	}
	if _, exists := j.terminatedSessions[sessionBinding]; exists {
		return nil
	}
	record := sessionTerminalRecord{
		SchemaVersion: sessionTerminalSchema, SessionBindingDigest: hex.EncodeToString(sessionBinding[:]),
		CauseRequestKey: hex.EncodeToString(cause[:]), Reason: reason, CreatedAt: now.UTC().Format(timeFormat),
	}
	encoded, err := journalJSONBytes(record)
	if err != nil || j.totalBytes+j.reservedBytes+int64(len(encoded)) > j.maxBytes {
		return ErrJournal
	}
	path := filepath.Join(j.root, sessionTerminalName(sessionBinding))
	if err := writeNoReplace(path, encoded, 0o600); err != nil {
		var existing sessionTerminalRecord
		if readStrictJSONExact(path, &existing, maxConfigBytes, 0o600) != nil || validateSessionTerminal(existing) != nil ||
			existing.SessionBindingDigest != record.SessionBindingDigest {
			return ErrJournal
		}
		j.terminatedSessions[sessionBinding] = existing
		return nil
	}
	j.totalBytes += int64(len(encoded))
	j.terminatedSessions[sessionBinding] = record
	return nil
}

func (j *requestJournal) pendingEntry(binding journalRequestBinding) (*journalEntry, error) {
	if j == nil {
		return nil, ErrJournal
	}
	entry := j.records[journalRequestKey(binding)]
	if entry == nil || entry.status != journalStatusPending || !recordMatchesBinding(entry.admission, binding) {
		return nil, ErrJournal
	}
	return entry, nil
}

func newJournalRecord(binding journalRequestBinding, status string, responseLimit int64, now time.Time) requestJournalRecord {
	return requestJournalRecord{
		SchemaVersion: requestJournalSchema, Status: status, OperatorPoint: binding.OperatorPoint,
		AuthorizationID: hex.EncodeToString(binding.AuthorizationID[:]), AuthorizationDigest: hex.EncodeToString(binding.AuthorizationDigest[:]),
		CeremonyID: hex.EncodeToString(binding.CeremonyID[:]), ContextDigest: hex.EncodeToString(binding.ContextDigest[:]),
		SessionBindingDigest: hex.EncodeToString(binding.SessionBindingDigest[:]), Operation: binding.Operation,
		RequestID: hex.EncodeToString(binding.RequestID[:]), Sequence: binding.Sequence,
		PayloadDigest: hex.EncodeToString(binding.PayloadDigest[:]), RequestExpiresAt: binding.RequestExpiresAt,
		ResponseLimit: responseLimit, AdmittedAt: now.UTC().Format(timeFormat),
	}
}

func (r requestJournalRecord) binding() (journalRequestBinding, error) {
	binding := journalRequestBinding{
		OperatorPoint: r.OperatorPoint, Operation: r.Operation, Sequence: r.Sequence, RequestExpiresAt: r.RequestExpiresAt,
	}
	if decodeFixed(r.AuthorizationID, binding.AuthorizationID[:]) != nil || decodeFixed(r.AuthorizationDigest, binding.AuthorizationDigest[:]) != nil ||
		decodeFixed(r.CeremonyID, binding.CeremonyID[:]) != nil || decodeFixed(r.ContextDigest, binding.ContextDigest[:]) != nil ||
		decodeFixed(r.SessionBindingDigest, binding.SessionBindingDigest[:]) != nil || decodeFixed(r.RequestID, binding.RequestID[:]) != nil ||
		decodeFixed(r.PayloadDigest, binding.PayloadDigest[:]) != nil || validateJournalBinding(binding) != nil {
		return journalRequestBinding{}, ErrJournal
	}
	return binding, nil
}

func validateJournalRecord(record requestJournalRecord, status string) error {
	if record.SchemaVersion != requestJournalSchema || record.Status != status || record.ResponseLimit <= 0 || record.ResponseLimit > maxResponseBytes ||
		record.AdmittedAt == "" {
		return ErrJournal
	}
	if _, err := time.Parse(timeFormat, record.AdmittedAt); err != nil {
		return ErrJournal
	}
	if _, err := record.binding(); err != nil {
		return ErrJournal
	}
	switch status {
	case journalStatusPending:
		if record.FinishedAt != "" || record.HTTPStatus != 0 || record.ResponseArtifact != "" || record.ResponseDigest != "" ||
			record.ResponseSize != 0 || record.TerminalReason != "" {
			return ErrJournal
		}
	case journalStatusCompleted:
		if record.FinishedAt == "" || record.HTTPStatus < 200 || record.HTTPStatus > 599 || record.ResponseArtifact == "" ||
			record.ResponseDigest == "" || record.ResponseSize <= 0 || record.ResponseSize > record.ResponseLimit || record.TerminalReason != "" {
			return ErrJournal
		}
	case journalStatusIndeterminate:
		if record.FinishedAt == "" || record.HTTPStatus != 409 || record.ResponseArtifact == "" || record.ResponseDigest == "" ||
			record.ResponseSize <= 0 || record.ResponseSize > record.ResponseLimit || record.TerminalReason == "" {
			return ErrJournal
		}
	default:
		return ErrJournal
	}
	if record.FinishedAt != "" {
		if _, err := time.Parse(timeFormat, record.FinishedAt); err != nil {
			return ErrJournal
		}
	}
	if record.ResponseDigest != "" {
		var digest [32]byte
		if decodeFixed(record.ResponseDigest, digest[:]) != nil {
			return ErrJournal
		}
	}
	return nil
}

func validateSessionTerminal(record sessionTerminalRecord) error {
	var sessionBinding, cause [32]byte
	if record.SchemaVersion != sessionTerminalSchema || record.Reason == "" ||
		decodeFixed(record.SessionBindingDigest, sessionBinding[:]) != nil || decodeFixed(record.CauseRequestKey, cause[:]) != nil ||
		zero32(sessionBinding) || zero32(cause) {
		return ErrJournal
	}
	if _, err := time.Parse(timeFormat, record.CreatedAt); err != nil {
		return ErrJournal
	}
	return nil
}

func validateJournalBinding(binding journalRequestBinding) error {
	if binding.OperatorPoint == 0 || zero32(binding.AuthorizationID) || zero32(binding.AuthorizationDigest) || zero32(binding.CeremonyID) ||
		zero32(binding.ContextDigest) || zero32(binding.SessionBindingDigest) ||
		!protectedOperation(binding.Operation) || zero32(binding.RequestID) || binding.Sequence == 0 || zero32(binding.PayloadDigest) ||
		binding.RequestExpiresAt <= 0 {
		return ErrJournal
	}
	return nil
}

func recordMatchesBinding(record requestJournalRecord, binding journalRequestBinding) bool {
	parsed, err := record.binding()
	return err == nil && parsed == binding
}

func sameJournalBinding(left, right requestJournalRecord) bool {
	leftBinding, leftErr := left.binding()
	rightBinding, rightErr := right.binding()
	return leftErr == nil && rightErr == nil && leftBinding == rightBinding && left.ResponseLimit == right.ResponseLimit && left.AdmittedAt == right.AdmittedAt
}

func journalRequestKey(binding journalRequestBinding) [32]byte {
	var encoder canonicalEncoder
	encoder.text("MordantOneShotRequestJournalKey/v2")
	encoder.u64(binding.OperatorPoint)
	encoder.fixed(binding.AuthorizationID[:])
	encoder.fixed(binding.AuthorizationDigest[:])
	encoder.fixed(binding.CeremonyID[:])
	encoder.fixed(binding.ContextDigest[:])
	encoder.fixed(binding.SessionBindingDigest[:])
	encoder.text(binding.Operation)
	encoder.fixed(binding.RequestID[:])
	return sha256.Sum256(encoder.bytes())
}

func journalRequestIDKey(requestID [32]byte) [32]byte {
	return sha256.Sum256(append([]byte("MordantOneShotRequestJournalGlobalRequestID/v2\x00"), requestID[:]...))
}

func journalSequenceKey(binding journalRequestBinding) [32]byte {
	var encoder canonicalEncoder
	encoder.text("MordantOneShotBilateralSequence/v2")
	encoder.u64(binding.OperatorPoint)
	encoder.fixed(binding.SessionBindingDigest[:])
	return sha256.Sum256(encoder.bytes())
}

func journalBinding(authorization SessionAuthorization, request AuthorizedRequest, operatorPoint uint64) journalRequestBinding {
	authorizationBytes, _ := authorization.MarshalBinary()
	authorizationDigest := sha256.Sum256(append([]byte("MordantOneShotJournalAuthorization/v2\x00"), authorizationBytes...))
	return journalRequestBinding{
		OperatorPoint: operatorPoint, AuthorizationID: request.AuthorizationID, AuthorizationDigest: authorizationDigest,
		CeremonyID: request.CeremonyID, ContextDigest: request.ContextDigest,
		SessionBindingDigest: authorization.SessionBindingDigest, Operation: request.Operation, RequestID: request.RequestID,
		Sequence: request.Sequence, PayloadDigest: request.PayloadDigest, RequestExpiresAt: request.ExpiresAtUnix,
	}
}

func writeJournalMarker(path string, data []byte) error {
	stage := path + ".stage"
	if err := writeNoReplace(stage, data, 0o600); err != nil {
		return ErrJournal
	}
	if err := os.Link(stage, path); err != nil {
		return ErrJournal
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil || directory.Sync() != nil || directory.Close() != nil {
		return ErrJournal
	}
	if err := os.Remove(stage); err != nil {
		return ErrJournal
	}
	directory, err = os.Open(filepath.Dir(path))
	if err != nil || directory.Sync() != nil || directory.Close() != nil {
		return ErrJournal
	}
	return nil
}

func journalJSONBytes(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, ErrJournal
	}
	return append(encoded, '\n'), nil
}

func classifyJournalFile(name string) (string, string, bool) {
	for _, item := range []struct {
		suffix string
		kind   string
	}{
		{suffix: ".terminal.response", kind: "terminal-response"},
		{suffix: ".indeterminate.json", kind: "indeterminate"},
		{suffix: ".completed.json", kind: "completed"},
		{suffix: ".pending.json", kind: "pending"},
		{suffix: ".response", kind: "response"},
	} {
		if strings.HasSuffix(name, item.suffix) {
			return strings.TrimSuffix(name, item.suffix), item.kind, true
		}
	}
	return "", "", false
}

func validJournalBase(base string) bool {
	var decoded [32]byte
	return decodeFixed(base, decoded[:]) == nil
}

func sessionTerminalName(sessionBinding [32]byte) string {
	return "session-" + hex.EncodeToString(sessionBinding[:]) + ".terminal.json"
}

func indeterminateResponseBytes() []byte {
	encoded, _ := json.Marshal(wireResponse{SchemaVersion: RuntimeWireSchema, OK: false, ErrorCode: indeterminateCode})
	return append(encoded, '\n')
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
