//go:build oneshot_runtime_faulttest

package oneshotruntime

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strconv"
)

// runtimeFault is compiled only into the dedicated test operator binary. No
// normal build or runtime configuration can activate these crash points.
func (s *OperatorService) runtimeFault(point, operation string) {
	if s == nil || os.Getenv("MORDANT_ONESHOT_FAULT") != point+":"+operation ||
		os.Getenv("MORDANT_ONESHOT_FAULT_POINT") != strconv.FormatUint(s.identity.Point, 10) {
		return
	}
	digest := sha256.Sum256([]byte(point + "\x00" + operation))
	marker := filepath.Join(s.config.StateRoot, "runtime-fault-"+encodeHex(digest[:8])+".fired")
	if _, err := os.Lstat(marker); err == nil {
		return
	}
	if writeNoReplace(marker, []byte("TEST-ONLY RUNTIME FAULT FIRED\n"), 0o600) != nil {
		os.Exit(87)
	}
	os.Exit(86)
}

func runtimeJournalLimits() (int, int64) {
	entries := requestJournalMaxEntries
	bytes := requestJournalMaxBytes
	if value, err := strconv.Atoi(os.Getenv("MORDANT_ONESHOT_TEST_JOURNAL_MAX_ENTRIES")); err == nil && value > 0 {
		entries = value
	}
	if value, err := strconv.ParseInt(os.Getenv("MORDANT_ONESHOT_TEST_JOURNAL_MAX_BYTES"), 10, 64); err == nil && value > 0 {
		bytes = value
	}
	return entries, bytes
}
