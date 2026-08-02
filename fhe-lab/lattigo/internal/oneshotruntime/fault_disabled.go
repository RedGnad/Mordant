//go:build !oneshot_runtime_faulttest

package oneshotruntime

func (s *OperatorService) runtimeFault(string, string) {}

func runtimeJournalLimits() (int, int64) {
	return requestJournalMaxEntries, requestJournalMaxBytes
}
