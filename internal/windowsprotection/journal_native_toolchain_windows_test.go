//go:build windows && routervpn_windows_protection_native

package windowsprotection

import "testing"

// These required channel and admission regressions use test-only Go 1.25 synctest.
// Keep their native CI selection mandatory even when a test file is excluded.
var (
	_ func(*testing.T) = TestWindowsProtectionJournalChannelFixture
	_ func(*testing.T) = TestWindowsProtectionJournalChannelActualCommit
	_ func(*testing.T) = TestWindowsProtectionJournalChannelRejectsForgedServer
	_ func(*testing.T) = TestWindowsProtectionJournalChannelRejectsDifferentChild
	_ func(*testing.T) = TestWindowsProtectionJournalChannelFailedPersistence
	_ func(*testing.T) = TestWindowsProtectionJournalChannelLateReplacement
	_ func(*testing.T) = TestWindowsProtectionJournalChannelCloseJoinsAppend
	_ func(*testing.T) = TestWindowsProtectionJournalChannelRetirementOwnership
	_ func(*testing.T) = TestWindowsProtectionJournalAdmissionTwoPhaseCheckpoint
	_ func(*testing.T) = TestWindowsProtectionJournalAdmissionPreparedReadFailures
	_ func(*testing.T) = TestWindowsProtectionJournalAdmissionSettlementWriteFailure
	_ func(*testing.T) = TestWindowsProtectionJournalAdmissionOperationReplacement
	_ func(*testing.T) = TestWindowsProtectionJournalAdmissionCandidateMismatch
	_ func(*testing.T) = TestWindowsProtectionJournalAdmissionCloseJoinsPreparedRead
	_ func(*testing.T) = TestWindowsProtectionJournalAdmissionRetainedAdmissionClose
)
