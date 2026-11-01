package windowsprotection

import "testing"

// These required recovery regressions use test-only Go 1.25 synctest.
// An older CI toolchain or an omitted test file must fail the test build.
var (
	_ func(*testing.T) = TestWindowsProtectionJournalRecoveryOwnedOrdering
	_ func(*testing.T) = TestWindowsProtectionJournalRecoveryRejectsMissingProof
	_ func(*testing.T) = TestWindowsProtectionJournalRecoveryExactWriteRetry
	_ func(*testing.T) = TestWindowsProtectionJournalRecoveryDurableErrorRetries
	_ func(*testing.T) = TestWindowsProtectionJournalRecoveryLostSnapshotStaysUnresolved
	_ func(*testing.T) = TestWindowsProtectionJournalRecoveryCancellationJoinsWriter
	_ func(*testing.T) = TestWindowsProtectionJournalRecoveryCapturesImmutableInputs
)
