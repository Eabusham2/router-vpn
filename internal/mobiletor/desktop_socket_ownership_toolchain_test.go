package mobiletor

import "testing"

// These required account and commit regressions use test-only Go 1.25 synctest.
// An older CI toolchain or an omitted test file must fail the test build.
var (
	_ func(*testing.T) = TestDesktopDarwinGuardianUIDAbsenceWait
	_ func(*testing.T) = TestDesktopDarwinGuardianUIDObserverProtocol
	_ func(*testing.T) = TestDesktopDarwinUIDSearchRequiresOneExactLocalAndNativeIdentity
	_ func(*testing.T) = TestDesktopDarwinUIDSearchDiagnosticsDoNotDiscloseDirectoryValues
	_ func(*testing.T) = TestDesktopDarwinAccountDiagnosticsRemainBoundedAndDoNotDiscloseValues
	_ func(*testing.T) = TestDesktopDarwinAccountReadbackPreservesExactDisabledNativeIdentity
	_ func(*testing.T) = TestDesktopWindowsProtectionCommitValidation
	_ func(*testing.T) = TestDesktopWindowsProtectionCommitCopiesTargets
	_ func(*testing.T) = TestDesktopWindowsProtectionCommitCancellation
	_ func(*testing.T) = TestDesktopWindowsProtectionCommitJoinsCallback
)
