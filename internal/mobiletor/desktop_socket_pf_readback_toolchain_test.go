package mobiletor

import "testing"

// These required readback regressions use the test-only Go 1.25 synctest API.
// An older CI toolchain or an omitted test file must fail the test build.
var (
	_ func(*testing.T) = TestDesktopPFReadbackCompleteWithinCapturedBudget
	_ func(*testing.T) = TestDesktopPFReadbackFailureAndCancellationJoin
	_ func(*testing.T) = TestDesktopPFReadbackDeadlineAndInvalidCapture
)
