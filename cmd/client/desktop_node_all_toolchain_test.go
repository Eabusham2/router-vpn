//go:build routervpn_node_all_prospective

package main

import "testing"

// These required regressions use test-only Go 1.25 synctest.
// An older CI toolchain or an omitted test file must fail the test build.
var (
	_ func(*testing.T) = TestDesktopNodeProspectiveALLProvesOrderedFallback
	_ func(*testing.T) = TestDesktopNodeProspectiveALLFailureRetainsSelectedProtection
	_ func(*testing.T) = TestDesktopNodeProspectiveALLStopsAtUnjoinedAttempt
	_ func(*testing.T) = TestDesktopNodeProspectiveALLTemporaryRestoreKeepsExactWinner
)
