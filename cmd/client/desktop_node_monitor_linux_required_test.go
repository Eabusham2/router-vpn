//go:build linux

package main

import "testing"

// These lifecycle regressions require the CI toolchain's deterministic
// scheduler. A toolchain that omits them must fail tests, not silently pass;
// production application compatibility remains governed by the module.
var _ = []func(*testing.T){
	TestDesktopLinuxNodeMonitorActivationLifetime,
	TestDesktopLinuxNodeMonitorConfirmedFailure,
	TestDesktopLinuxNodeMonitorTransientObservation,
	TestDesktopLinuxNodeMonitorBusyOperationAndCancel,
	TestDesktopLinuxNodeMonitorReplacedCapture,
	TestDesktopLinuxNodeMonitorRevalidatesObservation,
	TestDesktopLinuxNodeMonitorPreservesReplacementAfterStop,
	TestDesktopLinuxNodeMonitorJoinsBlockedObservation,
	TestDesktopLinuxNodeMonitorRetirementRetry,
	TestDesktopLinuxNodeMonitorGateContention,
	TestDesktopLinuxNodeMonitorCancelGateWait,
	TestDesktopLinuxNodeMonitorEnteredProofTimeout,
	TestDesktopLinuxNodeMonitorJoinReleasesHostGate,
	TestDesktopLinuxNodeMonitorForeignRetirement,
	TestDesktopLinuxNodeMonitorRejectsStartupReplay,
}
