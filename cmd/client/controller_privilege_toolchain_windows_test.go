//go:build windows && routervpn_controller_windows_native

package main

import "testing"

// These required regressions use test-only Go 1.25 synctest.
// An older CI toolchain or an omitted test file must fail the test build.
var (
	_ func(*testing.T) = TestWindowsOwnedControllerLauncherFixture
	_ func(*testing.T) = TestWindowsOwnedControllerPrivateRootRetainsNamespace
	_ func(*testing.T) = TestWindowsOwnedControllerProtectedSelfBeforeConfiguration
	_ func(*testing.T) = TestWindowsOwnedControllerProtectedSelfRetirement
	_ func(*testing.T) = TestWindowsOwnedControllerCodeAndPrivateACLPolicy
	_ func(*testing.T) = TestWindowsOwnedControllerNativeEntry
)
