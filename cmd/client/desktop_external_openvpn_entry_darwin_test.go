//go:build darwin

package main

import "testing"

func TestDesktopDarwinOpenVPNEntryDoesNotBorrowLinuxEligibility(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		_, _, launch := desktopExternalOpenVPNEntryFixture(t, network)
		if !desktopExternalOpenVPNEntryOwner(launch.external) {
			t.Fatal("fixture lost original bounded pair")
		}
		if desktopMacOSExternalEligible(launch) {
			t.Fatal("Linux-only ordinary OpenVPN entry claimed native Darwin eligibility")
		}
	}
}

func TestDesktopDarwinExternalFallbackCannotBorrowWindowsEntry(t *testing.T) {
	_, _, launch := desktopWindowsRouterServerFixture(t, "server")
	if !desktopWindowsExternalEligible(launch) || desktopExternalRetainedEntryForOS(launch.external, "darwin") {
		t.Fatal("fixture lost its Windows-only composed authority")
	}
	if desktopMacOSExternalEligible(launch) {
		t.Fatal("direct fallback borrowed a composed Windows native owner")
	}
}
