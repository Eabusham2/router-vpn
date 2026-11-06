package main

import (
	"errors"
	"router-vpn/internal/common"
)

// Graph admission is deliberately narrower than an external final's shape.
// Only this captured SS2022 entry pair gains the Windows retained host.
func desktopWindowsExternalGraphEligible(profile, entry common.RouterProfile, direct bool, restored string) bool {
	if !direct && desktopWindowsExternalRouterPairedGraph(profile, entry, restored) {
		return true
	}
	if !desktopWindowsExternalProfileEligible(profile, direct, restored) {
		return false
	}
	if direct {
		return entry.ID == ""
	}
	return desktopWindowsExternalSSEntryOwner(&desktopExternalRuntime{profile: profile, entry: entry, selection: "local"})
}

// app.mu is held. Compare the independently saved original entry, including
// options excluded from its source token, before publication or proof adoption.
func (owner *desktopWindowsExternalRuntime) entryCurrentLocked() bool {
	if owner == nil || owner.app == nil || owner.launch == nil || owner.launch.external == nil {
		return false
	}
	source := owner.launch.external
	if source.direct {
		return source.entry.ID == "" && owner.entryToken == ""
	}
	entry, found := owner.app.profileByIDLocked(source.entry.ID)
	return found && owner.entryToken != "" && desktopOwnedNodeProfileToken(entry) == owner.entryToken &&
		[3]bool{entry.DAITAEnabled, entry.JumboTUN, entry.SocksEnabled} == [3]bool{source.entry.DAITAEnabled, source.entry.JumboTUN, source.entry.SocksEnabled}
}

// Caller holds external.mu followed by app.mu, matching both proof observers.
func (owner *desktopWindowsExternalRuntime) sourcesCurrentLocked(profile common.RouterProfile) error {
	if !desktopWindowsExternalEligible(owner.launch) || !owner.entryCurrentLocked() {
		return errors.New("native external owner replaced its independently captured entry")
	}
	if owner.launch.external.direct {
		return validateDesktopWindowsExternalSourceLocked(profile, owner.launch)
	}
	entry, _ := owner.app.profileByIDLocked(owner.launch.external.entry.ID)
	return validateDesktopRetainedExternalSourcesLocked(profile, entry, owner.launch)
}

// Windows retains the same bounded ordinary SS2022 final family after the
// platform's own physical policy and native host have been selected.
func desktopWindowsExternalSSEntryFinalProfile(profile common.RouterProfile) bool {
	return desktopExternalSSEntryFinalProfile(profile)
}
func desktopWindowsExternalSSEntryOwner(owner *desktopExternalRuntime) bool {
	return desktopExternalSSEntryOwnerWithFinal(owner, desktopWindowsExternalSSEntryFinalProfile)
}
