package main

import (
	"crypto/sha256"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Read only the participants in this captured graph. Do not mutate either
// saved profile or substitute the final's protection for its original entry.
// Native source/journal/proof validation remains independently mandatory.
func desktopExternalProtectionPolicy(profile, entry common.RouterProfile, direct bool) string {
	if profile.ID == "" || direct && entry.ID != "" || !direct && (entry.ID == "" || entry.ID == profile.ID) {
		return ""
	}
	entryPolicy := ""
	if !direct {
		entryPolicy = desktopOwnedNodeProtectionPolicy(entry)
	}
	policy, err := mobilemultihop.AggregateExternalProtectionPolicy(desktopOwnedNodeProtectionPolicy(profile), entryPolicy)
	if err != nil {
		return ""
	}
	return policy
}

// Captured once by the original compiler. Hot ownership observations compare
// hashes and exact member policies without recompiling the original graph.
type desktopExternalProtectionCapture struct {
	source, capture                  [32]byte
	sourceID, finalID, entryID       string
	finalPolicy, entryPolicy, policy string
}

func captureDesktopExternalProtection(original *mobilemultihop.ExternalPolicy, source, capture []byte) desktopExternalProtectionCapture {
	if original == nil {
		return desktopExternalProtectionCapture{}
	}
	value, err := original.DesktopCapture()
	if err != nil {
		return desktopExternalProtectionCapture{}
	}
	return desktopExternalProtectionCapture{source: sha256.Sum256(source), capture: sha256.Sum256(capture), sourceID: value.SourceSHA256, finalID: value.ExitID, entryID: value.EntryID, finalPolicy: value.FinalKillSwitchPolicy, entryPolicy: value.EntryKillSwitchPolicy, policy: value.KillSwitchPolicy}
}
func desktopExternalCapturedProtectionPolicy(owner *desktopExternalRuntime) string {
	if owner == nil {
		return ""
	}
	c := owner.protection
	policy := desktopExternalProtectionPolicy(owner.profile, owner.entry, owner.direct)
	entryPolicy := ""
	if !owner.direct {
		entryPolicy = desktopOwnedNodeProtectionPolicy(owner.entry)
	}
	if c.policy == "" || policy != c.policy || owner.direct != (c.entryID == "") || c.finalID != owner.profile.ID || c.entryID != owner.entry.ID || c.finalPolicy != desktopOwnedNodeProtectionPolicy(owner.profile) || c.entryPolicy != entryPolicy || c.sourceID != owner.expected.SourceSHA256 || c.source != sha256.Sum256(owner.source) || c.capture != sha256.Sum256(owner.capture) {
		return ""
	}
	if owner.physical != nil {
		meta := owner.physical.Metadata()
		if meta.OriginalSourceSHA256 != c.sourceID || meta.KillSwitchPolicy != c.policy {
			return ""
		}
	}
	return c.policy
}

// This obligation is captured by the original compiler independently of the
// protection seal. A missing seal must refuse an originally native Off graph,
// while a graph outside this platform's retained scope keeps its legacy path.
func desktopExternalOffTargetBit(target string) uint8 {
	switch target {
	case "linux":
		return 1
	case "windows":
		return 2
	case "darwin":
		return 4
	}
	return 0
}
func desktopExternalOffShapeForOS(owner *desktopExternalRuntime, target string) bool {
	if owner == nil {
		return false
	}
	if target == "windows" {
		return desktopWindowsExternalGraphEligible(owner.profile, owner.entry, owner.direct, owner.selection)
	}
	if owner.predecessor != "" || target != "linux" && target != "darwin" {
		return false
	}
	if !owner.direct {
		if target == "linux" {
			return desktopExternalLinuxEntryOwner(owner)
		}
		return desktopExternalPacketEntryOwner(owner) || desktopExternalSSEntryOwner(owner) || desktopExternalOpenVPNEntryOwner(owner)
	}
	if owner.selection != "local" || owner.entry.ID != "" || owner.profile.External == nil {
		return false
	}
	if target == "darwin" {
		return desktopWindowsExternalProfileEligible(owner.profile, true, "local")
	}
	return desktopExternalStartLayerSupported(owner.profile.External.Protocol, owner.profile.StartLayer) && desktopExternalDarwinProtocol(owner.profile.External.Protocol)
}
func desktopExternalOriginalOffTargets(owner *desktopExternalRuntime) uint8 {
	if desktopExternalCapturedProtectionPolicy(owner) != "off" {
		return 0
	}
	var result uint8
	for _, target := range []string{"linux", "windows", "darwin"} {
		if desktopExternalOffShapeForOS(owner, target) {
			result |= desktopExternalOffTargetBit(target)
		}
	}
	return result
}
func desktopExternalOffRequiresRetainedForOS(owner *desktopExternalRuntime, target string) bool {
	if owner == nil || desktopExternalOffTargetBit(target) == 0 {
		return false
	}
	return owner.offRetainedTargets&desktopExternalOffTargetBit(target) != 0 || desktopExternalProtectionPolicy(owner.profile, owner.entry, owner.direct) == "off" && desktopExternalOffShapeForOS(owner, target)
}
