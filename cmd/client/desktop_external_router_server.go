package main

import (
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This shape check carries no socket or relay authority. The captured compiler,
// physical adapter and original execution controller must independently retain
// the paired assets, authenticated proposal and live lease before activation.
func desktopWindowsExternalRouterServerProfile(profile common.RouterProfile, restored string) bool {
	if !desktopExternalSS2022Profile(profile) || profile.StartLayer != "" && profile.StartLayer != common.StartLayerOff ||
		profile.MultihopExecution != "server" || restored != "" && restored != "server" ||
		profile.MultihopEntryMode != "" && profile.MultihopEntryMode != "wg" {
		return false
	}
	policy := desktopOwnedNodeProtectionPolicy(profile)
	return policy == "on-connect" || policy == "always"
}

func desktopWindowsExternalRouterServerGraph(profile, entry common.RouterProfile, restored string) bool {
	if !desktopWindowsExternalRouterServerProfile(profile, restored) || entry.ID == "" || entry.ID == profile.ID ||
		entry.NodeKind != "router-vpn" && entry.NodeKind != "" || entry.External != nil ||
		entry.StartLayer != "" && entry.StartLayer != common.StartLayerOff ||
		!common.ValidNodeProofID(entry.NodeProofID) || entry.RouterAPI == "" || entry.APIToken == "" {
		return false
	}
	mode, err := desktopExternalEntryMode(profile, entry, "", "")
	return err == nil && mode == "wg"
}

func desktopWindowsExternalRouterServerOwner(owner *desktopExternalRuntime) bool {
	return owner != nil && !owner.direct && owner.selection == "server" && owner.predecessor != "" &&
		desktopWindowsExternalRouterServerGraph(owner.profile, owner.entry, owner.selection)
}

// The lease remains inside the original child execution controller. Its final
// result can only be adopted under this exact paired identity and selection.
// Local and Server keep the same original paired entry and independent final.
// Compare remains outside this native admission until both candidates and the
// complete comparison lifecycle have their own native acceptance.
func desktopWindowsExternalRouterPairedGraph(profile, entry common.RouterProfile, restored string) bool {
	if profile.MultihopExecution == "server" {
		return desktopWindowsExternalRouterServerGraph(profile, entry, restored)
	}
	if profile.MultihopExecution != "local" || restored != "" && restored != "local" {
		return false
	}
	shape := cloneRouterProfile(profile)
	shape.MultihopExecution = "server"
	return desktopWindowsExternalRouterServerGraph(shape, entry, "")
}

func desktopWindowsExternalRouterPairedOwner(owner *desktopExternalRuntime) bool {
	return owner != nil && !owner.direct && owner.predecessor != "" &&
		(owner.selection == "local" || owner.selection == "server") && owner.selection == owner.profile.MultihopExecution &&
		desktopWindowsExternalRouterPairedGraph(owner.profile, owner.entry, owner.selection)
}

func desktopWindowsExternalExecutionProof(owner *desktopExternalRuntime, proof mobilemultihop.ExternalProofResult) bool {
	if desktopWindowsExternalRouterPairedOwner(owner) {
		return proof.Execution == owner.selection && proof.EntryNodeID == owner.entry.NodeProofID && proof.EntryNodeID == owner.expected.EntryNodeID
	}
	return proof.Execution == "local" && proof.EntryNodeID == ""
}
