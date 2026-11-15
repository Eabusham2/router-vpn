package main

import (
	"router-vpn/internal/common"
	"router-vpn/internal/nativeopenvpn"
)

// Linux, Windows and Darwin retained hosts admit only this ordinary Local pair. The
// shared native proof must retain the connected entry generation and capacity;
// the source shape cannot bypass physical preparation or grant a socket itself.
func desktopExternalOpenVPNEntryOwner(owner *desktopExternalRuntime) bool {
	if owner == nil || owner.direct || owner.predecessor != "" || owner.selection != "local" ||
		owner.entry.NodeKind != "external" || owner.entry.External == nil || owner.entry.External.Protocol != "openvpn" || owner.entry.External.OpenVPN == nil ||
		!desktopExternalSS2022Profile(owner.profile) || owner.entry.ID == "" || owner.entry.ID == owner.profile.ID ||
		owner.entry.StartLayer != "" && owner.entry.StartLayer != common.StartLayerOff || owner.entry.External.StartLayer != nil ||
		owner.profile.StartLayer != "" && owner.profile.StartLayer != common.StartLayerOff || owner.profile.External.StartLayer != nil ||
		owner.profile.MultihopExecution != "" && owner.profile.MultihopExecution != "local" || owner.profile.MultihopEntryMode != "" {
		return false
	}
	policy := desktopOwnedNodeProtectionPolicy(owner.profile)
	if policy != "on-connect" && policy != "always" {
		return false
	}
	endpoint, err := nativeopenvpn.CompileProfile(*owner.entry.External.OpenVPN, "external-entry", "")
	if err != nil {
		return false
	}
	remotes, err := nativeopenvpn.Remotes(endpoint)
	return err == nil && len(remotes) == 1 && remotes[0].Validate() == nil
}
