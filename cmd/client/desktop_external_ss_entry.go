package main

import "router-vpn/internal/common"

// A stream entry still owns its complete captured graph, independent source,
// native lower and entry proof. This shape alone grants no physical permission.
func desktopExternalRetainedEntryOwner(owner *desktopExternalRuntime) bool {
	return desktopExternalPacketEntryOwner(owner) || desktopExternalSSEntryOwner(owner)
}
func desktopExternalSSEntryOwner(owner *desktopExternalRuntime) bool {
	if owner == nil || owner.direct || owner.predecessor != "" || owner.selection != "local" ||
		!desktopExternalSS2022Profile(owner.entry) || !desktopExternalSSEntryFinalProfile(owner.profile) ||
		owner.entry.ID == "" || owner.entry.ID == owner.profile.ID ||
		owner.profile.MultihopExecution != "" && owner.profile.MultihopExecution != "local" || owner.profile.MultihopEntryMode != "" {
		return false
	}
	policy := desktopOwnedNodeProtectionPolicy(owner.profile)
	return policy == "on-connect" || policy == "always"
}
func desktopExternalSS2022Profile(profile common.RouterProfile) bool {
	if profile.NodeKind != "external" || profile.External == nil || profile.External.Protocol != "shadowsocks" || profile.External.Shadowsocks == nil ||
		profile.StartLayer != "" && profile.StartLayer != common.StartLayerOff || profile.External.StartLayer != nil {
		return false
	}
	switch profile.External.Shadowsocks.Method {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return true
	}
	return false
}

func desktopExternalSSEntryFinalProfile(profile common.RouterProfile) bool {
	if desktopExternalSS2022Profile(profile) {
		return true
	}
	if profile.NodeKind != "external" || profile.External == nil || profile.StartLayer != "" && profile.StartLayer != common.StartLayerOff || profile.External.StartLayer != nil {
		return false
	}
	return profile.External.Protocol == "http-connect" && profile.External.HTTPConnect != nil || profile.External.Protocol == "https-connect" && profile.External.HTTPSConnect != nil
}
