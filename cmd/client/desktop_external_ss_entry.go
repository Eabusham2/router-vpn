package main

import "router-vpn/internal/common"

// A stream entry still owns its complete captured graph, independent source,
// native lower and entry proof. This shape alone grants no physical permission.
func desktopExternalRetainedEntryOwner(owner *desktopExternalRuntime) bool {
	return desktopExternalPacketEntryOwner(owner) || desktopExternalSSEntryOwner(owner)
}
func desktopExternalSSEntryOwner(owner *desktopExternalRuntime) bool {
	return desktopExternalSSEntryOwnerWithFinal(owner, desktopExternalSSEntryFinalProfile)
}
func desktopExternalSSEntryOwnerWithFinal(owner *desktopExternalRuntime, final func(common.RouterProfile) bool) bool {
	if owner == nil || owner.direct || owner.predecessor != "" || owner.selection != "local" ||
		!desktopExternalSS2022Profile(owner.entry) || !final(owner.profile) ||
		owner.entry.ID == "" || owner.entry.ID == owner.profile.ID ||
		owner.profile.MultihopExecution != "" && owner.profile.MultihopExecution != "local" || owner.profile.MultihopEntryMode != "" {
		return false
	}
	if owner.entry.StartLayer != "" && owner.entry.StartLayer != common.StartLayerOff && !desktopExternalSS2022Profile(owner.profile) {
		return false
	}
	policy := desktopOwnedNodeProtectionPolicy(owner.profile)
	return policy == "on-connect" || policy == "always"
}
func desktopExternalSS2022Profile(profile common.RouterProfile) bool {
	if profile.NodeKind != "external" || profile.External == nil || profile.External.Protocol != "shadowsocks" || profile.External.Shadowsocks == nil ||
		!desktopExternalSSCapturedLayer(profile) {
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
	if profile.External.Protocol == "hysteria2" {
		h := profile.External.Hysteria2
		return h != nil && h.Server != "" && h.Port > 0 && h.Password != ""
	}
	return profile.External.Protocol == "http-connect" && profile.External.HTTPConnect != nil || profile.External.Protocol == "https-connect" && profile.External.HTTPSConnect != nil
}

// This is only an admission shape check. Full compiler capture validates the
// private API, exact transport credentials and source binding before retirement.
func desktopExternalSSCapturedLayer(profile common.RouterProfile) bool {
	if profile.External == nil {
		return false
	}
	layer := profile.External.StartLayer
	switch profile.StartLayer {
	case "", common.StartLayerOff:
		return layer == nil
	case common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR:
		return layer != nil && layer.Mode == profile.StartLayer && layer.API != "" && len(layer.Transport) == 6 && layer.Transport["type"] == "shadowsocks" && layer.Transport["method"] == common.StartLayerAES256GCMTransport
	default:
		return false
	}
}
