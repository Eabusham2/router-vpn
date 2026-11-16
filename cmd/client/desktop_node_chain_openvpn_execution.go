package main

import (
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativeopenvpn"
)

// This is a capability hint for an independently provisioned provider pair.
// The saved private source, complete compiler and original native owner remain
// authoritative; a normal unpaired import retains its existing Local path.
func desktopNodeChainOpenVPNExecutionMiddle(profile common.RouterProfile) bool {
	if !desktopNodeChainOpenVPNMiddle(profile, "openvpn") || profile.External.OpenVPNPairing == nil {
		return false
	}
	_, err := nativeopenvpn.ValidatePairing(*profile.External.OpenVPN, *profile.External.OpenVPNPairing)
	return err == nil
}

func desktopNodeChainOpenVPNExecutionShape(members []desktopNodeChainMember) bool {
	if len(members) < 3 || len(members) > mobilemultihop.NodeChainMaximumNodes {
		return false
	}
	middle, final := len(members)-2, len(members)-1
	if members[middle].Mode != "openvpn" || !desktopNodeChainOpenVPNExecutionMiddle(members[middle].Profile) || members[final].Mode != "shadowsocks" || !desktopOpenVPNExecutionPairedLayer(members[final].Profile.StartLayer) {
		return false
	}
	for _, member := range members[:middle] {
		if !mobilemultihop.NodeChainPrefixMode(member.Mode) || !desktopOpenVPNExecutionPairedLayer(member.Profile.StartLayer) {
			return false
		}
	}
	return true
}
func desktopOpenVPNExecutionPairedLayer(layer string) bool {
	return layer == "" || layer == "off" || layer == "aes-256-gcm" || layer == "aes-256-gcm+xor-whitening"
}
func desktopOpenVPNExecutionMembers(members []desktopNodeChainMember, requested string) bool {
	return (requested == "server" || requested == "auto") && desktopNodeChainOpenVPNExecutionShape(members) && desktopOrderedExecutionMembers(members, requested) == nil
}
func desktopOpenVPNExecutionChoices() []string {
	if nativeDesktopImportedTrioExecutionPlatformSupported() && nativeNodeChainOpenVPNPlatformSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
}
