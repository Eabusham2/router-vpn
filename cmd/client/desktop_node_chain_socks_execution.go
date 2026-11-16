package main

import "router-vpn/internal/mobilemultihop"

// This is only the saved-source shape. The original typed SOCKS compiler and
// schema-three preparation still precede physical admission or a connection
// change. In particular the middle keeps its UDP association and credentials.
func desktopNodeChainSOCKSExecutionShape(members []desktopNodeChainMember) bool {
	if len(members) < 3 || len(members) > mobilemultihop.NodeChainMaximumNodes {
		return false
	}
	middle, final := len(members)-2, len(members)-1
	if members[final].Mode != "shadowsocks" || !desktopNodeChainSOCKSMiddle(members[middle].Profile, members[middle].Mode) ||
		!desktopSOCKSExecutionPairedLayer(members[final].Profile.StartLayer) {
		return false
	}
	for _, member := range members[:middle] {
		layer := member.Profile.StartLayer
		if !mobilemultihop.NodeChainPrefixMode(member.Mode) || !desktopSOCKSExecutionPairedLayer(layer) {
			return false
		}
	}
	return true
}

func desktopSOCKSExecutionPairedLayer(layer string) bool {
	return layer == "" || layer == "off" || layer == "aes-256-gcm" || layer == "aes-256-gcm+xor-whitening"
}

func desktopSOCKSTrioExecutionMembers(members []desktopNodeChainMember, requested string) bool {
	return (requested == "server" || requested == "auto") && desktopNodeChainSOCKSExecutionShape(members) && desktopOrderedExecutionMembers(members, requested) == nil
}

func desktopSOCKSTrioExecutionChoices() []string {
	if nativeDesktopImportedTrioExecutionPlatformSupported() && nativeNodeChainSOCKSHostSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
}

func desktopNodeChainExecutionPhysicalCount(paired *mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy,
	connect *mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy, socks *mobilemultihop.DesktopNodeChainSOCKSExecutionPhysicalPolicy, openvpn ...*mobilemultihop.DesktopNodeChainOpenVPNExecutionPhysicalPolicy) int {
	count := 0
	if paired != nil {
		count++
	}
	if connect != nil {
		count++
	}
	if socks != nil {
		count++
	}
	for _, policy := range openvpn {
		if policy != nil {
			count++
		}
	}
	return count
}
