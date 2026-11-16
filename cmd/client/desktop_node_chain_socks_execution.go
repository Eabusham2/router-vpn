package main

import "router-vpn/internal/mobilemultihop"

// This is only the saved-source shape. The original typed SOCKS compiler and
// schema-three preparation still precede physical admission or a connection
// change. In particular the middle keeps its UDP association and credentials.
func desktopNodeChainSOCKSExecutionShape(members []desktopNodeChainMember) bool {
	if len(members) != 3 || !mobilemultihop.NodeChainPrefixMode(members[0].Mode) || members[2].Mode != "shadowsocks" ||
		!desktopNodeChainSOCKSMiddle(members[1].Profile, members[1].Mode) {
		return false
	}
	entry, final := members[0].Profile.StartLayer, members[2].Profile.StartLayer
	return (entry == "" || entry == "off" || entry == "aes-256-gcm" || entry == "aes-256-gcm+xor-whitening") &&
		(final == "" || final == "off")
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
	connect *mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy, socks *mobilemultihop.DesktopNodeChainSOCKSExecutionPhysicalPolicy) int {
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
	return count
}
