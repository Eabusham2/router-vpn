package main

import (
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This is the desktop producer's shape check. The sealed shared compiler still
// reconstructs and validates the complete original protocol, policy and owner.
// Imported-middle paths retain their separate SS2022-only final guard.
func desktopNodeChainFinalSupported(mode, startLayer string) bool {
	return mode == "shadowsocks" ||
		mode == "hysteria2" && (startLayer == "" || startLayer == "off" || startLayer == "aes-256-gcm" || startLayer == "aes-256-gcm+xor-whitening") ||
		mobilemultihop.NodeChainPrefixMode(mode) && (startLayer == "" || startLayer == "off")
}

// Packet finals retain the bounded all-paired Local graph. This descriptive
// check never authorizes a native endpoint, key, socket or measurement owner.
func desktopPacketFinalMembersSupported(members []desktopNodeChainMember, execution string) bool {
	if execution != "local" || !common.PairedPacketLocalMultihopSelection(nodeChainSelectedReferences(members)) {
		return false
	}
	for _, member := range members {
		p := member.Profile
		if p.External != nil || p.NodeKind != "" && p.NodeKind != "router-vpn" ||
			p.StartLayer != "" && p.StartLayer != "off" {
			return false
		}
	}
	return true
}
