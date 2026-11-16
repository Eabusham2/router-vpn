package main

import (
	"runtime"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This shape grants no native authority. The generic execution constructor
// still retains every original paired source, packet identity and physical owner.
// Imported middles keep their separate final-SS contracts.
func desktopHysteriaExecutionNodes(nodes []common.MultihopNodeSelection) bool {
	if len(nodes) < 2 || len(nodes) > mobilemultihop.NodeChainMaximumNodes || nodes[len(nodes)-1].Mode != "hysteria2" {
		return false
	}
	for _, node := range nodes[:len(nodes)-1] {
		if !mobilemultihop.NodeChainPrefixMode(node.Mode) {
			return false
		}
	}
	return true
}

func desktopHysteriaExecutionMembers(members []desktopNodeChainMember, requested string) bool {
	if (requested != "server" && requested != "auto") || !desktopHysteriaExecutionNodes(nodeChainSelectedReferences(members)) {
		return false
	}
	ids, proofs := map[string]bool{}, map[string]bool{}
	for index, member := range members {
		profile := member.Profile
		if !validProfileID(profile.ID) || ids[profile.ID] || profile.External != nil ||
			(profile.NodeKind != "" && profile.NodeKind != "router-vpn") || !common.ValidNodeProofID(profile.NodeProofID) || proofs[profile.NodeProofID] {
			return false
		}
		if index == len(members)-1 {
			if profile.StartLayer != "" && profile.StartLayer != "off" {
				return false
			}
		} else if profile.StartLayer != "" && profile.StartLayer != "off" && profile.StartLayer != "aes-256-gcm" && profile.StartLayer != "aes-256-gcm+xor-whitening" {
			return false
		}
		ids[profile.ID], proofs[profile.NodeProofID] = true, true
	}
	return true
}

func nativeDesktopHysteriaExecutionPlatformSupported() bool {
	return nativeNodeChainPlatformSupported() && retainedNativeMultihopSelected() &&
		(runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin") &&
		(runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
}

func desktopHysteriaExecutionChoices() []string {
	if nativeDesktopHysteriaExecutionPlatformSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
}
