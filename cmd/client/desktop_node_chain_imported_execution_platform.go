package main

import (
	"runtime"

	"router-vpn/internal/common"
)

// The separately retained imported Darwin parent/child is not authority for a paired
// server graph or a candidate-prefix owner. These choices are UI hints only.
func nativeDesktopImportedTrioExecutionPlatformSupported() bool {
	return nativeDesktopOrderedExecutionPlatformSupported() ||
		retainedNativeMultihopSelected() && runtime.GOOS == "darwin" &&
			(runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
}

func desktopImportedTrioExecutionChoices() []string {
	if nativeDesktopImportedTrioExecutionPlatformSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
}

func desktopDarwinImportedTrioExecutionMembers(members []desktopNodeChainMember, requested string) bool {
	if requested != "server" && requested != "auto" || len(members) < 3 || len(members) > common.MultihopMaximumNodes ||
		!(desktopNodeChainImportedExecutionMiddle(members[len(members)-2].Profile) || len(members) >= 4 && desktopNodeChainImportedHostnameExecutionMiddle(members[len(members)-2].Profile)) ||
		desktopOrderedExecutionMembers(members, requested) != nil {
		return false
	}
	for index, member := range members {
		if index == len(members)-2 {
			continue
		}
		layer := member.Profile.StartLayer
		if layer != "" && layer != "off" && layer != "aes-256-gcm" && layer != "aes-256-gcm+xor-whitening" {
			return false
		}
	}
	return true
}

func nativeDesktopOrderedExecutionSelectionPlatformSupported(members []desktopNodeChainMember, requested string) bool {
	if nativeDesktopOrderedExecutionPlatformSupported() {
		return true
	}
	if runtime.GOOS == "darwin" && nativeDesktopHysteriaExecutionPlatformSupported() && desktopHysteriaExecutionMembers(members, requested) {
		return true
	}
	return runtime.GOOS == "darwin" && nativeDesktopImportedTrioExecutionPlatformSupported() &&
		(desktopDarwinImportedTrioExecutionMembers(members, requested) || desktopCONNECTTrioExecutionMembers(members, requested) || desktopSOCKSTrioExecutionMembers(members, requested) || desktopOpenVPNExecutionMembers(members, requested))
}

func desktopCONNECTTrioExecutionChoices() []string {
	if nativeDesktopImportedTrioExecutionPlatformSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
}
