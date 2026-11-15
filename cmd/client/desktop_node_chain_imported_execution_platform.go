package main

import "runtime"

// The portable imported suffix has no native packet carrier on the server.
// Its separately retained Darwin parent/child is not authority for a paired
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
	if requested != "server" && requested != "auto" || len(members) != 3 ||
		!desktopNodeChainImportedExecutionMiddle(members[1].Profile) ||
		desktopOrderedExecutionMembers(members, requested) != nil {
		return false
	}
	for _, index := range []int{0, 2} {
		layer := members[index].Profile.StartLayer
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
	return runtime.GOOS == "darwin" && nativeDesktopImportedTrioExecutionPlatformSupported() &&
		(desktopDarwinImportedTrioExecutionMembers(members, requested) || desktopCONNECTTrioExecutionMembers(members, requested))
}

func desktopCONNECTTrioExecutionChoices() []string {
	if nativeDesktopImportedTrioExecutionPlatformSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
}
