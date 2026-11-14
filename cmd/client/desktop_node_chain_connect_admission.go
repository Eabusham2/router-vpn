package main

import "runtime"

// A typed CONNECT graph requires the retained desktop controller and the
// ordinary ordered host on the same supported native target. This capability
// does not grant a source, transport proof or another platform's admission.
func desktopNodeChainCONNECTAdmissionSupported(targetOS, targetArch string, retained, orderedHost bool) bool {
	return retained && orderedHost && (targetOS == "linux" || targetOS == "windows" || targetOS == "darwin") &&
		(targetArch == "amd64" || targetArch == "arm64")
}

func nativeNodeChainCONNECTHostSupported() bool {
	return desktopNodeChainCONNECTAdmissionSupported(runtime.GOOS, runtime.GOARCH,
		retainedNativeMultihopSelected(), nativeNodeChainPlatformSupported())
}
