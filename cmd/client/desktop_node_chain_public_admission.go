package main

import "runtime"

// Preserve the existing ordinary Linux/Windows admission boundary. Darwin
// uses only the architectures supported by its retained installed controller;
// source admission does not manufacture PF, utun, native proof, or retirement.
func desktopNodeChainPublicAdmissionSupported(targetOS, targetArch string, retained bool) bool {
	return retained && (targetOS == "linux" || targetOS == "windows" ||
		targetOS == "darwin" && (targetArch == "amd64" || targetArch == "arm64"))
}

func nativeNodeChainHostSupported() bool {
	return desktopNodeChainPublicAdmissionSupported(runtime.GOOS, runtime.GOARCH, retainedNativeMultihopSelected())
}
