package main

import "runtime"

// SOCKS public admission is limited to the installed retained-controller targets
// covered by the complete TUN/WFP path and joined-retirement acceptance gates.
// Source compilation and internal Darwin adapters do not grant admission.
func desktopNodeChainSOCKSAdmissionSupported(targetOS, targetArch string, retained bool) bool {
	return retained && (targetOS == "linux" || targetOS == "windows") &&
		(targetArch == "amd64" || targetArch == "arm64")
}

func nativeNodeChainSOCKSHostSupported() bool {
	return desktopNodeChainSOCKSAdmissionSupported(runtime.GOOS, runtime.GOARCH, retainedNativeMultihopSelected())
}
