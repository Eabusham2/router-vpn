package main

import "runtime"

// SOCKS public admission is limited to the installed retained-controller targets
// with complete TUN/WFP/PF path and joined-retirement acceptance gates.
// Source admission does not replace the actual installed native proofs.
func desktopNodeChainSOCKSAdmissionSupported(targetOS, targetArch string, retained bool) bool {
	return retained && (targetOS == "linux" || targetOS == "windows" || targetOS == "darwin") &&
		(targetArch == "amd64" || targetArch == "arm64")
}

func nativeNodeChainSOCKSHostSupported() bool {
	return desktopNodeChainSOCKSAdmissionSupported(runtime.GOOS, runtime.GOARCH, retainedNativeMultihopSelected())
}
