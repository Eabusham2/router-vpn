package main

import (
	"runtime"
	"testing"
)

func TestDesktopNodeChainPublicAdmissionPreservesPlatformBounds(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin", "android", "freebsd", ""} {
		for _, arch := range []string{"amd64", "arm64", "386", "arm", "riscv64", ""} {
			for _, retained := range []bool{false, true} {
				original := retained && (target == "linux" || target == "windows")
				added := retained && target == "darwin" && (arch == "amd64" || arch == "arm64")
				if got := desktopNodeChainPublicAdmissionSupported(target, arch, retained); got != (original || added) {
					t.Fatalf("ordinary public target %s/%s retained=%v: %v", target, arch, retained, got)
				}
			}
		}
	}
	if nativeNodeChainHostSupported() != desktopNodeChainPublicAdmissionSupported(runtime.GOOS, runtime.GOARCH, retainedNativeMultihopSelected()) {
		t.Fatal("ordinary public admission replaced its actual retained platform")
	}
	if nativeNodeChainPlatformSupported() != nativeNodeChainHostSupported() {
		t.Fatal("ordinary public route bypassed its captured target admission")
	}
}
