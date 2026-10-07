package main

import (
	"errors"
	"fmt"
)

// Tor and Lyrebird are userspace helpers, not VPN drivers. The ARM64 client
// keeps the ARM64 packet engine/driver and may use Windows' supported x64
// execution layer for the checksum-pinned helper processes only.
func windowsTorArchitecture(arch string, canRunX64 func() (bool, error)) (string, error) {
	switch arch {
	case "amd64":
		return "x64 helpers", nil
	case "arm64":
		if canRunX64 == nil {
			return "", errors.New("Windows ARM64 Tor requires a verified x64 userspace execution capability")
		}
		ok, err := canRunX64()
		if err != nil {
			return "", fmt.Errorf("Windows ARM64 could not verify x64 Tor helper execution: %w", err)
		}
		if !ok {
			return "", errors.New("Windows ARM64 Tor requires Windows 11 x64 userspace emulation; this system did not report it enabled")
		}
		return "x64 helpers via Windows emulation; ARM64 VPN engine and driver", nil
	default:
		return "", fmt.Errorf("Tor helper execution is not implemented for Windows architecture %q", arch)
	}
}
