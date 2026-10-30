//go:build darwin

package mobiletor

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
)

func desktopDarwinPFCapturedABI() (string, error) {
	release, err := syscall.Sysctl("kern.osrelease")
	if err != nil {
		return "", fmt.Errorf("capture Darwin PF kernel release: %w", err)
	}
	build, err := syscall.Sysctl("kern.osversion")
	if err != nil {
		return "", fmt.Errorf("capture Darwin PF kernel build: %w", err)
	}
	version, err := syscall.Sysctl("kern.version")
	if err != nil {
		return "", fmt.Errorf("capture Darwin PF kernel source version: %w", err)
	}
	if version == "" || len(version) > 1024 || strings.ContainsAny(version, "\x00\r\n") {
		return "", fmt.Errorf("Darwin PF kernel source version is not a bounded receipt")
	}
	if err := desktopPFValidateABI(release, build, runtime.GOARCH); err != nil {
		return "", fmt.Errorf("%w (kern.version=%q)", err, version)
	}
	return fmt.Sprintf("source=%s release=%s build=%s architecture=%s kern.version=%q", desktopPFABIUpstream, release, build, runtime.GOARCH, version), nil
}
