//go:build darwin

package mobiletor

import (
	"fmt"
	"runtime"
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
	if err := desktopPFValidateABI(release, build, runtime.GOARCH); err != nil {
		return "", err
	}
	return fmt.Sprintf("source=%s release=%s build=%s architecture=%s", desktopPFABIUpstream, release, build, runtime.GOARCH), nil
}
