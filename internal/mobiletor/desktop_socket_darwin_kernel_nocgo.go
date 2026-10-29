//go:build darwin && !cgo

package mobiletor

import (
	"errors"
	"os"
)

// Ordinary controller cross-compilation does not provide native libproc socket
// proof. The actual desktop engine is built with the matching Apple SDK; a
// nonnative/no-cgo build cannot manufacture the privileged factory capability.
func desktopDarwinReadSocket(int) (desktopDarwinKernelSocket, error) {
	return desktopDarwinKernelSocket{}, errors.New("Darwin physical socket ownership requires the native libproc adapter")
}
func desktopDarwinUIDAvailable(uint32) bool       { return false }
func desktopDarwinUIDAccount(uint32, string) bool { return false }
func desktopDarwinUIDAbsentReadback(uint32) (bool, error) {
	return false, errors.New("Darwin physical identity lookup requires the native system namespace adapter")
}
func desktopDarwinNoUIDProcesses(uint32) error {
	return errors.New("Darwin process identity readback requires the native libproc adapter")
}
func desktopDarwinKernelAvailable() bool { return false }
func desktopDarwinReadTunnel(*os.File) (string, error) {
	return "", errors.New("Darwin tunnel control requires native libproc proof")
}
