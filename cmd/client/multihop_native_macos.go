//go:build !darwin

package main

import (
	"errors"
	"os/exec"
)

// The real nativeDarwinMultihopCommand lives in multihop_native_darwin.go and
// is selected automatically by Go's _darwin filename constraint. Non-Darwin
// builds still need the symbol because nativeMultihopPlatformCommand contains a
// runtime.GOOS branch, but they must never carry a duplicate macOS launcher.
func nativeDarwinMultihopCommand(_ *app, _ multihopSelection) (*exec.Cmd, error) {
	return nil, errors.New("native macOS multihop launcher is unavailable on this platform")
}
