//go:build !linux

package mobiletor

import (
	"errors"
	"os/exec"
)

func startServerTorChild(_ *exec.Cmd, done chan struct{}) error {
	close(done)
	return errors.New("server Tor requires the Linux owned runtime")
}
