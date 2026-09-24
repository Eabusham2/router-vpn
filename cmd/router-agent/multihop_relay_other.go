//go:build !linux

package main

import (
	"errors"
	"os/exec"
)

func configureRelayProcess(cmd *exec.Cmd) error {
	return errors.New("the server relay owner requires the Linux router-agent runtime")
}
