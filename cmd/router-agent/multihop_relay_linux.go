//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

func configureRelayProcess(cmd *exec.Cmd) error {
	// An orphaned privileged relay must not survive a router-agent crash/restart.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return nil
}
