//go:build linux

package mobiletor

import (
	"os/exec"
	"runtime"
	"syscall"
)

func startServerTorChild(command *exec.Cmd, done chan struct{}) error {
	started := make(chan error, 1)
	go func() {
		// Linux's parent-death signal is owned by the creating thread. Retain
		// that exact thread through Wait rather than losing it to Go's pool.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		err := command.Start()
		started <- err
		if err == nil {
			_ = command.Wait()
		}
		close(done)
	}()
	return <-started
}
