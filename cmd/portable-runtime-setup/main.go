//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const createNewConsole = 0x00000010

func main() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	root := filepath.Dir(exe)
	script := filepath.Join(root, "App", "RouterVPN", "client", "Setup-Windows-Runtime.ps1")
	if _, err := os.Stat(script); err != nil {
		fmt.Fprintf(os.Stderr, "Router VPN runtime setup is missing: %s: %v\n", script, err)
		os.Exit(1)
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script)
	cmd.Dir = root
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewConsole}
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
