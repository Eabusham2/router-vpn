//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func hidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

func stop(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func run() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	root := filepath.Dir(exe)
	core := filepath.Join(root, "RouterVPNPortableCore.exe")
	updater := filepath.Join(root, "App", "RouterVPN", "router-vpn-update.exe")
	for _, path := range []string{core, updater} {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return fmt.Errorf("Portable package is incomplete: %s", path)
		}
	}

	// Self-test must stay fully deterministic/offline. The core launcher already
	// owns the relocation and process-cleanup checks used by CI.
	for _, arg := range os.Args[1:] {
		if arg == "--self-test" {
			cmd := hidden(core, os.Args[1:]...)
			cmd.Dir = root
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}
	}

	// Portable auto-update is supervised, never detached. It may download and
	// stage a verified exact-SHA Portable ZIP while the app is open. If the user
	// exits before that finishes, the updater is killed before this bootstrap
	// returns so no process can keep the portable folder/USB mounted.
	update := hidden(updater, "--portable", "--download", "--json")
	update.Dir = filepath.Dir(updater)
	update.Env = append(os.Environ(), "ROUTER_VPN_UPDATE_LAUNCH=windows-portable")
	if err := update.Start(); err != nil {
		update = nil // Network/update failure never blocks normal VPN startup.
	}

	coreCmd := hidden(core, os.Args[1:]...)
	coreCmd.Dir = root
	coreCmd.Stdout = os.Stdout
	coreCmd.Stderr = os.Stderr
	err = coreCmd.Run()
	stop(update)
	if err != nil {
		return fmt.Errorf("Portable Router VPN exited unsuccessfully: %w", err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		_ = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show($args[0], 'Router VPN Portable') | Out-Null", err.Error()).Run()
		os.Exit(1)
	}
}
