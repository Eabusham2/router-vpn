//go:build windows
// +build windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const localBaseURL = "http://127.0.0.1:8788"

func packageRoot() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

func localClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: dialer.DialContext,
		},
	}
}

func ready() bool {
	resp, err := localClient(time.Second).Get(localBaseURL + "/api/status")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func waitReady(deadline time.Time) bool {
	for time.Now().Before(deadline) {
		if ready() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return ready()
}

func emergencyStop() {
	req, err := http.NewRequest(http.MethodPost, localBaseURL+"/api/emergency-stop", bytes.NewBufferString("{}"))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := localClient(2 * time.Second).Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func hiddenCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

func requiredFiles(root string) (controller, app, tray, icon string, err error) {
	controller = filepath.Join(root, "router-vpn-client.exe")
	app = filepath.Join(root, "client", "RouterVPN-Windows-App.ps1")
	tray = filepath.Join(root, "client", "RouterVPN-Windows-Tray.ps1")
	icon = filepath.Join(root, "RouterVPN.ico")
	for _, path := range []string{controller, app, tray, icon, filepath.Join(root, "client.json"), filepath.Join(root, "modes.json"), filepath.Join(root, "logical-modes.json")} {
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() {
			return "", "", "", "", fmt.Errorf("required Router VPN package file is missing: %s", path)
		}
	}
	return controller, app, tray, icon, nil
}

func runSelfTest(root string) error {
	_, app, tray, _, err := requiredFiles(root)
	if err != nil {
		return err
	}
	env := append(os.Environ(), "HOMEVPN_ROOT="+root, "HOMEVPN_CLIENT_CONFIG="+filepath.Join(root, "client.json"), "HOMEVPN_NATIVE_APP=windows-wpf-product")
	uiTest := hiddenCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", app, "-BaseUrl", localBaseURL, "-SelfTest")
	uiTest.Dir = root
	uiTest.Env = env
	out, err := uiTest.CombinedOutput()
	if err != nil {
		return fmt.Errorf("native WPF self-test failed: %w: %s", err, string(out))
	}
	trayTest := hiddenCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", tray, "-BaseUrl", localBaseURL, "-SelfTest")
	trayTest.Dir = root
	trayTest.Env = env
	out, err = trayTest.CombinedOutput()
	if err != nil {
		return fmt.Errorf("native system-tray self-test failed: %w: %s", err, string(out))
	}
	return nil
}

func stopChild(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func run() error {
	root, err := packageRoot()
	if err != nil {
		return err
	}
	controller, app, tray, _, err := requiredFiles(root)
	if err != nil {
		return err
	}
	if len(os.Args) > 1 && os.Args[1] == "--self-test" {
		return runSelfTest(root)
	}

	owned := false
	var child *exec.Cmd
	if !ready() {
		child = hiddenCommand(controller)
		child.Dir = root
		child.Env = append(os.Environ(), "HOMEVPN_ROOT="+root, "HOMEVPN_CLIENT_CONFIG="+filepath.Join(root, "client.json"), "HOMEVPN_NATIVE_APP=windows-launcher")
		if err := child.Start(); err != nil {
			return fmt.Errorf("start local Router VPN controller: %w", err)
		}
		owned = true
		defer func() {
			emergencyStop()
			stopChild(child)
		}()
	}
	if !waitReady(time.Now().Add(12 * time.Second)) {
		return errors.New("local Router VPN controller did not become ready on 127.0.0.1:8788")
	}

	ui := hiddenCommand("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", app, "-BaseUrl", localBaseURL)
	ui.Dir = root
	ui.Env = append(os.Environ(), "HOMEVPN_ROOT="+root, "HOMEVPN_CLIENT_CONFIG="+filepath.Join(root, "client.json"), "HOMEVPN_NATIVE_APP=windows-wpf-product")
	ui.Stdout = os.Stdout
	ui.Stderr = os.Stderr
	if err := ui.Start(); err != nil {
		return fmt.Errorf("start native Router VPN app: %w", err)
	}

	trayCmd := hiddenCommand("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", tray, "-BaseUrl", localBaseURL, "-UiPid", fmt.Sprintf("%d", ui.Process.Pid))
	trayCmd.Dir = root
	trayCmd.Env = append(os.Environ(), "HOMEVPN_ROOT="+root, "HOMEVPN_CLIENT_CONFIG="+filepath.Join(root, "client.json"), "HOMEVPN_NATIVE_APP=windows-system-tray")
	if err := trayCmd.Start(); err != nil {
		stopChild(ui)
		return fmt.Errorf("start Router VPN system tray: %w", err)
	}

	uiErr := ui.Wait()
	stopChild(trayCmd)
	if uiErr != nil {
		return fmt.Errorf("native Router VPN app exited with an error: %w", uiErr)
	}
	if !owned {
		return nil
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		_ = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show($args[0], 'Router VPN') | Out-Null", err.Error()).Run()
		os.Exit(1)
	}
}
