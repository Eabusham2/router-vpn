package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const localURL = "http://127.0.0.1:8788/"

var nativeLayeredWindowsModes = map[string]bool{
	"hysteria2": true, "shadowsocks": true, "naive-h2": true, "naive-h3": true,
	"reality-vision": true, "reality-pq-vision": true, "split": true, "max": true,
}

func main() {
	selfTest := false
	for _, arg := range os.Args[1:] {
		if arg == "--self-test" {
			selfTest = true
		}
	}
	exe, err := os.Executable()
	if err != nil {
		fatal(err)
	}
	root := filepath.Dir(exe)
	appDir := filepath.Join(root, "App", "RouterVPN")
	dataDir := filepath.Join(root, "Data")
	generatedDir := filepath.Join(dataDir, "generated")
	modesDir := filepath.Join(appDir, "modes")
	dataModes := filepath.Join(dataDir, "modes.windows.json")
	dataLogical := filepath.Join(dataDir, "logical-modes.json")
	nativeApp := filepath.Join(appDir, "client", "RouterVPN-Windows-App.ps1")

	if err := validatePortablePrivateParent(filepath.Join(dataDir, ".root-check")); err != nil {
		portableFatal(dataDir, selfTest, fmt.Errorf("unsafe Portable Data path: %w", err))
	}
	if err := ensurePortablePrivateDir(dataDir); err != nil {
		portableFatal(dataDir, selfTest, fmt.Errorf("prepare Portable Data directory: %w", err))
	}
	if err := ensurePortablePrivateDir(generatedDir); err != nil {
		portableFatal(dataDir, selfTest, fmt.Errorf("prepare Portable generated directory: %w", err))
	}

	for _, required := range []string{
		filepath.Join(appDir, "router-vpn-client.exe"),
		filepath.Join(appDir, "modes.json"),
		filepath.Join(appDir, "logical-modes.json"),
		modesDir,
		nativeApp,
	} {
		if _, err := os.Stat(required); err != nil {
			portableFatal(dataDir, selfTest, fmt.Errorf("portable package is incomplete: %s: %w", required, err))
		}
	}
	if err := copyPortablePrivate(filepath.Join(appDir, "routers.json"), filepath.Join(dataDir, "routers.json"), false); err != nil {
		portableFatal(dataDir, selfTest, fmt.Errorf("prepare Portable router store: %w", err))
	}
	if err := copyPortablePrivate(filepath.Join(appDir, "logical-modes.json"), dataLogical, true); err != nil {
		portableFatal(dataDir, selfTest, fmt.Errorf("publish Portable logical-mode catalog: %w", err))
	}
	nativeOK, nativeReason, err := prepareWindowsModeCatalog(filepath.Join(appDir, "modes.json"), dataModes, modesDir)
	if err != nil {
		portableFatal(dataDir, selfTest, err)
	}
	if err := ensurePortableConfig(filepath.Join(dataDir, "client.json"), dataModes, modesDir, dataDir); err != nil {
		portableFatal(dataDir, selfTest, err)
	}
	if err := writeRuntimeStatus(filepath.Join(dataDir, "windows-runtime.json"), nativeOK, nativeReason, dataDir); err != nil {
		portableFatal(dataDir, selfTest, err)
	}

	binary := filepath.Join(appDir, "router-vpn-client.exe")
	started := false
	var cmd *exec.Cmd
	if !controllerReady(250 * time.Millisecond) {
		cmd = exec.Command(binary)
		cmd.Dir = dataDir
		cmd.Env = append(os.Environ(),
			"HOMEVPN_ROOT="+dataDir,
			"HOMEVPN_CLIENT_CONFIG="+filepath.Join(dataDir, "client.json"),
			"HOMEVPN_PORTABLE=1",
			"HOMEVPN_MODES_DIR="+modesDir,
			"PATH="+appDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			portableFatal(dataDir, selfTest, err)
		}
		started = true
	}
	if !waitForController(30 * time.Second) {
		if started && cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		portableFatal(dataDir, selfTest, errors.New("local Router VPN controller did not become ready on 127.0.0.1:8788 within 30 seconds"))
	}
	if selfTest {
		if err := runSelfTest(dataDir, nativeApp); err != nil {
			if started {
				stopPortableController(cmd)
			}
			portableFatal(dataDir, selfTest, err)
		}
		if started {
			stopPortableController(cmd)
		}
		fmt.Println("Router VPN Portable self-test: OK")
		return
	}
	nativeCmd, err := openNativeApp(nativeApp)
	if err != nil {
		if started {
			stopPortableController(cmd)
		}
		fatal(err)
	}
	if err = nativeCmd.Wait(); err != nil {
		if started {
			stopPortableController(cmd)
		}
		fatal(fmt.Errorf("native Windows app exited unsuccessfully: %w", err))
	}
	if started {
		stopPortableController(cmd)
	}
}

func runSelfTest(dataDir, nativeApp string) error {
	for _, file := range []string{
		filepath.Join(dataDir, "client.json"),
		filepath.Join(dataDir, "routers.json"),
		filepath.Join(dataDir, "modes.windows.json"),
		filepath.Join(dataDir, "logical-modes.json"),
		filepath.Join(dataDir, "windows-runtime.json"),
	} {
		body, err := readPortablePrivate(file, maxPortablePrivateBytes)
		if err != nil || len(body) == 0 {
			return fmt.Errorf("portable self-test missing/unsafe generated Data file: %s: %w", file, err)
		}
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(localURL + "api/logical-modes")
	if err != nil {
		return fmt.Errorf("logical mode API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("logical mode API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var modes []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&modes); err != nil {
		return fmt.Errorf("decode logical modes: %w", err)
	}
	if len(modes) != 16 {
		return fmt.Errorf("portable UI expected 16 logical modes, got %d", len(modes))
	}
	forbidden := map[string]bool{"max-quic-wg": true, "max-quic-awg": true, "max-tls-wg": true, "max-tls-awg": true}
	for _, mode := range modes {
		if forbidden[mode.ID] {
			return fmt.Errorf("raw duplicate mode leaked into portable logical API: %s", mode.ID)
		}
	}
	test := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", nativeApp, "-BaseUrl", "http://127.0.0.1:8788", "-SelfTest")
	output, err := test.CombinedOutput()
	if err != nil {
		// RouterVPNPortable.exe is a GUI binary and may not inherit a hosted-CI
		// console. Capture only this bounded local shell self-test diagnostic so
		// self-test-error.txt names the failed UI/source assertion.
		detail := strings.TrimSpace(string(output))
		if len(detail) > 4096 {
			detail = detail[len(detail)-4096:]
		}
		if detail == "" {
			detail = "PowerShell produced no diagnostic output"
		}
		return fmt.Errorf("native WPF shell self-test: %w: %s", err, detail)
	}
	return nil
}

func ensurePortableConfig(path, modesFile, modesDir, dataDir string) error {
	cfg := map[string]any{}
	if _, err := os.Lstat(path); err == nil {
		body, err := readPortablePrivate(path, maxPortablePrivateBytes)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(body, &cfg); err != nil {
			return fmt.Errorf("existing Portable client.json is invalid; refusing silent reset: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, ok := cfg["listen"]; !ok {
		cfg["listen"] = "127.0.0.1:8788"
	}
	if _, ok := cfg["health_url"]; !ok {
		cfg["health_url"] = "http://10.77.0.1:8787/health"
	}
	if _, ok := cfg["auto_test_seconds"]; !ok {
		cfg["auto_test_seconds"] = 8
	}
	cfg["modes_file"] = modesFile
	cfg["scripts_dir"] = modesDir
	cfg["state_file"] = filepath.Join(dataDir, "state.json")
	cfg["profiles_file"] = filepath.Join(dataDir, "routers.json")
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWritePortablePrivate(path, append(body, '\n'))
}

func prepareWindowsModeCatalog(src, dst, windowsModesDir string) (bool, string, error) {
	body, err := readPortablePackageFile(src, maxPortablePrivateBytes)
	if err != nil {
		return false, "", err
	}
	var modes []map[string]any
	if err := json.Unmarshal(body, &modes); err != nil {
		return false, "", fmt.Errorf("invalid portable modes.json: %w", err)
	}
	helpers := filepath.Join(filepath.Dir(windowsModesDir), "client")
	nativeWG := filepath.Join(helpers, "native-wireguard-windows.ps1")
	nativeLayered := filepath.Join(helpers, "native-windows-mode.ps1")
	dataRoot := filepath.Dir(dst)
	runtimeDir := filepath.Join(dataRoot, "runtime", "windows")
	nativeReady := fileExists(filepath.Join(runtimeDir, "sing-box.exe")) && fileExists(filepath.Join(runtimeDir, "xray.exe"))
	reason := "Native Windows sing-box/Xray TUN runtime is ready"
	if !nativeReady {
		reason = "Native layered Windows runtime is not installed yet; run Setup-Windows-Runtime.ps1. Supported modes stay grey until their real engine check passes."
	}
	for _, mode := range modes {
		modeID, _ := mode["id"].(string)
		if modeID == "wg" && fileExists(nativeWG) {
			mode["command"] = psCommand(nativeWG, "up")
			mode["check_command"] = psCommand(nativeWG, "check")
			mode["stop_command"] = psCommand(nativeWG, "down")
			continue
		}
		if nativeLayeredWindowsModes[modeID] && fileExists(nativeLayered) {
			mode["command"] = psModeCommand(nativeLayered, modeID, "up")
			mode["check_command"] = psModeCommand(nativeLayered, modeID, "check")
			mode["stop_command"] = psModeCommand(nativeLayered, modeID, "down")
			continue
		}
		for _, key := range []string{"command", "check_command", "stop_command"} {
			raw, ok := mode[key].([]any)
			if !ok || len(raw) == 0 {
				continue
			}
			first, _ := raw[0].(string)
			if !strings.HasPrefix(first, "./") {
				continue
			}
			msg := fmt.Sprintf("Mode '%s' has no native Windows adapter yet. Router VPN will not pretend this mode is ready through a compatibility layer.", modeID)
			mode[key] = []any{"cmd.exe", "/d", "/c", "echo " + strings.ReplaceAll(msg, "&", "and") + " 1>&2 & exit /b 127"}
		}
	}
	out, err := json.MarshalIndent(modes, "", "  ")
	if err != nil {
		return false, "", err
	}
	if err := atomicWritePortablePrivate(dst, append(out, '\n')); err != nil {
		return false, "", err
	}
	return nativeReady, reason, nil
}

func psCommand(script, action string) []any {
	return []any{"powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, action}
}

func psModeCommand(script, mode, action string) []any {
	return []any{"powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Mode", mode, "-Action", action}
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular()
}

func writeRuntimeStatus(path string, ready bool, message, dataRoot string) error {
	body, err := json.MarshalIndent(map[string]any{
		"native_layered_ready": ready,
		"sing_box_ready":       fileExists(filepath.Join(dataRoot, "runtime", "windows", "sing-box.exe")),
		"xray_ready":           fileExists(filepath.Join(dataRoot, "runtime", "windows", "xray.exe")),
		"message":              message,
		"checked_at":           time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWritePortablePrivate(path, append(body, '\n'))
}

func controllerReady(timeout time.Duration) bool {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(localURL + "api/status")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode/100 == 2
}

func waitForController(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if controllerReady(500 * time.Millisecond) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func openNativeApp(script string) (*exec.Cmd, error) {
	if !fileExists(script) {
		return nil, fmt.Errorf("native Windows WPF app missing: %s", script)
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-BaseUrl", "http://127.0.0.1:8788")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start native Windows app: %w", err)
	}
	return cmd, nil
}

func stopPortableController(cmd *exec.Cmd) {
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, localURL+"api/emergency-stop", bytes.NewReader(nil))
	req.Header.Set("content-type", "application/json")
	if resp, err := client.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

func portableFatal(dataDir string, selfTest bool, err error) {
	if selfTest && dataDir != "" {
		// RouterVPNPortable.exe is built as a Windows GUI binary, so hosted CI may
		// not inherit stderr. Persist only the bounded self-test failure reason in
		// the disposable Portable Data directory; never include node/profile bytes.
		_ = ensurePortablePrivateDir(dataDir)
		_ = atomicWritePortablePrivate(filepath.Join(dataDir, "self-test-error.txt"), []byte(err.Error()+"\n"))
	}
	fatal(err)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "Router VPN Portable:", err)
	os.Exit(1)
}
