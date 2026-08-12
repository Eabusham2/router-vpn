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
	"runtime"
	"strings"
	"time"
)

const localURL = "http://127.0.0.1:8788/"

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

	for _, dir := range []string{dataDir, generatedDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fatal(err)
		}
	}

	for _, required := range []string{
		filepath.Join(appDir, "router-vpn-client.exe"),
		filepath.Join(appDir, "modes.json"),
		filepath.Join(appDir, "logical-modes.json"),
		modesDir,
	} {
		if _, err := os.Stat(required); err != nil {
			fatal(fmt.Errorf("portable package is incomplete: %s: %w", required, err))
		}
	}

	copyDefault(filepath.Join(appDir, "routers.json"), filepath.Join(dataDir, "routers.json"))
	copyAlways(filepath.Join(appDir, "logical-modes.json"), dataLogical)
	wslOK, wslReason := prepareWindowsModeCatalog(filepath.Join(appDir, "modes.json"), dataModes, modesDir)
	if err := ensurePortableConfig(filepath.Join(dataDir, "client.json"), dataModes, modesDir, dataDir); err != nil {
		fatal(err)
	}
	writeRuntimeStatus(filepath.Join(dataDir, "windows-runtime.json"), wslOK, wslReason)

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
			"WSLENV="+portableWSLEnv(os.Getenv("WSLENV")),
			"PATH="+appDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fatal(err)
		}
		started = true
	}

	if !waitForController(12 * time.Second) {
		if started && cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		fatal(errors.New("local Router VPN controller did not become ready on 127.0.0.1:8788"))
	}

	if selfTest {
		if err := runSelfTest(dataDir); err != nil {
			if started {
				stopPortableController(cmd)
			}
			fatal(err)
		}
		if started {
			stopPortableController(cmd)
		}
		fmt.Println("Router VPN Portable self-test: OK")
		return
	}

	browserCmd, ownedWindow := openAppWindow(localURL, dataDir)
	if !ownedWindow || browserCmd == nil {
		// Portable must own the app-window lifetime. Falling back to an arbitrary
		// default browser gives us no reliable close signal and can leave the VPN
		// controller holding the portable directory/USB after the user closes UI.
		// Fail closed instead; supported Windows installations normally include
		// Edge, and Chrome/Brave are also accepted.
		if started {
			stopPortableController(cmd)
		}
		fatal(errors.New("Portable clean-exit requires Microsoft Edge, Chrome, or Brave app-window support; no lifecycle-owned browser was found"))
	}

	_ = browserCmd.Wait()
	if started {
		stopPortableController(cmd)
	}
}

func runSelfTest(dataDir string) error {
	for _, file := range []string{
		filepath.Join(dataDir, "client.json"),
		filepath.Join(dataDir, "routers.json"),
		filepath.Join(dataDir, "modes.windows.json"),
		filepath.Join(dataDir, "logical-modes.json"),
		filepath.Join(dataDir, "windows-runtime.json"),
	} {
		if st, err := os.Stat(file); err != nil || st.Size() == 0 {
			return fmt.Errorf("portable self-test missing generated Data file: %s", file)
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
	forbidden := map[string]bool{
		"max-quic-wg": true, "max-quic-awg": true,
		"max-tls-wg": true, "max-tls-awg": true,
	}
	for _, mode := range modes {
		if forbidden[mode.ID] {
			return fmt.Errorf("raw duplicate mode leaked into portable logical API: %s", mode.ID)
		}
	}
	return nil
}

func ensurePortableConfig(path, modesFile, modesDir, dataDir string) error {
	cfg := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &cfg)
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
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func prepareWindowsModeCatalog(src, dst, windowsModesDir string) (bool, string) {
	b, err := os.ReadFile(src)
	if err != nil {
		fatal(err)
	}
	var modes []map[string]any
	if err := json.Unmarshal(b, &modes); err != nil {
		fatal(fmt.Errorf("invalid portable modes.json: %w", err))
	}

	linuxModesDir, wslErr := wslPath(windowsModesDir)
	wslOK := wslErr == nil
	reason := "WSL2/default Linux distro is ready"
	if !wslOK {
		reason = "Windows full-tunnel runtime needs WSL2 with a default Linux distro; run Setup-Windows-Runtime.ps1 or use a native protocol client"
	}

	for _, mode := range modes {
		for _, key := range []string{"command", "check_command", "stop_command"} {
			raw, ok := mode[key].([]any)
			if !ok || len(raw) == 0 {
				continue
			}
			first, _ := raw[0].(string)
			if !strings.HasPrefix(first, "./") {
				continue
			}
			args := make([]any, 0, len(raw)+4)
			if wslOK {
				args = append(args, "wsl.exe", "--exec", "bash", strings.TrimRight(linuxModesDir, "/")+"/"+filepath.Base(first))
				args = append(args, raw[1:]...)
			} else {
				msg := strings.ReplaceAll(reason, "&", "and")
				args = append(args, "cmd.exe", "/d", "/c", "echo "+msg+" 1>&2 & exit /b 127")
			}
			mode[key] = args
		}
	}

	out, err := json.MarshalIndent(modes, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(dst, append(out, '\n'), 0o600); err != nil {
		fatal(err)
	}
	return wslOK, reason
}

func wslPath(path string) (string, error) {
	cmd := exec.Command("wsl.exe", "--exec", "wslpath", "-a", "-u", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	value := strings.TrimSpace(string(out))
	if value == "" {
		return "", errors.New("wslpath returned an empty path")
	}
	return value, nil
}

func portableWSLEnv(existing string) string {
	wanted := []string{
		"HOMEVPN_ROOT/p", "HOMEVPN_CLIENT_CONFIG/p", "HOMEVPN_PROFILE_ID",
		"HOMEVPN_ENDPOINT", "HOMEVPN_ADGUARD4", "HOMEVPN_ADGUARD6",
		"HOMEVPN_SOCKS_HOST", "HOMEVPN_SOCKS_PORT", "HOMEVPN_SOCKS_USER",
		"HOMEVPN_SOCKS_PASSWORD", "HOMEVPN_DAITA", "HOMEVPN_JUMBO",
		"HOMEVPN_SOCKS", "HOMEVPN_MTU", "HOMEVPN_PORTABLE",
	}
	seen := map[string]bool{}
	parts := make([]string, 0, len(wanted)+8)
	for _, part := range strings.Split(existing, ":") {
		part = strings.TrimSpace(part)
		if part != "" && !seen[part] {
			seen[part] = true
			parts = append(parts, part)
		}
	}
	for _, part := range wanted {
		if !seen[part] {
			seen[part] = true
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, ":")
}

func writeRuntimeStatus(path string, ready bool, message string) {
	b, _ := json.MarshalIndent(map[string]any{
		"wsl_ready": ready,
		"message": message,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	_ = os.WriteFile(path, append(b, '\n'), 0o600)
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

func openAppWindow(url, dataDir string) (*exec.Cmd, bool) {
	if runtime.GOOS != "windows" {
		return nil, false
	}
	profileDir := filepath.Join(dataDir, "BrowserProfile")
	_ = os.MkdirAll(profileDir, 0o700)
	candidates := []string{
		filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
	}
	for _, browser := range candidates {
		if strings.TrimSpace(browser) == "" {
			continue
		}
		if st, err := os.Stat(browser); err == nil && !st.IsDir() {
			cmd := exec.Command(browser,
				"--app="+url,
				"--user-data-dir="+profileDir,
				"--no-first-run",
				"--no-default-browser-check",
			)
			if cmd.Start() == nil {
				return cmd, true
			}
		}
	}
	return nil, false
}

func stopPortableController(cmd *exec.Cmd) {
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, localURL+"api/emergency-stop", bytes.NewReader(nil))
	if resp, err := client.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

func copyDefault(src, dst string) {
	if _, err := os.Stat(dst); err == nil {
		return
	}
	copyAlways(src, dst)
}

func copyAlways(src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "Router VPN Portable:", err)
	os.Exit(1)
}
