package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
	exe, err := os.Executable()
	if err != nil {
		fatal(err)
	}
	root := filepath.Dir(exe)
	appDir := filepath.Join(root, "App", "RouterVPN")
	dataDir := filepath.Join(root, "Data")
	generatedDir := filepath.Join(dataDir, "generated")
	modesDir := filepath.Join(appDir, "modes")

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
	if err := ensurePortableConfig(filepath.Join(dataDir, "client.json"), appDir, dataDir); err != nil {
		fatal(err)
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
			fatal(err)
		}
		started = true
	}

	if !waitForController(12 * time.Second) {
		if started && cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		fatal(errors.New("local Router VPN controller did not become ready on 127.0.0.1:8788"))
	}
	openAppWindow(localURL)

	// Keep the PortableApps launcher alive with the child it started. This keeps
	// the writable Data directory self-contained and avoids orphaning the
	// controller when the portable package itself was responsible for launching it.
	if started && cmd != nil {
		if err := cmd.Wait(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			fatal(err)
		}
	}
}

func ensurePortableConfig(path, appDir, dataDir string) error {
	cfg := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	if _, ok := cfg["listen"]; !ok {
		cfg["listen"] = "127.0.0.1:8788"
	}
	if _, ok := cfg["health_url"]; !ok {
		cfg["health_url"] = "https://connectivitycheck.gstatic.com/generate_204"
	}
	if _, ok := cfg["auto_test_seconds"]; !ok {
		cfg["auto_test_seconds"] = 8
	}
	// Static code/catalog stays under App. All mutable state and imported private
	// material stays under Data. Rewriting these paths on every launch also
	// migrates older portable packages that incorrectly pointed at Data/modes.
	cfg["modes_file"] = filepath.Join(appDir, "modes.json")
	cfg["scripts_dir"] = filepath.Join(appDir, "modes")
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

func openAppWindow(url string) {
	if runtime.GOOS != "windows" {
		return
	}
	candidates := []struct {
		path string
		args []string
	}{
		{filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Microsoft", "Edge", "Application", "msedge.exe"), []string{"--app=" + url}},
		{filepath.Join(os.Getenv("PROGRAMFILES"), "Microsoft", "Edge", "Application", "msedge.exe"), []string{"--app=" + url}},
		{filepath.Join(os.Getenv("PROGRAMFILES"), "Google", "Chrome", "Application", "chrome.exe"), []string{"--app=" + url}},
		{filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Google", "Chrome", "Application", "chrome.exe"), []string{"--app=" + url}},
		{filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"), []string{"--app=" + url}},
		{filepath.Join(os.Getenv("PROGRAMFILES"), "BraveSoftware", "Brave-Browser", "Application", "brave.exe"), []string{"--app=" + url}},
		{filepath.Join(os.Getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "Application", "brave.exe"), []string{"--app=" + url}},
	}
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.path) == "" {
			continue
		}
		if st, err := os.Stat(candidate.path); err == nil && !st.IsDir() {
			if exec.Command(candidate.path, candidate.args...).Start() == nil {
				return
			}
		}
	}
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func copyDefault(src, dst string) {
	if _, err := os.Stat(dst); err == nil {
		return
	}
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
