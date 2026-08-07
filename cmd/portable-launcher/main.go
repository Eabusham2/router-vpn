package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

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
	copyDefault(filepath.Join(appDir, "client.json"), filepath.Join(dataDir, "client.json"))
	copyDefault(filepath.Join(appDir, "routers.json"), filepath.Join(dataDir, "routers.json"))
	copyDefault(filepath.Join(appDir, "modes.json"), filepath.Join(dataDir, "modes.json"))

	binary := filepath.Join(appDir, "router-vpn-client.exe")
	if _, err := os.Stat(binary); err != nil {
		fatal(fmt.Errorf("missing portable client: %w", err))
	}

	cmd := exec.Command(binary)
	cmd.Dir = dataDir
	cmd.Env = append(os.Environ(),
		"HOMEVPN_ROOT="+dataDir,
		"HOMEVPN_CLIENT_CONFIG="+filepath.Join(dataDir, "client.json"),
		"HOMEVPN_PORTABLE=1",
		"HOMEVPN_MODES_DIR="+modesDir,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fatal(err)
	}

	time.Sleep(900 * time.Millisecond)
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", "http://127.0.0.1:8788").Start()
	if err := cmd.Wait(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		fatal(err)
	}
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
