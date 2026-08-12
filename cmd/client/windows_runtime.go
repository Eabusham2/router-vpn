package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// prepareWindowsCatalogBeforeMain makes the generic installed Windows package
// usable without a separate wrapper script. Raw WireGuard is mapped to the
// official native WireGuard tunnel service; layered modes use WSL only when it
// is actually available and otherwise fail closed as unavailable.
func init() {
	if runtime.GOOS != "windows" {
		return
	}
	configPath := os.Getenv("HOMEVPN_CLIENT_CONFIG")
	if configPath == "" {
		configPath = ".\\client.json"
	}
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		log.Printf("Windows runtime catalog: resolve client config: %v", err)
		return
	}
	root := filepath.Dir(absConfig)
	helper := filepath.Join(root, "client", "Prepare-Windows-Mode-Catalog-v2.ps1")
	if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
		// Portable has a different immutable App/Data layout and prepares its
		// catalog in RouterVPNPortable.exe before the controller starts.
		return
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper, "-Root", root)
	cmd.Dir = root
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		log.Printf("Windows runtime catalog preparation failed: %v: %s", runErr, string(out))
	}
}
