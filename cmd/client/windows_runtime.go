package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// prepareWindowsCatalogBeforeMain makes the generic installed Windows package
// usable without a wrapper. Raw WireGuard maps to the official WireGuard
// tunnel service. Compatible layered modes map to the pinned native
// sing-box/Xray TUN adapter; unsupported modes remain fail-closed and WSL is
// never treated as native readiness.
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
		// Portable has an immutable App/Data layout and prepares its catalog in
		// RouterVPNPortable.exe before the controller starts.
		return
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper, "-Root", root)
	cmd.Dir = root
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		log.Printf("Windows runtime catalog preparation failed: %v: %s", runErr, string(out))
	}
}
