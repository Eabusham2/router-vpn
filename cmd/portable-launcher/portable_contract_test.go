package main

import (
	"os"
	"strings"
	"testing"
)

func TestPortableCleanExitSourceContract(t *testing.T) {
	b, err := os.ReadFile("main_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"//go:build windows",
		`"router-vpn/internal/windowsapp"`,
		"os.Exit(windowsapp.Main(true))",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("portable native-app clean-exit contract missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"url.dll,FileProtocolHandler",
		"connectivitycheck.gstatic.com/generate_204",
		"openAppWindow",
		"browserCmd",
		"msedge.exe",
		"chrome.exe",
		"--app=",
		"BrowserProfile",
		".Process.Kill()",
		"legacyMain()",
		"controllerReady",
		"exec.Command",
		"http://127.0.0.1",
	} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("portable launcher contains retired browser/path fallback %q", forbidden)
		}
	}
}
