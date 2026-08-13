package main

import (
	"os"
	"strings"
	"testing"
)

func TestPortableCleanExitSourceContract(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"RouterVPN-Windows-App.ps1",
		"openNativeApp(nativeApp)",
		"nativeCmd.Wait()",
		"-SelfTest",
		"stopPortableController(cmd)",
		`localURL+"api/emergency-stop"`,
		"http://10.77.0.1:8787/health",
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
	} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("portable launcher contains retired browser/path fallback %q", forbidden)
		}
	}
}
