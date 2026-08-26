package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareWindowsModeCatalogUsesNativeAdaptersAndFailsClosed(t *testing.T) {
	root := t.TempDir()
	appModes := filepath.Join(root, "App", "RouterVPN", "modes")
	appClient := filepath.Join(root, "App", "RouterVPN", "client")
	data := filepath.Join(root, "Data")
	for _, dir := range []string{appModes, appClient, data} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, helper := range []string{"native-wireguard-windows.ps1", "native-windows-mode.ps1"} {
		if err := os.WriteFile(filepath.Join(appClient, helper), []byte("# helper\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	modes := []map[string]any{
		{"id": "wg", "command": []string{"./run-mode.sh", "wg"}, "check_command": []string{"./check-mode.sh", "wg"}, "stop_command": []string{"./stop-mode.sh", "wg"}},
		{"id": "shadowsocks", "command": []string{"./run-mode.sh", "shadowsocks"}, "check_command": []string{"./check-mode.sh", "shadowsocks"}, "stop_command": []string{"./stop-mode.sh", "shadowsocks"}},
		{"id": "wg-pq", "command": []string{"./run-mode.sh", "wg-pq"}, "check_command": []string{"./check-mode.sh", "wg-pq"}, "stop_command": []string{"./stop-mode.sh", "wg-pq"}},
	}
	src := filepath.Join(root, "modes.json")
	dst := filepath.Join(data, "modes.windows.json")
	body, _ := json.Marshal(modes)
	if err := os.WriteFile(src, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareWindowsModeCatalog(src, dst, appModes); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	command := func(i int) []any { return got[i]["command"].([]any) }
	wg := command(0)
	if wg[0] != "powershell.exe" || !strings.Contains(wg[5].(string), "native-wireguard-windows.ps1") {
		t.Fatalf("WG not native: %#v", wg)
	}
	ss := command(1)
	joined := strings.Join(toStrings(ss), " ")
	if !strings.Contains(joined, "native-windows-mode.ps1") || !strings.Contains(joined, "shadowsocks") {
		t.Fatalf("layered mode not native: %s", joined)
	}
	pq := command(2)
	joined = strings.Join(toStrings(pq), " ")
	if pq[0] != "cmd.exe" || !strings.Contains(joined, "no native Windows adapter") {
		t.Fatalf("unsupported mode not fail-closed: %s", joined)
	}
	if strings.Contains(string(out), "wsl.exe") {
		t.Fatal("Windows catalog must not route through WSL")
	}
}

func toStrings(values []any) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.(string))
	}
	return out
}
