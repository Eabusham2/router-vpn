package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPortableCatalogMapsRawWireGuardToNativeWindowsHelper(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "App", "RouterVPN")
	modesDir := filepath.Join(app, "modes")
	clientDir := filepath.Join(app, "client")
	if err := os.MkdirAll(modesDir, 0o755); err != nil { t.Fatal(err) }
	if err := os.MkdirAll(clientDir, 0o755); err != nil { t.Fatal(err) }
	helper := filepath.Join(clientDir, "native-wireguard-windows.ps1")
	if err := os.WriteFile(helper, []byte("# test\n"), 0o644); err != nil { t.Fatal(err) }

	src := filepath.Join(root, "modes.json")
	dst := filepath.Join(root, "modes.windows.json")
	input := []map[string]any{
		{"id":"wg", "command":[]string{"./run-mode.sh","wg"}, "check_command":[]string{"./check-mode.sh","wg"}, "stop_command":[]string{"./stop-mode.sh","wg"}},
		{"id":"wg-pq", "command":[]string{"./run-mode.sh","wg-pq"}, "check_command":[]string{"./check-mode.sh","wg-pq"}, "stop_command":[]string{"./stop-mode.sh","wg-pq"}},
	}
	b, _ := json.Marshal(input)
	if err := os.WriteFile(src, b, 0o644); err != nil { t.Fatal(err) }
	_, _ = prepareWindowsModeCatalog(src, dst, modesDir)
	outBytes, err := os.ReadFile(dst)
	if err != nil { t.Fatal(err) }
	var out []map[string]any
	if err := json.Unmarshal(outBytes, &out); err != nil { t.Fatal(err) }
	if len(out) != 2 { t.Fatalf("modes=%d", len(out)) }
	cmd, ok := out[0]["command"].([]any)
	if !ok || len(cmd) < 7 || cmd[0] != "powershell.exe" || cmd[len(cmd)-1] != "up" {
		t.Fatalf("raw WG was not mapped to native PowerShell helper: %#v", out[0]["command"])
	}
	if cmd[len(cmd)-2] != helper {
		t.Fatalf("wrong helper path: %#v", cmd)
	}
	pq, ok := out[1]["command"].([]any)
	if !ok || len(pq) < 1 || pq[0] != "cmd.exe" {
		t.Fatalf("layered WG-PQ should remain capability-gated when WSL is absent: %#v", out[1]["command"])
	}
}
