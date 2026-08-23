package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortableWritableStateStaysUnderData(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "Data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(data, "client.json")
	modes := filepath.Join(data, "modes.windows.json")
	modesDir := filepath.Join(root, "App", "RouterVPN", "modes")
	if err := ensurePortableConfig(cfgPath, modes, modesDir, data); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["listen"] != "127.0.0.1:8788" {
		t.Fatalf("portable controller listen=%v", cfg["listen"])
	}
	for _, key := range []string{"state_file", "profiles_file"} {
		got, _ := cfg[key].(string)
		rel, err := filepath.Rel(data, got)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			t.Fatalf("%s escaped portable Data directory: %q rel=%q err=%v", key, got, rel, err)
		}
	}
	if got, _ := cfg["modes_file"].(string); got != modes {
		t.Fatalf("modes_file=%q want %q", got, modes)
	}
}
