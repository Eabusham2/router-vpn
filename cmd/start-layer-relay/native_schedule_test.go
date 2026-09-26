package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"router-vpn/internal/startwhitening"
	"testing"
)

func TestNativeWhiteningScheduleMatchesShippingRelay(t *testing.T) {
	const password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	path := filepath.Join(t.TempDir(), "private-key.json")
	raw, _ := json.Marshal(singBoxConfig{Inbounds: []singBoxEndpoint{{Type: "shadowsocks", Method: startwhitening.Method, Password: password}}})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := deriveKey(path)
	if err != nil {
		t.Fatal(err)
	}
	native, err := startwhitening.Key(startwhitening.Method, password)
	if err != nil {
		t.Fatal(err)
	}
	if actual != native {
		t.Fatal("native and shipping relay whitening schedules differ")
	}
}
