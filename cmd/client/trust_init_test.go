package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedPathProbeURL(t *testing.T) {
	accepted := []string{
		defaultPrivatePathProbeURL,
		"https://192.168.50.1/health",
		"http://127.0.0.1:8787/health",
		"http://router.home.arpa/health",
		"http://node.local/health",
		"http://[fd77:77::1]:8787/health",
	}
	for _, value := range accepted {
		if !trustedPathProbeURL(value) {
			t.Errorf("expected trusted path probe: %s", value)
		}
	}
	rejected := []string{
		legacyPublicHealthURL,
		"https://example.com/health",
		"https://1.1.1.1/health",
		"ftp://10.77.0.1/health",
		"not-a-url",
	}
	for _, value := range rejected {
		if trustedPathProbeURL(value) {
			t.Errorf("expected untrusted path probe: %s", value)
		}
	}
}

func TestMigrateClientTrustConfigCreatesSafeDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "client.json")
	if err := migrateClientTrustConfig(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil { t.Fatal(err) }
	if raw["health_url"] != defaultPrivatePathProbeURL {
		t.Fatalf("health_url=%v", raw["health_url"])
	}
}

func TestMigrateClientTrustConfigReplacesLegacyPublicProbe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, []byte(`{"listen":"127.0.0.1:8788","health_url":"`+legacyPublicHealthURL+`","custom":"preserve"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateClientTrustConfig(path); err != nil { t.Fatal(err) }
	b, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil { t.Fatal(err) }
	if raw["health_url"] != defaultPrivatePathProbeURL { t.Fatalf("health_url=%v", raw["health_url"]) }
	if raw["custom"] != "preserve" { t.Fatalf("unknown field lost: %v", raw) }
}

func TestMigrateClientTrustConfigPreservesPrivateCustomProbe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	custom := "https://192.168.50.133:9443/path-proof"
	if err := os.WriteFile(path, []byte(`{"health_url":"`+custom+`"}`), 0o600); err != nil { t.Fatal(err) }
	if err := migrateClientTrustConfig(path); err != nil { t.Fatal(err) }
	b, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil { t.Fatal(err) }
	if raw["health_url"] != custom { t.Fatalf("custom private probe changed: %v", raw["health_url"]) }
}
