package common

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShippedClientUsesPrivatePathProbe(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "client", "client.json.example")
	b, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	var cfg ClientConfig
	if err := json.Unmarshal(b, &cfg); err != nil { t.Fatal(err) }
	u, err := url.Parse(cfg.HealthURL)
	if err != nil { t.Fatal(err) }
	if u.Hostname() != "10.77.0.1" || u.Port() != "8787" || u.Path != "/health" {
		t.Fatalf("health_url must prove the private Router VPN path, got %q", cfg.HealthURL)
	}
}

func TestBundleGeneratorCarriesVersionedPrivateProbe(t *testing.T) {
	path := filepath.Join("..", "..", "server", "scripts", "create-bundle-json.py")
	b, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	text := string(b)
	for _, want := range []string{"'profileSchemaVersion':3", "'schema_version':3", "'node_kind':'router-vpn'", "'path_probe_url':'http://10.77.0.1:8787/health'", "'health_url':'http://10.77.0.1:8787/health'"} {
		if !strings.Contains(text, want) { t.Fatalf("bundle generator missing %s", want) }
	}
}
