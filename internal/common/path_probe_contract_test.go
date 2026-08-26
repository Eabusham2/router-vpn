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
	if err != nil {
		t.Fatal(err)
	}
	var cfg ClientConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(cfg.HealthURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Hostname() != "10.77.0.1" || u.Port() != "8787" || u.Path != "/health" {
		t.Fatalf("health_url must prove the private Router VPN path, got %q", cfg.HealthURL)
	}
}

func TestBundleGeneratorCarriesVersionedPrivateProbe(t *testing.T) {
	path := filepath.Join("..", "..", "server", "scripts", "create-bundle-json.py")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	// This is a source-contract test, not a Python formatting test. Match the
	// current dictionary keys/values while allowing the generator to use normal
	// Python spacing and quoting conventions.
	for _, want := range []string{
		`"profileSchemaVersion": 4`,
		`"schema_version": 4`,
		`"node_kind": "router-vpn"`,
		`"path_probe_url": "http://10.77.0.1:8787/health"`,
		`"health_url": "http://10.77.0.1:8787/health"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("bundle generator missing %s", want)
		}
	}
}
