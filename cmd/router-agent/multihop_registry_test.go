package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"router-vpn/internal/multihoprelay"
	"testing"
)

func TestRegistryReadSupportsBoundedLargePQMaterials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	assets, node := pqPairingFixture("wg-pq")
	// Structural size-policy fixture, not a successful KEM negotiation. The
	// native ABI validates real algorithm key lengths independently.
	assets["rosenpass-client-public"] = bytes.Repeat([]byte{8}, 512*1024)
	assets["rosenpass-server-public"] = bytes.Repeat([]byte{9}, 512*1024)
	input, _ := json.Marshal(assets)
	var output bytes.Buffer
	if err := compilePQRelayProfile(bytes.NewReader(input), &output, "wg-pq", node, "198.51.100.2"); err != nil {
		t.Fatal(err)
	}
	var transport map[string]any
	if err := json.Unmarshal(output.Bytes(), &transport); err != nil {
		t.Fatal(err)
	}
	config := multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26271, TTLSeconds: 90,
		Exits: []multihoprelay.Exit{{ID: "exit", Mode: "wg-pq", NodeID: node, DNS: "192.168.50.133", Transport: transport}}}
	raw, _ := json.Marshal(config)
	if len(raw) <= 1<<20 || len(raw) >= multihoprelay.MaxRegistryBytes {
		t.Fatal("fixture does not exercise the changed boundary")
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readRelayRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(got)
	if !bytes.Equal(raw, encoded) {
		t.Fatal("large private credentials changed while loading")
	}
}

func TestRegistryReadRetainsPrivateFileAndSizeGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	if _, err := readRelayRegistry(path); !os.IsNotExist(err) {
		t.Fatal("missing registry lost optional startup semantics", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(multihoprelay.MaxRegistryBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err = readRelayRegistry(path); err == nil {
		t.Fatal("oversized registry accepted")
	}
	if err = os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readRelayRegistry(path); err == nil {
		t.Fatal("public key file accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = readRelayRegistry(link); err == nil {
		t.Fatal("linked registry accepted")
	}
}
