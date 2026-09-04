package main

import (
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestPublicTorBridgeProfileHidesPrivateRelayMetadata(t *testing.T) {
	bridge := "Bridge obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abcdefghijklmnopqrstuvwxyz012345 iat-mode=0"
	p := common.RouterProfile{
		SchemaVersion: common.RouterProfileSchemaVersion,
		ID:            "tor-private",
		Name:          "Tor obfs4",
		NodeKind:      "external",
		Endpoint:      "203.0.113.44:443",
		External: &common.ExternalNodeConfig{
			Protocol: "tor-bridge",
			TorBridge: &common.ExternalTorBridgeConfig{Transport: "obfs4", Bridges: []string{bridge}, SocksPort: 19050},
		},
		DNSMode: "rescue",
	}
	view := publicProfileFor(p)
	if view.Endpoint != "" {
		t.Fatalf("public Tor profile exposed its private bridge relay endpoint: %q", view.Endpoint)
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, private := range []string{"203.0.113.44:443", "0123456789ABCDEF0123456789ABCDEF01234567", "cert="} {
		if strings.Contains(text, private) {
			t.Fatalf("public Tor profile leaked private bridge material %q: %s", private, text)
		}
	}
	if !strings.Contains(text, `"protocol":"tor-bridge"`) {
		t.Fatalf("public Tor profile lost safe protocol identity: %s", text)
	}
}
